"""
Bedrock Access Control Gateway — Streaming Handler (FastAPI + Lambda Web Adapter).

Handles /converse-stream requests via Lambda Function URL with response streaming.
Performs pre-flight checks (auth, policy, model access, quota), streams Bedrock
ConverseStream tokens as SSE events, and runs post-stream settlement (cost
estimation, usage update, ledger write, warning check).

Uses Lambda Web Adapter layer to enable Python-based response streaming.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from shared import (
    normalize_principal_id,
    lookup_principal_policy,
    check_model_access,
    lookup_model_pricing,
    check_quota,
    estimate_cost_krw,
    update_monthly_usage,
    write_request_ledger,
    _check_and_send_warning_email,
    log_structured,
)

# ---------------------------------------------------------------------------
# AWS Clients
# ---------------------------------------------------------------------------
bedrock_runtime = boto3.client("bedrock-runtime")

# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI()


def _sse(event: dict) -> str:
    """Format a dict as an SSE data line."""
    return f"data: {json.dumps(event, default=str)}\n\n"


# ---------------------------------------------------------------------------
# Identity Extraction for Lambda Web Adapter / Function URL
# ---------------------------------------------------------------------------

def extract_identity_from_furl_headers(request: Request) -> dict:
    """Extract IAM identity from Lambda Web Adapter request headers.

    Lambda Web Adapter passes the full requestContext as the
    ``x-amzn-request-context`` header (JSON-encoded).  We extract
    IAM fields from ``authorizer.iam`` and HTTP context for sourceIp.

    Returns a dict compatible with ``normalize_principal_id()``.
    On missing/malformed header, returns empty strings (fail-closed).
    """
    request_context_str = request.headers.get("x-amzn-request-context", "")
    if request_context_str:
        try:
            rc = json.loads(request_context_str)
            iam = rc.get("authorizer", {}).get("iam", {})
            http_ctx = rc.get("http", {})
            return {
                "userArn": iam.get("userArn", ""),
                "caller": iam.get("accessKey", ""),
                "accountId": iam.get("accountId", ""),
                "accessKey": iam.get("accessKey", ""),
                "sourceIp": http_ctx.get(
                    "sourceIp",
                    request.client.host if request.client else "",
                ),
                "userAgent": request.headers.get("user-agent", ""),
            }
        except (json.JSONDecodeError, AttributeError):
            pass

    # Fallback: empty fields (fail-closed downstream)
    return {
        "userArn": "",
        "caller": "",
        "accountId": "",
        "accessKey": "",
        "sourceIp": request.client.host if request.client else "",
        "userAgent": request.headers.get("user-agent", ""),
    }


# ---------------------------------------------------------------------------
# Bedrock ConverseStream Invocation
# ---------------------------------------------------------------------------

def invoke_bedrock_stream(model_id: str, request_body: dict):
    """Call Bedrock ConverseStream and yield parsed event dicts.

    Forwards ``messages`` and optional ``system``, ``inferenceConfig``,
    ``toolConfig`` from the client request body.  Yields one dict per
    stream event with a deterministic ``type`` field.

    No retry — streaming is not retryable mid-stream.
    """
    converse_params = {"modelId": model_id}
    for key in ("messages", "system", "inferenceConfig", "toolConfig"):
        if key in request_body:
            converse_params[key] = request_body[key]

    response = bedrock_runtime.converse_stream(**converse_params)

    for event in response["stream"]:
        if "contentBlockStart" in event:
            yield {
                "type": "content_block_start",
                "index": event["contentBlockStart"]["contentBlockIndex"],
                "content_block": event["contentBlockStart"].get("start", {}),
            }
        elif "contentBlockDelta" in event:
            yield {
                "type": "content_block_delta",
                "index": event["contentBlockDelta"]["contentBlockIndex"],
                "delta": event["contentBlockDelta"]["delta"],
            }
        elif "contentBlockStop" in event:
            yield {
                "type": "content_block_stop",
                "index": event["contentBlockStop"]["contentBlockIndex"],
            }
        elif "messageStop" in event:
            yield {
                "type": "message_stop",
                "stop_reason": event["messageStop"].get("stopReason", ""),
            }
        elif "metadata" in event:
            yield {
                "type": "metadata",
                "usage": event["metadata"].get("usage", {}),
            }


# ---------------------------------------------------------------------------
# Post-Stream Settlement
# ---------------------------------------------------------------------------

def run_settlement(
    principal_id: str,
    model_id: str,
    pricing: dict,
    input_tokens: int,
    output_tokens: int,
    request_id: str,
    start_time: float,
    identity_fields: dict,
    policy: dict,
    quota_result: dict,
) -> dict:
    """Post-stream cost settlement: estimate, update usage, write ledger, warn.

    Called only after Bedrock returns final usage metadata.  If ledger or
    usage writes fail, logs with ``alarm=True`` but does NOT retroactively
    fail the stream (tokens already delivered).
    """
    # Step 1: Estimate cost
    cost_krw = estimate_cost_krw(input_tokens, output_tokens, pricing)

    # Step 2: Update monthly usage (atomic ADD)
    try:
        update_monthly_usage(
            principal_id, model_id, cost_krw, input_tokens, output_tokens,
            pricing=pricing,
        )
    except Exception as e:
        log_structured(
            "error", "stream_monthly_usage_update_failed",
            request_id=request_id, error=str(e), alarm=True,
        )

    # Step 3: Write request ledger
    duration_ms = int((time.time() - start_time) * 1000)
    # Pending-pricing safety: persist 0 in the ledger when prices are None
    # so the ledger row is still write-able. The auto-sync backfill never
    # touches the ledger (it is immutable), so the zero is a permanent
    # record of "charged at zero because price was Pending at the time".
    _ledger_input_price = pricing.get("input_price_per_1k") if isinstance(pricing, dict) else None
    _ledger_output_price = pricing.get("output_price_per_1k") if isinstance(pricing, dict) else None
    _ledger_fx = pricing.get("exchange_rate_krw_per_usd") if isinstance(pricing, dict) else None
    ledger_entry = {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principal_id": principal_id,
        "model_id": model_id,
        "region": os.environ.get("AWS_REGION", "us-west-2"),
        "decision": "ALLOW",
        "denial_reason": "",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "estimated_cost_krw": cost_krw,
        "input_price_per_1k_krw": _ledger_input_price if _ledger_input_price is not None else Decimal(0),
        "output_price_per_1k_krw": _ledger_output_price if _ledger_output_price is not None else Decimal(0),
        "fx_rate": _ledger_fx if _ledger_fx is not None else Decimal("1482.5"),
        "pricing_source_at_charge": "pending" if (_ledger_input_price is None or _ledger_output_price is None) else (pricing.get("pricing_source") if isinstance(pricing, dict) else None),
        "duration_ms": duration_ms,
        "source_path": "gateway-stream",
    }
    try:
        write_request_ledger(ledger_entry)
    except Exception as e:
        # Stream already delivered — log alarm but don't fail
        log_structured(
            "error", "stream_ledger_write_failed",
            request_id=request_id, error=str(e), alarm=True,
        )

    # Step 4: Warning email check
    try:
        new_usage = quota_result["usage"]["cost_krw"] + float(cost_krw)
        _check_and_send_warning_email(
            principal_id, policy, new_usage,
            int(quota_result["limit"]["cost_krw"]),
        )
    except Exception as e:
        log_structured(
            "error", "stream_warning_check_failed",
            request_id=request_id, error=str(e),
        )

    remaining = max(
        0,
        float(Decimal(str(quota_result["remaining"]["cost_krw"])) - cost_krw),
    )

    return {
        "estimated_cost_krw": float(cost_krw),
        "remaining_quota_krw": remaining,
        "request_id": request_id,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "duration_ms": duration_ms,
    }


# ---------------------------------------------------------------------------
# Main Streaming Endpoint
# ---------------------------------------------------------------------------

@app.post("/")
async def stream_converse(request: Request):
    """Streaming Converse handler (FastAPI + Lambda Web Adapter).

    Phase 1 (pre-flight): extract identity, normalize, policy, model access,
        pricing, quota.  Returns SSE error on failure.
    Phase 2 (streaming): stream_start event, relay Bedrock events as SSE.
    Phase 3 (settlement): estimate cost, update usage, write ledger, warn.
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())

    # Parse request body
    try:
        body = await request.json()
    except Exception:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "invalid_request",
                        "message": "invalid JSON body"})]),
            media_type="text/event-stream", status_code=400,
        )

    # ── Phase 1: Pre-flight checks ──────────────────────────────────────

    identity_fields = extract_identity_from_furl_headers(request)
    principal_id = normalize_principal_id(identity_fields)

    if not principal_id:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "auth_failed",
                        "message": "unable to determine principal identity"})]),
            media_type="text/event-stream", status_code=403,
        )

    model_id = body.get("modelId", "")
    if not model_id:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "invalid_request",
                        "message": "modelId is required"})]),
            media_type="text/event-stream", status_code=400,
        )

    policy = lookup_principal_policy(principal_id)
    if not policy:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "no_policy",
                        "message": "no policy defined for principal"})]),
            media_type="text/event-stream", status_code=403,
        )

    if not check_model_access(policy, model_id):
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "model_denied",
                        "message": f"model {model_id} not in allowed list"})]),
            media_type="text/event-stream", status_code=403,
        )

    pricing = lookup_model_pricing(model_id)
    if not pricing:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "no_pricing",
                        "message": f"no pricing for model {model_id}"})]),
            media_type="text/event-stream", status_code=403,
        )

    quota_result = check_quota(principal_id, policy)
    if not quota_result["allowed"]:
        return StreamingResponse(
            iter([_sse({"type": "error", "error_code": "quota_exceeded",
                        "message": "monthly cost quota exceeded"})]),
            media_type="text/event-stream", status_code=429,
        )

    # ── Phase 2 + 3: Streaming generator ────────────────────────────────

    async def event_generator():
        try:
            # Phase 2: stream_start
            yield _sse({
                "type": "stream_start",
                "request_id": request_id,
                "model_id": model_id,
            })

            input_tokens = 0
            output_tokens = 0
            stop_reason = ""

            # Bedrock sends messageStop before metadata, but Req 5.4
            # requires message_stop to include usage.  Buffer the stop
            # reason and emit message_stop after metadata arrives.
            for evt in invoke_bedrock_stream(model_id, body):
                if evt["type"] in (
                    "content_block_start",
                    "content_block_delta",
                    "content_block_stop",
                ):
                    yield _sse(evt)
                elif evt["type"] == "message_stop":
                    stop_reason = evt.get("stop_reason", "")
                elif evt["type"] == "metadata":
                    usage = evt.get("usage", {})
                    input_tokens = usage.get("inputTokens", 0)
                    output_tokens = usage.get("outputTokens", 0)

            # Emit message_stop with usage (Req 5.4)
            yield _sse({
                "type": "message_stop",
                "stop_reason": stop_reason,
                "usage": {
                    "inputTokens": input_tokens,
                    "outputTokens": output_tokens,
                },
            })

            # Phase 3: Settlement
            settlement = run_settlement(
                principal_id, model_id, pricing,
                input_tokens, output_tokens,
                request_id, start_time,
                identity_fields, policy, quota_result,
            )
            yield _sse({"type": "settlement", **settlement})

        except Exception as e:
            log_structured(
                "error", "stream_error",
                request_id=request_id, error=str(e),
            )
            yield _sse({
                "type": "error",
                "error_code": "stream_error",
                "message": str(e),
            })
            # Mid-stream error: skip settlement, close stream

    return StreamingResponse(event_generator(), media_type="text/event-stream")
