"""
Bedrock Access Control Gateway — Lambda Handler (v1).

Implements: request parsing, principal extraction, policy lookup,
model access control, KRW cost-based monthly quota enforcement,
model pricing lookup, Bedrock Converse invocation,
idempotency, audit ledger, session metadata, and approval flow.

Phase 2: KRW cost-based monthly quota (replaces token-count daily quota).
KST (UTC+9) for all monthly boundaries per Q3 decision.

v1: Converse API only (non-streaming).
ConverseStream, InvokeModel, InvokeModelWithResponseStream → v2.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class ConflictError(Exception):
    """Raised when an idempotency record is already IN_PROGRESS (409)."""
    pass

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENV = os.environ.get("ENVIRONMENT", "dev")
TABLE_PRINCIPAL_POLICY = os.environ.get("TABLE_PRINCIPAL_POLICY", "")
TABLE_DAILY_USAGE = os.environ.get("TABLE_DAILY_USAGE", "")
TABLE_MONTHLY_USAGE = os.environ.get("TABLE_MONTHLY_USAGE", "")
TABLE_MODEL_PRICING = os.environ.get("TABLE_MODEL_PRICING", "")
TABLE_TEMPORARY_QUOTA_BOOST = os.environ.get("TABLE_TEMPORARY_QUOTA_BOOST", "")
TABLE_APPROVAL_REQUEST = os.environ.get("TABLE_APPROVAL_REQUEST", "")
TABLE_REQUEST_LEDGER = os.environ.get("TABLE_REQUEST_LEDGER", "")
TABLE_SESSION_METADATA = os.environ.get("TABLE_SESSION_METADATA", "")
TABLE_IDEMPOTENCY_RECORD = os.environ.get("TABLE_IDEMPOTENCY_RECORD", "")
TABLE_APPROVAL_PENDING_LOCK = os.environ.get("TABLE_APPROVAL_PENDING_LOCK", "")

# Team config table — derived from existing table name pattern
# (not passed as env var to avoid terraform change)
_TABLE_TEAM_CONFIG = ""
def _get_team_config_table_name():
    global _TABLE_TEAM_CONFIG
    if not _TABLE_TEAM_CONFIG:
        # Derive from any existing table name: bedrock-gw-{env}-{region}-{name}
        ref = TABLE_PRINCIPAL_POLICY  # e.g. bedrock-gw-dev-us-west-2-principal-policy
        if ref:
            prefix = ref.rsplit("-principal-policy", 1)[0]  # bedrock-gw-dev-us-west-2
            _TABLE_TEAM_CONFIG = f"{prefix}-team-config"
    return _TABLE_TEAM_CONFIG
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "")
SES_ADMIN_GROUP_EMAIL = os.environ.get("SES_ADMIN_GROUP_EMAIL", "")
SES_REGION = os.environ.get("SES_REGION", "us-east-1")

# ---------------------------------------------------------------------------
# KST Timezone (Q3 decision: KST for all monthly boundaries)
# ---------------------------------------------------------------------------
KST = timezone(timedelta(hours=9))

# ---------------------------------------------------------------------------
# Model Pricing Cache (cold-start loaded, fail-closed if empty)
# ---------------------------------------------------------------------------
_model_pricing_cache: dict = {}

# ---------------------------------------------------------------------------
# AWS Clients (initialized once per Lambda container)
# ---------------------------------------------------------------------------
import boto3

dynamodb = boto3.resource("dynamodb")
bedrock_runtime = boto3.client("bedrock-runtime")
ses_client = boto3.client("ses", region_name=SES_REGION)
sfn_client = boto3.client("stepfunctions")
s3_client = boto3.client("s3")
sqs_client = boto3.client("sqs")

# v2 async job config
TABLE_JOB_STATE = os.environ.get("TABLE_JOB_STATE", "")
TABLE_CONCURRENCY_SEMAPHORE = os.environ.get("TABLE_CONCURRENCY_SEMAPHORE", "")
PAYLOAD_BUCKET = os.environ.get("PAYLOAD_BUCKET", "")
SFN_STATE_MACHINE_ARN = os.environ.get("SFN_STATE_MACHINE_ARN", "")
SQS_JOB_QUEUE_URL = os.environ.get("SQS_JOB_QUEUE_URL", "")
GLOBAL_QUEUE_LIMIT = int(os.environ.get("GLOBAL_QUEUE_LIMIT", "500"))
PER_USER_QUEUE_LIMIT = int(os.environ.get("PER_USER_QUEUE_LIMIT", "100"))


# ---------------------------------------------------------------------------
# Principal Extraction
# ---------------------------------------------------------------------------

def extract_identity(request_context: dict) -> dict:
    """Extract raw identity fields from API Gateway requestContext.

    Returns all fields for SessionMetadata audit preservation.
    Normalization is handled by normalize_principal_id() (Candidate F).
    """
    identity = request_context.get("identity", {})
    return {
        "userArn": identity.get("userArn", ""),
        "caller": identity.get("caller", ""),
        "accountId": identity.get("accountId", ""),
        "accessKey": identity.get("accessKey", ""),
        "sourceIp": identity.get("sourceIp", ""),
        "userAgent": identity.get("userAgent", ""),
    }


def normalize_principal_id(identity_fields: dict) -> str:
    """Derive a canonical principal_id from raw identity fields.

    Normalization rule: Candidate F — ``<account>#<role-name>``.
    Based on C1 live evidence (admin FSx, 2026-03-17).

    Input userArn pattern (assumed-role):
        arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>

    Fail-closed conditions (returns "" → deny-by-default):
        - No userArn
        - Not an assumed-role ARN
        - Malformed ARN (fewer than 3 ``/``-delimited segments)
        - Role name does not start with ``BedrockUser-``
        - Role name is ``BedrockUser-Shared`` (non-personal admin role)
        - Account ID not extractable
    """
    user_arn = identity_fields.get("userArn", "")
    if not user_arn:
        return ""  # fail closed — no userArn

    if ":assumed-role/" not in user_arn:
        return ""  # fail closed — not an assumed-role ARN

    parts = user_arn.split("/")
    if len(parts) < 3:
        return ""  # fail closed — malformed

    role_name = parts[1]

    if not role_name.startswith("BedrockUser-"):
        return ""  # fail closed — unexpected role pattern

    if role_name == "BedrockUser-Shared":
        return ""  # fail closed — shared/admin role, not per-user

    account_id = user_arn.split(":")[4]
    if not account_id:
        return ""  # fail closed — account not extractable

    return f"{account_id}#{role_name}"


# ---------------------------------------------------------------------------
# Response Helpers
# ---------------------------------------------------------------------------

def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }

def deny_response(reason: str, status_code: int = 403) -> dict:
    """Deny-by-default response structure."""
    return _response(status_code, {
        "decision": "DENY",
        "denial_reason": reason,
    })

def error_response(message: str, status_code: int = 500) -> dict:
    return _response(status_code, {
        "decision": "ERROR",
        "error": message,
    })


# ---------------------------------------------------------------------------
# Structured Logging
# ---------------------------------------------------------------------------

def log_structured(level: str, message: str, **kwargs):
    """Emit structured JSON log entry to CloudWatch."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "environment": ENV,
        **kwargs,
    }
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(json.dumps(entry, default=str))


# ---------------------------------------------------------------------------
# Interface Placeholders (Task 4-9 will implement)
# ---------------------------------------------------------------------------

def check_idempotency(request_id: str) -> dict | None:
    """Check IdempotencyRecord for duplicate request_id.

    Returns cached response dict if COMPLETED.
    Raises ConflictError (409) if IN_PROGRESS.
    Returns None if no record exists.
    Req 7.2: duplicate request_id → return previous result without re-invoking Bedrock.
    """
    table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
    resp = table.get_item(Key={"request_id": request_id})
    item = resp.get("Item")
    if not item:
        return None
    status = item.get("status", "")
    if status == "COMPLETED":
        cached = item.get("cached_response")
        if cached:
            if isinstance(cached, str):
                return json.loads(cached)
            return cached
        return {}
    if status == "IN_PROGRESS":
        raise ConflictError(f"Request {request_id} is already in progress")
    return None

def create_idempotency_record(request_id: str, principal_id: str) -> bool:
    """Create IdempotencyRecord with status IN_PROGRESS.

    Uses conditional PutItem (attribute_not_exists) for atomicity.
    TTL: 24 hours. Req 7.3.
    Returns True if created, False if already exists.
    """
    table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
    ttl_val = int(time.time()) + 24 * 3600
    try:
        table.put_item(
            Item={
                "request_id": request_id,
                "principal_id": principal_id,
                "status": "IN_PROGRESS",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl": ttl_val,
            },
            ConditionExpression="attribute_not_exists(request_id)",
        )
        return True
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def complete_idempotency_record(request_id: str, response_body: dict) -> None:
    """Update IdempotencyRecord to COMPLETED with cached response.

    Req 7.2, 7.3: store enough state to replay previous result.
    """
    table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
    table.update_item(
        Key={"request_id": request_id},
        UpdateExpression="SET #s = :s, cached_response = :r, completed_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "COMPLETED",
            ":r": json.dumps(response_body, default=str),
            ":t": datetime.now(timezone.utc).isoformat(),
        },
    )


def lookup_principal_policy(principal_id: str) -> dict | None:
    """Fetch PrincipalPolicy from DynamoDB.

    Returns policy dict or None if not found.
    Req 1.4, 1.5: lookup policy, deny if absent.
    """
    table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    resp = table.get_item(Key={"principal_id": principal_id})
    item = resp.get("Item")
    if not item:
        return None
    # Convert Decimal values to int for JSON serialization
    for k in ("daily_input_token_limit", "daily_output_token_limit",
              "monthly_cost_limit_krw", "max_monthly_cost_limit_krw"):
        if k in item and isinstance(item[k], Decimal):
            item[k] = int(item[k])
    return item


def check_model_access(policy: dict, model_id: str) -> bool:
    """Check if model_id is in policy's allowed_models list.

    Req 3.1-3.3: model must be in allowed_models; empty list → deny all.
    """
    allowed = policy.get("allowed_models", [])
    if not allowed:
        return False
    return model_id in allowed


# ---------------------------------------------------------------------------
# KST Date Helpers (Q3: KST for all monthly boundaries)
# ---------------------------------------------------------------------------

def current_month_kst() -> str:
    """Return current month as YYYY-MM in KST (UTC+9)."""
    return datetime.now(KST).strftime("%Y-%m")


def end_of_month_ttl_kst() -> int:
    """Return Unix epoch for ~35 days from now (MonthlyUsage TTL).

    TTL is relative, not boundary-dependent. 35 days ensures records
    survive the full month plus a few days for late queries.
    """
    return int(time.time()) + 35 * 24 * 3600


# ---------------------------------------------------------------------------
# Model Pricing Lookup (Task 2.1 — fail-closed if missing)
# ---------------------------------------------------------------------------

def _load_model_pricing_cache() -> dict:
    """Scan ModelPricing table and return {model_id: {input_price_per_1k, output_price_per_1k}}.

    Called once at cold start. Returns empty dict on error (fail-closed).
    """
    if not TABLE_MODEL_PRICING:
        return {}
    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        resp = table.scan()
        cache = {}
        for item in resp.get("Items", []):
            mid = item.get("model_id", "")
            if mid:
                cache[mid] = {
                    "input_price_per_1k": Decimal(str(item.get("input_price_per_1k", 0))),
                    "output_price_per_1k": Decimal(str(item.get("output_price_per_1k", 0))),
                }
        return cache
    except Exception as e:
        logger.error(f"Failed to load model pricing cache: {e}")
        return {}


def lookup_model_pricing(model_id: str) -> dict | None:
    """Look up pricing for a model. Returns pricing dict or None (fail-closed).

    Uses cold-start cache. If cache is empty, attempts one reload.
    Missing pricing → caller must deny.
    """
    global _model_pricing_cache
    if not _model_pricing_cache:
        _model_pricing_cache = _load_model_pricing_cache()
    pricing = _model_pricing_cache.get(model_id)
    if pricing is not None:
        return pricing
    # Cache miss — try one reload in case pricing was added after cold start
    _model_pricing_cache = _load_model_pricing_cache()
    return _model_pricing_cache.get(model_id)


# ---------------------------------------------------------------------------
# Cost Estimation (Task 2.2)
# ---------------------------------------------------------------------------

def estimate_cost_krw(input_tokens: int, output_tokens: int, pricing: dict) -> Decimal:
    """Calculate estimated KRW cost for a request.

    Formula (Q1 decision): (input × input_price_per_1k / 1000) + (output × output_price_per_1k / 1000)
    Returns Decimal for DynamoDB compatibility.
    """
    input_cost = Decimal(str(input_tokens)) * pricing["input_price_per_1k"] / Decimal("1000")
    output_cost = Decimal(str(output_tokens)) * pricing["output_price_per_1k"] / Decimal("1000")
    return input_cost + output_cost


# ---------------------------------------------------------------------------
# Gateway Config — operator-configurable controls (DynamoDB-backed)
# ---------------------------------------------------------------------------
# Stored as a reserved item in principal-policy table:
#   principal_id = "__gateway_config__"
# No new table, no Terraform change, no IAM change.
# ---------------------------------------------------------------------------

_gateway_config_cache: dict = {}
_gateway_config_ts: float = 0
GATEWAY_CONFIG_CACHE_TTL_S = 30  # refresh every 30s

GATEWAY_CONFIG_KEY = "__gateway_config__"


def _get_gateway_config() -> dict:
    """Read operator config from principal-policy table. Cached 30s.

    Returns dict with at least:
      quota_enforcement_enabled: bool (default True)
    """
    global _gateway_config_cache, _gateway_config_ts
    now = time.time()
    if _gateway_config_cache and (now - _gateway_config_ts) < GATEWAY_CONFIG_CACHE_TTL_S:
        return _gateway_config_cache

    defaults = {"quota_enforcement_enabled": True}
    try:
        table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        resp = table.get_item(Key={"principal_id": GATEWAY_CONFIG_KEY})
        item = resp.get("Item")
        if not item:
            _gateway_config_cache = defaults
        else:
            _gateway_config_cache = {
                "quota_enforcement_enabled": bool(item.get("quota_enforcement_enabled", True)),
            }
        _gateway_config_ts = now
    except Exception as e:
        log_structured("error", "gateway_config_read_failed", error=str(e))
        # Fail-closed: if config read fails, enforce quota
        _gateway_config_cache = defaults
        _gateway_config_ts = now
    return _gateway_config_cache


# ---------------------------------------------------------------------------
# Quota Check — KRW Monthly (Task 2.3, replaces old token-count daily check)
# ---------------------------------------------------------------------------

def check_quota(principal_id: str, policy: dict) -> dict:
    """Check monthly KRW cost usage against principal quota.

    Aggregates MonthlyUsage across all models for current month (KST),
    checks TemporaryQuotaBoost for active boosts, caps at hard limit.
    Returns {"allowed": bool, "usage": {...}, "limit": {...}, "remaining": {...}}.
    Req 4.1-4.2, 4.5, 4.8: global quota, model-level accounting.
    Q1: KRW cost-based. Q3: KST monthly boundary.

    Operator toggle: if quota_enforcement_enabled=false in gateway config,
    quota check always returns allowed=true but still computes and reports
    usage/limit for monitoring. Fail-closed: config read failure → enforce.
    """
    month = current_month_kst()
    pk = f"{principal_id}#{month}"

    # Aggregate MonthlyUsage across all models for this month
    table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    resp = table.query(
        KeyConditionExpression="principal_id_month = :pk",
        ExpressionAttributeValues={":pk": pk},
    )
    total_cost_krw = Decimal("0")
    for item in resp.get("Items", []):
        total_cost_krw += Decimal(str(item.get("cost_krw", 0)))

    # Base limit from policy (default 500,000 KRW)
    base_limit = int(policy.get("monthly_cost_limit_krw", 500000))
    # Hard cap (default 2,000,000 KRW)
    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 2000000))

    # Check TemporaryQuotaBoost for active KRW boosts
    boost_cost_krw = 0
    now_epoch = int(time.time())
    boost_table = dynamodb.Table(TABLE_TEMPORARY_QUOTA_BOOST)
    boost_resp = boost_table.query(
        KeyConditionExpression="principal_id = :pid",
        ExpressionAttributeValues={":pid": principal_id},
    )
    for item in boost_resp.get("Items", []):
        ttl_val = int(item.get("ttl", 0))
        if ttl_val > now_epoch:  # still active
            boost_cost_krw += int(item.get("extra_cost_krw", 0))

    # Effective limit = base + boosts, capped at hard cap
    effective_limit = min(base_limit + boost_cost_krw, hard_cap)

    # Compare: current cost >= effective limit → deny
    would_deny = total_cost_krw >= Decimal(str(effective_limit))

    # Operator toggle: check gateway config
    gw_config = _get_gateway_config()
    enforcement_enabled = gw_config.get("quota_enforcement_enabled", True)

    if would_deny and not enforcement_enabled:
        log_structured("warning", "quota_exceeded_but_enforcement_disabled",
                       principal_id=principal_id,
                       usage_krw=float(total_cost_krw),
                       limit_krw=effective_limit)
        allowed = True
    else:
        allowed = not would_deny

    return {
        "allowed": allowed,
        "enforcement_enabled": enforcement_enabled,
        "usage": {"cost_krw": float(total_cost_krw)},
        "limit": {"cost_krw": effective_limit},
        "remaining": {
            "cost_krw": max(0, float(Decimal(str(effective_limit)) - total_cost_krw)),
        },
    }


def invoke_bedrock(model_id: str, request_body: dict) -> dict:
    """Call Bedrock Converse API (v1: non-streaming only).

    Returns {"output": ..., "usage": {"inputTokens": N, "outputTokens": N,
             "cacheReadInputTokens": N, "cacheWriteInputTokens": N}}.
    Req 6.1-6.4, 6.6: Converse only, error handling, v1 scope.
    """
    try:
        # Build Converse params from request body
        converse_params = {"modelId": model_id}
        if "messages" in request_body:
            converse_params["messages"] = request_body["messages"]
        if "system" in request_body:
            converse_params["system"] = request_body["system"]
        if "inferenceConfig" in request_body:
            converse_params["inferenceConfig"] = request_body["inferenceConfig"]
        if "toolConfig" in request_body:
            converse_params["toolConfig"] = request_body["toolConfig"]

        resp = bedrock_runtime.converse(**converse_params)

        usage = resp.get("usage", {})
        return {
            "output": resp.get("output", {}),
            "usage": {
                "inputTokens": usage.get("inputTokens", 0),
                "outputTokens": usage.get("outputTokens", 0),
                "cacheReadInputTokens": usage.get("cacheReadInputTokenCount", 0),
                "cacheWriteInputTokens": usage.get("cacheWriteInputTokenCount", 0),
            },
            "stopReason": resp.get("stopReason", ""),
        }
    except bedrock_runtime.exceptions.ValidationException as e:
        error_msg = str(e)
        if "does not support converse" in error_msg.lower():
            raise ValueError(
                f"Model {model_id} does not support Converse API. "
                "Only Converse-compatible models are available in v1."
            )
        raise


def update_daily_usage(
    principal_id: str, model_id: str,
    input_tokens: int, output_tokens: int,
) -> None:
    """Atomically add token counts to DailyUsage (DynamoDB ADD).

    Req 4.3, 4.4, 4.8: atomic ADD per model, TTL 25h, model-level records.
    DEPRECATED: Phase 2 uses update_monthly_usage(). Kept for post-validation cleanup.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pk = f"{principal_id}#{today}"
    ttl_val = int(time.time()) + 25 * 3600  # 25 hours

    table = dynamodb.Table(TABLE_DAILY_USAGE)
    table.update_item(
        Key={"principal_id_date": pk, "model_id": model_id},
        UpdateExpression="ADD input_tokens :i, output_tokens :o SET #t = :ttl",
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues={
            ":i": input_tokens,
            ":o": output_tokens,
            ":ttl": ttl_val,
        },
    )


def update_monthly_usage(
    principal_id: str, model_id: str,
    cost_krw: Decimal, input_tokens: int, output_tokens: int,
) -> None:
    """Atomically ADD cost_krw, input_tokens, output_tokens to MonthlyUsage.

    PK: <principal_id>#YYYY-MM (KST). SK: model_id.
    TTL: ~35 days. Q6 decision: keep token counts alongside cost_krw.
    Task 2.4.
    """
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    ttl_val = end_of_month_ttl_kst()

    table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    table.update_item(
        Key={"principal_id_month": pk, "model_id": model_id},
        UpdateExpression="ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl",
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues={
            ":c": cost_krw,
            ":i": input_tokens,
            ":o": output_tokens,
            ":ttl": ttl_val,
        },
    )


def write_request_ledger(entry: dict) -> None:
    """Append immutable audit entry to RequestLedger.

    PutItem only — no UpdateItem/DeleteItem. Locked decision #9.
    Req 8.1-8.3: immutable audit, request_id PK, includes decision/tokens/duration.
    Raises on failure (caller must deny + alarm). Req 12.4.
    """
    table = dynamodb.Table(TABLE_REQUEST_LEDGER)
    table.put_item(Item=entry)


def write_session_metadata(entry: dict) -> None:
    """Write session context to SessionMetadata (TTL 30d).

    Req 2.3: preserve raw identity fields for audit.
    """
    ttl_val = int(time.time()) + 30 * 24 * 3600  # 30 days
    entry["ttl"] = ttl_val
    table = dynamodb.Table(TABLE_SESSION_METADATA)
    table.put_item(Item=entry)


# ---------------------------------------------------------------------------
# Discovery Support (Task 3)
# ---------------------------------------------------------------------------

DISCOVERY_MODE = os.environ.get("DISCOVERY_MODE", "false").lower() == "true"


def handle_discovery(request_context: dict) -> dict:
    """Return raw requestContext.identity for Task 3 principal discovery.

    When DISCOVERY_MODE=true, the Lambda returns the full identity block
    instead of processing the request. This allows capturing real
    requestContext from both laptop and FSx environments to finalize
    the principal normalization rule.

    This endpoint is temporary and must be disabled after Task 3.
    """
    identity_fields = extract_identity(request_context)
    principal_id = normalize_principal_id(identity_fields)

    log_structured("info", "discovery_capture", **identity_fields,
                   derived_principal_id=principal_id)

    return _response(200, {
        "discovery": True,
        "raw_identity": identity_fields,
        "derived_principal_id": principal_id,
        "note": "Task 3: capture this from both laptop and FSx environments",
    })


# ---------------------------------------------------------------------------
# Approval Endpoint (Task 9)
# ---------------------------------------------------------------------------

def handle_approval_request(principal_id: str, identity_fields: dict,
                            request_body: dict, request_id: str) -> dict:
    """POST /approval/request — create ApprovalRequest with race-safe lock.

    Phase 3 hardened flow:
    1. Validate reason non-empty.
    2. Validate requested_increment_krw == 500000.
    3. Hard cap pre-validation: effective + 500K <= 2M.
    4. Acquire ApprovalPendingLock via conditional PutItem (attribute_not_exists).
    5. Create ApprovalRequest with status "pending" (enriched fields).
    6. Send SES notification to admin group with deep link.
    Req 5.2-5.5, Locked decision #10. Phase 3 approval ladder rewrite.

    Validation is performed BEFORE lock acquisition to avoid orphan locks
    when the request is invalid.
    """
    # --- Phase 3: Input validation (before lock acquisition) ---

    # V1: Validate reason non-empty
    reason = request_body.get("reason", "")
    if not reason or not reason.strip():
        log_structured("warning", "approval_empty_reason",
                       principal_id=principal_id, request_id=request_id)
        return _response(400, {
            "decision": "DENY",
            "denial_reason": "reason is required and must be non-empty",
        })

    # V2: Validate requested_increment_krw == 500000 (fixed increment)
    requested_increment = request_body.get("requested_increment_krw")
    if requested_increment is None:
        log_structured("warning", "approval_missing_increment",
                       principal_id=principal_id, request_id=request_id)
        return _response(400, {
            "decision": "DENY",
            "denial_reason": "requested_increment_krw is required (must be 500000)",
        })
    try:
        requested_increment = int(requested_increment)
    except (ValueError, TypeError):
        return _response(400, {
            "decision": "DENY",
            "denial_reason": "requested_increment_krw must be an integer",
        })
    if requested_increment != 500000:
        log_structured("warning", "approval_wrong_increment",
                       principal_id=principal_id, request_id=request_id,
                       requested=requested_increment)
        return _response(400, {
            "decision": "DENY",
            "denial_reason": f"requested_increment_krw must be 500000 (got {requested_increment})",
        })

    # V3: Hard cap pre-validation (effective + 500K <= 2M)
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "approval_policy_lookup_failed",
                       principal_id=principal_id, error=str(e))
        return deny_response("policy lookup failed during approval pre-validation")

    if not policy:
        return deny_response("no policy defined for principal")

    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 2000000))
    base_limit = int(policy.get("monthly_cost_limit_krw", 500000))

    # Calculate current effective limit (same formula as check_quota)
    boost_cost_krw = 0
    now_epoch = int(time.time())
    boost_table = dynamodb.Table(TABLE_TEMPORARY_QUOTA_BOOST)
    try:
        boost_resp = boost_table.query(
            KeyConditionExpression="principal_id = :pid",
            ExpressionAttributeValues={":pid": principal_id},
        )
        for item in boost_resp.get("Items", []):
            ttl_val = int(item.get("ttl", 0))
            if ttl_val > now_epoch:
                boost_cost_krw += int(item.get("extra_cost_krw", 0))
    except Exception as e:
        log_structured("error", "approval_boost_lookup_failed",
                       principal_id=principal_id, error=str(e))
        return deny_response("boost lookup failed during approval pre-validation")

    current_effective = min(base_limit + boost_cost_krw, hard_cap)
    new_effective = current_effective + requested_increment

    if new_effective > hard_cap:
        log_structured("info", "approval_hard_cap_exceeded",
                       principal_id=principal_id, request_id=request_id,
                       current_effective=current_effective,
                       requested_new=new_effective, hard_cap=hard_cap)
        return _response(422, {
            "decision": "DENY",
            "denial_reason": "hard cap exceeded — cannot approve further boosts this month",
            "current_effective_limit_krw": current_effective,
            "requested_new_limit_krw": new_effective,
            "hard_cap_krw": hard_cap,
        })

    # --- Lock acquisition (only after all validation passes) ---

    lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
    lock_ttl = int(time.time()) + 7 * 24 * 3600  # 7-day safety net
    try:
        lock_table.put_item(
            Item={
                "principal_id": principal_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl": lock_ttl,
            },
            ConditionExpression="attribute_not_exists(principal_id)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        log_structured("warning", "approval_lock_exists",
                       principal_id=principal_id, request_id=request_id)
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "pending approval request already exists for this principal",
        })

    # --- Create ApprovalRequest (enriched with Phase 3 fields) ---
    approval_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())  # one-time token for email approve/reject
    approver_email = SES_ADMIN_GROUP_EMAIL or SES_SENDER_EMAIL or ""
    approval_table = dynamodb.Table(TABLE_APPROVAL_REQUEST)
    approval_table.put_item(Item={
        "request_id": approval_id,
        "principal_id": principal_id,
        "status": "pending",
        "reason": reason.strip(),
        "requested_amount_krw": requested_increment,
        "current_effective_limit_krw": current_effective,
        "approver_email": approver_email,
        "action_token": action_token,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": identity_fields.get("sourceIp", ""),
    })

    log_structured("info", "approval_request_created",
                   principal_id=principal_id, approval_id=approval_id,
                   request_id=request_id,
                   current_effective=current_effective,
                   requested_new=new_effective)

    # --- SES notification (best-effort — R7 accepted risk) ---
    _send_approval_email(principal_id, approval_id, reason.strip(),
                         current_effective, new_effective, hard_cap, action_token)

    return _response(201, {
        "decision": "ACCEPTED",
        "approval_id": approval_id,
        "current_effective_limit_krw": current_effective,
        "requested_new_limit_krw": new_effective,
        "message": "한도 증액 요청이 접수되었습니다. 관리자 승인 대기 중입니다.",
    })


def _send_approval_email(principal_id: str, approval_id: str,
                         reason: str, current_limit_krw: int = 0,
                         requested_new_limit_krw: int = 0,
                         hard_cap_krw: int = 2000000,
                         action_token: str = "") -> None:
    """Send approval email with Outlook Actionable Message (Adaptive Card).

    Primary path: Outlook renders Adaptive Card inline with Approve/Reject
    buttons. Action.Http POSTs to backend-admin, card refreshes in-place.
    Fallback: non-Outlook clients see HTML with safe GET→JS→POST links.
    """
    if not SES_SENDER_EMAIL or not SES_ADMIN_GROUP_EMAIL:
        log_structured("warning", "ses_not_configured",
                       principal_id=principal_id, approval_id=approval_id)
        return
    try:
        username = principal_id.split("#")[-1] if "#" in principal_id else principal_id

        # Determine recipient: team admin emails if available, else fallback to SES_ADMIN_GROUP_EMAIL
        recipient_emails = [SES_ADMIN_GROUP_EMAIL]
        try:
            team_table_name = _get_team_config_table_name()
            if team_table_name:
                team_table = dynamodb.Table(team_table_name)
                team_resp = team_table.scan()
                for team_item in team_resp.get("Items", []):
                    team_users = team_item.get("users", [])
                    if isinstance(team_users, set):
                        team_users = list(team_users)
                    # Extract username from principal_id for matching
                    user_short = username.replace("BedrockUser-", "")
                    if user_short in team_users:
                        admin_emails = team_item.get("notification_admin_emails", [])
                        if isinstance(admin_emails, set):
                            admin_emails = list(admin_emails)
                        if admin_emails:
                            recipient_emails = admin_emails
                            log_structured("info", "approval_email_routed_to_team_admin",
                                           principal_id=principal_id,
                                           team_id=team_item.get("team_id", ""),
                                           recipients=admin_emails)
                        break
        except Exception as team_err:
            log_structured("warning", "team_lookup_failed_for_email",
                           principal_id=principal_id, error=str(team_err))
        portal_base = os.environ.get("PORTAL_BASE_URL", "http://203.0.113.10")

        # Action.Http target URL (POST only — no GET mutation)
        action_url = (f"{portal_base}/api/gateway/approvals/{approval_id}"
                      f"/email-action")

        # Fallback URLs for non-Outlook clients (GET → JS page → POST)
        approve_fallback = f"{action_url}?action=approve&token={action_token}"
        reject_fallback = f"{action_url}?action=reject&token={action_token}"

        # --- HTML body: fallback HTML links only (no Adaptive Card) ---
        # Adaptive Card removed — unregistered provider causes Outlook to
        # auto-execute Action.Http on email open, consuming the token before
        # the admin can click. HTML <a> links are safe and predictable.
        html_body = f"""<html><head></head><body style="font-family: sans-serif; max-width: 600px;">
<h2 style="color: #333;">Bedrock Gateway 한도 증액 승인 요청</h2>
<table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; width: 40%;"><b>요청자</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">{username}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>Principal</b></td>
<td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 12px;">{principal_id}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>사유</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">{reason}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>현재 적용 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {current_limit_krw:,}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>요청 증액분</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW 500,000</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>승인 시 새 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;"><b>KRW {requested_new_limit_krw:,}</b></td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>월간 최대 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {hard_cap_krw:,}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>유효기간</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">당월 말 (KST) 자동 만료</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>승인 요청 ID</b></td>
<td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 12px;">{approval_id}</td></tr>
</table>
<div style="margin: 24px 0;">
<a href="{approve_fallback}" style="display: inline-block; padding: 12px 32px; background: #28a745; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold; margin-right: 12px;">승인</a>
<a href="{reject_fallback}" style="display: inline-block; padding: 12px 32px; background: #dc3545; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold;">거절</a>
</div>
<p style="color: #999; font-size: 11px;">위 버튼을 클릭하여 승인 또는 거절하세요.</p>
</body></html>"""

        text_body = (
            f"Bedrock Gateway 한도 증액 승인 요청\n\n"
            f"요청자: {username} ({principal_id})\n"
            f"사유: {reason}\n"
            f"현재 적용 한도: KRW {current_limit_krw:,}\n"
            f"승인 시 새 한도: KRW {requested_new_limit_krw:,}\n"
            f"승인 요청 ID: {approval_id}\n\n"
            f"승인: {approve_fallback}\n"
            f"거절: {reject_fallback}\n"
        )

        ses_client.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={"ToAddresses": recipient_emails},
            Message={
                "Subject": {
                    "Data": f"[Bedrock Gateway] 한도 증액 승인 요청 — {username}",
                },
                "Body": {
                    "Text": {"Data": text_body},
                    "Html": {"Data": html_body},
                },
            },
        )
        log_structured("info", "approval_email_sent",
                       principal_id=principal_id, approval_id=approval_id)
    except Exception as e:
        log_structured("error", "approval_email_failed",
                       principal_id=principal_id, approval_id=approval_id,
                       error=str(e))


# ---------------------------------------------------------------------------
# Auto Approval Request — triggered from quota exhaustion path
# ---------------------------------------------------------------------------

def _auto_create_approval_request(principal_id: str, identity_fields: dict,
                                  current_effective: int, hard_cap: int,
                                  usage_krw: float, request_id: str) -> dict | None:
    """Automatically create an approval request when quota is exhausted.

    Non-portal flow: the system detects quota exhaustion during normal
    inference and creates the request on behalf of the user.
    Returns approval_id if created, None if skipped (lock exists, hard cap, etc).
    """
    increment = 500000
    new_effective = current_effective + increment

    # Hard cap check
    if new_effective > hard_cap:
        log_structured("info", "auto_approval_hard_cap",
                       principal_id=principal_id, current=current_effective,
                       hard_cap=hard_cap)
        return None

    # Try to acquire lock (skip if already pending)
    lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
    lock_ttl = int(time.time()) + 7 * 24 * 3600
    try:
        lock_table.put_item(
            Item={
                "principal_id": principal_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl": lock_ttl,
            },
            ConditionExpression="attribute_not_exists(principal_id)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        log_structured("info", "auto_approval_lock_exists",
                       principal_id=principal_id)
        return None

    # Create approval request
    approval_id = str(uuid.uuid4())
    approver_email = SES_ADMIN_GROUP_EMAIL or SES_SENDER_EMAIL or ""
    approval_table = dynamodb.Table(TABLE_APPROVAL_REQUEST)
    reason_text = f"자동 생성: 한도 소진 (사용 KRW {usage_krw:,.0f} >= 한도 KRW {current_effective:,})"
    approval_table.put_item(Item={
        "request_id": approval_id,
        "principal_id": principal_id,
        "status": "pending",
        "reason": reason_text,
        "requested_amount_krw": increment,
        "current_effective_limit_krw": current_effective,
        "approver_email": approver_email,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": identity_fields.get("sourceIp", ""),
        "auto_generated": True,
    })

    log_structured("info", "auto_approval_request_created",
                   principal_id=principal_id, approval_id=approval_id,
                   request_id=request_id,
                   current_effective=current_effective,
                   requested_new=new_effective)

    # Send admin email
    _send_approval_email(principal_id, approval_id, reason_text,
                         current_effective, new_effective, hard_cap)

    return approval_id


# ---------------------------------------------------------------------------
# User Warning Emails — 30% / 10% remaining threshold
# ---------------------------------------------------------------------------

def _check_and_send_warning_email(principal_id: str, policy: dict,
                                  usage_krw: float, effective_limit: int) -> None:
    """Check if user's remaining allowance in the CURRENT BAND SLICE crossed 30% or 10%.

    Band slices are 500K KRW each: 0-500K, 500K-1M, 1M-1.5M, 1.5M-2M.
    Warnings are based on remaining room within the current active band slice,
    not the total effective limit.

    Dedup via warning_30pct_sent_for_limit / warning_10pct_sent_for_limit
    on principal-policy item, keyed to effective_limit value.
    """
    if effective_limit <= 0:
        return

    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 2000000))
    band_size = 500000

    # Compute current band slice floor/ceiling
    # effective_limit is always a multiple of band_size (500K, 1M, 1.5M, 2M)
    band_ceiling = effective_limit
    band_floor = max(0, effective_limit - band_size)

    # Remaining within the current band slice
    usage_in_band = max(0, usage_krw - band_floor)
    remaining_in_band = max(0, band_size - usage_in_band)
    if band_size > 0:
        remaining_pct_in_band = remaining_in_band / band_size
    else:
        return

    send_30 = remaining_pct_in_band <= 0.30
    send_10 = remaining_pct_in_band <= 0.10

    if not send_30 and not send_10:
        return

    already_sent_30_for = policy.get("warning_30pct_sent_for_limit")
    already_sent_10_for = policy.get("warning_10pct_sent_for_limit")
    if isinstance(already_sent_30_for, Decimal):
        already_sent_30_for = int(already_sent_30_for)
    if isinstance(already_sent_10_for, Decimal):
        already_sent_10_for = int(already_sent_10_for)

    need_30 = send_30 and already_sent_30_for != effective_limit
    need_10 = send_10 and already_sent_10_for != effective_limit

    if not need_30 and not need_10:
        return

    user_email = policy.get("notification_email", "")
    if not user_email or not SES_SENDER_EMAIL:
        log_structured("warning", "warning_email_no_recipient",
                       principal_id=principal_id)
        return

    username = principal_id.split("#")[-1] if "#" in principal_id else principal_id

    if need_10:
        threshold_label = "10%"
        subject = f"[Bedrock Gateway] 사용량 알림: 현재 밴드 잔여 {threshold_label} 이하"
        guidance = (
            "현재 밴드 한도가 거의 소진되었습니다.\n"
            "한도 소진 시 추가 요청이 필요하며, 터미널에서 안내에 따라 증액을 요청할 수 있습니다."
        )
    elif need_30:
        threshold_label = "30%"
        subject = f"[Bedrock Gateway] 사용량 알림: 현재 밴드 잔여 {threshold_label} 이하"
        guidance = "현재 밴드 사용량이 70%를 넘었습니다. 참고하시기 바랍니다."
    else:
        return

    total_remaining = max(0, effective_limit - usage_krw)

    try:
        ses_client.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={"ToAddresses": [user_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Text": {
                        "Data": (
                            f"Bedrock Gateway 사용량 알림\n"
                            f"{'='*50}\n\n"
                            f"사용자: {username}\n\n"
                            f"현재 밴드: KRW {band_floor:,} ~ {band_ceiling:,} (밴드 크기 KRW {band_size:,})\n"
                            f"밴드 내 사용 금액: KRW {usage_in_band:,.0f}\n"
                            f"밴드 내 잔여 한도: KRW {remaining_in_band:,.0f} ({remaining_pct_in_band*100:.0f}%)\n"
                            f"알림 기준: 밴드 잔여 {threshold_label} 이하\n\n"
                            f"전체 현황:\n"
                            f"  현재 적용 한도: KRW {effective_limit:,}\n"
                            f"  총 사용 금액: KRW {usage_krw:,.0f}\n"
                            f"  총 잔여 한도: KRW {total_remaining:,.0f}\n"
                            f"  월간 최대 한도: KRW {hard_cap:,}\n\n"
                            f"{guidance}\n"
                        ),
                    },
                },
            },
        )
        log_structured("info", "warning_email_sent",
                       principal_id=principal_id, threshold=threshold_label,
                       band_floor=band_floor, band_ceiling=band_ceiling,
                       remaining_in_band=remaining_in_band,
                       effective_limit=effective_limit)
    except Exception as e:
        log_structured("error", "warning_email_failed",
                       principal_id=principal_id, threshold=threshold_label,
                       error=str(e))
        return

    # Update dedup state — mark both thresholds if both crossed
    try:
        policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        update_expr_parts = []
        expr_values = {}
        if need_30 or send_30:
            update_expr_parts.append("warning_30pct_sent_for_limit = :w30")
            expr_values[":w30"] = effective_limit
        if need_10 or send_10:
            update_expr_parts.append("warning_10pct_sent_for_limit = :w10")
            expr_values[":w10"] = effective_limit
        if update_expr_parts:
            policy_table.update_item(
                Key={"principal_id": principal_id},
                UpdateExpression="SET " + ", ".join(update_expr_parts),
                ExpressionAttributeValues=expr_values,
            )
    except Exception as e:
        log_structured("error", "warning_dedup_update_failed",
                       principal_id=principal_id, error=str(e))


# ---------------------------------------------------------------------------
# Quota Status Query (read-only, for shell hook / thin clients)
# ---------------------------------------------------------------------------

def handle_quota_status(principal_id: str, identity_fields: dict) -> dict:
    """GET /quota/status — read-only quota state for shell hook integration.

    Returns current usage, effective limit, approval band, pending state,
    and server-side decision on whether to prompt for increase.
    Zero DynamoDB writes. Reuses existing check_quota() and policy lookup.
    """
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "quota_status_policy_failed",
                       principal_id=principal_id, error=str(e))
        return _response(500, {"error": "policy lookup failed"})

    if not policy:
        return _response(404, {"error": "no policy defined for principal",
                                "principal_id": principal_id})

    try:
        quota_result = check_quota(principal_id, policy)
    except Exception as e:
        log_structured("error", "quota_status_check_failed",
                       principal_id=principal_id, error=str(e))
        return _response(500, {"error": "quota check failed"})

    usage_krw = quota_result["usage"]["cost_krw"]
    effective_limit = int(quota_result["limit"]["cost_krw"])
    base_limit = int(policy.get("monthly_cost_limit_krw", 500000))
    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 2000000))
    increment = 500000

    # Active boost calculation (same as check_quota internals)
    active_boost_krw = max(0, effective_limit - base_limit)
    approval_band = active_boost_krw // increment

    # Pending approval check
    has_pending = False
    pending_id = None
    try:
        lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
        lock_resp = lock_table.get_item(Key={"principal_id": principal_id})
        lock_item = lock_resp.get("Item")
        if lock_item and int(lock_item.get("ttl", 0)) > int(time.time()):
            has_pending = True
            # Try to find the pending approval ID
            try:
                ar_table = dynamodb.Table(TABLE_APPROVAL_REQUEST)
                ar_resp = ar_table.query(
                    IndexName="principal-status-index",
                    KeyConditionExpression="principal_id = :pid AND #s = :st",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":pid": principal_id, ":st": "pending"},
                    Limit=1,
                )
                items = ar_resp.get("Items", [])
                if items:
                    pending_id = items[0].get("request_id", "")
            except Exception:
                pass
    except Exception:
        pass

    at_hard_cap = effective_limit >= hard_cap
    can_request = (effective_limit + increment <= hard_cap) and not has_pending

    # Server-side prompt decision: 2-tier thresholds
    # Tier 1: 30% remaining (70% used) — early warning
    # Tier 2: 10% remaining (90% used) — urgent warning
    prompt_eligible = not has_pending and not at_hard_cap and can_request
    hit_30pct = usage_krw >= effective_limit * 0.7 and prompt_eligible
    hit_10pct = usage_krw >= effective_limit * 0.9 and prompt_eligible

    # Active threshold: 10pct takes priority over 30pct
    if hit_10pct:
        active_threshold = "10pct"
    elif hit_30pct:
        active_threshold = "30pct"
    else:
        active_threshold = None

    # Backward compat: should_prompt_for_increase = any threshold hit
    should_prompt = active_threshold is not None

    # Suppress reason
    suppress_reason = None
    if has_pending:
        suppress_reason = "pending_approval"
    elif at_hard_cap:
        suppress_reason = "hard_cap"
    elif not can_request:
        suppress_reason = "cannot_request"

    # Message
    message = ""
    if has_pending:
        message = "한도 증액 요청이 관리자 승인 대기 중입니다."
    elif at_hard_cap:
        message = f"월간 최대 한도(KRW {hard_cap:,})에 도달하여 추가 증액이 불가합니다."
    elif active_threshold == "10pct":
        message = f"이번 달 Bedrock Gateway 한도의 90%에 도달했습니다."
    elif active_threshold == "30pct":
        message = f"이번 달 Bedrock Gateway 한도의 70%에 도달했습니다."

    return _response(200, {
        "principal_id": principal_id,
        "month": current_month_kst(),
        "current_usage_krw": round(usage_krw, 2),
        "effective_limit_krw": effective_limit,
        "base_limit_krw": base_limit,
        "active_boost_krw": active_boost_krw,
        "approval_band": approval_band,
        "has_pending_approval": has_pending,
        "pending_approval_id": pending_id,
        "should_prompt_for_increase": should_prompt,
        "active_threshold": active_threshold,
        "should_prompt_30pct": hit_30pct,
        "should_prompt_10pct": hit_10pct,
        "can_request_increase": can_request,
        "recommended_increment_krw": increment,
        "hard_cap_krw": hard_cap,
        "at_hard_cap": at_hard_cap,
        "cooldown_seconds": 300,
        "suppress_reason": suppress_reason,
        "message": message,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Long-Running Request Handlers (Tier 3 — gateway-mediated direct Bedrock)
# ---------------------------------------------------------------------------
TABLE_LONGRUN_REQUEST = os.environ.get("TABLE_LONGRUN_REQUEST", "")

# Pessimistic reserve multiplier: reserve 2x estimated cost to cover
# output token uncertainty. Actual cost settled after completion.
LONGRUN_RESERVE_MULTIPLIER = Decimal("2")
# Maximum reserve per single longrun request (KRW)
LONGRUN_MAX_RESERVE_KRW = Decimal("100000")
# Authorization TTL: 1 hour to complete the call
LONGRUN_AUTH_TTL_SECONDS = 3600


def handle_longrun_authorize(principal_id: str, identity_fields: dict,
                              body: dict, request_id: str) -> dict:
    """POST /longrun/authorize — pre-authorize a long-running Bedrock call.

    Control plane only. Does NOT call Bedrock.
    1. Validates principal, policy, model access, pricing
    2. Checks quota (remaining budget)
    3. Reserves budget (pessimistic estimate)
    4. Creates longrun-request record (state=authorized)
    5. Returns tracking_id + authorization for client to proceed

    Client then calls Bedrock directly (ConverseStream) and settles via /longrun/settle.
    """
    model_id = body.get("modelId", "")
    if not model_id:
        return deny_response("modelId is required", status_code=400)

    estimated_input_tokens = int(body.get("estimated_input_tokens", 0))

    # Step 1: Policy lookup
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "longrun_policy_failed", request_id=request_id, error=str(e))
        return deny_response("policy lookup failed")
    if not policy:
        return deny_response("no policy defined for principal")

    # Step 2: Model access check
    if not check_model_access(policy, model_id):
        return deny_response(f"model {model_id} not in allowed list")

    # Step 3: Pricing lookup
    try:
        pricing = lookup_model_pricing(model_id)
    except Exception as e:
        log_structured("error", "longrun_pricing_failed", request_id=request_id, error=str(e))
        return deny_response("pricing lookup failed")
    if not pricing:
        return deny_response(f"no pricing defined for model {model_id}")

    # Step 4: Quota check
    try:
        quota_result = check_quota(principal_id, policy)
    except Exception as e:
        log_structured("error", "longrun_quota_failed", request_id=request_id, error=str(e))
        return deny_response("quota check failed")

    if not quota_result["allowed"]:
        return _response(429, {
            "decision": "DENY",
            "denial_reason": "monthly cost quota exceeded",
            "quota": quota_result,
        })

    # Step 5: Calculate reserve budget
    # If client provides estimated_input_tokens, use it for reserve calculation
    # Otherwise use a fixed pessimistic reserve
    if estimated_input_tokens > 0:
        input_price = pricing.get("input_price_per_1k", Decimal("0"))
        output_price = pricing.get("output_price_per_1k", Decimal("0"))
        # Estimate: input cost + assume output = 20% of input tokens
        est_output = max(int(estimated_input_tokens * 0.2), 4096)
        est_cost = estimate_cost_krw(estimated_input_tokens, est_output, pricing)
        reserve_krw = min(est_cost * LONGRUN_RESERVE_MULTIPLIER, LONGRUN_MAX_RESERVE_KRW)
    else:
        # Default reserve: 50,000 KRW (covers ~2.3M input tokens on Opus)
        reserve_krw = Decimal("50000")

    reserve_krw = min(reserve_krw, LONGRUN_MAX_RESERVE_KRW)

    # Check if reserve fits in remaining budget
    remaining_krw = Decimal(str(quota_result["remaining"]["cost_krw"]))
    if reserve_krw > remaining_krw:
        # Deny if estimated cost exceeds remaining budget
        return _response(429, {"decision": "DENY", "denial_reason": f"estimated cost ({float(reserve_krw):.0f} KRW) exceeds remaining budget ({float(remaining_krw):.0f} KRW). Request a quota increase."})
    # Step 6: Create longrun-request record
    tracking_id = f"lr-{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    ttl_val = int(time.time()) + LONGRUN_AUTH_TTL_SECONDS

    if not TABLE_LONGRUN_REQUEST:
        log_structured("error", "longrun_table_not_configured", request_id=request_id)
        return error_response("longrun request table not configured")

    lr_table = dynamodb.Table(TABLE_LONGRUN_REQUEST)
    lr_item = {
        "request_id": tracking_id,
        "principal_id": principal_id,
        "model_id": model_id,
        "region": os.environ.get("AWS_REGION", "us-west-2"),
        "state": "authorized",
        "reserved_cost_krw": reserve_krw,
        "settled_cost_krw": Decimal("0"),
        "reserved_input_tokens_estimate": estimated_input_tokens,
        "actual_input_tokens": 0,
        "actual_output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "input_price_per_1k_krw": pricing.get("input_price_per_1k", Decimal("0")),
        "output_price_per_1k_krw": pricing.get("output_price_per_1k", Decimal("0")),
        "fx_rate": 1450,
        "pricing_source": "dynamodb:model-pricing",
        "source_path": "gateway-longrun",
        "created_at": now_iso,
        "updated_at": now_iso,
        "completed_at": "",
        "ttl": ttl_val,
        "caller_request_id": request_id,
    }
    try:
        lr_table.put_item(Item=lr_item)
    except Exception as e:
        log_structured("error", "longrun_record_create_failed",
                       request_id=request_id, error=str(e))
        return error_response("failed to create longrun request record")

    # Step 7: Reserve budget in monthly_usage (atomic ADD)
    # We add the reserve as a special "reserved" entry so it counts against quota
    month = current_month_kst()
    try:
        usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
        pk = f"{principal_id}#{month}"
        usage_table.update_item(
            Key={"principal_id_month": pk, "model_id": f"__reserved__{tracking_id}"},
            UpdateExpression="ADD cost_krw :c SET #t = :ttl, source_path = :sp",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={
                ":c": reserve_krw,
                ":ttl": ttl_val,
                ":sp": "gateway-longrun-reserve",
            },
        )
    except Exception as e:
        log_structured("error", "longrun_reserve_failed",
                       request_id=request_id, error=str(e))
        # Clean up the longrun record
        try:
            lr_table.delete_item(Key={"request_id": tracking_id})
        except Exception:
            pass
        return error_response("failed to reserve budget")

    log_structured("info", "longrun_authorized",
                   request_id=request_id, tracking_id=tracking_id,
                   principal_id=principal_id, model_id=model_id,
                   reserved_krw=float(reserve_krw))

    effective_limit = int(quota_result["limit"]["cost_krw"])
    return _response(200, {
        "decision": "AUTHORIZED",
        "tracking_id": tracking_id,
        "principal_id": principal_id,
        "model_id": model_id,
        "reserved_cost_krw": float(reserve_krw),
        "effective_limit_krw": effective_limit,
        "remaining_after_reservation_krw": float(remaining_krw - reserve_krw),
        "authorization_ttl_seconds": LONGRUN_AUTH_TTL_SECONDS,
        "settle_endpoint": "/longrun/settle",
        "pricing": {
            "input_price_per_1k_krw": float(pricing.get("input_price_per_1k", 0)),
            "output_price_per_1k_krw": float(pricing.get("output_price_per_1k", 0)),
        },
    })


def handle_longrun_settle(principal_id: str, identity_fields: dict,
                           body: dict, request_id: str) -> dict:
    """POST /longrun/settle — finalize a long-running Bedrock call.

    Called by client after Bedrock call completes (success or failure).
    1. Validates tracking_id belongs to principal
    2. Computes actual cost from reported tokens
    3. Adjusts monthly_usage: remove reserve, add actual
    4. Writes request_ledger entry
    5. Updates longrun-request state to settled/failed
    """
    tracking_id = body.get("tracking_id", "")
    if not tracking_id:
        return deny_response("tracking_id is required", status_code=400)

    failed = body.get("failed", False)
    input_tokens = int(body.get("input_tokens", 0))
    output_tokens = int(body.get("output_tokens", 0))
    cache_read_tokens = int(body.get("cache_read_tokens", 0))
    cache_write_tokens = int(body.get("cache_write_tokens", 0))
    stop_reason = body.get("stop_reason", "")
    duration_seconds = int(body.get("duration_seconds", 0))
    error_message = body.get("error", "")

    if not TABLE_LONGRUN_REQUEST:
        return error_response("longrun request table not configured")

    # Step 1: Fetch and validate longrun record
    lr_table = dynamodb.Table(TABLE_LONGRUN_REQUEST)
    try:
        resp = lr_table.get_item(Key={"request_id": tracking_id})
        lr_item = resp.get("Item")
    except Exception as e:
        log_structured("error", "longrun_settle_fetch_failed",
                       tracking_id=tracking_id, error=str(e))
        return error_response("failed to fetch longrun request")

    if not lr_item:
        return deny_response("tracking_id not found", status_code=404)

    # Validate ownership
    if lr_item.get("principal_id") != principal_id:
        log_structured("warning", "longrun_settle_principal_mismatch",
                       tracking_id=tracking_id,
                       expected=lr_item.get("principal_id"),
                       actual=principal_id)
        return deny_response("tracking_id does not belong to this principal", status_code=403)

    # Idempotency: already settled
    current_state = lr_item.get("state", "")
    if current_state in ("settled", "failed"):
        return _response(200, {
            "already_settled": True,
            "tracking_id": tracking_id,
            "state": current_state,
            "settled_cost_krw": float(lr_item.get("settled_cost_krw", 0)),
        })

    model_id = lr_item.get("model_id", "")
    reserved_krw = Decimal(str(lr_item.get("reserved_cost_krw", 0)))

    # Step 2: Compute actual cost
    actual_cost_krw = Decimal("0")
    if not failed and (input_tokens > 0 or output_tokens > 0):
        pricing = lookup_model_pricing(model_id)
        if pricing:
            actual_cost_krw = estimate_cost_krw(input_tokens, output_tokens, pricing)
        else:
            log_structured("warning", "longrun_settle_no_pricing",
                           tracking_id=tracking_id, model_id=model_id)

    # Step 3: Adjust monthly_usage
    # Remove reservation, add actual cost
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)

    # 3a: Delete the reservation entry
    try:
        usage_table.delete_item(
            Key={"principal_id_month": pk, "model_id": f"__reserved__{tracking_id}"}
        )
    except Exception as e:
        log_structured("error", "longrun_settle_reserve_delete_failed",
                       tracking_id=tracking_id, error=str(e))

    # 3b: Add actual usage (if not failed)
    if not failed and actual_cost_krw > 0:
        try:
            update_monthly_usage(principal_id, model_id,
                                 actual_cost_krw, input_tokens, output_tokens)
        except Exception as e:
            log_structured("error", "longrun_settle_usage_update_failed",
                           tracking_id=tracking_id, error=str(e), alarm=True)

    # Step 4: Write request_ledger
    new_state = "failed" if failed else "settled"
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        write_request_ledger({
            "request_id": tracking_id,
            "timestamp": now_iso,
            "principal_id": principal_id,
            "model_id": model_id,
            "region": lr_item.get("region", "us-west-2"),
            "decision": "DENY" if failed else "ALLOW",
            "denial_reason": error_message if failed else "",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cache_write_tokens": cache_write_tokens,
            "estimated_cost_krw": actual_cost_krw,
            "input_price_per_1k_krw": lr_item.get("input_price_per_1k_krw", Decimal("0")),
            "output_price_per_1k_krw": lr_item.get("output_price_per_1k_krw", Decimal("0")),
            "fx_rate": 1450,
            "pricing_source": "dynamodb:model-pricing",
            "duration_ms": duration_seconds * 1000,
            "source_path": "gateway-longrun",
            "reserved_cost_krw": reserved_krw,
        })
    except Exception as e:
        log_structured("error", "longrun_settle_ledger_failed",
                       tracking_id=tracking_id, error=str(e), alarm=True)

    # Step 5: Update longrun-request record
    adjustment_krw = actual_cost_krw - reserved_krw
    try:
        lr_table.update_item(
            Key={"request_id": tracking_id},
            UpdateExpression="SET #s = :state, settled_cost_krw = :cost, "
                             "actual_input_tokens = :inp, actual_output_tokens = :out, "
                             "cache_read_tokens = :cr, cache_write_tokens = :cw, "
                             "completed_at = :ts, updated_at = :ts, "
                             "stop_reason = :sr, duration_seconds = :dur, "
                             "error_message = :err",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":state": new_state,
                ":cost": actual_cost_krw,
                ":inp": input_tokens,
                ":out": output_tokens,
                ":cr": cache_read_tokens,
                ":cw": cache_write_tokens,
                ":ts": now_iso,
                ":sr": stop_reason,
                ":dur": duration_seconds,
                ":err": error_message,
            },
        )
    except Exception as e:
        log_structured("error", "longrun_settle_record_update_failed",
                       tracking_id=tracking_id, error=str(e))

    log_structured("info", "longrun_settled",
                   tracking_id=tracking_id, principal_id=principal_id,
                   model_id=model_id, state=new_state,
                   reserved_krw=float(reserved_krw),
                   actual_krw=float(actual_cost_krw),
                   adjustment_krw=float(adjustment_krw))

    return _response(200, {
        "settled": True,
        "tracking_id": tracking_id,
        "state": new_state,
        "model_id": model_id,
        "reserved_cost_krw": float(reserved_krw),
        "settled_cost_krw": float(actual_cost_krw),
        "adjustment_krw": float(adjustment_krw),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "duration_seconds": duration_seconds,
    })



# ---------------------------------------------------------------------------
# Concurrency Semaphore (DynamoDB-based admission control)
# ---------------------------------------------------------------------------
MAX_CONCURRENT_JOBS = 5  # Legacy — kept for semaphore TTL cleanup compatibility
PER_USER_ACTIVE_LIMIT = 50  # Per-user active job limit (ACCEPTED+QUEUED+RUNNING)

def _acquire_semaphore_slot(job_id: str) -> str:
    """Try to acquire a concurrency slot. Returns slot_id or empty string if saturated."""
    if not TABLE_CONCURRENCY_SEMAPHORE:
        return "no-semaphore"
    sem_table = dynamodb.Table(TABLE_CONCURRENCY_SEMAPHORE)
    for i in range(MAX_CONCURRENT_JOBS):
        slot_id = f"slot-{i}"
        try:
            sem_table.update_item(
                Key={"slot_id": slot_id},
                UpdateExpression="SET job_id = :jid, acquired_at = :ts, #t = :ttl",
                ConditionExpression="job_id = :empty OR attribute_not_exists(job_id)",
                ExpressionAttributeNames={"#t": "ttl"},
                ExpressionAttributeValues={
                    ":jid": job_id,
                    ":empty": "",
                    ":ts": datetime.now(timezone.utc).isoformat(),
                    ":ttl": int(time.time()) + 7200,
                },
            )
            log_structured("info", "semaphore_acquired", slot_id=slot_id, job_id=job_id)
            return slot_id
        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            continue
    return ""

def _release_semaphore_slot(job_id: str) -> None:
    """Release the semaphore slot held by this job."""
    if not TABLE_CONCURRENCY_SEMAPHORE:
        return
    sem_table = dynamodb.Table(TABLE_CONCURRENCY_SEMAPHORE)
    for i in range(MAX_CONCURRENT_JOBS):
        slot_id = f"slot-{i}"
        try:
            sem_table.update_item(
                Key={"slot_id": slot_id},
                UpdateExpression="SET job_id = :empty",
                ConditionExpression="job_id = :jid",
                ExpressionAttributeValues={":empty": "", ":jid": job_id},
            )
            log_structured("info", "semaphore_released", slot_id=slot_id, job_id=job_id)
            return
        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            continue

# ---------------------------------------------------------------------------
# Sync path routing enforcement: block long-running candidates on /converse
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Async routing — generalized long-run detection
# ---------------------------------------------------------------------------
# Requests hitting POST /converse are routed to async/Fargate when ANY condition:
#   1. Model is in ALWAYS_ASYNC_MODELS (known slow: Opus, DeepSeek-R1, Nova Premier)
#   2. Model contains a SLOW_MODEL_PATTERN substring (catch variants/cross-region)
#   3. Requested maxTokens >= ASYNC_MAX_TOKENS_THRESHOLD (large output risk)
#   4. Input payload size > ASYNC_INPUT_SIZE_THRESHOLD bytes (large context)
#
# Rationale: API Gateway hard 29s timeout. Any request risking timeout must go
# through async path (SQS → SFN → Fargate) which has no timeout constraint.
#
# Category 1 — ALWAYS_ASYNC_MODELS: models that routinely exceed 29s even for
# small inputs. Reasoning models (deepseek-r1), large models (opus, nova-premier).
#
# Category 2 — SLOW_MODEL_PATTERNS: substring patterns to catch cross-region
# inference profile variants (us.*, global.*) without enumerating every ID.
#
# Category 3/4 — size-based: any model can be slow with large input/output.
# ---------------------------------------------------------------------------
ASYNC_MAX_TOKENS_THRESHOLD = 8192    # maxTokens >= 8K → async (lowered from 16K)
ASYNC_INPUT_SIZE_THRESHOLD = 100000  # input body > ~100KB → async (lowered from 200KB)

# Models that ALWAYS route to async regardless of input size.
# These are known to routinely exceed 29s even for trivial inputs.
ALWAYS_ASYNC_MODELS = {
    # Opus variants (always slow, 30-120s typical)
    "us.anthropic.claude-opus-4-6-v1",
    "global.anthropic.claude-opus-4-6-v1",
    "us.anthropic.claude-opus-4-5-20251101-v1:0",
    "us.anthropic.claude-opus-4-20250514-v1:0",
    "us.anthropic.claude-opus-4-1-20250805-v1:0",
    "anthropic.claude-opus-4-6-v1",
    "anthropic.claude-opus-4-5-20251101-v1:0",
    "anthropic.claude-opus-4-20250514-v1:0",
    "anthropic.claude-opus-4-1-20250805-v1:0",
    # DeepSeek R1 — reasoning model, routinely 30-120s
    "us.deepseek.r1-v1:0",
    "deepseek.r1-v1:0",
    # Nova Premier — large model, routinely 20-60s
    "us.amazon.nova-premier-v1:0",
    "amazon.nova-premier-v1:0",
}

# Backward compat alias
LONGRUN_MODELS = ALWAYS_ASYNC_MODELS

# Substring patterns — if model_id contains any of these, route async.
# Catches cross-region variants without enumerating every ID.
SLOW_MODEL_PATTERNS = [
    "opus",        # all opus variants
    "deepseek.r1", # all deepseek-r1 variants
    "nova-premier", # all nova premier variants
]


def _should_route_async(model_id: str, body: dict) -> tuple:
    """Determine if a /converse request should be routed to async path.

    Returns (should_async: bool, reason: str) for structured logging.
    Decision table (evaluated in order, first match wins):
      1. model_id in ALWAYS_ASYNC_MODELS     → async (reason: always_async_model)
      2. model_id matches SLOW_MODEL_PATTERNS → async (reason: slow_model_pattern)
      3. maxTokens >= 8192                    → async (reason: max_tokens_N)
      4. messages+system JSON > 100KB         → async (reason: input_size_N)
      5. otherwise                            → sync
    """
    # 1. Exact match — known always-slow models
    if model_id in ALWAYS_ASYNC_MODELS:
        return True, "always_async_model"

    # 2. Pattern match — catch cross-region/versioned variants
    model_lower = model_id.lower()
    for pattern in SLOW_MODEL_PATTERNS:
        if pattern in model_lower:
            return True, f"slow_model_pattern_{pattern}"

    # 3. Large output request
    max_tokens = (body.get("inferenceConfig") or {}).get("maxTokens", 0)
    if isinstance(max_tokens, (int, float)) and max_tokens >= ASYNC_MAX_TOKENS_THRESHOLD:
        return True, f"max_tokens_{int(max_tokens)}"

    # 4. Large input context
    input_size = len(json.dumps(body.get("messages", []), ensure_ascii=False))
    system = body.get("system")
    if system:
        input_size += len(json.dumps(system, ensure_ascii=False))
    if input_size > ASYNC_INPUT_SIZE_THRESHOLD:
        return True, f"input_size_{input_size}"

    return False, ""


# ---------------------------------------------------------------------------
# Async Job Handlers (v2 — Step Functions + Fargate)
# ---------------------------------------------------------------------------

def handle_converse_job_submit(principal_id: str, identity_fields: dict,
                                body: dict, request_id: str) -> dict:
    """POST /converse-jobs — submit async Bedrock job.

    Control plane: validates, reserves budget, creates job, starts Step Functions.
    Returns 202 + jobId immediately.
    """
    model_id = body.get("modelId", "")
    if not model_id:
        return deny_response("modelId is required", status_code=400)

    # Orphan cleanup: remove stale reservations before quota check
    _cleanup_stale_reservations(principal_id, current_month_kst())

    # Feature flag check
    config = _get_gateway_config()
    if not config.get("async_jobs_enabled", True):
        return _response(503, {"error": "async jobs not available"})

    # Policy lookup
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        return deny_response("policy lookup failed")
    if not policy:
        return deny_response("no policy defined for principal")

    # Model access check
    if not check_model_access(policy, model_id):
        return deny_response(f"model {model_id} not in allowed list")

    # Pricing lookup
    pricing = lookup_model_pricing(model_id)
    if not pricing:
        return deny_response(f"no pricing defined for model {model_id}")

    # Quota pre-check
    try:
        quota_result = check_quota(principal_id, policy)
    except Exception as e:
        return deny_response("quota check failed")
    if not quota_result["allowed"]:
        return _response(429, {"decision": "DENY", "denial_reason": "monthly cost quota exceeded"})

    # Idempotency check
    try:
        cached = check_idempotency(request_id)
        if cached is not None:
            return _response(200, cached)
    except ConflictError:
        return _response(409, {"decision": "DENY", "denial_reason": "request already in progress"})

    # Create idempotency record
    if not create_idempotency_record(request_id, principal_id):
        return _response(409, {"decision": "DENY", "denial_reason": "request already in progress"})

    # Reserve budget
    estimated_input = int(body.get("estimated_input_tokens", 50000))
    est_cost = estimate_cost_krw(estimated_input, max(int(estimated_input * 0.2), 4096), pricing)
    reserve_krw = min(est_cost * Decimal("2"), Decimal("100000"))
    remaining = Decimal(str(quota_result["remaining"]["cost_krw"]))
    if reserve_krw > remaining:
        return _response(429, {"decision": "DENY", "denial_reason": f"estimated cost ({float(reserve_krw):.0f} KRW) exceeds remaining budget ({float(remaining):.0f} KRW). Request a quota increase."})
    if reserve_krw <= 0:
        return _response(429, {"decision": "DENY", "denial_reason": "insufficient budget for reservation"})

    job_id = f"job-{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    month = current_month_kst()
    pricing_version = pricing.get("pricing_version", "v1")

    # Store payload in S3 if large, else inline
    payload_ref = "inline"
    converse_body = json.dumps(body, default=str)
    if len(converse_body) > 256000:
        s3_key = f"payloads/{job_id}.json"
        try:
            s3_client.put_object(Bucket=PAYLOAD_BUCKET, Key=s3_key,
                                 Body=converse_body, ContentType="application/json")
            payload_ref = f"s3://{PAYLOAD_BUCKET}/{s3_key}"
        except Exception as e:
            log_structured("error", "s3_payload_store_failed", job_id=job_id, error=str(e))
            return error_response("failed to store payload")

    # Create job record
    if TABLE_JOB_STATE:
        job_table = dynamodb.Table(TABLE_JOB_STATE)
        job_item = {
            "job_id": job_id,
            "request_id": request_id,
            "principal_id": principal_id,
            "model_id": model_id,
            "region": os.environ.get("AWS_REGION", "us-west-2"),
            "status": "ACCEPTED",
            "pricing_version": pricing_version,
            "reserved_cost_krw": reserve_krw,
            "settled_cost_krw": Decimal("0"),
            "input_tokens": 0,
            "output_tokens": 0,
            "input_payload_ref": payload_ref,
            "result_ref": "",
            "sfn_execution_arn": "",
            "ecs_task_arn": "",
            "retry_count": 0,
            "error_message": "",
            "source_path": "gateway-async",
            "created_at": now_iso,
            "updated_at": now_iso,
            "completed_at": "",
            "ttl": int(time.time()) + 7 * 24 * 3600,
        }
        if payload_ref == "inline":
            job_item["inline_payload"] = converse_body
        try:
            job_table.put_item(Item=job_item)
        except Exception as e:
            log_structured("error", "job_create_failed", job_id=job_id, error=str(e))
            return error_response("failed to create job record")

    # Reserve budget in MonthlyUsage
    try:
        pk = f"{principal_id}#{month}"
        usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
        usage_table.update_item(
            Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"},
            UpdateExpression="ADD cost_krw :c SET #t = :ttl, source_path = :sp",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={
                ":c": reserve_krw,
                ":ttl": int(time.time()) + 7200,
                ":sp": "gateway-async-reserve",
            },
        )
    except Exception as e:
        log_structured("error", "budget_reserve_failed", job_id=job_id, error=str(e))

    # Ledger: REQUEST_ACCEPTED
    try:
        write_request_ledger({
            "request_id": f"{request_id}#REQUEST_ACCEPTED",
            "timestamp": now_iso,
            "principal_id": principal_id,
            "model_id": model_id,
            "decision": "ALLOW",
            "event_type": "REQUEST_ACCEPTED",
            "job_id": job_id,
            "source_path": "gateway-async",
            "reserved_cost_krw": reserve_krw,
            "pricing_version": pricing_version,
        })
    except Exception as e:
        log_structured("error", "ledger_accepted_failed", job_id=job_id, error=str(e))

    # Per-user active job count check (soft limit, not global hard cap)
    # Allows burst up to PER_USER_ACTIVE_LIMIT per user; no global semaphore.
    if TABLE_JOB_STATE:
        try:
            active_resp = job_table.query(
                IndexName="principal-created-index",
                KeyConditionExpression="principal_id = :pid",
                FilterExpression="#s IN (:s1, :s2, :s3)",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pid": principal_id,
                    ":s1": "ACCEPTED", ":s2": "QUEUED", ":s3": "RUNNING",
                },
                Select="COUNT",
            )
            active_count = active_resp.get("Count", 0)
            if active_count >= PER_USER_ACTIVE_LIMIT:
                log_structured("warning", "per_user_active_limit",
                               job_id=job_id, principal_id=principal_id, active=active_count)
                return _response(429, {
                    "decision": "DENY",
                    "denial_reason": f"per-user active job limit reached ({active_count}/{PER_USER_ACTIVE_LIMIT})",
                    "job_id": job_id, "active_jobs": active_count,
                })
        except Exception as e:
            log_structured("error", "active_count_check_failed", job_id=job_id, error=str(e))
            # fail-open: allow submission if count check fails

    sfn_execution_arn = ""
    # Enqueue to SQS job queue (dispatcher will start SFN after checking limits)
    if SQS_JOB_QUEUE_URL:
        try:
            sqs_message = {
                "job_id": job_id,
                "request_id": request_id,
                "principal_id": principal_id,
                "model_id": model_id,
                "region": os.environ.get("AWS_REGION", "us-west-2"),
                "pricing_version": pricing_version,
                "payload_ref": payload_ref,
            }
            sqs_client.send_message(
                QueueUrl=SQS_JOB_QUEUE_URL,
                MessageBody=json.dumps(sqs_message),
                MessageGroupId=principal_id if ".fifo" in SQS_JOB_QUEUE_URL else None,
                MessageDeduplicationId=job_id if ".fifo" in SQS_JOB_QUEUE_URL else None,
            ) if ".fifo" in SQS_JOB_QUEUE_URL else sqs_client.send_message(
                QueueUrl=SQS_JOB_QUEUE_URL,
                MessageBody=json.dumps(sqs_message),
            )
            log_structured("info", "job_enqueued", job_id=job_id, principal_id=principal_id)
        except Exception as e:
            log_structured("error", "sqs_enqueue_failed", job_id=job_id, error=str(e))
            if TABLE_JOB_STATE:
                try:
                    job_table.update_item(
                        Key={"job_id": job_id},
                        UpdateExpression="SET #s = :status, error_message = :err, updated_at = :ts",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":status": "FAILED",
                            ":err": f"Queue enqueue failed: {str(e)}",
                            ":ts": now_iso,
                        },
                    )
                except Exception:
                    pass
            return error_response("failed to enqueue job")
    elif SFN_STATE_MACHINE_ARN:
        # Fallback: direct SFN start (legacy, no queue)
        try:
            sfn_input = json.dumps({
                "job_id": job_id,
                "request_id": request_id,
                "principal_id": principal_id,
                "model_id": model_id,
                "region": os.environ.get("AWS_REGION", "us-west-2"),
                "pricing_version": pricing_version,
                "payload_ref": payload_ref,
            })
            sfn_resp = sfn_client.start_execution(
                stateMachineArn=SFN_STATE_MACHINE_ARN,
                name=job_id,
                input=sfn_input,
            )
            sfn_execution_arn = sfn_resp.get("executionArn", "")
            if TABLE_JOB_STATE:
                job_table.update_item(
                    Key={"job_id": job_id},
                    UpdateExpression="SET sfn_execution_arn = :arn",
                    ExpressionAttributeValues={":arn": sfn_execution_arn},
                )
        except Exception as e:
            log_structured("error", "sfn_start_failed", job_id=job_id, error=str(e))
            if TABLE_JOB_STATE:
                try:
                    job_table.update_item(
                        Key={"job_id": job_id},
                        UpdateExpression="SET #s = :status, error_message = :err, updated_at = :ts",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":status": "FAILED",
                            ":err": f"Step Functions start failed: {str(e)}",
                            ":ts": now_iso,
                        },
                    )
                except Exception:
                    pass
            return error_response("failed to start job execution")

    # Complete idempotency record
    response_body = {
        "decision": "ACCEPTED",
        "job_id": job_id,
        "status": "ACCEPTED",
        "model_id": model_id,
        "reserved_cost_krw": float(reserve_krw),
        "sfn_execution_arn": sfn_execution_arn,
    }
    try:
        complete_idempotency_record(request_id, response_body)
    except Exception:
        pass

    log_structured("info", "job_submitted", job_id=job_id, principal_id=principal_id,
                   model_id=model_id, reserved_krw=float(reserve_krw))

    return _response(202, response_body)


def handle_converse_job_status(principal_id: str, path: str) -> dict:
    """GET /converse-jobs/{jobId} — check async job status."""
    # Extract jobId from path
    parts = path.rstrip("/").split("/")
    if len(parts) < 2:
        return deny_response("jobId required", status_code=400)
    job_id = parts[-1]

    if not TABLE_JOB_STATE:
        return error_response("job state table not configured")

    job_table = dynamodb.Table(TABLE_JOB_STATE)
    try:
        resp = job_table.get_item(Key={"job_id": job_id})
        item = resp.get("Item")
    except Exception as e:
        return error_response(f"failed to read job: {str(e)}")

    if not item:
        return _response(404, {"error": "job not found"})

    # Validate ownership
    if item.get("principal_id") != principal_id:
        return deny_response("job does not belong to this principal", status_code=403)

    # Clean Decimal values
    def clean(v):
        if isinstance(v, Decimal):
            return int(v) if v == int(v) else float(v)
        return v

    return _response(200, {
        "job_id": job_id,
        "status": item.get("status", ""),
        "model_id": item.get("model_id", ""),
        "reserved_cost_krw": clean(item.get("reserved_cost_krw", 0)),
        "settled_cost_krw": clean(item.get("settled_cost_krw", 0)),
        "input_tokens": clean(item.get("input_tokens", 0)),
        "output_tokens": clean(item.get("output_tokens", 0)),
        "result_ref": item.get("result_ref", ""),
        "retry_count": clean(item.get("retry_count", 0)),
        "error_message": item.get("error_message", ""),
        "created_at": item.get("created_at", ""),
        "completed_at": item.get("completed_at", ""),
        "source_path": item.get("source_path", ""),
    })




def handle_converse_job_cancel(principal_id: str, path: str, request_id: str) -> dict:
    """POST /converse-jobs/{jobId}/cancel — cancel a running async job."""
    parts = path.rstrip("/").split("/")
    # path: /converse-jobs/{jobId}/cancel
    if len(parts) < 3:
        return deny_response("jobId required", status_code=400)
    job_id = parts[-2]

    if not TABLE_JOB_STATE:
        return error_response("job state table not configured")

    job_table = dynamodb.Table(TABLE_JOB_STATE)
    try:
        resp = job_table.get_item(Key={"job_id": job_id})
        item = resp.get("Item")
    except Exception as e:
        return error_response(f"failed to read job: {str(e)}")

    if not item:
        return _response(404, {"error": "job not found"})
    if item.get("principal_id") != principal_id:
        return deny_response("job does not belong to this principal", status_code=403)

    current_status = item.get("status", "")
    if current_status in ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"):
        return _response(200, {"job_id": job_id, "status": current_status, "message": "job already terminal"})

    # Stop Step Functions execution
    sfn_arn = item.get("sfn_execution_arn", "")
    if sfn_arn:
        try:
            sfn_client.stop_execution(executionArn=sfn_arn, cause="canceled by user")
            log_structured("info", "sfn_stopped", job_id=job_id, sfn_arn=sfn_arn)
        except Exception as e:
            log_structured("error", "sfn_stop_failed", job_id=job_id, error=str(e))

    # Release reservation
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    try:
        usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
        usage_table.delete_item(Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})
        log_structured("info", "reservation_released_cancel", job_id=job_id)
    except Exception as e:
        log_structured("error", "reservation_release_cancel_failed", job_id=job_id, error=str(e))

    # Release semaphore slot
    _release_semaphore_slot(job_id)

    # Update job state
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        job_table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :status, updated_at = :ts, completed_at = :ts, error_message = :msg",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "CANCELED", ":ts": now_iso, ":msg": "canceled by user"},
        )
    except Exception as e:
        log_structured("error", "job_cancel_update_failed", job_id=job_id, error=str(e))

    # Ledger
    try:
        write_request_ledger({
            "request_id": f"{item.get('request_id', request_id)}#JOB_CANCELED",
            "timestamp": now_iso,
            "principal_id": principal_id,
            "model_id": item.get("model_id", ""),
            "decision": "CANCELED",
            "event_type": "JOB_CANCELED",
            "job_id": job_id,
            "source_path": "gateway-async",
        })
    except Exception as e:
        log_structured("error", "cancel_ledger_failed", job_id=job_id, error=str(e))

    log_structured("info", "job_canceled", job_id=job_id, principal_id=principal_id)
    return _response(200, {"job_id": job_id, "status": "CANCELED", "message": "job canceled, reservation released"})



def _cleanup_stale_reservations(principal_id: str, month: str) -> int:
    """Scan and delete stale __reserved__ entries for this principal/month.
    Stale = reservation older than 2 hours (TTL should have expired but DDB TTL is async).
    Returns count of cleaned entries.
    """
    if not TABLE_MONTHLY_USAGE:
        return 0
    usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    pk = f"{principal_id}#{month}"
    try:
        resp = usage_table.query(
            KeyConditionExpression="principal_id_month = :pk",
            ExpressionAttributeValues={":pk": pk},
        )
    except Exception:
        return 0

    now_epoch = int(time.time())
    cleaned = 0
    for item in resp.get("Items", []):
        mid = item.get("model_id", "")
        if not mid.startswith("__reserved__"):
            continue
        ttl_val = int(item.get("ttl", 0))
        if ttl_val > 0 and ttl_val < now_epoch:
            # Stale — TTL expired, DDB hasn't cleaned yet
            try:
                usage_table.delete_item(Key={"principal_id_month": pk, "model_id": mid})
                cleaned += 1
                log_structured("info", "stale_reservation_cleaned",
                               principal_id=principal_id, model_id=mid)
            except Exception:
                pass
    return cleaned

# ---------------------------------------------------------------------------
# Main Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context) -> dict:
    """Gateway Lambda entry point.

    Request flow:
      1. Parse request, extract principal
      2. Route: discovery / approval / inference
      3. Inference pipeline: idempotency → policy → model access →
         quota → bedrock → usage update → idempotency complete →
         ledger → session metadata
    Deny-by-default: any unhandled exception → deny.
    """
    start_time = time.time()
    request_id = (
        (event.get("headers") or {}).get("X-Request-Id")
        or (event.get("headers") or {}).get("x-request-id")
        or str(uuid.uuid4())
    )
    request_context = event.get("requestContext", {})
    http_method = event.get("httpMethod", "")
    path = event.get("path", "")

    log_structured("info", "request_received",
                   request_id=request_id, method=http_method, path=path)

    # --- Discovery mode (Task 3) ---
    if DISCOVERY_MODE:
        return handle_discovery(request_context)

    # --- Principal extraction ---
    try:
        identity_fields = extract_identity(request_context)
        principal_id = normalize_principal_id(identity_fields)
    except Exception as e:
        log_structured("error", "principal_extraction_failed", error=str(e),
                       request_id=request_id)
        return deny_response("principal extraction failed")

    if not principal_id:
        log_structured("warning", "empty_principal_id", request_id=request_id)
        return deny_response("unable to determine principal identity")

    log_structured("info", "principal_identified",
                   request_id=request_id, principal_id=principal_id)

    # --- Route: approval endpoint ---
    if path.rstrip("/") == "/approval/request" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_approval_request(
            principal_id, identity_fields, body, request_id)

    # --- Route: quota status query (read-only, for shell hook) ---
    if path.rstrip("/") == "/quota/status" and http_method == "GET":
        return handle_quota_status(principal_id, identity_fields)

    # --- Route: longrun authorize (Tier 3 pre-authorization) ---
    if path.rstrip("/") == "/longrun/authorize" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_longrun_authorize(
            principal_id, identity_fields, body, request_id)

    # --- Route: longrun settle (Tier 3 post-completion) ---
    if path.rstrip("/") == "/longrun/settle" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_longrun_settle(
            principal_id, identity_fields, body, request_id)

    # --- Route: async job submit (v2) ---
    if path.rstrip("/") == "/converse-jobs" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_converse_job_submit(
            principal_id, identity_fields, body, request_id)

    # --- Route: async job status (v2) ---
    if path.startswith("/converse-jobs/") and http_method == "GET":
        return handle_converse_job_status(principal_id, path)
    # --- Route: async job cancel (v2) ---
    if path.rstrip("/").endswith("/cancel") and "/converse-jobs/" in path and http_method == "POST":
        return handle_converse_job_cancel(principal_id, path, request_id)


    # --- Inference pipeline (POST /converse or root) ---
    if http_method != "POST":
        return deny_response("method not allowed", status_code=405)

    # Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return deny_response("invalid JSON body", status_code=400)

    model_id = body.get("modelId", "")
    if not model_id:
        return deny_response("modelId is required", status_code=400)

    # -----------------------------------------------------------------------
    # ALL /converse requests route through async path.
    # API Gateway has a hard 29-second timeout. Rather than guessing which
    # requests will exceed 29s (impossible to predict reliably), we route
    # every request through the async pipeline (SQS → SFN → Fargate).
    #
    # Short requests: Fargate completes in 1-10s, user polls once or twice.
    # Long requests: Fargate takes 30-300s, user polls until done.
    # Result: zero 504 timeouts, regardless of model or input size.
    #
    # Trade-off: ~5-15s additional latency for short requests due to
    # SQS → Dispatcher → SFN → Fargate cold start. Acceptable for
    # a quota-managed gateway where reliability > latency.
    # -----------------------------------------------------------------------
    log_structured("info", "async_routing_all",
                   request_id=request_id, principal_id=principal_id,
                   model_id=model_id, reason="all_requests_async")
    return handle_converse_job_submit(principal_id, identity_fields, body, request_id)

    # Variables for ledger entry (populated as pipeline progresses)
    decision = "DENY"
    denial_reason = ""
    input_tokens = 0
    output_tokens = 0
    estimated_cost_krw = Decimal("0")
    bedrock_response = None

    try:
        # Step 1: Idempotency check
        try:
            cached = check_idempotency(request_id)
            if cached is not None:
                log_structured("info", "idempotency_hit",
                               request_id=request_id, principal_id=principal_id)
                return _response(200, cached)
        except ConflictError:
            return _response(409, {
                "decision": "DENY",
                "denial_reason": "request already in progress",
            })

        # Step 2: Create idempotency record (IN_PROGRESS)
        if not create_idempotency_record(request_id, principal_id):
            # Race: another invocation created it between check and create
            return _response(409, {
                "decision": "DENY",
                "denial_reason": "request already in progress",
            })

        # Step 3: PrincipalPolicy lookup (Req 1.4, 1.5)
        try:
            policy = lookup_principal_policy(principal_id)
        except Exception as e:
            log_structured("error", "policy_lookup_failed",
                           request_id=request_id, error=str(e))
            denial_reason = "policy lookup failed"
            return deny_response(denial_reason)

        if not policy:
            denial_reason = "no policy defined for principal"
            log_structured("warning", "no_policy",
                           request_id=request_id, principal_id=principal_id)
            return deny_response(denial_reason)

        # Step 4: Model access check (Req 3.1-3.3)
        if not check_model_access(policy, model_id):
            denial_reason = f"model {model_id} not in allowed list"
            log_structured("warning", "model_denied",
                           request_id=request_id, model_id=model_id)
            return deny_response(denial_reason)

        # Step 5: Pricing lookup (Task 2.7 — fail-closed if missing)
        try:
            pricing = lookup_model_pricing(model_id)
        except Exception as e:
            log_structured("error", "pricing_lookup_failed",
                           request_id=request_id, model_id=model_id,
                           error=str(e))
            denial_reason = "pricing lookup failed"
            return deny_response(denial_reason)

        if not pricing:
            denial_reason = f"no pricing defined for model {model_id}"
            log_structured("warning", "no_pricing",
                           request_id=request_id, model_id=model_id)
            return deny_response(denial_reason)

        # Step 6: Quota check (Req 4.1-4.2, KRW monthly)
        try:
            quota_result = check_quota(principal_id, policy)
        except Exception as e:
            log_structured("error", "quota_check_failed",
                           request_id=request_id, error=str(e))
            denial_reason = "quota check failed"
            return deny_response(denial_reason)

        if not quota_result["allowed"]:
            denial_reason = "monthly cost quota exceeded"
            log_structured("info", "quota_exceeded",
                           request_id=request_id, principal_id=principal_id,
                           usage=quota_result["usage"],
                           limit=quota_result["limit"])

            hard_cap = int(policy.get("max_monthly_cost_limit_krw", 2000000))
            effective = int(quota_result["limit"]["cost_krw"])
            usage_krw = quota_result["usage"]["cost_krw"]
            band_size = 500000
            band_floor = max(0, effective - band_size)
            can_request_more = (effective + band_size) <= hard_cap
            has_pending = False
            try:
                lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
                lock_resp = lock_table.get_item(Key={"principal_id": principal_id})
                lock_item = lock_resp.get("Item")
                if lock_item and int(lock_item.get("ttl", 0)) > int(time.time()):
                    has_pending = True
            except Exception:
                pass

            resp_body = {
                "decision": "DENY",
                "denial_reason": denial_reason,
                "quota": quota_result,
                "band": {
                    "floor_krw": band_floor,
                    "ceiling_krw": effective,
                    "size_krw": band_size,
                },
                "increase_request": {
                    "has_pending": has_pending,
                    "can_request": can_request_more and not has_pending,
                    "increment_krw": band_size,
                    "new_limit_if_approved_krw": effective + band_size if can_request_more else effective,
                    "hard_cap_krw": hard_cap,
                },
            }
            if has_pending:
                resp_body["message"] = "한도 증액 요청이 관리자 승인 대기 중입니다."
            elif can_request_more:
                resp_body["message"] = "현재 밴드 한도가 소진되었습니다. 한도 증액을 요청할 수 있습니다."
            else:
                resp_body["message"] = "월간 최대 한도에 도달하여 추가 증액이 불가합니다."

            return _response(429, resp_body)

        # Step 7: Bedrock Converse invocation (Req 6.1-6.4)
        try:
            bedrock_response = invoke_bedrock(model_id, body)
        except ValueError as e:
            # Model does not support Converse API (Req 6.6)
            denial_reason = str(e)
            log_structured("warning", "model_not_converse",
                           request_id=request_id, model_id=model_id)
            return deny_response(denial_reason, status_code=400)
        except Exception as e:
            denial_reason = f"bedrock invocation failed: {str(e)}"
            log_structured("error", "bedrock_failed",
                           request_id=request_id, error=str(e))
            return error_response(denial_reason)

        input_tokens = bedrock_response["usage"]["inputTokens"]
        output_tokens = bedrock_response["usage"]["outputTokens"]
        cache_read_tokens = bedrock_response["usage"].get("cacheReadInputTokens", 0)
        cache_write_tokens = bedrock_response["usage"].get("cacheWriteInputTokens", 0)
        decision = "ALLOW"

        # Step 8: Estimate cost (Task 2.2)
        # NOTE: Cache token costs are NOT included in estimate_cost_krw().
        # Current environment has cache=0. If cache becomes non-zero,
        # this log entry alerts operators that cost may be undercounted.
        estimated_cost_krw = estimate_cost_krw(input_tokens, output_tokens, pricing)

        if cache_read_tokens > 0 or cache_write_tokens > 0:
            log_structured("warning", "cache_tokens_nonzero_cost_not_included",
                           request_id=request_id, principal_id=principal_id,
                           model_id=model_id,
                           cache_read_tokens=cache_read_tokens,
                           cache_write_tokens=cache_write_tokens,
                           estimated_cost_krw=float(estimated_cost_krw),
                           note="Cache token cost not reflected in quota. Undercount risk.")

        # Step 9: MonthlyUsage atomic update (Task 2.4, Req 4.3, 12.6)
        try:
            update_monthly_usage(principal_id, model_id,
                                 estimated_cost_krw, input_tokens, output_tokens)
        except Exception as e:
            # Req 12.6: Bedrock succeeded, return response but alarm
            log_structured("error", "monthly_usage_update_failed",
                           request_id=request_id, error=str(e),
                           alarm=True)

        # Step 9b: Check user warning thresholds (30% / 10% remaining)
        try:
            new_usage = quota_result["usage"]["cost_krw"] + float(estimated_cost_krw)
            _check_and_send_warning_email(
                principal_id, policy, new_usage,
                int(quota_result["limit"]["cost_krw"]))
        except Exception as e:
            log_structured("error", "warning_check_failed",
                           request_id=request_id, error=str(e))

        # Step 10: Complete idempotency record
        response_body = {
            "decision": "ALLOW",
            "output": bedrock_response.get("output", {}),
            "stopReason": bedrock_response.get("stopReason", ""),
            "usage": bedrock_response["usage"],
            "estimated_cost_krw": float(estimated_cost_krw),
            "remaining_quota": {
                "cost_krw": max(0, float(Decimal(str(quota_result["remaining"]["cost_krw"])) - estimated_cost_krw)),
            },
            "request_id": request_id,
        }
        try:
            complete_idempotency_record(request_id, response_body)
        except Exception as e:
            log_structured("error", "idempotency_complete_failed",
                           request_id=request_id, error=str(e))

        # Step 11: RequestLedger (Req 8.1-8.3, 12.4, Task 2.6)
        duration_ms = int((time.time() - start_time) * 1000)
        ledger_entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id,
            "model_id": model_id,
            "region": os.environ.get("AWS_REGION", "us-west-2"),
            "decision": decision,
            "denial_reason": "",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": bedrock_response["usage"].get("cacheReadInputTokens", 0),
            "cache_write_tokens": bedrock_response["usage"].get("cacheWriteInputTokens", 0),
            "estimated_cost_krw": estimated_cost_krw,
            "input_price_per_1k_krw": pricing["input_price_per_1k"],
            "output_price_per_1k_krw": pricing["output_price_per_1k"],
            "fx_rate": 1450,
            "pricing_source": "dynamodb:model-pricing",
            "duration_ms": duration_ms,
        }
        try:
            write_request_ledger(ledger_entry)
        except Exception as e:
            # Req 12.4: ledger write failure → deny + alarm
            log_structured("error", "ledger_write_failed",
                           request_id=request_id, error=str(e),
                           alarm=True)
            return deny_response("audit ledger write failed")

        # Step 12: SessionMetadata (Req 2.3)
        try:
            write_session_metadata({
                "request_id": request_id,
                "principal_id": principal_id,
                "userArn": identity_fields.get("userArn", ""),
                "caller": identity_fields.get("caller", ""),
                "accountId": identity_fields.get("accountId", ""),
                "accessKey": identity_fields.get("accessKey", ""),
                "sourceIp": identity_fields.get("sourceIp", ""),
                "userAgent": identity_fields.get("userAgent", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            # SessionMetadata failure is non-fatal
            log_structured("error", "session_metadata_failed",
                           request_id=request_id, error=str(e))

        return _response(200, response_body)

    except Exception as e:
        # Deny-by-default catch-all (Req 12.5)
        log_structured("error", "unhandled_exception",
                       request_id=request_id, error=str(e))
        denial_reason = "internal error"
        return deny_response(denial_reason)
    finally:
        # Write ledger for deny cases (best-effort)
        if decision == "DENY" and denial_reason:
            duration_ms = int((time.time() - start_time) * 1000)
            try:
                write_request_ledger({
                    "request_id": request_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "principal_id": principal_id,
                    "model_id": model_id,
                    "decision": "DENY",
                    "denial_reason": denial_reason,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "estimated_cost_krw": 0,
                    "duration_ms": duration_ms,
                })
            except Exception:
                log_structured("error", "deny_ledger_write_failed",
                               request_id=request_id, alarm=True)
