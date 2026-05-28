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
import urllib.parse
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from botocore.exceptions import ClientError

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
PORTAL_BASE_URL = os.environ.get("PORTAL_BASE_URL", "http://203.0.113.10")

# ---------------------------------------------------------------------------
# KST Timezone (Q3 decision: KST for all monthly boundaries)
# ---------------------------------------------------------------------------
KST = timezone(timedelta(hours=9))

# ---------------------------------------------------------------------------
# Model Pricing Cache (cold-start loaded, fail-closed if empty)
# TTL-based: reloads from DynamoDB every hour to pick up exchange rate updates.
# ---------------------------------------------------------------------------
_model_pricing_cache: dict = {}
_model_pricing_cache_ts: float = 0.0  # epoch seconds when cache was last loaded
_MODEL_PRICING_CACHE_TTL: int = 3600  # 1 hour

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
# Tiered Boost Increment (below 2M: 500K, at/above 2M: 1M)
# ---------------------------------------------------------------------------

def _get_boost_increment(effective_limit_krw: int) -> int:
    """Return boost increment based on current effective limit.

    Below 2,000,000 KRW: 500,000 KRW increments
    At or above 2,000,000 KRW: 1,000,000 KRW increments
    """
    if effective_limit_krw >= 2000000:
        return 1000000
    return 500000


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

    Uses TTL-based cache (reloads every _MODEL_PRICING_CACHE_TTL seconds).
    Missing pricing → caller must deny.
    """
    global _model_pricing_cache, _model_pricing_cache_ts
    now = time.time()
    if not _model_pricing_cache or (now - _model_pricing_cache_ts) > _MODEL_PRICING_CACHE_TTL:
        _model_pricing_cache = _load_model_pricing_cache()
        _model_pricing_cache_ts = now
    pricing = _model_pricing_cache.get(model_id)
    if pricing is not None:
        return pricing
    # Cache miss — try one reload in case pricing was added after cold start
    _model_pricing_cache = _load_model_pricing_cache()
    _model_pricing_cache_ts = now
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
    # Hard cap (default 5,000,000 KRW)
    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))

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


class SyncFallbackError(Exception):
    """Raised when sync path should fall back to async."""
    pass

# Sync path: no retry, strict time budget.
# If Bedrock doesn't respond within SYNC_TIMEOUT, we can't retry (already consumed time).
# Instead, caller catches any error and falls back to async immediately.
SYNC_TIMEOUT_SECONDS = 20  # Leave 9s buffer for API Gateway 29s limit
SYNC_FALLBACK_ERRORS = {'ThrottlingException', 'ServiceUnavailableException', 'ServiceException'}

# Bedrock client with short timeout for sync path
_bedrock_sync = None
def _get_sync_bedrock_client():
    global _bedrock_sync
    if _bedrock_sync is None:
        from botocore.config import Config as BotoConfig
        _bedrock_sync = boto3.client("bedrock-runtime", config=BotoConfig(
            retries={"max_attempts": 0},
            read_timeout=SYNC_TIMEOUT_SECONDS,
            connect_timeout=5,
        ))
    return _bedrock_sync


def invoke_bedrock(model_id: str, request_body: dict) -> dict:
    """Call Bedrock Converse API on sync path.

    No retry — single attempt with strict timeout.
    Raises SyncFallbackError on throttle/timeout → caller falls back to async.
    """
    converse_params = {"modelId": model_id}
    for k in ("messages", "system", "inferenceConfig", "toolConfig"):
        if k in request_body:
            converse_params[k] = request_body[k]

    try:
        client = _get_sync_bedrock_client()
        resp = client.converse(**converse_params)
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
        if "does not support converse" in str(e).lower():
            raise ValueError(
                f"Model {model_id} does not support Converse API. "
                "Only Converse-compatible models are available in v1."
            )
        raise
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code in SYNC_FALLBACK_ERRORS:
            raise SyncFallbackError(f"sync bedrock error: {error_code}")
        raise
    except Exception as e:
        # ReadTimeoutError, ConnectTimeoutError etc → async fallback
        if "timeout" in str(type(e).__name__).lower() or "timeout" in str(e).lower():
            raise SyncFallbackError(f"sync timeout: {e}")
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

    # V2: Validate requested_increment_krw (tiered: 500K below 2M, 1M at/above 2M)
    requested_increment = request_body.get("requested_increment_krw")
    if requested_increment is None:
        log_structured("warning", "approval_missing_increment",
                       principal_id=principal_id, request_id=request_id)
        return _response(400, {
            "decision": "DENY",
            "denial_reason": "requested_increment_krw is required",
        })
    try:
        requested_increment = int(requested_increment)
    except (ValueError, TypeError):
        return _response(400, {
            "decision": "DENY",
            "denial_reason": "requested_increment_krw must be an integer",
        })
    if requested_increment not in (500000, 1000000):
        log_structured("warning", "approval_wrong_increment",
                       principal_id=principal_id, request_id=request_id,
                       requested=requested_increment)
        return _response(400, {
            "decision": "DENY",
            "denial_reason": f"requested_increment_krw must be 500000 or 1000000 (got {requested_increment})",
        })

    # V3: Hard cap pre-validation (tiered increment, max 5M)
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "approval_policy_lookup_failed",
                       principal_id=principal_id, error=str(e))
        return deny_response("policy lookup failed during approval pre-validation")

    if not policy:
        return deny_response("no policy defined for principal")

    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))
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
                         hard_cap_krw: int = 5000000,
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
    increment = _get_boost_increment(current_effective)
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
# User Warning Emails — 90% warning + 100% exhaustion per band
# ---------------------------------------------------------------------------
#
# Per-band email schedule:
#   - Non-final bands (effective_limit < hard_cap):
#       90% usage → 한도증액요청 메일 (with increase button)
#      100% usage → 한도증액요청 메일 한번 더 (with increase button)
#   - Final band (effective_limit == hard_cap):
#       90% usage → 경고 메일 (증액 불가)
#      100% usage → 이번달 전부 소진 메일
#
# Dedup keys on principal-policy item (keyed to effective_limit value):
#   - warning_90pct_sent_for_limit  → one 90% email per effective_limit
#   - exhaustion_email_sent_for_limit → one 100% email per effective_limit
#
# Both keys are REMOVED when:
#   - Admin approves increase (approve_request)
#   - Admin direct boost (admin_direct_boost)
#   - Email-based approval (email_action_approve)
# ---------------------------------------------------------------------------


def _check_and_send_warning_email(principal_id: str, policy: dict,
                                  usage_krw: float, effective_limit: int) -> None:
    """Check usage thresholds and send appropriate warning/exhaustion emails.

    Two thresholds per band:
      1) 90% of effective_limit → warning email (dedup: warning_90pct_sent_for_limit)
      2) 100% of effective_limit → exhaustion email (dedup: exhaustion_email_sent_for_limit)

    For non-final bands: both emails include 한도증액요청 button.
    For final band (effective_limit == hard_cap): 90% = warning only, 100% = 소진 알림.
    """
    if effective_limit <= 0:
        return

    # Skip for direct-access exception users
    if policy.get("direct_access_exception") is True:
        log_structured("info", "warning_email_skip_exception", principal_id=principal_id)
        return

    remaining = max(0, effective_limit - usage_krw)
    remaining_pct = remaining / effective_limit
    usage_pct = usage_krw / effective_limit * 100

    # Determine which thresholds are crossed
    crossed_100 = usage_krw >= effective_limit
    crossed_90 = usage_pct >= 90.0  # remaining_pct <= 0.10

    if not crossed_90:
        return  # Not yet at any threshold

    # Read dedup flags
    sent_90_for = policy.get("warning_90pct_sent_for_limit")
    if isinstance(sent_90_for, Decimal):
        sent_90_for = int(sent_90_for)
    # Legacy compat: also check old key name
    if sent_90_for is None:
        sent_90_for = policy.get("warning_10pct_sent_for_limit")
        if isinstance(sent_90_for, Decimal):
            sent_90_for = int(sent_90_for)

    sent_100_for = policy.get("exhaustion_email_sent_for_limit")
    if isinstance(sent_100_for, Decimal):
        sent_100_for = int(sent_100_for)

    already_sent_90 = (sent_90_for == effective_limit)
    already_sent_100 = (sent_100_for == effective_limit)

    # Decide which email to send (prefer 100% over 90% if both crossed)
    if crossed_100 and not already_sent_100:
        _send_band_email(principal_id, policy, usage_krw, effective_limit,
                         threshold_type="exhaustion")
    elif crossed_90 and not already_sent_90:
        _send_band_email(principal_id, policy, usage_krw, effective_limit,
                         threshold_type="warning_90")


def _send_band_email(principal_id: str, policy: dict,
                     usage_krw: float, effective_limit: int,
                     threshold_type: str) -> None:
    """Send a single band-level email (90% warning or 100% exhaustion).

    threshold_type: "warning_90" or "exhaustion"

    Email content varies by:
      - threshold_type (90% vs 100%)
      - is_final_band (effective_limit == hard_cap)
    """
    user_email = policy.get("notification_email", "")
    if not user_email or not SES_SENDER_EMAIL:
        log_structured("warning", "band_email_no_recipient",
                       principal_id=principal_id, threshold_type=threshold_type)
        return

    username = principal_id.split("#")[-1] if "#" in principal_id else principal_id
    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))
    band_size = _get_boost_increment(effective_limit)
    new_limit = effective_limit + band_size
    is_final_band = (effective_limit >= hard_cap)
    can_increase = not is_final_band
    has_pending = _check_pending_lock(principal_id)

    remaining = max(0, effective_limit - usage_krw)
    remaining_pct = remaining / effective_limit if effective_limit > 0 else 0
    usage_pct = usage_krw / effective_limit * 100 if effective_limit > 0 else 0

    # --- Determine subject, guidance, button ---
    if threshold_type == "exhaustion":
        if is_final_band:
            # Final band 100%: 이번달 전부 소진
            subject = "[Bedrock Gateway] 월간 한도 전부 소진 — 요청 차단됨"
            guidance_html = (
                f"이번 달 월간 최대 한도(KRW {hard_cap:,})를 전부 소진하였습니다. "
                "추가 증액이 불가하며, 다음 달 초에 한도가 초기화됩니다."
            )
            guidance_text = guidance_html
            button_html = ""
            header_title = "Bedrock Gateway 월간 한도 소진 알림"
            header_color = "#d9534f"
            status_msg = f"월간 최대 한도(KRW {hard_cap:,})를 전부 소진하였습니다."
        else:
            # Non-final band 100%: 한도증액요청 메일
            subject = "[Bedrock Gateway] 한도 소진 — 요청 차단됨"
            header_title = "Bedrock Gateway 한도 소진 알림"
            header_color = "#d9534f"
            status_msg = "한도 초과로 인해 Bedrock 요청이 차단되었습니다."
            if can_increase and not has_pending:
                try:
                    action_token = str(uuid.uuid4())
                    _store_action_token(principal_id, action_token)
                    increase_url = (
                        f"{PORTAL_BASE_URL}/api/gateway/increase-request"
                        f"?principal_id={urllib.parse.quote(principal_id)}"
                        f"&token={action_token}"
                    )
                    button_html = (
                        f'<div style="margin: 24px 0;">'
                        f'<a href="{increase_url}" style="display: inline-block; padding: 12px 32px; '
                        f'background: #007bff; color: white; text-decoration: none; border-radius: 6px; '
                        f'font-size: 16px; font-weight: bold;">한도 증액 요청</a></div>'
                    )
                    guidance_html = "한도가 소진되어 Bedrock 요청이 차단되었습니다. 아래 버튼을 클릭하면 관리자에게 한도 증액 승인 요청이 전송됩니다."
                    guidance_text = f"한도가 소진되어 Bedrock 요청이 차단되었습니다.\n한도 증액 요청: {increase_url}"
                except Exception as e:
                    log_structured("error", "band_email_increase_link_failed",
                                   principal_id=principal_id, error=str(e))
                    button_html = ""
                    guidance_html = "한도가 소진되어 Bedrock 요청이 차단되었습니다. 포털(Bedrock Gateway 페이지)에서 한도 증액을 요청할 수 있습니다."
                    guidance_text = guidance_html
            elif has_pending:
                button_html = ""
                guidance_html = "한도 증액 요청이 관리자 승인 대기 중입니다."
                guidance_text = guidance_html
            else:
                button_html = ""
                guidance_html = f"월간 최대 한도(KRW {hard_cap:,})에 도달하여 추가 증액이 불가합니다."
                guidance_text = guidance_html
    else:
        # threshold_type == "warning_90"
        if is_final_band:
            # Final band 90%: 경고 (증액 불가)
            subject = f"[Bedrock Gateway] 사용량 경고: 한도의 {usage_pct:.0f}% 사용 (증액 불가)"
            header_title = "Bedrock Gateway 사용량 경고"
            header_color = "#333"
            status_msg = f"현재 적용 한도의 {usage_pct:.0f}%를 사용하였습니다. (잔여 {remaining_pct*100:.0f}%)"
            button_html = ""
            guidance_html = (
                f"월간 최대 한도(KRW {hard_cap:,})에 도달하여 추가 증액이 불가합니다. "
                "잔여 한도를 초과하면 Bedrock 요청이 차단됩니다."
            )
            guidance_text = guidance_html
        else:
            # Non-final band 90%: 한도증액요청 메일
            subject = f"[Bedrock Gateway] 사용량 알림: 한도의 {usage_pct:.0f}% 사용 (잔여 {remaining_pct*100:.0f}%)"
            header_title = "Bedrock Gateway 사용량 알림"
            header_color = "#333"
            status_msg = f"현재 적용 한도의 {usage_pct:.0f}%를 사용하였습니다. (잔여 {remaining_pct*100:.0f}%)"
            if can_increase and not has_pending:
                try:
                    action_token = str(uuid.uuid4())
                    _store_action_token(principal_id, action_token)
                    increase_url = (
                        f"{PORTAL_BASE_URL}/api/gateway/increase-request"
                        f"?principal_id={urllib.parse.quote(principal_id)}"
                        f"&token={action_token}"
                    )
                    button_html = (
                        f'<div style="margin: 24px 0;">'
                        f'<a href="{increase_url}" style="display: inline-block; padding: 12px 32px; '
                        f'background: #007bff; color: white; text-decoration: none; border-radius: 6px; '
                        f'font-size: 16px; font-weight: bold;">한도 증액 요청</a></div>'
                    )
                    guidance_html = "한도가 거의 소진되었습니다. 아래 버튼을 클릭하면 관리자에게 한도 증액 승인 요청이 전송됩니다."
                    guidance_text = f"한도가 거의 소진되었습니다.\n한도 증액 요청: {increase_url}"
                except Exception as e:
                    log_structured("error", "band_email_increase_link_failed",
                                   principal_id=principal_id, error=str(e))
                    button_html = ""
                    guidance_html = "한도가 거의 소진되었습니다. 포털(Bedrock Gateway 페이지)에서 한도 증액을 요청할 수 있습니다."
                    guidance_text = guidance_html
            elif has_pending:
                button_html = ""
                guidance_html = "한도 증액 요청이 관리자 승인 대기 중입니다."
                guidance_text = guidance_html
            else:
                button_html = ""
                guidance_html = f"월간 최대 한도(KRW {hard_cap:,})에 도달하여 추가 증액이 불가합니다."
                guidance_text = guidance_html

    # --- Build email body (same HTML template as before) ---
    html_body = f"""<html><head></head><body style="font-family: sans-serif; max-width: 600px;">
<h2 style="color: {header_color};">{header_title}</h2>
<p style="color: #d9534f; font-weight: bold;">{status_msg}</p>
<table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; width: 40%;"><b>사용자</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">{username}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>현재 적용 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {effective_limit:,}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>총 사용 금액</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {usage_krw:,.0f} ({usage_pct:.1f}%)</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>잔여 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {remaining:,.0f} ({remaining_pct*100:.1f}%)</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>승인 시 새 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;"><b>KRW {new_limit:,}</b></td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9;"><b>월간 최대 한도</b></td>
<td style="padding: 8px; border: 1px solid #ddd;">KRW {hard_cap:,}</td></tr>
</table>
<p>{guidance_html}</p>
{button_html}
<p style="color: #999; font-size: 11px;">이 메일은 Bedrock Gateway에서 자동 발송되었습니다.</p>
</body></html>"""

    text_body = (
        f"{header_title}\n"
        f"{'='*50}\n\n"
        f"사용자: {username}\n\n"
        f"현재 적용 한도: KRW {effective_limit:,}\n"
        f"총 사용 금액: KRW {usage_krw:,.0f} ({usage_pct:.1f}%)\n"
        f"잔여 한도: KRW {remaining:,.0f} ({remaining_pct*100:.1f}%)\n"
        f"월간 최대 한도: KRW {hard_cap:,}\n\n"
        f"{guidance_text}\n"
    )

    # --- Send email ---
    try:
        ses_client.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={"ToAddresses": [user_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Text": {"Data": text_body},
                    "Html": {"Data": html_body},
                },
            },
        )
        log_structured("info", "band_email_sent",
                       principal_id=principal_id,
                       threshold_type=threshold_type,
                       usage_krw=usage_krw, remaining_krw=remaining,
                       remaining_pct=remaining_pct,
                       effective_limit=effective_limit,
                       is_final_band=is_final_band)
    except Exception as e:
        log_structured("error", "band_email_failed",
                       principal_id=principal_id,
                       threshold_type=threshold_type, error=str(e))
        return

    # --- Update dedup state ---
    try:
        policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        if threshold_type == "exhaustion":
            policy_table.update_item(
                Key={"principal_id": principal_id},
                UpdateExpression="SET exhaustion_email_sent_for_limit = :val",
                ExpressionAttributeValues={":val": effective_limit},
            )
        else:
            # warning_90 — also set legacy key for backward compat
            policy_table.update_item(
                Key={"principal_id": principal_id},
                UpdateExpression="SET warning_90pct_sent_for_limit = :w90, warning_10pct_sent_for_limit = :w90",
                ExpressionAttributeValues={":w90": effective_limit},
            )
    except Exception as e:
        log_structured("error", "band_email_dedup_update_failed",
                       principal_id=principal_id,
                       threshold_type=threshold_type, error=str(e))



# ---------------------------------------------------------------------------
# Exhaustion Email — sent when quota is exhausted (429 path)
# Delegates to _send_band_email for consistent behavior.
# ---------------------------------------------------------------------------

def _send_exhaustion_email(principal_id: str, policy: dict,
                           usage_krw: float, effective_limit: int) -> None:
    """Send quota exhaustion email (called from 429 response path).

    Delegates to _send_band_email with threshold_type="exhaustion".
    Handles dedup, direct_access_exception, and missing recipient checks
    inside _send_band_email / _check_and_send_warning_email.

    Non-fatal: all errors caught and logged, never raises.
    """
    try:
        if effective_limit <= 0:
            return
        if policy.get("direct_access_exception") is True:
            log_structured("info", "exhaustion_email_skip_exception",
                           principal_id=principal_id)
            return

        # Dedup check
        already_sent_for = policy.get("exhaustion_email_sent_for_limit")
        if isinstance(already_sent_for, Decimal):
            already_sent_for = int(already_sent_for)
        if already_sent_for == effective_limit:
            log_structured("info", "exhaustion_email_dedup_skip",
                           principal_id=principal_id,
                           effective_limit=effective_limit)
            return

        _send_band_email(principal_id, policy, usage_krw, effective_limit,
                         threshold_type="exhaustion")
    except Exception as e:
        log_structured("error", "exhaustion_email_failed",
                       principal_id=principal_id, error=str(e))


# ---------------------------------------------------------------------------
# Action Token & Pending Lock Helpers (email-based approval request)
# ---------------------------------------------------------------------------

def _store_action_token(principal_id: str, token: str) -> None:
    """Store increase_action_token + TTL (7 days) in principal-policy table.

    Uses atomic UpdateExpression to set both attributes in a single call.
    Fail-safe: logs error on failure but does NOT raise.
    """
    try:
        ttl = int(time.time()) + 604800  # 7 days in seconds
        policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        policy_table.update_item(
            Key={"principal_id": principal_id},
            UpdateExpression="SET increase_action_token = :tok, increase_action_token_ttl = :ttl",
            ExpressionAttributeValues={
                ":tok": token,
                ":ttl": ttl,
            },
        )
        log_structured("info", "action_token_stored",
                       principal_id=principal_id, ttl=ttl)
    except Exception as e:
        log_structured("error", "action_token_store_failed",
                       principal_id=principal_id, error=str(e))


def _check_pending_lock(principal_id: str) -> bool:
    """Check if an active approval-pending-lock exists for the principal.

    Returns True if a non-expired lock exists, False otherwise.
    Fail-open: on any exception returns False (log warning).
    Duplicate requests are ultimately prevented at lock acquisition time.
    """
    try:
        lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
        resp = lock_table.get_item(Key={"principal_id": principal_id})
        item = resp.get("Item")
        if not item:
            return False
        lock_ttl = item.get("ttl", 0)
        if isinstance(lock_ttl, Decimal):
            lock_ttl = int(lock_ttl)
        return int(lock_ttl) > int(time.time())
    except Exception as e:
        log_structured("warning", "pending_lock_check_failed",
                       principal_id=principal_id, error=str(e))
        return False


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
    hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))
    increment = _get_boost_increment(effective_limit)

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
ASYNC_MAX_TOKENS_THRESHOLD = 4096    # maxTokens >= 8K → async (lowered from 16K)
ASYNC_INPUT_SIZE_THRESHOLD = 100000  # input body > ~100KB → async (lowered from 200KB)

# Models that ALWAYS route to async regardless of input size.
# These are known to routinely exceed 29s even for trivial inputs.
ALWAYS_ASYNC_MODELS = {
    # Opus variants (always slow, 30-120s typical)
    "us.anthropic.claude-opus-4-7",
    "global.anthropic.claude-opus-4-7",
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

    Returns (should_async: bool, reason: str).
    Known slow models (opus, deepseek-r1, nova-premier) always async.
    Other models start sync by default. Async only for large input/output.
    Sync throttle errors are caught by caller and fall back to async.
    """
    # 1. Known slow models — always async (routinely exceed 29s)
    model_lower = model_id.lower()
    for pattern in SLOW_MODEL_PATTERNS:
        if pattern in model_lower:
            return True, f"slow_model_{pattern}"

    # 2. Large output request
    max_tokens = (body.get("inferenceConfig") or {}).get("maxTokens", 0)
    if isinstance(max_tokens, (int, float)) and max_tokens >= ASYNC_MAX_TOKENS_THRESHOLD:
        return True, f"max_tokens_{int(max_tokens)}"

    # 3. Large input context
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

    # Per-user active job count check — BEFORE creating any records
    if TABLE_JOB_STATE:
        try:
            _job_table = dynamodb.Table(TABLE_JOB_STATE)
            active_resp = _job_table.query(
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
                               principal_id=principal_id, active=active_count)
                return _response(429, {
                    "decision": "DENY",
                    "denial_reason": f"per-user active job limit reached ({active_count}/{PER_USER_ACTIVE_LIMIT})",
                    "active_jobs": active_count,
                })
        except Exception as e:
            log_structured("error", "active_count_check_failed", principal_id=principal_id, error=str(e))
            # fail-open: allow submission if count check fails

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
        # Send exhaustion email — user needs to know they're blocked and can request increase
        try:
            _send_exhaustion_email(principal_id, policy, float(Decimal(str(quota_result["usage"]["cost_krw"]))),
                                   int(quota_result["limit"]["cost_krw"]))
        except Exception:
            pass
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
# Internal Warning Check Handler (async settlement path)
# ---------------------------------------------------------------------------

def _handle_warning_check(event: dict) -> dict:
    """Handle warning-check internal route invoked by Worker after settlement.

    Extracts principal_id and usage from event, queries policy and boost tables,
    then delegates to _check_and_send_warning_email.
    """
    principal_id = event.get("principal_id", "")
    usage_krw = float(event.get("usage_after_settlement_krw", 0))
    source = event.get("source", "unknown")
    job_id = event.get("job_id", "")

    log_structured("info", "warning_check_start",
                   principal_id=principal_id, usage_krw=usage_krw,
                   source=source, job_id=job_id)

    try:
        # Query principal-policy table
        policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        resp = policy_table.get_item(Key={"principal_id": principal_id})
        policy = resp.get("Item")
        if not policy:
            log_structured("warning", "warning_check_no_policy",
                           principal_id=principal_id, job_id=job_id)
            return {"status": "skip", "reason": "no_policy"}

        # Calculate effective_limit (base + active TemporaryQuotaBoost)
        base_limit = int(policy.get("monthly_cost_limit_krw", 500000))
        hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))

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
            log_structured("error", "warning_check_boost_lookup_failed",
                           principal_id=principal_id, error=str(e))

        effective_limit = min(base_limit + boost_cost_krw, hard_cap)

        _check_and_send_warning_email(principal_id, policy, usage_krw, effective_limit)

        log_structured("info", "warning_check_complete",
                       principal_id=principal_id, job_id=job_id,
                       effective_limit=effective_limit)
        return {"status": "success"}

    except Exception as e:
        log_structured("error", "warning_check_failed",
                       principal_id=principal_id, job_id=job_id, error=str(e))
        return {"status": "error", "error": str(e)}


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

    # Internal routes (Lambda direct invoke, not via API Gateway)
    if event.get("_internal_route") == "warning-check":
        return _handle_warning_check(event)

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

    # --- Route: /invoke — InvokeModel passthrough (image / embedding / rerank) ---
    if path.rstrip("/") == "/invoke" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_invoke(principal_id, identity_fields, body, request_id)


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
    # Smart routing: sync first, async for large requests or throttle fallback.
    # All models start sync. Large input/output → async from the start.
    # Sync fallback (SyncFallbackError) → automatic async fallback.
    # -----------------------------------------------------------------------
    should_async, async_reason = _should_route_async(model_id, body)
    if should_async:
        log_structured("info", "async_routing",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id, reason=async_reason)
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

            hard_cap = int(policy.get("max_monthly_cost_limit_krw", 5000000))
            effective = int(quota_result["limit"]["cost_krw"])
            usage_krw = quota_result["usage"]["cost_krw"]
            band_size = _get_boost_increment(effective)
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

            # Send exhaustion email with increase request link (replaces _auto_create_approval_request)
            _send_exhaustion_email(principal_id, policy, usage_krw, effective)

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
        except SyncFallbackError as e:
            # Sync failed (throttle or timeout) → fallback to async path
            log_structured("warning", "sync_fallback_to_async",
                           request_id=request_id, model_id=model_id,
                           error=str(e))
            return handle_converse_job_submit(
                principal_id, identity_fields, body, request_id)
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


# ===========================================================================
# /invoke route — InvokeModel passthrough (image / embedding / rerank)
# ===========================================================================
# ISOLATED MODULE — does not modify any existing function or route.
# Independent helpers (prefixed with _invoke_) and one route handler
# (handle_invoke) are appended at the bottom of this file.
#
# Existing /converse, /converse-jobs, /longrun/*, /quota/status, /approval/*,
# ConverseStream, write_request_ledger, update_monthly_usage are NOT modified.
#
# RequestLedger contract preserved (immutable, append-only):
#   - /invoke writes a single PutItem to RequestLedger AFTER successful
#     settlement (matches existing /converse contract). No Update/Delete
#     ever performed on RequestLedger.
#
# Idempotency contract (request_id-based) — uses existing IdempotencyRecord
# table which is purpose-built for this and already permits Update/Delete:
#   1. IN_PROGRESS claim — conditional PutItem on IdempotencyRecord
#      (request_id MUST NOT exist). Bedrock invoked only on success.
#   2. COMPLETED commit — TransactWriteItems atomically:
#        - IdempotencyRecord UpdateItem (IN_PROGRESS → COMPLETED, conditional)
#        - MonthlyUsage UpdateItem (cost/usage ADD)
#      RequestLedger PutItem happens AFTER successful transaction (immutable).
#   3. FAILED — IdempotencyRecord UpdateItem (IN_PROGRESS → FAILED).
#      MonthlyUsage NOT incremented. RequestLedger DENY entry written
#      (existing pattern from /converse).
#   4. Duplicate request_id (already present) → no Bedrock re-invocation:
#        - COMPLETED → cached response read from IdempotencyRecord
#        - IN_PROGRESS → 409 with retry_after
#        - FAILED → 409 with hint to retry with new request_id
# ===========================================================================

# Allowlist — only these models are accepted on /invoke (gateway-level gate).
_INVOKE_ALLOWLIST = frozenset({
    # Image generation (17)
    "stability.sd3-5-large-v1:0",
    "stability.stable-image-core-v1:1",
    "stability.stable-image-ultra-v1:1",
    "stability.stable-conservative-upscale-v1:0",
    "stability.stable-creative-upscale-v1:0",
    "stability.stable-fast-upscale-v1:0",
    "stability.stable-image-control-sketch-v1:0",
    "stability.stable-image-control-structure-v1:0",
    "stability.stable-image-erase-object-v1:0",
    "stability.stable-image-inpaint-v1:0",
    "stability.stable-image-remove-background-v1:0",
    "stability.stable-image-search-recolor-v1:0",
    "stability.stable-image-search-replace-v1:0",
    "stability.stable-image-style-guide-v1:0",
    "stability.stable-outpaint-v1:0",
    "stability.stable-style-transfer-v1:0",
    "amazon.titan-image-generator-v2:0",
    "amazon.nova-canvas-v1:0",
    # Video generation (1)
    "luma.ray-v2:0",
    # Embedding (6)
    "amazon.titan-embed-text-v2:0",
    "amazon.titan-embed-text-v1",
    "amazon.titan-embed-g1-text-02",
    "amazon.titan-embed-image-v1",
    "cohere.embed-english-v3",
    "cohere.embed-multilingual-v3",
    # Rerank (2)
    "amazon.rerank-v1:0",
    "cohere.rerank-v3-5:0",
})

_INVOKE_IMAGE_MODELS = frozenset({
    "stability.sd3-5-large-v1:0",
    "stability.stable-image-core-v1:1",
    "stability.stable-image-ultra-v1:1",
    "stability.stable-conservative-upscale-v1:0",
    "stability.stable-creative-upscale-v1:0",
    "stability.stable-fast-upscale-v1:0",
    "stability.stable-image-control-sketch-v1:0",
    "stability.stable-image-control-structure-v1:0",
    "stability.stable-image-erase-object-v1:0",
    "stability.stable-image-inpaint-v1:0",
    "stability.stable-image-remove-background-v1:0",
    "stability.stable-image-search-recolor-v1:0",
    "stability.stable-image-search-replace-v1:0",
    "stability.stable-image-style-guide-v1:0",
    "stability.stable-outpaint-v1:0",
    "stability.stable-style-transfer-v1:0",
    "amazon.titan-image-generator-v2:0",
    "amazon.nova-canvas-v1:0",
    "luma.ray-v2:0",
})
_INVOKE_EMBEDDING_MODELS = frozenset({
    "amazon.titan-embed-text-v2:0",
    "amazon.titan-embed-text-v1",
    "amazon.titan-embed-g1-text-02",
    "amazon.titan-embed-image-v1",
    "cohere.embed-english-v3",
    "cohere.embed-multilingual-v3",
})
_INVOKE_RERANK_MODELS = frozenset({
    "amazon.rerank-v1:0",
    "cohere.rerank-v3-5:0",
})

_INVOKE_IDEMPOTENCY_TTL_SECONDS = 24 * 3600
_INVOKE_PENDING_RETRY_AFTER_SECONDS = 30


def _invoke_classify_modal(model_id: str) -> str:
    """Return 'image' | 'embedding' | 'rerank' | '' (unsupported)."""
    if model_id in _INVOKE_IMAGE_MODELS:
        return "image"
    if model_id in _INVOKE_EMBEDDING_MODELS:
        return "embedding"
    if model_id in _INVOKE_RERANK_MODELS:
        return "rerank"
    return ""


def _invoke_extract_usage(model_id: str, request_body: dict,
                          response_body: dict) -> dict:
    """Return {"unit": str, "count": int} or {} on failure (caller must deny).

    Deterministic extraction from official Bedrock response shapes.
    """
    modal = _invoke_classify_modal(model_id)
    try:
        if modal == "image":
            images = response_body.get("images") if isinstance(response_body, dict) else None
            if not isinstance(images, list) or len(images) <= 0:
                return {}
            return {"unit": "per_image", "count": len(images)}

        if modal == "embedding":
            tok = response_body.get("inputTextTokenCount") if isinstance(response_body, dict) else None
            if not isinstance(tok, (int, float)) or tok <= 0:
                return {}
            return {"unit": "input_tokens", "count": int(tok)}

        if modal == "rerank":
            # Rerank: count documents from request (deterministic)
            docs = (request_body or {}).get("documents") or []
            if isinstance(docs, list) and len(docs) > 0:
                return {"unit": "per_doc", "count": len(docs)}
            # Amazon Rerank uses 'sources' key
            sources = (request_body or {}).get("sources") or []
            if isinstance(sources, list) and len(sources) > 0:
                return {"unit": "per_doc", "count": len(sources)}
            return {}
    except Exception:
        return {}
    return {}


def _invoke_estimate_cost_krw(model_id: str, usage: dict,
                              pricing_row: dict) -> Decimal:
    """Compute KRW cost as Decimal. Returns Decimal('-1') on unit mismatch
    or missing price (caller must deny — never accumulate 0)."""
    if not usage or not pricing_row:
        return Decimal("-1")
    unit = usage.get("unit", "")
    count = int(usage.get("count", 0))
    if count <= 0:
        return Decimal("-1")

    pricing_unit = pricing_row.get("pricing_unit", "")

    if unit == "per_image":
        if pricing_unit not in ("per_image", ""):
            return Decimal("-1")
        per = pricing_row.get("per_image_price_krw")
        if per is None:
            per = pricing_row.get("per_image_krw")
        if per is None:
            return Decimal("-1")
        return Decimal(str(per)) * Decimal(str(count))

    if unit == "input_tokens":
        per1k = pricing_row.get("input_price_per_1k")
        if per1k is None:
            return Decimal("-1")
        return (Decimal(str(count)) * Decimal(str(per1k))) / Decimal("1000")

    if unit == "per_doc":
        # Rerank: per_doc_price_per_1k_krw or fallback to input_price_per_1k
        per1k = pricing_row.get("per_doc_price_per_1k_krw")
        if per1k is None:
            per1k = pricing_row.get("input_price_per_1k")
        if per1k is None:
            return Decimal("-1")
        return (Decimal(str(count)) * Decimal(str(per1k))) / Decimal("1000")

    return Decimal("-1")


def _invoke_lookup_pricing(model_id: str) -> dict:
    """Direct GetItem on ModelPricing for /invoke. Returns {} if missing."""
    if not TABLE_MODEL_PRICING:
        return {}
    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        resp = table.get_item(Key={"model_id": model_id})
        return resp.get("Item") or {}
    except Exception as e:
        log_structured("error", "invoke_pricing_lookup_failed",
                       model_id=model_id, error=str(e))
        return {}


_invoke_bedrock_client = None


def _invoke_get_bedrock_client():
    global _invoke_bedrock_client
    if _invoke_bedrock_client is None:
        from botocore.config import Config as BotoConfig
        _invoke_bedrock_client = boto3.client(
            "bedrock-runtime",
            config=BotoConfig(
                retries={"max_attempts": 0},
                read_timeout=25,
                connect_timeout=5,
            ),
        )
    return _invoke_bedrock_client


def _invoke_call_bedrock(model_id: str, body: dict) -> dict:
    """Call bedrock-runtime.invoke_model and return parsed response body."""
    client = _invoke_get_bedrock_client()
    resp = client.invoke_model(
        modelId=model_id,
        body=json.dumps(body or {}),
        contentType="application/json",
        accept="application/json",
    )
    raw = resp["body"].read()
    return json.loads(raw.decode("utf-8"))


def _invoke_claim_in_progress(request_id: str, principal_id: str,
                              model_id: str) -> str:
    """Claim IN_PROGRESS in IdempotencyRecord via conditional PutItem.

    Returns:
      "claimed"   — claim succeeded; caller MAY invoke Bedrock
      "duplicate" — request_id already exists; caller MUST handle duplicate
    """
    table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
    now_iso = datetime.now(timezone.utc).isoformat()
    ttl_val = int(time.time()) + _INVOKE_IDEMPOTENCY_TTL_SECONDS
    try:
        table.put_item(
            Item={
                "request_id": request_id,
                "route": "/invoke",
                "status": "IN_PROGRESS",
                "principal_id": principal_id,
                "model_id": model_id,
                "created_at": now_iso,
                "ttl": ttl_val,
            },
            ConditionExpression="attribute_not_exists(request_id)",
        )
        return "claimed"
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return "duplicate"


def _invoke_get_idempotency_item(request_id: str) -> dict:
    """Read IdempotencyRecord item by request_id. Returns {} if missing."""
    try:
        table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
        resp = table.get_item(Key={"request_id": request_id})
        return resp.get("Item") or {}
    except Exception as e:
        log_structured("error", "invoke_idempotency_get_failed",
                       request_id=request_id, error=str(e))
        return {}


def _invoke_handle_duplicate(request_id: str) -> dict:
    """Handle duplicate request_id by inspecting existing IdempotencyRecord."""
    item = _invoke_get_idempotency_item(request_id)
    if not item:
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "duplicate request_id but record disappeared",
            "request_id": request_id,
        })

    route = item.get("route", "")
    if route and route != "/invoke":
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "request_id already used on a different route",
            "request_id": request_id,
        })

    status = item.get("status", "")
    if status == "COMPLETED":
        cached = item.get("cached_response", "")
        if cached:
            try:
                if isinstance(cached, str):
                    cached_body = json.loads(cached)
                else:
                    cached_body = cached
                cached_body["duplicate_already_settled"] = True
                return _response(200, cached_body)
            except Exception:
                pass
        # Fallback minimal response
        cost = item.get("cost_krw", 0)
        return _response(200, {
            "decision": "ALLOW",
            "duplicate_already_settled": True,
            "request_id": request_id,
            "model_id": item.get("model_id", ""),
            "usage": {
                "unit": item.get("usage_unit", ""),
                "count": int(item.get("usage_count", 0)),
            },
            "cost_krw": float(cost) if cost is not None else 0.0,
            "note": "duplicate request_id — cached settlement returned",
        })
    if status == "IN_PROGRESS":
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "request already in progress",
            "request_id": request_id,
            "retry_after_seconds": _INVOKE_PENDING_RETRY_AFTER_SECONDS,
        })
    if status == "FAILED":
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "request previously failed — retry with a new request_id",
            "request_id": request_id,
        })
    return _response(409, {
        "decision": "DENY",
        "denial_reason": f"request_id in unexpected state: {status}",
        "request_id": request_id,
    })


def _invoke_settle_transaction(request_id: str, principal_id: str,
                               model_id: str, usage: dict,
                               cost_krw: Decimal,
                               cached_payload: dict) -> str:
    """Atomically commit settlement.

    TransactWriteItems:
      - IdempotencyRecord Update: IN_PROGRESS → COMPLETED (with cached response)
      - MonthlyUsage Update: ADD cost_krw + token counts

    Returns: "settled" | "duplicate_already_settled" | "still_in_progress" | "failed"
    """
    # Use a dedicated low-level dynamodb client (avoids resource serializer
    # interfering with typed-dict expression values inside TransactWriteItems).
    client = boto3.client("dynamodb", region_name=os.environ.get(
        "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2")))
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    ttl_val = end_of_month_ttl_kst()
    now_iso = datetime.now(timezone.utc).isoformat()

    in_tok = usage["count"] if usage.get("unit") == "input_tokens" else 0
    out_tok = 0

    try:
        client.transact_write_items(TransactItems=[
            {
                "Update": {
                    "TableName": TABLE_IDEMPOTENCY_RECORD,
                    "Key": {"request_id": {"S": request_id}},
                    "UpdateExpression": (
                        "SET #s = :completed, settled_at = :now, "
                        "cost_krw = :c, usage_unit = :u, usage_count = :n, "
                        "cached_response = :resp"
                    ),
                    "ConditionExpression": (
                        "attribute_exists(request_id) AND #s = :in_progress "
                        "AND #r = :inv_route"
                    ),
                    "ExpressionAttributeNames": {
                        "#s": "status",
                        "#r": "route",
                    },
                    "ExpressionAttributeValues": {
                        ":completed": {"S": "COMPLETED"},
                        ":in_progress": {"S": "IN_PROGRESS"},
                        ":inv_route": {"S": "/invoke"},
                        ":now": {"S": now_iso},
                        ":c": {"N": str(cost_krw)},
                        ":u": {"S": usage.get("unit", "")},
                        ":n": {"N": str(int(usage.get("count", 0)))},
                        ":resp": {"S": json.dumps(cached_payload, default=str)},
                    },
                }
            },
            {
                "Update": {
                    "TableName": TABLE_MONTHLY_USAGE,
                    "Key": {
                        "principal_id_month": {"S": pk},
                        "model_id": {"S": model_id},
                    },
                    "UpdateExpression": (
                        "ADD cost_krw :c, input_tokens :i, output_tokens :o "
                        "SET #t = :ttl"
                    ),
                    "ExpressionAttributeNames": {"#t": "ttl"},
                    "ExpressionAttributeValues": {
                        ":c": {"N": str(cost_krw)},
                        ":i": {"N": str(in_tok)},
                        ":o": {"N": str(out_tok)},
                        ":ttl": {"N": str(ttl_val)},
                    },
                }
            },
        ])
        return "settled"
    except Exception as e:
        # TransactionCanceledException check via class name to avoid
        # tightly coupling to a specific client instance.
        cls_name = type(e).__name__
        if cls_name == "TransactionCanceledException":
            reasons = getattr(e, "response", {}).get("CancellationReasons", []) or []
            codes = [r.get("Code", "") for r in reasons]
            if codes and codes[0] == "ConditionalCheckFailed":
                current = _invoke_get_idempotency_item(request_id)
                cur_status = current.get("status", "")
                if cur_status == "COMPLETED":
                    return "duplicate_already_settled"
                if cur_status == "IN_PROGRESS":
                    return "still_in_progress"
                return "failed"
            log_structured("error", "invoke_settle_txn_cancelled",
                           request_id=request_id, codes=codes, error=str(e),
                           alarm=True)
            return "failed"
        log_structured("error", "invoke_settle_txn_error",
                       request_id=request_id, error=str(e), alarm=True)
        return "failed"


def _invoke_mark_failed(request_id: str, reason: str) -> None:
    """Best-effort IN_PROGRESS → FAILED in IdempotencyRecord."""
    try:
        table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
        table.update_item(
            Key={"request_id": request_id},
            UpdateExpression=(
                "SET #s = :failed, failed_at = :now, fail_reason = :r"
            ),
            ConditionExpression=(
                "attribute_exists(request_id) AND #s = :in_progress "
                "AND #rt = :inv_route"
            ),
            ExpressionAttributeNames={"#s": "status", "#rt": "route"},
            ExpressionAttributeValues={
                ":failed": "FAILED",
                ":in_progress": "IN_PROGRESS",
                ":inv_route": "/invoke",
                ":now": datetime.now(timezone.utc).isoformat(),
                ":r": reason[:512],
            },
        )
    except Exception as e:
        log_structured("error", "invoke_mark_failed_error",
                       request_id=request_id, error=str(e), alarm=True)


def _invoke_write_ledger(request_id: str, principal_id: str, model_id: str,
                         decision: str, usage: dict, cost_krw,
                         duration_ms: int, denial_reason: str = "") -> None:
    """Append immutable RequestLedger record (PutItem only — preserves
    existing /converse contract). Best-effort."""
    try:
        entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id,
            "model_id": model_id,
            "decision": decision,
            "source_path": "/invoke",
            "input_tokens": usage["count"] if usage.get("unit") == "input_tokens" else 0,
            "output_tokens": 0,
            "estimated_cost_krw": cost_krw if cost_krw is not None else Decimal("0"),
            "duration_ms": duration_ms,
        }
        if usage.get("unit"):
            entry["usage_unit"] = usage["unit"]
            entry["usage_count"] = int(usage.get("count", 0))
        if denial_reason:
            entry["denial_reason"] = denial_reason[:512]
        write_request_ledger(entry)
    except Exception as e:
        log_structured("error", "invoke_ledger_write_failed",
                       request_id=request_id, error=str(e), alarm=True)


def handle_invoke(principal_id: str, identity_fields: dict,
                  body: dict, request_id: str) -> dict:
    """POST /invoke — InvokeModel with idempotent, transactional settlement.

    Pipeline:
      1. Parse modelId + inner body
      2. Allowlist gate
      3. Pricing lookup (fail-closed)
      4. PrincipalPolicy + per-principal allowed_models
      5. Quota pre-check
      6. IN_PROGRESS claim (conditional PutItem on IdempotencyRecord)
         duplicate → return cached/409 (Bedrock NOT invoked)
      7. Bedrock InvokeModel
         failure → mark FAILED, ledger DENY, return error
      8. Extract usage (fail-closed)
         failure → mark FAILED, return settlement_failed
      9. Compute cost (Decimal)
     10. TransactWriteItems(COMPLETED + MonthlyUsage ADD)
         settled → ledger ALLOW + 200 OK
         duplicate_already_settled → return cached
         still_in_progress → 409
         failed → mark FAILED, return 500 settlement_failed
    """
    start_time = time.time()
    model_id = body.get("modelId", "")
    inner_body = body.get("body") or {}

    if not model_id:
        return deny_response("modelId is required", status_code=400)

    # Step 2: allowlist
    if model_id not in _INVOKE_ALLOWLIST:
        log_structured("warning", "invoke_not_allowlisted",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id)
        return deny_response(
            f"model {model_id} is not on /invoke allowlist", status_code=400)

    # Step 3: pricing (fail-closed)
    pricing_row = _invoke_lookup_pricing(model_id)
    if not pricing_row:
        return deny_response(f"no pricing defined for model {model_id}")

    # Step 4: policy + per-principal allowed_models
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "invoke_policy_lookup_failed",
                       request_id=request_id, error=str(e))
        return deny_response("policy lookup failed")
    if not policy:
        return deny_response("no policy defined for principal")
    if not check_model_access(policy, model_id):
        return deny_response(f"model {model_id} not in allowed list")

    # Step 5: quota pre-check
    try:
        quota_result = check_quota(principal_id, policy)
    except Exception as e:
        log_structured("error", "invoke_quota_check_failed",
                       request_id=request_id, error=str(e))
        return deny_response("quota check failed")
    if not quota_result["allowed"]:
        return _response(429, {
            "decision": "DENY",
            "denial_reason": "monthly cost quota exceeded",
            "quota": quota_result,
        })

    # Step 6: IN_PROGRESS claim
    claim = _invoke_claim_in_progress(request_id, principal_id, model_id)
    if claim == "duplicate":
        log_structured("info", "invoke_duplicate_request_id",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id)
        return _invoke_handle_duplicate(request_id)

    # Step 7: Bedrock
    try:
        response_body = _invoke_call_bedrock(model_id, inner_body)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        msg = f"bedrock_client_error:{code}"
        log_structured("error", "invoke_bedrock_client_error",
                       request_id=request_id, model_id=model_id, code=code,
                       error=str(e), alarm=True)
        _invoke_mark_failed(request_id, msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             {}, None, duration_ms, msg)
        return error_response(f"bedrock error: {code}")
    except Exception as e:
        msg = f"bedrock_failed:{str(e)[:200]}"
        log_structured("error", "invoke_bedrock_failed",
                       request_id=request_id, model_id=model_id, error=str(e),
                       alarm=True)
        _invoke_mark_failed(request_id, msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             {}, None, duration_ms, msg)
        return error_response(f"bedrock invocation failed: {str(e)[:200]}")

    # Step 8: extract usage (fail-closed)
    usage = _invoke_extract_usage(model_id, inner_body, response_body)
    if not usage:
        log_structured("error", "invoke_usage_extract_failed",
                       request_id=request_id, model_id=model_id, alarm=True)
        _invoke_mark_failed(request_id, "usage_extract_failed")
        duration_ms = int((time.time() - start_time) * 1000)
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             {}, None, duration_ms, "usage_extract_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "usage extraction failed — settlement_failed",
            "request_id": request_id,
        })

    # Step 9: cost
    cost_krw = _invoke_estimate_cost_krw(model_id, usage, pricing_row)
    if cost_krw < Decimal("0"):
        log_structured("error", "invoke_cost_compute_failed",
                       request_id=request_id, model_id=model_id,
                       usage_unit=usage.get("unit"),
                       pricing_unit=pricing_row.get("pricing_unit"),
                       alarm=True)
        _invoke_mark_failed(request_id, "cost_compute_failed")
        duration_ms = int((time.time() - start_time) * 1000)
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             usage, None, duration_ms, "cost_compute_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "cost computation failed",
            "request_id": request_id,
        })

    # Build cached payload — TWO versions:
    #   - response_payload: full payload (output included) → returned to client
    #   - cache_meta: metadata only (no output) → stored in IdempotencyRecord
    # Reason: DynamoDB UpdateExpression has a 4KB size limit. Image models
    # return base64 payloads >>4KB, which would blow up the transaction.
    duration_ms = int((time.time() - start_time) * 1000)
    new_usage_krw = Decimal(str(quota_result["usage"]["cost_krw"])) + cost_krw
    remaining = max(Decimal("0"),
                    Decimal(str(quota_result["limit"]["cost_krw"])) - new_usage_krw)

    response_payload = {
        "decision": "ALLOW",
        "output": response_body,
        "usage": {"unit": usage["unit"], "count": usage["count"]},
        "cost_krw": float(cost_krw),
        "remaining_quota_krw": float(remaining),
        "model_id": model_id,
        "request_id": request_id,
    }
    cache_meta = {
        "decision": "ALLOW",
        "usage": {"unit": usage["unit"], "count": usage["count"]},
        "cost_krw": float(cost_krw),
        "remaining_quota_krw": float(remaining),
        "model_id": model_id,
        "request_id": request_id,
        "note": "duplicate request_id — output omitted (only metadata cached)",
    }

    # Step 10: transactional settle (uses lightweight cache_meta)
    settle_result = _invoke_settle_transaction(
        request_id, principal_id, model_id, usage, cost_krw, cache_meta)

    if settle_result == "duplicate_already_settled":
        log_structured("warning", "invoke_settle_already_settled",
                       request_id=request_id, model_id=model_id)
        return _invoke_handle_duplicate(request_id)

    if settle_result == "still_in_progress":
        log_structured("warning", "invoke_settle_still_in_progress",
                       request_id=request_id, model_id=model_id)
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "settlement conflict — still IN_PROGRESS",
            "request_id": request_id,
        })

    if settle_result != "settled":
        log_structured("error", "invoke_settlement_failed",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id,
                       usage_unit=usage.get("unit"),
                       usage_count=usage.get("count"),
                       cost_krw=str(cost_krw),
                       alarm=True)
        _invoke_mark_failed(request_id, "settlement_failed")
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             usage, cost_krw, duration_ms,
                             "settlement_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "settlement_failed — bedrock invoked but cost not recorded",
            "request_id": request_id,
        })

    # Step 11: success — write ledger ALLOW (immutable, append-only)
    _invoke_write_ledger(request_id, principal_id, model_id, "ALLOW",
                         usage, cost_krw, duration_ms)

    log_structured("info", "invoke_allowed",
                   request_id=request_id, principal_id=principal_id,
                   model_id=model_id,
                   usage_unit=usage["unit"], usage_count=usage["count"],
                   cost_krw=str(cost_krw), duration_ms=duration_ms)

    return _response(200, response_payload)
