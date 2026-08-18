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
import urllib.request
import urllib.error
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

# Fallback FX (KRW per USD) for ledger metadata only — used solely when a
# pricing row lacks `exchange_rate_krw_per_usd`. The authoritative rate is
# always read per-row from the pricing table; this constant must match the
# rate the pricing pipeline applies (see auto_sync_models EXCHANGE_RATE).
DEFAULT_FX_RATE: Decimal = Decimal("1482.5")


def get_fx_rate_krw_per_usd() -> Decimal:
    """Single source of truth for the fixed reference FX rate (R6.5).

    Reads env var FX_RATE_KRW_PER_USD once; falls back to DEFAULT_FX_RATE
    (1482.5) when unset or unparseable. The Responses_Route and any new
    pricing-seed code MUST call this rather than embedding a literal.
    """
    raw = os.environ.get("FX_RATE_KRW_PER_USD")
    if raw is None:
        return DEFAULT_FX_RATE
    try:
        return Decimal(str(raw))
    except (ArithmeticError, ValueError):
        return DEFAULT_FX_RATE

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
cloudwatch_client = boto3.client("cloudwatch")

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

    Called once at cold start (and on cache miss). Returns empty dict only
    on a hard table-level error (fail-closed).

    Robustness (bedrock-model-auto-sync, Property 9 — Pending pricing):
    a model row may legitimately carry ``None`` for one or both price
    fields while it is in Tier_4 Pending. Such a row MUST be loaded with
    ``None`` prices preserved (NOT coerced to 0, so the caller can still
    distinguish "priced" from "pending") and, critically, a single bad
    row MUST NOT abort the whole scan — otherwise one Pending row would
    blank the entire pricing cache and deny every model. Each row is
    therefore parsed defensively and in isolation; the full result set is
    paginated so rows beyond the first 1MB page are never dropped.
    """
    if not TABLE_MODEL_PRICING:
        return {}

    def _coerce_price(value):
        # Preserve None (Pending) verbatim; never let a null/garbage value
        # raise and take down the whole cache load.
        if value is None:
            return None
        try:
            return Decimal(str(value))
        except (ArithmeticError, ValueError, TypeError):
            return None

    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        cache = {}
        scan_kwargs: dict = {}
        while True:
            resp = table.scan(**scan_kwargs)
            for item in resp.get("Items", []):
                mid = item.get("model_id", "")
                if not mid:
                    continue
                cache[mid] = {
                    "model_id": mid,
                    "input_price_per_1k": _coerce_price(item.get("input_price_per_1k")),
                    "output_price_per_1k": _coerce_price(item.get("output_price_per_1k")),
                    "exchange_rate_krw_per_usd": _coerce_price(item.get("exchange_rate_krw_per_usd")),
                }
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
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

    Pending-pricing safety (bedrock-model-auto-sync, Property 9):
    When a model row is in Tier_4 Pending — i.e. either
    ``input_price_per_1k`` or ``output_price_per_1k`` is ``None`` — the
    cost calculator MUST NOT raise. It returns ``Decimal(0)`` and emits
    the ``BedrockAutoSync/PendingPricingCostCharged`` CloudWatch metric
    with ``model_id`` as a dimension so backfill (Task 10.2) can later
    overwrite the zero-cost rows once Tier_1 prices land.
    """
    # Pending-pricing guard — Req 8.1, 8.2.
    input_price = pricing.get("input_price_per_1k") if isinstance(pricing, dict) else None
    output_price = pricing.get("output_price_per_1k") if isinstance(pricing, dict) else None
    if input_price is None or output_price is None:
        try:
            model_id = pricing.get("model_id", "") if isinstance(pricing, dict) else ""
            cloudwatch_client.put_metric_data(
                Namespace="BedrockAutoSync",
                MetricData=[{
                    "MetricName": "PendingPricingCostCharged",
                    "Value": 0,
                    "Unit": "Count",
                    "Dimensions": [{"Name": "model_id", "Value": str(model_id) or "unknown"}],
                }],
            )
        except Exception:
            # Never raise from the cost calculator on Pending pricing.
            pass
        return Decimal(0)

    input_cost = Decimal(str(input_tokens)) * input_price / Decimal("1000")
    output_cost = Decimal(str(output_tokens)) * output_price / Decimal("1000")
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
    for k in ("messages", "system", "inferenceConfig", "toolConfig",
              "additionalModelRequestFields"):
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
    pricing: dict | None = None,
) -> None:
    """Atomically ADD cost_krw, input_tokens, output_tokens to MonthlyUsage.

    PK: <principal_id>#YYYY-MM (KST). SK: model_id.
    TTL: ~35 days. Q6 decision: keep token counts alongside cost_krw.
    Task 2.4.

    Pending-pricing tag (bedrock-model-auto-sync, Req 8.3 / Task 11.2):
    When ``cost_krw`` is ``Decimal(0)`` and the source ``pricing`` dict
    has either ``input_price_per_1k is None`` or ``output_price_per_1k
    is None``, the persisted row is tagged with
    ``pricing_source_at_charge = "pending"`` so the daily auto-sync
    backfill (Task 10.2) can later identify and overwrite it.
    """
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    ttl_val = end_of_month_ttl_kst()

    # Pending-pricing tag: only set when (a) cost is exactly zero and
    # (b) either of the source prices is null. The happy-path (non-zero
    # cost or fully-priced) is preserved verbatim — no extra attribute
    # is written.
    pending_charge = (
        cost_krw == Decimal(0)
        and isinstance(pricing, dict)
        and (
            pricing.get("input_price_per_1k") is None
            or pricing.get("output_price_per_1k") is None
        )
    )

    update_expression = "ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl"
    expr_values = {
        ":c": cost_krw,
        ":i": input_tokens,
        ":o": output_tokens,
        ":ttl": ttl_val,
    }
    expr_names = {"#t": "ttl"}
    if pending_charge:
        update_expression += ", pricing_source_at_charge = :psac"
        expr_values[":psac"] = "pending"

    table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    table.update_item(
        Key={"principal_id_month": pk, "model_id": model_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
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
    # Enforce the server-side tiered increment (50만 below 2M, 100만 from 2M)
    # regardless of any caller-supplied requested_increment_krw, so the request
    # record and the admin/user emails match exactly what the approval handler
    # will apply (which recomputes _get_boost_increment at approval time).
    requested_increment = _get_boost_increment(current_effective)
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

        # NOTE (self-approval): the approve/reject links below are bearer
        # capability URLs — whoever holds approval_id + action_token can approve,
        # and the portal cannot distinguish "admin clicked the button" from
        # "requester pasted the URL". Filtering the requester out of
        # recipient_emails was evaluated and deliberately NOT done: an audit of
        # the live team-config showed 0 cases where a requester sits alongside a
        # second approver, and 4 cases (business-support/bk86,
        # computational-biology/user01, mrna-ai/admin, small-molecule-ai/user08)
        # where the team lead is their own team's only configured approver — so
        # filtering would have removed their approval path while protecting
        # nobody. Requester-vs-approver identity must be enforced at the portal's
        # approve endpoint, which is where the clicker's identity actually exists.
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
<td style="padding: 8px; border: 1px solid #ddd;">KRW {max(requested_new_limit_krw - current_limit_krw, 0):,}</td></tr>
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
    # One-time token for email approve/reject. MUST be generated and persisted
    # here exactly as in handle_approval_request — omitting it emits an approve
    # link with an empty token, which reduces the approval gate to knowledge of
    # approval_id alone (and approval_id is returned to the requester via
    # GET /quota/status as pending_approval_id).
    action_token = str(uuid.uuid4())
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
        "action_token": action_token,
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
                         current_effective, new_effective, hard_cap,
                         action_token)

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

    # Month-aware dedup: read sent-month flags (YYYY-MM, may be absent)
    sent_90_month = policy.get("warning_90pct_sent_month")
    sent_100_month = policy.get("exhaustion_email_sent_month")
    cur_month = current_month_kst()

    already_sent_90 = (sent_90_for == effective_limit and sent_90_month == cur_month)
    already_sent_100 = (sent_100_for == effective_limit and sent_100_month == cur_month)

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
        cur_month = current_month_kst()
        if threshold_type == "exhaustion":
            policy_table.update_item(
                Key={"principal_id": principal_id},
                UpdateExpression="SET exhaustion_email_sent_for_limit = :val, exhaustion_email_sent_month = :m",
                ExpressionAttributeValues={":val": effective_limit, ":m": cur_month},
            )
        else:
            # warning_90 — also set legacy key for backward compat
            policy_table.update_item(
                Key={"principal_id": principal_id},
                UpdateExpression="SET warning_90pct_sent_for_limit = :w90, warning_10pct_sent_for_limit = :w90, warning_90pct_sent_month = :m",
                ExpressionAttributeValues={":w90": effective_limit, ":m": cur_month},
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

        # Dedup check (month-aware)
        already_sent_for = policy.get("exhaustion_email_sent_for_limit")
        if isinstance(already_sent_for, Decimal):
            already_sent_for = int(already_sent_for)
        already_sent_month = policy.get("exhaustion_email_sent_month")
        if already_sent_for == effective_limit and already_sent_month == current_month_kst():
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

    # Pending approval check — union of pending-lock AND pending request record.
    # Bug B fix: judge has_pending independently from the lock so that a desynced
    # state (pending request record exists but lock missing/expired) still
    # suppresses re-prompting. Read-only: lock get_item + GSI query, no writes.
    has_pending = False
    pending_id = None

    # 1) Pending-lock (immediately consistent PutItem source).
    has_valid_lock = False
    try:
        lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
        lock_resp = lock_table.get_item(Key={"principal_id": principal_id})
        lock_item = lock_resp.get("Item")
        has_valid_lock = bool(lock_item) and int(lock_item.get("ttl", 0)) > int(time.time())
    except Exception:
        # Conservative: on lock read failure, leave has_valid_lock False and
        # defer to the request-record query below for suppression.
        has_valid_lock = False

    # 2) Pending request record via principal-status-index GSI (read-only).
    def _query_pending_request(pid: str):
        """Return (has_pending_request_record, pending_request_id). Read-only GSI query."""
        try:
            ar_table = dynamodb.Table(TABLE_APPROVAL_REQUEST)
            ar_resp = ar_table.query(
                IndexName="principal-status-index",
                KeyConditionExpression="principal_id = :pid AND #s = :st",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":pid": pid, ":st": "pending"},
                Limit=1,
            )
            items = ar_resp.get("Items", [])
            if items:
                return True, items[0].get("request_id", "")
            return False, None
        except Exception:
            # Conservative: on GSI read failure, do not assert a pending record.
            return False, None

    has_pending_request_record, pending_id_from_record = _query_pending_request(principal_id)

    has_pending = has_valid_lock or has_pending_request_record
    if pending_id_from_record:
        pending_id = pending_id_from_record

    at_hard_cap = effective_limit >= hard_cap
    can_request = (effective_limit + increment <= hard_cap) and not has_pending

    # Server-side prompt decision: single-tier threshold aligned with mail path.
    # Bug A fix: only the 90% (10% remaining) signal triggers a prompt; the 70%
    # tier is removed so prompt timing matches the mail path (90%/100%).
    prompt_eligible = not has_pending and not at_hard_cap and can_request
    hit_10pct = usage_krw >= effective_limit * 0.9 and prompt_eligible

    active_threshold = "10pct" if hit_10pct else None
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
        "should_prompt_30pct": False,
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
        "fx_rate": pricing.get("exchange_rate_krw_per_usd") or DEFAULT_FX_RATE,
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
            "fx_rate": lr_item.get("fx_rate") or DEFAULT_FX_RATE,
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
# Hold TTLs — the two outermost layers of the timeout nesting chain
# (long-output-streaming task 7.3, R7.3/R7.4)
# ---------------------------------------------------------------------------
# Chain the deployment must satisfy (design.md §Data Models):
#
#   job_state TTL 604800 > reservation TTL 10800 = semaphore lease TTL 10800
#     > state machine 8100 > RunTask 7800 > worker total deadline 7500
#     > per-attempt timeout 7200
#
# Both values were 7200, which is *below* the state machine ceiling raised to
# 8100 by task 5.4: a job still legally running would have an expired hold.
# Raised to 10800 so every hold outlives the longest execution the
# orchestration allows.
#
# A TTL is a safety net, not the reclaim mechanism. DynamoDB gives no deletion
# latency guarantee (observed lag up to 48h), so the real release paths are the
# worker settlement, the SIGTERM handler and the cancel handler; expiry only
# stops an abandoned row from holding budget forever.
#
# Direction of safety: longer is safe, shorter is not. Reverting these to 7200
# would expire the holds of in-flight jobs, so task 7.3 is documented as
# non-reverting even though the rest of the raise rolls back by task-definition
# revision.
#
# `_cleanup_stale_reservations` (task 5.1) refuses to delete an expired hold
# whose job is still non-terminal, which is what makes raising the ceiling safe
# in the first place.
#
# Not to be confused with: the Job_State item TTL (7 days, top of the chain,
# unchanged) and the MonthlyUsage settlement-row TTL (~35 days,
# `end_of_month_ttl_kst`) — neither is part of this hold pair.

#: TTL of the `__reserved__{job_id}` MonthlyUsage budget hold (R7.3, R7.4).
RESERVATION_TTL_SECONDS = 10800

#: TTL of a concurrency-semaphore slot lease. Kept equal to the reservation
#: TTL: the two holds cover the same execution.
SEMAPHORE_LEASE_TTL_SECONDS = 10800

# ---------------------------------------------------------------------------
# Reservation sizing — the output side of the budget hold (R7.1, R7.2)
# ---------------------------------------------------------------------------
#: Declared Output_Token_Ceiling for the async Delivery_Path, in tokens
#: (design.md §"모델별 상한", R1.1).
#:
#: One constant rather than a per-family table because every text model that
#: appears in this gateway's async traffic declares the same figure: opus-5,
#: sonnet-5 and opus-4-8 from live Bedrock error messages, gpt-5.6-sol / luna /
#: terra from documentation. `worker.MODEL_DURATION_CEILING_SECONDS` needs a
#: table because Nova's *duration* ceiling genuinely differs (3600 vs 7200);
#: no such divergence exists for the output ceiling among models we serve
#: asynchronously, and inventing one would put a number in the tree that no
#: measurement supports.
#:
#: Deliberately **not** `_BATCH_MODEL_MAX_OUTPUT_DEFAULT`: that map covers the
#: batch allowlist (gpt-oss and Claude 4.x at 8k–32k) and its `__default__` of
#: 8,192 would under-reserve an opus-5 async job by more than 15x.
#:
#: Direction of error, since one is possible: for a *hold* the safe direction is
#: high. A model whose real ceiling is lower only means the hold is larger than
#: it needed to be, and the refusal simulation behind this constant
#: (`scripts/long_output_verify/measure_reservation_coverage.py`) measured how
#: much room that leaves — 430,427 KRW at the tightest point of 2,196 replayed
#: submissions. A ceiling set too *low* would silently reintroduce the
#: under-coverage this constant exists to close.
ASYNC_OUTPUT_TOKEN_CEILING = 128000


def declared_output_ceiling(body: dict):
    """The output ceiling this request declared, or ``None`` if it declared none.

    Two field names, because one submit path serves two request shapes:

      * ``inferenceConfig.maxTokens`` — Converse (`/converse-jobs`), the same
        field `_should_route_async` already reads to make its routing decision.
      * ``max_output_tokens`` — OpenAI Responses (`/openai/responses-jobs`).

    Measured over the 2,196 submissions `job_state` still held on 2026-08-18
    (7-day TTL, so 2026-08-11..18 is the whole window a stored payload survives
    in): 1,573 declared via `inferenceConfig.maxTokens`, 505 via
    `max_output_tokens`, and no other spelling appeared at all. 118 (5.4%)
    declared nothing — see :func:`reservation_output_tokens` for what happens to
    those.

    A malformed, zero or negative value counts as *not declared* rather than as
    a ceiling of zero. A zero-output hold would make R7.2 false for a request
    that can still emit the model ceiling, and `_batch_record_output_upper`
    already resolves the same ambiguity the same way (R3.6).
    """
    candidates = []
    infer = body.get("inferenceConfig")
    if isinstance(infer, dict):
        candidates.append(infer.get("maxTokens"))
    candidates.append(body.get("max_output_tokens"))
    for raw in candidates:
        if raw is None or isinstance(raw, bool):
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return None


def reservation_output_tokens(body: dict, ceiling: int = ASYNC_OUTPUT_TOKEN_CEILING):
    """Output tokens the budget hold is computed for. Returns ``(tokens, basis)``.

    R7.1 in one function: the hold's output figure is "요청이 선언한 값, 미선언 시
    모델 Output_Token_Ceiling". Three cases, each named in the returned basis so
    the ledger can record *why* a hold was the size it was after the request
    payload has aged out:

    ``"declared"``
        the request declared a figure the model can emit. 94.6% of measured
        traffic. For the part of it that declares *below* the model ceiling the
        new hold is **smaller** than today's — 0.49x at the <=4k bucket and
        0.91x at <=16k, measured medians — because today's hold pays for
        ``max(est_in * 0.2, 4096)`` output tokens whether the request wants them
        or not.

    ``"clamped"``
        the request declared more than the model can emit. Measured: 4
        submissions declaring 999,999. Bedrock will not produce those tokens, so
        a hold that pays for them is holding against a settlement that cannot
        happen — 120.9x today's figure instead of 15.5x. Same clamp as
        `_batch_record_output_upper` (R12.7), for the same reason.

    ``"model_ceiling"``
        the request declared nothing, so there is nothing to reserve against and
        R7.1 names the model ceiling. Measured: 118 submissions, 5.4%, and 116 of
        those on the Responses route where the field is optional. This is the
        one case that costs more without a request asking for it — median hold
        3,538.72 KRW against 896.91 KRW today, 3.94x — so it is stated here
        rather than left implicit. Two things justify it: an undeclared request
        may legally emit up to the ceiling, so no smaller figure makes R7.2
        true; and it is affordable — replaying all 2,196 submissions against
        their principal's remaining quota at the moment of submission produced
        **zero** refusals, the tightest headroom being 430,427 KRW.

    Pure: no clock, no I/O, no config read.
    """
    declared = declared_output_ceiling(body)
    if declared is None:
        return int(ceiling), "model_ceiling"
    if declared > ceiling:
        return int(ceiling), "clamped"
    return int(declared), "declared"


# ---------------------------------------------------------------------------
# Reservation cap (R7.2 auditability)
# ---------------------------------------------------------------------------

#: Ceiling on a single async budget hold. Unchanged in value — this constant
#: replaces two inline `Decimal("100000")` literals in `handle_converse_async`
#: so the cap has one name and one place to read it from.
ASYNC_MAX_RESERVE_KRW = Decimal("100000")


def apply_reservation_cap(est_cost: Decimal,
                          cap: Decimal = ASYNC_MAX_RESERVE_KRW) -> tuple:
    """Clamp a computed hold to ``cap``, and say so. Returns ``(hold, fact)``.

    Why this exists: ``min(est_cost, cap)`` is a **silent truncation of the one
    invariant this spec spent its whole reservation work establishing.** R7.2 is
    "the hold covers the worst settlement the submission is allowed to reach";
    the instant the cap binds, the hold is deliberately *below* that worst case
    and R7.2 is false for that job — with nothing anywhere in the record saying
    so. The job then settles above its hold, which reads in an audit exactly like
    the R7.1 sizing defect task 7.5 just closed, and there is no way to tell the
    two apart after the request payload's 7-day TTL has passed.

    So the cap keeps truncating, and starts leaving a trace. This function does
    not refuse, does not raise, and does not change the value of the hold — the
    returned ``hold`` is exactly what ``min()`` returned before. It only makes
    the fact reconstructible.

    ``fact`` is ``None`` when the cap does not bind. That is deliberate: the
    ledger row stays byte-identical for the 100% of today's traffic that does not
    reach the cap, so this change cannot be read as a schema migration, and a
    query for "capped submissions" is `attribute_exists`, not a comparison
    against a sentinel.

    When the cap does bind, ``fact`` carries the three numbers an auditor needs
    and cannot recover otherwise:

    ``reservation_cap_krw``
        the cap that was applied. Recorded rather than assumed, because a future
        change to the cap must not silently re-interpret old rows.
    ``reservation_uncapped_krw``
        what the hold *would* have been. This is the R7.2-satisfying figure, and
        it is the only one of the three that is unrecoverable later — the
        declared ceiling lives in the payload, which ages out in 7 days.
    ``reservation_capped_by_krw``
        the shortfall, ``uncapped - cap``. Redundant arithmetic, stored anyway:
        it is what a settlement-vs-hold report needs to sort by, and computing it
        in the query would require every consumer to know the subtraction.

    Measured headroom as of 2026-08-18: the cap does not bind today. A full
    128,000-token ceiling at the dearest live text rate (37.0625 KRW/1k output,
    the opus family) holds 16,455.75 KRW — 16% of the cap — and reaching the cap
    needs an ``estimated_input_tokens`` around 1.93M. So this records a fact that
    is currently never emitted, which is the point: the first time it binds, the
    row will say so instead of the overrun looking like a sizing bug.

    Pure: no clock, no I/O, no metric emission (the caller does that, where the
    other CloudWatch emissions in this module already live).
    """
    if est_cost <= cap:
        return est_cost, None
    return cap, {
        "reservation_capped": True,
        "reservation_cap_krw": cap,
        "reservation_uncapped_krw": est_cost,
        "reservation_capped_by_krw": est_cost - cap,
    }

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
                    ":ttl": int(time.time()) + SEMAPHORE_LEASE_TTL_SECONDS,
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
    # Opus 4-7 / 4-8 seed (scripts/seed_opus_4_8)
    "anthropic.claude-opus-4-7",
    "us.anthropic.claude-opus-4-8",
    "global.anthropic.claude-opus-4-8",
    "anthropic.claude-opus-4-8",
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
# Catches cross-region variants without enumerating every ID. The set is
# kept aligned with ``scripts/auto_sync_models/routing_writer.ALWAYS_ASYNC_SIGNAL_KEYWORDS``
# so the DynamoDB-driven path and the in-code fallback path classify the
# same set of Model_Ids as always-async (Req 4.6 / 4.8).
SLOW_MODEL_PATTERNS = [
    # Documented heavy tiers
    "opus",          # all opus variants
    "premier",       # nova-premier and any future *-premier
    "nova-premier",  # explicit Amazon Nova Premier marker
    # Reasoning markers (cross-vendor)
    "reasoning",
    "thinking",
    # DeepSeek reasoning series (numeric variants)
    "deepseek.r1",
    "deepseek.r2",
    "deepseek.r3",
    "deepseek-r1",
    "deepseek-r2",
    "deepseek-r3",
    # OpenAI reasoning series ports
    ".o1",
    ".o3",
    ".o4",
    "-o1-",
    "-o3-",
    "-o4-",
]


# ---------------------------------------------------------------------------
# Routing-table cache (bedrock-model-auto-sync, Tasks 12.1-12.3)
# ---------------------------------------------------------------------------
# The Sync_Lambda upserts ``always_async`` and ``slow_pattern`` rules into a
# DynamoDB table whose name is read from MODEL_ROUTING_TABLE. The handler
# scans it once per cold start and caches the result for the warm-container
# lifetime. On any DynamoDB read error the cache stays empty and
# ``_ensure_async_rules`` falls back to the hard-coded ALWAYS_ASYNC_MODELS
# and SLOW_MODEL_PATTERNS literals above.
#
# Adding a new model row to the routing table is therefore enough to make
# the handler treat it as always-async on the next cold start — no code
# deployment required (Req 4.4).
# ---------------------------------------------------------------------------

MODEL_ROUTING_TABLE = os.environ.get("MODEL_ROUTING_TABLE", "")
_async_rules_cache: dict | None = None


def _load_async_rules_from_routing_table() -> dict | None:
    """Return ``{"always_async": set[str], "slow_pattern": set[str]}`` or
    ``None`` on error. Best-effort: scans the MODEL_ROUTING_TABLE once.
    """
    if not MODEL_ROUTING_TABLE:
        return None
    try:
        resp = dynamodb.Table(MODEL_ROUTING_TABLE).scan(
            ProjectionExpression="rule_type, rule_value",
            ConsistentRead=False,
        )
    except Exception as exc:
        # Any read failure → fallback path will be taken.
        try:
            cloudwatch_client.put_metric_data(
                Namespace="BedrockAutoSync",
                MetricData=[{
                    "MetricName": "HandlerRoutingFallback",
                    "Value": 1,
                    "Unit": "Count",
                }],
            )
        except Exception:
            pass
        return None

    out: dict[str, set[str]] = {"always_async": set(), "slow_pattern": set()}
    for item in resp.get("Items", []):
        rt = item.get("rule_type")
        rv = item.get("rule_value")
        if rt in out and isinstance(rv, str) and rv:
            out[rt].add(rv)
    return out


def _ensure_async_rules() -> dict:
    """Return the cached routing rules, loading them on first call.

    On any read error the cache is NOT populated so the next request
    retries the load. The hard-coded baseline pair is returned as the
    fallback (Property 8).
    """
    global _async_rules_cache
    if _async_rules_cache is not None:
        return _async_rules_cache
    loaded = _load_async_rules_from_routing_table()
    if loaded is None:
        # Fallback: hard-coded baseline. Do NOT memoize so the next call
        # retries the routing-table read.
        return {
            "always_async": ALWAYS_ASYNC_MODELS,
            "slow_pattern": set(SLOW_MODEL_PATTERNS),
        }
    _async_rules_cache = loaded
    return _async_rules_cache


def _should_route_async(model_id: str, body: dict) -> tuple:
    """Determine if a /converse request should be routed to async path.

    Returns (should_async: bool, reason: str).
    Known slow models (opus, deepseek-r1, nova-premier) always async.
    Other models start sync by default. Async only for large input/output.
    Sync throttle errors are caught by caller and fall back to async.
    """
    rules = _ensure_async_rules()

    # 1a. Exact-match against the routing-table's always_async set.
    if model_id in rules["always_async"]:
        return True, "always_async_table"

    # 1b. Substring fallback against the routing-table's slow_pattern set
    #     unioned with the in-code SLOW_MODEL_PATTERNS literal.
    model_lower = model_id.lower()
    for pattern in rules["slow_pattern"]:
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

    # Reserve budget. Image models (async /invoke-jobs) are priced per-image —
    # the per-image KRW is stored in input_price_per_1k — so reserve on an image
    # count basis instead of the token estimate to avoid huge over-reservation.
    # Unchanged by the R7.1 fix below: an image response has no output tokens, so
    # an output ceiling is not a quantity that exists for these models.
    reserve_output_tokens = 0
    ceiling_basis = "image"
    reservation_cap_fact = None
    if model_id in _INVOKE_IMAGE_MODELS:
        per_img = Decimal(str(pricing.get("input_price_per_1k", 0) or 0))
        est_images = max(int(body.get("estimated_images", 4)), 1)
        est_cost = per_img * Decimal(est_images)
        reserve_krw, reservation_cap_fact = apply_reservation_cap(
            est_cost * Decimal("2"))
    else:
        # R7.1 / R7.2: the hold's output figure is the request's *declared*
        # ceiling, not a share of the input estimate. Until this changed, the
        # output side was `max(est_in * 0.2, 4096)` — with the 50,000 default that
        # is 10,000 output tokens against a declared ceiling of 128,000, and the
        # gap was real money: 28 of the 2,058 settled jobs in the last 7 days
        # settled above their hold (max 847 KRW), 105 of 98,615 over the ledger's
        # whole 5-month history (worst 4,448 KRW).
        #
        # The `2x` moved to the input side alone, and that asymmetry is the whole
        # design: the input figure is an *estimate* a client may get wrong (20 of
        # those 28 overruns were input-side), while a declared ceiling is a limit
        # Bedrock enforces — it needs no safety factor, and doubling it would
        # raise the hold at the 128k bucket to 6.90x today's instead of 3.70x for
        # coverage that is already exact.
        #
        # Written as one `estimate_cost_krw` call on twice the estimate because
        # `2 * in_cost + ceiling_cost == estimate_cost_krw(2 * est_in, ceiling)`
        # exactly, and one call keeps the Pending-pricing metric at one emission
        # per submission as before. It also says what the hold *means*: the cost
        # of the worst settlement this submission is allowed to reach.
        #
        # `max(.., 0)`: a negative estimate is refused today (negative cost ->
        # `reserve_krw <= 0` -> 429). Under this formula it would instead
        # subtract from the ceiling's cost and produce a hold too small to cover
        # the output — the one way the change could make R7.2 *less* true.
        estimated_input = max(int(body.get("estimated_input_tokens", 50000)), 0)
        reserve_output_tokens, ceiling_basis = reservation_output_tokens(body)
        est_cost = estimate_cost_krw(2 * estimated_input, reserve_output_tokens, pricing)
        reserve_krw, reservation_cap_fact = apply_reservation_cap(est_cost)
    # The cap truncates the hold below the worst settlement the submission may
    # reach, which makes R7.2 false for that job. It stays a truncation (no
    # refusal, no larger hold — that is a decision for a person, not a silent
    # policy change), but it stops being invisible: the fact rides the
    # REQUEST_ACCEPTED ledger row below, which is append-only and outlives the
    # payload's 7-day TTL. `None` when the cap does not bind, so the row is
    # unchanged for traffic that never reaches it.
    if reservation_cap_fact:
        log_structured("warning", "reservation_capped",
                       principal_id=principal_id, model_id=model_id,
                       cap_krw=float(reservation_cap_fact["reservation_cap_krw"]),
                       uncapped_krw=float(reservation_cap_fact["reservation_uncapped_krw"]),
                       capped_by_krw=float(reservation_cap_fact["reservation_capped_by_krw"]),
                       reserved_output_tokens=reserve_output_tokens,
                       reservation_ceiling_basis=ceiling_basis)
        # Same namespace and shape as the other three emissions in this module
        # (`PendingPricingCostCharged` etc.), so the cap shows up wherever those
        # are already watched rather than in a new place nobody has a dashboard
        # for. Never raises: an audit trail that can 500 a submission is worse
        # than one that occasionally misses a datapoint — the ledger row is the
        # durable record, this is the alarm surface.
        try:
            cloudwatch_client.put_metric_data(
                Namespace="BedrockAutoSync",
                MetricData=[{
                    "MetricName": "ReservationCapTruncated",
                    "Value": float(reservation_cap_fact["reservation_capped_by_krw"]),
                    "Unit": "None",
                    "Dimensions": [{"Name": "model_id", "Value": str(model_id) or "unknown"}],
                }],
            )
        except Exception:
            pass
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
                ":ttl": int(time.time()) + RESERVATION_TTL_SECONDS,
                ":sp": "gateway-async-reserve",
            },
        )
    except Exception as e:
        log_structured("error", "budget_reserve_failed", job_id=job_id, error=str(e))

    # Ledger: REQUEST_ACCEPTED
    try:
        ledger_entry = {
            "request_id": f"{request_id}#REQUEST_ACCEPTED",
            "timestamp": now_iso,
            "principal_id": principal_id,
            "model_id": model_id,
            "decision": "ALLOW",
            "event_type": "REQUEST_ACCEPTED",
            "job_id": job_id,
            "source_path": "gateway-async",
            "reserved_cost_krw": reserve_krw,
            # R7.7: the hold's *basis*, not just its size. The declared ceiling
            # lives only in the request payload, which ages out in 7 days, so
            # without these two fields an audit later cannot tell a hold sized
            # from a declared ceiling from one sized by the undeclared fallback.
            # Additive — the ledger stays PutItem-only (R11.2).
            "reserved_output_tokens": reserve_output_tokens,
            "reservation_ceiling_basis": ceiling_basis,
            "pricing_version": pricing_version,
        }
        # Cap truncation, only when it bound. Merged rather than written as
        # `"reservation_capped": bool(...)` so the absent case leaves the row
        # exactly as task 7.5 wrote it: a `False` on every row would make the
        # interesting case invisible in a scan and would be a schema change to
        # 100% of traffic in order to describe 0% of it.
        if reservation_cap_fact:
            ledger_entry.update(reservation_cap_fact)
        write_request_ledger(ledger_entry)
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



# ---------------------------------------------------------------------------
# Stale reservation cleanup — job-status gated (long-output-streaming task 5.1)
# ---------------------------------------------------------------------------
#: ``model_id`` prefix of the MonthlyUsage budget-hold row (`__reserved__{job_id}`).
_RESERVED_MODEL_ID_PREFIX = "__reserved__"

#: JobState values meaning "nothing is generating any more", so the hold behind
#: the job owns no live budget and may be swept (R7.5). Its complement
#: (`ACCEPTED`, `QUEUED`, `RUNNING`) is a *live* hold that R7.3 requires to stay
#: counted in the reservation-inclusive total, TTL or no TTL.
#: A row whose ``status`` is missing or unrecognised is treated as NON-terminal
#: on purpose: "not provably finished" must not authorise a delete.
_TERMINAL_JOB_STATUSES = frozenset(
    {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"})

#: `StaleReservationSkipped` reason dimension values — why a TTL-expired hold was
#: left in place. Kept low-cardinality (3 values) so the metric is cheap.
_SKIP_REASON_NON_TERMINAL = "non_terminal_job"
_SKIP_REASON_LOOKUP_FAILED = "job_lookup_failed"
_SKIP_REASON_JOB_TABLE_UNSET = "job_table_unconfigured"


def _emit_stale_reservation_skipped(reason: str) -> None:
    """Publish one ``StaleReservationSkipped`` count with a ``reason`` dimension.

    Same shape as the other gateway metrics (`BedrockAutoSync` namespace, Count
    unit, best-effort). Swallowing publish failures is deliberate: this metric is
    observability for the task 5.1 rollout, and a CloudWatch hiccup must never
    turn a *preserved* hold into a deleted one.
    """
    try:
        cloudwatch_client.put_metric_data(
            Namespace="BedrockAutoSync",
            MetricData=[{
                "MetricName": "StaleReservationSkipped",
                "Value": 1,
                "Unit": "Count",
                "Dimensions": [{"Name": "reason", "Value": reason}],
            }],
        )
    except Exception:
        pass


def _cleanup_stale_reservations(principal_id: str, month: str) -> int:
    """Sweep TTL-expired ``__reserved__`` holds for this principal/month.

    Deletes a hold only when **nobody owns it any more**: the JobState row behind
    it is in a terminal state, or the row is gone entirely (JobState carries a
    7-day TTL, so an old finished job leaves an orphaned hold behind).

    Before task 5.1 this function judged a hold on its TTL alone and never read
    the job (defect D3). Reservation TTL is 2h today and rises with the duration
    ceiling, so a perfectly healthy long generation outlives its own hold — and
    the same principal's next submit swept that live budget hold away, letting
    the quota be over-committed. R7.3 (a hold is *maintained while* generation is
    in progress) and R7.5 (it is removed *when* generation ends) say the job's
    state is what decides, not the clock.

    Direction of the change: the gate only ever deletes **less** than before. If
    the gate errs, budget holds linger a while longer (the quota under-counts
    headroom, i.e. denies too early) rather than releasing budget that is still
    being spent. That is the safe side of this trade, so every uncertain case
    below resolves to "keep":

      * job row present, non-terminal status  -> keep, ``non_terminal_job``
      * lookup raised                         -> keep, ``job_lookup_failed``
        (a failed read means "we do not know whether it finished"; deleting on
        an unknown state is exactly the D3 over-commit, just with a different
        trigger)
      * ``TABLE_JOB_STATE`` unset             -> keep, ``job_table_unconfigured``
        (with no job table the status can never be established; both writers of
        these rows need that table, so nothing new is accumulating anyway)
      * job row absent / terminal status      -> delete

    Each skip publishes one ``StaleReservationSkipped`` datum carrying the reason
    so the rollout can tell "gate is holding live budget" from "gate cannot see
    the job table" (design.md §Rollout aborts on this metric leaving its expected
    range).

    Cost: one GetItem per TTL-expired ``__reserved__`` row on the submit path.
    Measured reserved-row counts are a handful per principal-month, and only
    expired rows are looked up at all, so submit latency is unaffected.

    Rollback note: reverting this function restores the original, more
    aggressive — i.e. buggy — behaviour of deleting live holds on TTL alone.

    Returns the number of holds actually deleted (a delete that failed is not
    counted; the reported number is what the sweep really did).
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
    job_table = None
    for item in resp.get("Items", []):
        mid = item.get("model_id", "")
        if not mid.startswith(_RESERVED_MODEL_ID_PREFIX):
            continue
        ttl_val = int(item.get("ttl", 0))
        # Unchanged staleness test: strict `<`, and ttl == 0 (no TTL written)
        # is never stale.
        if not (ttl_val > 0 and ttl_val < now_epoch):
            continue

        job_id = mid[len(_RESERVED_MODEL_ID_PREFIX):]

        if not TABLE_JOB_STATE:
            log_structured("warning", "stale_reservation_skipped",
                           principal_id=principal_id, model_id=mid,
                           job_id=job_id,
                           reason=_SKIP_REASON_JOB_TABLE_UNSET)
            _emit_stale_reservation_skipped(_SKIP_REASON_JOB_TABLE_UNSET)
            continue

        try:
            if job_table is None:
                job_table = dynamodb.Table(TABLE_JOB_STATE)
            job_item = job_table.get_item(Key={"job_id": job_id}).get("Item")
        except Exception as exc:
            log_structured("error", "stale_reservation_skipped",
                           principal_id=principal_id, model_id=mid,
                           job_id=job_id,
                           reason=_SKIP_REASON_LOOKUP_FAILED, error=str(exc))
            _emit_stale_reservation_skipped(_SKIP_REASON_LOOKUP_FAILED)
            continue

        if job_item:
            job_status = str(job_item.get("status", ""))
            if job_status not in _TERMINAL_JOB_STATUSES:
                # R7.3 — generation is still in progress somewhere; the hold is
                # live budget and stays counted.
                log_structured("info", "stale_reservation_skipped",
                               principal_id=principal_id, model_id=mid,
                               job_id=job_id, job_status=job_status,
                               reason=_SKIP_REASON_NON_TERMINAL)
                _emit_stale_reservation_skipped(_SKIP_REASON_NON_TERMINAL)
                continue
            sweep_reason = "terminal_job"
        else:
            # JobState row expired (7-day TTL) — nobody can own this hold.
            sweep_reason = "job_row_absent"

        # R7.5 — the hold is orphaned and its TTL has passed; DDB TTL deletion
        # is asynchronous (observed lag up to ~48h) so reclaim it here.
        try:
            usage_table.delete_item(Key={"principal_id_month": pk, "model_id": mid})
            cleaned += 1
            log_structured("info", "stale_reservation_cleaned",
                           principal_id=principal_id, model_id=mid,
                           job_id=job_id, sweep_reason=sweep_reason)
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

    # --- Route: /openai/responses-jobs — async (long-running) Responses jobs ---
    # Reuses the model-agnostic async pipeline (submit/status/cancel + SFN +
    # Fargate worker). The worker detects OpenAI Responses models by model_id
    # and calls bedrock-mantle instead of Converse. Submit body carries
    # `modelId` (openai.gpt-5.x) plus the Responses payload (input, etc.).
    if path.rstrip("/") == "/openai/responses-jobs" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_converse_job_submit(
            principal_id, identity_fields, body, request_id)
    if path.rstrip("/").endswith("/cancel") and "/openai/responses-jobs/" in path and http_method == "POST":
        return handle_converse_job_cancel(principal_id, path, request_id)
    if path.startswith("/openai/responses-jobs/") and http_method == "GET":
        return handle_converse_job_status(principal_id, path)

    # --- Route: /invoke-jobs — async (long-running) image InvokeModel jobs ---
    # Reuses the model-agnostic async pipeline (submit/status/cancel + SQS/SFN +
    # Fargate worker). The worker detects image models by model_id and calls
    # InvokeModel (with the inference-profile remap) instead of Converse. This
    # exists for slow Stability image ops (e.g. Creative/Conservative Upscale at
    # 40-58s) that cannot complete under the 29s API Gateway / sync limit.
    # Submit body carries `modelId` plus the InvokeModel payload under `body`.
    if path.rstrip("/") == "/invoke-jobs" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_converse_job_submit(
            principal_id, identity_fields, body, request_id)
    if path.rstrip("/").endswith("/cancel") and "/invoke-jobs/" in path and http_method == "POST":
        return handle_converse_job_cancel(principal_id, path, request_id)
    if path.startswith("/invoke-jobs/") and http_method == "GET":
        return handle_converse_job_status(principal_id, path)

    # --- Route: /invoke — InvokeModel passthrough (image / embedding / rerank) ---
    if path.rstrip("/") == "/invoke" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)
        return handle_invoke(principal_id, identity_fields, body, request_id)

    # --- Route: /openai/responses — OpenAI Responses API (bedrock-mantle) passthrough ---
    if path.rstrip("/") == "/openai/responses" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)  # R1.5
        return handle_responses(principal_id, identity_fields, body, request_id)

    # --- Route: POST /batch — Bedrock batch inference submit (NEW) ---
    if path.rstrip("/") == "/batch" and http_method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except (json.JSONDecodeError, TypeError):
            return deny_response("invalid JSON body", status_code=400)  # R1.3
        return handle_batch_submit(principal_id, identity_fields, body, request_id)

    # --- Route: GET /batch/{job_id} — Bedrock batch inference status (NEW) ---
    if path.startswith("/batch/") and http_method == "GET":
        return handle_batch_status(principal_id, path)


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
            "fx_rate": pricing.get("exchange_rate_krw_per_usd") or DEFAULT_FX_RATE,
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
    # Cohere Embed 4 (Marketplace; on-demand unsupported -> inference profile).
    # Callers send the bare id; _INVOKE_PROFILE_REMAP routes to us. profile.
    "cohere.embed-v4:0",
    "us.cohere.embed-v4:0",
    "global.cohere.embed-v4:0",
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
    "cohere.embed-v4:0",
    "us.cohere.embed-v4:0",
    "global.cohere.embed-v4:0",
})
_INVOKE_RERANK_MODELS = frozenset({
    "amazon.rerank-v1:0",
    "cohere.rerank-v3-5:0",
})

# Stability image-EDIT models do NOT support on-demand InvokeModel; they can only
# be invoked through their system-defined cross-region inference profile (us.<id>).
# LIVE-CONFIRMED 2026-07: all 13 bare edit ids return "Invocation ... with
# on-demand throughput isn't supported. Retry ... with the ID or ARN of an
# inference profile", while the us. profile id reaches the model (image validated).
# We keep allowlist / pricing / settlement keyed on the caller's bare id and
# rewrite ONLY the modelId passed to invoke_model, so no pricing/allowlist churn
# is needed and callers can keep sending the canonical bare id.
_INVOKE_PROFILE_REMAP = {
    "stability.stable-conservative-upscale-v1:0": "us.stability.stable-conservative-upscale-v1:0",
    "stability.stable-creative-upscale-v1:0":     "us.stability.stable-creative-upscale-v1:0",
    "stability.stable-fast-upscale-v1:0":         "us.stability.stable-fast-upscale-v1:0",
    "stability.stable-image-control-sketch-v1:0": "us.stability.stable-image-control-sketch-v1:0",
    "stability.stable-image-control-structure-v1:0": "us.stability.stable-image-control-structure-v1:0",
    "stability.stable-image-erase-object-v1:0":   "us.stability.stable-image-erase-object-v1:0",
    "stability.stable-image-inpaint-v1:0":        "us.stability.stable-image-inpaint-v1:0",
    "stability.stable-image-remove-background-v1:0": "us.stability.stable-image-remove-background-v1:0",
    "stability.stable-image-search-recolor-v1:0": "us.stability.stable-image-search-recolor-v1:0",
    "stability.stable-image-search-replace-v1:0": "us.stability.stable-image-search-replace-v1:0",
    "stability.stable-image-style-guide-v1:0":    "us.stability.stable-image-style-guide-v1:0",
    "stability.stable-outpaint-v1:0":             "us.stability.stable-outpaint-v1:0",
    "stability.stable-style-transfer-v1:0":       "us.stability.stable-style-transfer-v1:0",
    # Cohere Embed 4 also rejects on-demand; route bare -> us. profile.
    "cohere.embed-v4:0":                          "us.cohere.embed-v4:0",
}

# Models whose latency exceeds the API Gateway 29s synchronous limit
# (LIVE-MEASURED: Creative Upscale ~58s, Conservative Upscale ~40s). A sync
# /invoke for these can only time out, so handle_invoke transparently hands them
# off to the async /invoke-jobs pipeline and returns 202 + job_id. Every other
# image model completes under the limit and keeps the synchronous path.
_INVOKE_SLOW_ASYNC_MODELS = frozenset({
    "stability.stable-creative-upscale-v1:0", "us.stability.stable-creative-upscale-v1:0",
    "stability.stable-conservative-upscale-v1:0", "us.stability.stable-conservative-upscale-v1:0",
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
            # Fallback to the exact AWS billing header (Cohere Embed omits the
            # body field but the x-amzn-bedrock-input-token-count header is set).
            if (not isinstance(tok, (int, float)) or tok <= 0) and isinstance(response_body, dict):
                tok = response_body.get("_bedrock_input_token_count")
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
            # Image pricing rows written by the sync pipeline store the
            # per-image KRW price in `input_price_per_1k` (e.g. stable-image-core
            # = 44.475 = $0.03 x 1482.5), with no dedicated per_image field.
            # Fall back to it so priced image models settle correctly.
            per = pricing_row.get("input_price_per_1k")
        if per is None:
            return Decimal("-1")
        per_d = Decimal(str(per))
        # Fail-closed: a priced call must never settle at 0. Rows with an unknown
        # price (0) — e.g. Stability edit models seeded regen_zero_class — must be
        # given a real per-image price before they can be billed/served.
        if per_d <= 0:
            return Decimal("-1")
        return per_d * Decimal(str(count))

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
    """Call bedrock-runtime.invoke_model and return parsed response body.

    For Stability image-edit models that reject on-demand invocation, transparently
    route to the system-defined cross-region inference profile (bare -> us.<id>).
    Cost/usage/settlement remain keyed on the caller's bare model_id.
    """
    client = _invoke_get_bedrock_client()
    invoke_model_id = _INVOKE_PROFILE_REMAP.get(model_id, model_id)
    resp = client.invoke_model(
        modelId=invoke_model_id,
        body=json.dumps(body or {}),
        contentType="application/json",
        accept="application/json",
    )
    raw = resp["body"].read()
    parsed = json.loads(raw.decode("utf-8"))
    # Capture the authoritative input-token-count header (AWS bills on this).
    # Some embedding models (e.g. Cohere Embed) omit inputTextTokenCount from the
    # response body; the header carries the exact count for accurate settlement.
    try:
        hdrs = resp.get("ResponseMetadata", {}).get("HTTPHeaders", {}) or {}
        tc = hdrs.get("x-amzn-bedrock-input-token-count")
        if tc is not None and isinstance(parsed, dict):
            parsed.setdefault("_bedrock_input_token_count", int(tc))
    except Exception:
        pass
    return parsed


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

    # Step 2b: slow models can't complete within the 29s sync limit — hand off
    # to the async /invoke-jobs pipeline and return 202 + job_id so the caller
    # polls instead of hitting a timeout ("일시적 오류"). Transparent to callers
    # that handle 202; fast image models are unaffected (stay synchronous).
    if model_id in _INVOKE_SLOW_ASYNC_MODELS:
        log_structured("info", "invoke_slow_model_async_handoff",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id)
        resp = handle_converse_job_submit(
            principal_id, identity_fields, body, request_id)
        try:
            if resp.get("statusCode") == 202:
                rb = json.loads(resp.get("body") or "{}")
                jid = rb.get("job_id", "")
                rb["async"] = True
                rb["status_url"] = f"/invoke-jobs/{jid}"
                rb["message"] = (
                    "model exceeds the 29s synchronous limit; poll "
                    f"GET /invoke-jobs/{jid} until status is SUCCEEDED")
                resp["body"] = json.dumps(rb)
        except Exception:
            pass
        return resp

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
        # Surface the Bedrock error message (not just the code) so callers can
        # self-diagnose (e.g. "on-demand throughput isn't supported ... use an
        # inference profile"). Previously only the code was returned, masking
        # the real cause. The full exception is still logged with alarm=True.
        bedrock_msg = e.response.get("Error", {}).get("Message", "") or str(e)
        msg = f"bedrock_client_error:{code}"
        log_structured("error", "invoke_bedrock_client_error",
                       request_id=request_id, model_id=model_id, code=code,
                       error=str(e), alarm=True)
        _invoke_mark_failed(request_id, msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _invoke_write_ledger(request_id, principal_id, model_id, "DENY",
                             {}, None, duration_ms, msg)
        return error_response(f"bedrock error: {code}: {bedrock_msg[:400]}")
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


# ===========================================================================
# Responses_Route — OpenAI Responses API (bedrock-mantle) passthrough
# ---------------------------------------------------------------------------
# Strictly-additive module (R3). Mirrors the handle_invoke() + _invoke_*
# helper family with a parallel handle_responses() + _responses_* family.
# Reuses the shared pipeline helpers verbatim: lookup_principal_policy,
# check_model_access, check_quota, current_month_kst, end_of_month_ttl_kst,
# write_request_ledger, _response, deny_response, error_response,
# log_structured. No existing route, helper, or the Stream_Lambda is
# modified. See design.md §2.1–§2.3, §3.1–§3.6, §4.5.
# ===========================================================================

# --- Task 2.1: constants + exception classes ------------------------------

# Responses_Route allowlist — OpenAI models served on the bedrock-mantle
# Responses API. Live-verified (2026-06) available on this account's
# us-west-2 mantle endpoint: the gpt-oss family responds to /v1/responses
# NOW; gpt-5.4 (and gpt-5.5 when published) light up automatically once
# Bedrock console Model Access is granted — no code change needed.
_RESPONSES_ALLOWLIST = frozenset({
    "openai.gpt-5.5",
    "openai.gpt-5.4",
    # gpt-5.6 family (GA 2026-07-13, bedrock-mantle Responses API). Sol is
    # published In-Region only in us-east-1 / us-east-2; Terra and Luna add
    # us-west-2. See _RESPONSES_MODEL_REGION for Sol's cross-region routing.
    "openai.gpt-5.6-sol",
    "openai.gpt-5.6-terra",
    "openai.gpt-5.6-luna",
    "openai.gpt-oss-120b",
    "openai.gpt-oss-20b",
    "openai.gpt-oss-safeguard-120b",
    "openai.gpt-oss-safeguard-20b",
})

# bedrock-mantle endpoint (single source of truth — R2.3).
_RESPONSES_ENDPOINT_HOST = "bedrock-mantle.us-west-2.api.aws"
# Path prefix — LIVE-CONFIRMED 2026-06: the OpenAI-native Responses API is
# served at "/openai/v1" and supports BOTH the gpt-oss family AND the frontier
# gpt-5.4 (verified 200 + usage). The bare "/v1/responses" surface only serves
# gpt-oss and rejects gpt-5.4 ("does not support"), so "/openai/v1" is the
# correct universal path. Full request path: "/openai/v1/responses".
_RESPONSES_PATH_PREFIX = "/openai/v1"
_RESPONSES_SIGV4_SERVICE = "bedrock"           # SigV4 signing service name (live-confirmed)
_RESPONSES_REGION = "us-west-2"

_RESPONSES_HTTP_TIMEOUT_SECONDS = 60           # buffered (non-streamed) call
_RESPONSES_IDEMPOTENCY_TTL_SECONDS = 24 * 3600
_RESPONSES_PENDING_RETRY_AFTER_SECONDS = 30

# Per-model region routing for bedrock-mantle. Most OpenAI Responses models are
# published in us-west-2 (_RESPONSES_REGION default). gpt-5.5 is currently only
# published in us-east-2, so it is pulled CROSS-REGION: the gateway signs SigV4
# for us-east-2 and targets the us-east-2 mantle host. LIVE-CONFIRMED 2026-06
# (gpt-5.5 @ us-east-2 -> 200). Cost tracking is region-agnostic (usage-based).
_RESPONSES_MODEL_REGION = {
    "openai.gpt-5.5": "us-east-2",
    "openai.gpt-5.5-2026-04-23": "us-east-2",
    # gpt-5.4: us-west-2 engine availability is intermittent (mantle returns
    # 400 "Engine not found" under load); us-east-2 serves gpt-5.4 reliably.
    # LIVE-CONFIRMED 2026-07 (us-west-2 flaky -> 400; us-east-2 -> 200). Route
    # gpt-5.4 cross-region to us-east-2 for parity with gpt-5.5.
    "openai.gpt-5.4": "us-east-2",
    "openai.gpt-5.4-2026-03-05": "us-east-2",
    # gpt-5.6 Sol is published In-Region ONLY in us-east-1 / us-east-2 (NOT
    # us-west-2), so it MUST be pulled cross-region to us-east-2 (parity with
    # gpt-5.5). Terra and Luna are additionally published in us-west-2, so
    # they use the default _RESPONSES_REGION and are intentionally NOT
    # overridden here.
    "openai.gpt-5.6-sol": "us-east-2",
}


def _responses_region_for(model_id: str) -> str:
    """Return the bedrock-mantle region that serves model_id (default
    _RESPONSES_REGION)."""
    return _RESPONSES_MODEL_REGION.get(model_id, _RESPONSES_REGION)


def _responses_host_for(region: str) -> str:
    """Return the bedrock-mantle endpoint host for a region."""
    return f"bedrock-mantle.{region}.api.aws"


class ResponsesAuthError(Exception):
    """Raised on bedrock-mantle HTTP 401/403 (auth/authz) — R2.4 path."""
    pass


class ResponsesApiError(Exception):
    """Raised on any other bedrock-mantle 4xx/5xx, transport, or timeout."""
    pass


# --- Task 3.1: usage extraction -------------------------------------------

def _responses_is_nonneg_int(value) -> bool:
    """True iff value is a non-negative int (bools excluded)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _responses_extract_usage(response_body: dict) -> dict:
    """Extract token usage from a Responses_API response.

    Returns {"input_tokens": int, "output_tokens": int,
             "reasoning_tokens": int, "cached_input_tokens": int}
    or {} on failure (caller must deny — R5.4 → R4.7 path).

    Reads usage.input_tokens and usage.output_tokens (required,
    non-negative ints); returns {} (fail-closed) when either is missing,
    non-numeric, or negative. Optionally reads
    usage.output_tokens_details.reasoning_tokens and
    usage.input_tokens_details.cached_tokens (default 0 when absent/invalid).
    """
    if not isinstance(response_body, dict):
        return {}
    usage = response_body.get("usage")
    if not isinstance(usage, dict):
        return {}

    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if not _responses_is_nonneg_int(input_tokens):
        return {}
    if not _responses_is_nonneg_int(output_tokens):
        return {}

    reasoning_tokens = 0
    otd = usage.get("output_tokens_details")
    if isinstance(otd, dict):
        rt = otd.get("reasoning_tokens", 0)
        if _responses_is_nonneg_int(rt):
            reasoning_tokens = int(rt)

    cached_input_tokens = 0
    itd = usage.get("input_tokens_details")
    if isinstance(itd, dict):
        ct = itd.get("cached_tokens", 0)
        if _responses_is_nonneg_int(ct):
            cached_input_tokens = int(ct)

    return {
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "reasoning_tokens": reasoning_tokens,
        "cached_input_tokens": cached_input_tokens,
    }


# --- Task 3.3: pricing lookup + cost mapping ------------------------------

def _responses_lookup_pricing(model_id: str) -> dict:
    """Direct GetItem on Model_Pricing_Table for /responses. Returns {} if
    missing (fail-closed — caller denies before any backend call). Mirrors
    _invoke_lookup_pricing."""
    if not TABLE_MODEL_PRICING:
        return {}
    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        resp = table.get_item(Key={"model_id": model_id})
        return resp.get("Item") or {}
    except Exception as e:
        log_structured("error", "responses_pricing_lookup_failed",
                       model_id=model_id, error=str(e))
        return {}


def _responses_estimate_cost_krw(usage: dict, pricing_row: dict) -> Decimal:
    """Compute KRW cost as Decimal per design §3.6. Returns Decimal('-1') on
    missing price (caller must deny — never accumulate 0 from a real call).

    Billable input = input_tokens; billable output = output_tokens (reasoning
    is already included in output_tokens and is NEVER added again). The
    cached-input split is applied only when the pricing row carries
    `cached_input_price_per_1k`; otherwise cached tokens fold into the
    standard input rate (R5.2, R5.3)."""
    if not usage or not pricing_row:
        return Decimal("-1")

    input_price_raw = pricing_row.get("input_price_per_1k")
    output_price_raw = pricing_row.get("output_price_per_1k")
    if input_price_raw is None or output_price_raw is None:
        return Decimal("-1")

    input_tokens = int(usage.get("input_tokens", 0))
    output_tokens = int(usage.get("output_tokens", 0))
    cached_input_tokens = int(usage.get("cached_input_tokens", 0))

    input_price = Decimal(str(input_price_raw))
    output_price = Decimal(str(output_price_raw))

    cached_price_raw = pricing_row.get("cached_input_price_per_1k")
    if cached_price_raw is not None:
        cached_price = Decimal(str(cached_price_raw))
        standard_input_tokens = input_tokens - cached_input_tokens
        if standard_input_tokens < 0:
            standard_input_tokens = 0
        input_cost = (
            (Decimal(str(standard_input_tokens)) * input_price)
            + (Decimal(str(cached_input_tokens)) * cached_price)
        ) / Decimal("1000")
    else:
        input_cost = (Decimal(str(input_tokens)) * input_price) / Decimal("1000")

    output_cost = (Decimal(str(output_tokens)) * output_price) / Decimal("1000")
    return input_cost + output_cost


# --- Task 4.1: idempotency claim + duplicate ------------------------------

def _responses_claim_in_progress(request_id: str, principal_id: str,
                                 model_id: str) -> str:
    """Claim IN_PROGRESS in IdempotencyRecord via conditional PutItem with
    route='/responses'. Mirrors _invoke_claim_in_progress.

    Returns:
      "claimed"   — claim succeeded; caller MAY call mantle
      "duplicate" — request_id already exists; caller MUST handle duplicate
    """
    table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
    now_iso = datetime.now(timezone.utc).isoformat()
    ttl_val = int(time.time()) + _RESPONSES_IDEMPOTENCY_TTL_SECONDS
    try:
        table.put_item(
            Item={
                "request_id": request_id,
                "route": "/openai/responses",
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


def _responses_get_idempotency_item(request_id: str) -> dict:
    """Read IdempotencyRecord item by request_id. Returns {} if missing."""
    try:
        table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
        resp = table.get_item(Key={"request_id": request_id})
        return resp.get("Item") or {}
    except Exception as e:
        log_structured("error", "responses_idempotency_get_failed",
                       request_id=request_id, error=str(e))
        return {}


def _responses_handle_duplicate(request_id: str) -> dict:
    """Handle duplicate request_id by inspecting existing IdempotencyRecord.
    COMPLETED→cached 200, IN_PROGRESS→409, FAILED→409 retry-with-new-id,
    route-mismatch→409. Mirrors _invoke_handle_duplicate, gated on
    route='/responses'."""
    item = _responses_get_idempotency_item(request_id)
    if not item:
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "duplicate request_id but record disappeared",
            "request_id": request_id,
        })

    route = item.get("route", "")
    if route and route != "/openai/responses":
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
                "input_tokens": int(item.get("usage_input_tokens", 0)),
                "output_tokens": int(item.get("usage_output_tokens", 0)),
            },
            "cost_krw": float(cost) if cost is not None else 0.0,
            "note": "duplicate request_id — cached settlement returned",
        })
    if status == "IN_PROGRESS":
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "request already in progress",
            "request_id": request_id,
            "retry_after_seconds": _RESPONSES_PENDING_RETRY_AFTER_SECONDS,
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


# --- Task 4.2: settlement, mark-failed, ledger ----------------------------

def _responses_settle_transaction(request_id: str, principal_id: str,
                                  model_id: str, usage: dict,
                                  cost_krw: Decimal,
                                  cached_payload: dict) -> str:
    """Atomically commit settlement.

    Single TransactWriteItems:
      - IdempotencyRecord Update: IN_PROGRESS → COMPLETED (conditional on
        route='/responses', with cached response)
      - MonthlyUsage Update: ADD cost_krw + input/output token counts

    Returns: "settled" | "duplicate_already_settled" | "still_in_progress"
             | "failed". Mirrors _invoke_settle_transaction; token counts
    come from usage['input_tokens']/usage['output_tokens']."""
    client = boto3.client("dynamodb", region_name=os.environ.get(
        "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2")))
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    ttl_val = end_of_month_ttl_kst()
    now_iso = datetime.now(timezone.utc).isoformat()

    in_tok = int(usage.get("input_tokens", 0))
    out_tok = int(usage.get("output_tokens", 0))

    try:
        client.transact_write_items(TransactItems=[
            {
                "Update": {
                    "TableName": TABLE_IDEMPOTENCY_RECORD,
                    "Key": {"request_id": {"S": request_id}},
                    "UpdateExpression": (
                        "SET #s = :completed, settled_at = :now, "
                        "cost_krw = :c, usage_input_tokens = :i, "
                        "usage_output_tokens = :o, cached_response = :resp"
                    ),
                    "ConditionExpression": (
                        "attribute_exists(request_id) AND #s = :in_progress "
                        "AND #r = :resp_route"
                    ),
                    "ExpressionAttributeNames": {
                        "#s": "status",
                        "#r": "route",
                    },
                    "ExpressionAttributeValues": {
                        ":completed": {"S": "COMPLETED"},
                        ":in_progress": {"S": "IN_PROGRESS"},
                        ":resp_route": {"S": "/openai/responses"},
                        ":now": {"S": now_iso},
                        ":c": {"N": format(cost_krw, "f")},
                        ":i": {"N": str(in_tok)},
                        ":o": {"N": str(out_tok)},
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
                        ":c": {"N": format(cost_krw, "f")},
                        ":i": {"N": str(in_tok)},
                        ":o": {"N": str(out_tok)},
                        ":ttl": {"N": str(ttl_val)},
                    },
                }
            },
        ])
        return "settled"
    except Exception as e:
        cls_name = type(e).__name__
        if cls_name == "TransactionCanceledException":
            reasons = getattr(e, "response", {}).get("CancellationReasons", []) or []
            codes = [r.get("Code", "") for r in reasons]
            if codes and codes[0] == "ConditionalCheckFailed":
                current = _responses_get_idempotency_item(request_id)
                cur_status = current.get("status", "")
                if cur_status == "COMPLETED":
                    return "duplicate_already_settled"
                if cur_status == "IN_PROGRESS":
                    return "still_in_progress"
                return "failed"
            log_structured("error", "responses_settle_txn_cancelled",
                           request_id=request_id, codes=codes, error=str(e),
                           alarm=True)
            return "failed"
        log_structured("error", "responses_settle_txn_error",
                       request_id=request_id, error=str(e), alarm=True)
        return "failed"


def _responses_mark_failed(request_id: str, reason: str) -> None:
    """Best-effort IN_PROGRESS → FAILED in IdempotencyRecord, conditional on
    route='/responses'."""
    try:
        table = dynamodb.Table(TABLE_IDEMPOTENCY_RECORD)
        table.update_item(
            Key={"request_id": request_id},
            UpdateExpression=(
                "SET #s = :failed, failed_at = :now, fail_reason = :r"
            ),
            ConditionExpression=(
                "attribute_exists(request_id) AND #s = :in_progress "
                "AND #rt = :resp_route"
            ),
            ExpressionAttributeNames={"#s": "status", "#rt": "route"},
            ExpressionAttributeValues={
                ":failed": "FAILED",
                ":in_progress": "IN_PROGRESS",
                ":resp_route": "/openai/responses",
                ":now": datetime.now(timezone.utc).isoformat(),
                ":r": reason[:512],
            },
        )
    except Exception as e:
        log_structured("error", "responses_mark_failed_error",
                       request_id=request_id, error=str(e), alarm=True)


def _responses_write_ledger(request_id: str, principal_id: str, model_id: str,
                            decision: str, usage: dict, cost_krw,
                            duration_ms: int, denial_reason: str = "") -> None:
    """Append immutable RequestLedger record (PutItem only) with
    source_path='/responses'. Records input/output tokens from usage.
    Mirrors _invoke_write_ledger. Best-effort."""
    try:
        entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": principal_id,
            "model_id": model_id,
            "decision": decision,
            "source_path": "/openai/responses",
            "input_tokens": int(usage.get("input_tokens", 0)) if usage else 0,
            "output_tokens": int(usage.get("output_tokens", 0)) if usage else 0,
            "estimated_cost_krw": cost_krw if cost_krw is not None else Decimal("0"),
            "duration_ms": duration_ms,
        }
        if usage:
            entry["reasoning_tokens"] = int(usage.get("reasoning_tokens", 0))
            entry["cached_input_tokens"] = int(usage.get("cached_input_tokens", 0))
        if denial_reason:
            entry["denial_reason"] = denial_reason[:512]
        write_request_ledger(entry)
    except Exception as e:
        log_structured("error", "responses_ledger_write_failed",
                       request_id=request_id, error=str(e), alarm=True)


# --- Task 5.1: handle_responses orchestrator ------------------------------

def handle_responses(principal_id: str, identity_fields: dict,
                     body: dict, request_id: str) -> dict:
    """POST /responses — OpenAI Responses API (bedrock-mantle) passthrough
    with idempotent, transactional settlement.

    Identical stage order to handle_invoke (R4.1):
      1. Extract model from body
      2. Allowlist gate (R1.4)
      3. Pricing lookup (fail-closed)
      4. PrincipalPolicy + per-principal allowed_models
      5. Quota pre-check
      6. IN_PROGRESS claim (conditional PutItem)
         duplicate → return cached/409 (mantle NOT called — R4.5)
      7. SigV4-signed mantle call
         auth/api error → mark FAILED, ledger DENY, error (R2.4)
      8. Extract usage (fail-closed)
         failure → mark FAILED, ledger DENY, settlement_failed (R5.4)
      9. Compute cost (Decimal)
     10. TransactWriteItems(COMPLETED + MonthlyUsage ADD)
     11. success → ledger ALLOW + 200 buffered payload (R1.6, R9.1)
    """
    start_time = time.time()
    model_id = body.get("model", "") if isinstance(body, dict) else ""

    if not model_id:
        return deny_response("model is required", status_code=400)

    # Step 2: allowlist
    if model_id not in _RESPONSES_ALLOWLIST:
        log_structured("warning", "responses_not_allowlisted",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id)
        return deny_response(
            f"model {model_id} is not on /responses allowlist",
            status_code=400)

    # Step 3: pricing (fail-closed — mantle not called)
    pricing_row = _responses_lookup_pricing(model_id)
    if not pricing_row:
        return deny_response(f"no pricing defined for model {model_id}")

    # Step 4: policy + per-principal allowed_models
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "responses_policy_lookup_failed",
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
        log_structured("error", "responses_quota_check_failed",
                       request_id=request_id, error=str(e))
        return deny_response("quota check failed")
    if not quota_result["allowed"]:
        return _response(429, {
            "decision": "DENY",
            "denial_reason": "monthly cost quota exceeded",
            "quota": quota_result,
        })

    # Step 6: IN_PROGRESS claim
    claim = _responses_claim_in_progress(request_id, principal_id, model_id)
    if claim == "duplicate":
        log_structured("info", "responses_duplicate_request_id",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id)
        return _responses_handle_duplicate(request_id)

    # Step 7: mantle call (SigV4-signed HTTPS)
    try:
        response_body = _responses_call_mantle(model_id, body)
    except ResponsesAuthError as e:
        msg = f"mantle_auth_error:{str(e)[:200]}"
        log_structured("error", "responses_mantle_auth_error",
                       request_id=request_id, model_id=model_id,
                       error=str(e), alarm=True)
        _responses_mark_failed(request_id, msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _responses_write_ledger(request_id, principal_id, model_id, "DENY",
                                {}, None, duration_ms, msg)
        return error_response("mantle authentication/authorization error",
                              status_code=502)
    except ResponsesApiError as e:
        msg = f"mantle_api_error:{str(e)[:200]}"
        log_structured("error", "responses_mantle_api_error",
                       request_id=request_id, model_id=model_id,
                       error=str(e), alarm=True)
        _responses_mark_failed(request_id, msg)
        duration_ms = int((time.time() - start_time) * 1000)
        _responses_write_ledger(request_id, principal_id, model_id, "DENY",
                                {}, None, duration_ms, msg)
        return error_response(f"mantle call failed: {str(e)[:200]}",
                              status_code=502)

    # Step 8: extract usage (fail-closed)
    usage = _responses_extract_usage(response_body)
    if not usage:
        log_structured("error", "responses_usage_extract_failed",
                       request_id=request_id, model_id=model_id, alarm=True)
        _responses_mark_failed(request_id, "usage_extract_failed")
        duration_ms = int((time.time() - start_time) * 1000)
        _responses_write_ledger(request_id, principal_id, model_id, "DENY",
                                {}, None, duration_ms, "usage_extract_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "usage extraction failed — settlement_failed",
            "request_id": request_id,
        })

    # Step 9: cost
    cost_krw = _responses_estimate_cost_krw(usage, pricing_row)
    if cost_krw < Decimal("0"):
        log_structured("error", "responses_cost_compute_failed",
                       request_id=request_id, model_id=model_id, alarm=True)
        _responses_mark_failed(request_id, "cost_compute_failed")
        duration_ms = int((time.time() - start_time) * 1000)
        _responses_write_ledger(request_id, principal_id, model_id, "DENY",
                                usage, None, duration_ms, "cost_compute_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "cost computation failed",
            "request_id": request_id,
        })

    # Build response payload (full, returned to client) and a lightweight
    # cache_meta (no output) stored in IdempotencyRecord — DynamoDB
    # UpdateExpression has a 4KB limit, and Responses payloads can exceed it.
    duration_ms = int((time.time() - start_time) * 1000)
    new_usage_krw = Decimal(str(quota_result["usage"]["cost_krw"])) + cost_krw
    remaining = max(Decimal("0"),
                    Decimal(str(quota_result["limit"]["cost_krw"])) - new_usage_krw)

    usage_view = {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "reasoning_tokens": usage["reasoning_tokens"],
        "cached_input_tokens": usage["cached_input_tokens"],
    }
    response_payload = {
        "decision": "ALLOW",
        "output": response_body,
        "usage": usage_view,
        "cost_krw": float(cost_krw),
        "remaining_quota_krw": float(remaining),
        "model_id": model_id,
        "request_id": request_id,
    }
    cache_meta = {
        "decision": "ALLOW",
        "usage": usage_view,
        "cost_krw": float(cost_krw),
        "remaining_quota_krw": float(remaining),
        "model_id": model_id,
        "request_id": request_id,
        "note": "duplicate request_id — output omitted (only metadata cached)",
    }

    # Step 10: transactional settle
    settle_result = _responses_settle_transaction(
        request_id, principal_id, model_id, usage, cost_krw, cache_meta)

    if settle_result == "duplicate_already_settled":
        log_structured("warning", "responses_settle_already_settled",
                       request_id=request_id, model_id=model_id)
        return _responses_handle_duplicate(request_id)

    if settle_result == "still_in_progress":
        log_structured("warning", "responses_settle_still_in_progress",
                       request_id=request_id, model_id=model_id)
        return _response(409, {
            "decision": "DENY",
            "denial_reason": "settlement conflict — still IN_PROGRESS",
            "request_id": request_id,
        })

    if settle_result != "settled":
        log_structured("error", "responses_settlement_failed",
                       request_id=request_id, principal_id=principal_id,
                       model_id=model_id, cost_krw=str(cost_krw), alarm=True)
        _responses_mark_failed(request_id, "settlement_failed")
        _responses_write_ledger(request_id, principal_id, model_id, "DENY",
                                usage, cost_krw, duration_ms,
                                "settlement_failed")
        return _response(500, {
            "decision": "DENY",
            "denial_reason": "settlement_failed — mantle invoked but cost not recorded",
            "request_id": request_id,
        })

    # Step 11: success — write ledger ALLOW (immutable, append-only)
    _responses_write_ledger(request_id, principal_id, model_id, "ALLOW",
                            usage, cost_krw, duration_ms)

    log_structured("info", "responses_allowed",
                   request_id=request_id, principal_id=principal_id,
                   model_id=model_id,
                   input_tokens=usage["input_tokens"],
                   output_tokens=usage["output_tokens"],
                   cost_krw=str(cost_krw), duration_ms=duration_ms)

    return _response(200, response_payload)

# --- SigV4 mantle client helpers (R1.3, R2.1, R2.2, R2.3, R9.1) ------------
#
# botocore is part of the Lambda runtime (already imported above for
# ClientError). The signing primitives live under botocore.auth /
# botocore.awsrequest / botocore.session; they are imported at module scope
# here, consistent with the existing `from botocore.exceptions import
# ClientError` at the top of the file.
import urllib.request
import urllib.error
import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

# Module-scope cache of the botocore session and frozen credentials. The
# session is created once per warm Lambda container; botocore transparently
# refreshes the underlying execution-role credentials before they expire, so
# we cache the session (not a static key) and re-read credentials on demand.
_RESPONSES_BOTO_SESSION = None


def _responses_get_credentials():
    """Return the Lambda execution role's credentials for SigV4 signing.

    Obtains credentials via ``botocore.session.Session().get_credentials()``,
    which resolves the Lambda execution-role temporary credentials from the
    runtime environment. The session is cached at module scope so the
    container reuses it across warm invocations; botocore handles the
    automatic refresh of the temporary credentials behind that object.

    NEVER reads or stores a static API key (R2.2): the returned object is a
    botocore Credentials handle backed by the execution role only.
    """
    global _RESPONSES_BOTO_SESSION
    if _RESPONSES_BOTO_SESSION is None:
        _RESPONSES_BOTO_SESSION = botocore.session.Session()
    credentials = _RESPONSES_BOTO_SESSION.get_credentials()
    if credentials is None:
        # No execution-role credentials available — treat as an auth failure
        # so the caller follows the fail-closed R2.4 path.
        raise ResponsesAuthError("no execution-role credentials available")
    return credentials


def _responses_sign_request(method, url, body, headers, region=None):
    """Sign a bedrock-mantle request with SigV4 and return signed headers.

    ``region`` selects the SigV4 signing region (defaults to
    ``_RESPONSES_REGION``); cross-region models (e.g. gpt-5.5 in us-east-2)
    pass their own region so the signature scope matches the target host.
    """
    credentials = _responses_get_credentials()
    request = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(credentials, _RESPONSES_SIGV4_SERVICE,
              region or _RESPONSES_REGION).add_auth(request)
    return dict(request.headers)


def _responses_call_mantle(model_id, payload):
    """POST a buffered Responses request to bedrock-mantle and return its JSON.

    Constructs the URL
    ``https://{_RESPONSES_ENDPOINT_HOST}{_RESPONSES_PATH_PREFIX}/responses``,
    JSON-encodes ``payload`` to bytes, sets ``Content-Type: application/json``
    and the ``Host`` header, signs via :func:`_responses_sign_request`, and
    sends the request with ``urllib.request.urlopen`` under
    ``_RESPONSES_HTTP_TIMEOUT_SECONDS``. The buffered JSON response body is
    parsed and returned.

    Streaming is forced OFF (R9.1 — buffered only): if the payload requests
    ``stream``, it is overridden to ``False`` before signing/sending so the
    backend never returns an SSE stream.

    Raises:
        ResponsesAuthError: on HTTP 401/403 (authentication/authorization) —
            drives the R2.4 fail-closed path (no billable settlement).
        ResponsesApiError: on any other HTTP 4xx/5xx, transport failure
            (URLError), socket timeout, or JSON parse failure. The status
            code / reason is included in the message (truncated).
    """
    # R9.1 — buffered only: never forward a streaming request.
    if isinstance(payload, dict) and payload.get("stream"):
        payload = dict(payload)
        payload["stream"] = False

    # Per-model region routing (cross-region for models not in _RESPONSES_REGION).
    region = _responses_region_for(model_id)
    host = _responses_host_for(region)
    url = "https://{host}{prefix}/responses".format(
        host=host, prefix=_RESPONSES_PATH_PREFIX)
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Host": host,
    }
    signed = _responses_sign_request("POST", url, body, headers, region)

    try:
        request = urllib.request.Request(url, data=body, headers=signed, method="POST")
        with urllib.request.urlopen(
                request, timeout=_RESPONSES_HTTP_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        # Read whatever detail the backend returned, truncated for the message.
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:
            detail = ""
        if exc.code in (401, 403):
            raise ResponsesAuthError(
                "bedrock-mantle auth error {code}: {detail}".format(
                    code=exc.code, detail=detail[:500])) from exc
        raise ResponsesApiError(
            "bedrock-mantle HTTP {code}: {detail}".format(
                code=exc.code, detail=detail[:500])) from exc
    except urllib.error.URLError as exc:
        raise ResponsesApiError(
            "bedrock-mantle transport error: {reason}".format(
                reason=str(exc.reason)[:500])) from exc
    except (TimeoutError, OSError) as exc:
        # socket.timeout is an alias of TimeoutError/OSError on 3.10+.
        raise ResponsesApiError(
            "bedrock-mantle request failed: {err}".format(
                err=str(exc)[:500])) from exc

    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ResponsesApiError(
            "bedrock-mantle returned unparseable JSON: {err}".format(
                err=str(exc)[:500])) from exc


# ===========================================================================
# Batch_Route — Bedrock batch inference (POST /batch, GET /batch/{job_id}).
# Appended, strictly-additive module (design.md §2.1, §3.2, §4.6). Nothing
# above this banner is modified. Mirrors the appended _responses_* family and
# the async /converse-jobs reserve-then-settle convention. See requirements
# R8, R10, R12, R13. This block is constants + config accessor + local
# exception only (Task 2.1); the helper / orchestrator families follow.
# ===========================================================================

# --- Task 2.1: Batch_Route constants --------------------------------------

# Batch_Allowlist — models Amazon Bedrock supports for batch inference. This
# frozenset is the in-code DEFAULT; the operator may override it via the
# gateway config key "batch_allowlist" (R8, R12.6), so precise membership is
# not load-bearing — it is a config-overridable safety default.
#
# Opus ceiling is 4-6 (R8.3): anthropic.claude-opus-4-6-v1 is the highest
# supported Opus. Opus 4.7 / 4.8, Fable 5, and the gpt-5.x family are
# intentionally EXCLUDED (R8.3) and therefore deliberately absent below.
#
# Model-id spelling follows the gateway's existing convention (cf.
# _RESPONSES_ALLOWLIST and scripts/add_missing_models): bare/`us.`/`global.`
# prefix variants of the same family all denote the same model. The Anthropic
# entries use the exact identifiers named in R8.3/R8.4. For the
# Llama / Mistral / DeepSeek / Qwen / gpt-oss families the precise
# batch-capable id set is account-dependent; the documented batch-capable ids
# (and their common prefix variants) are included here and can be refined via
# config without a code change. (R8.4)
_BATCH_ALLOWLIST_DEFAULT = frozenset({
    # Official us-west-2 batch-supported model ids (AWS docs
    # batch-inference-supported.html) — bare ids plus the cross-region
    # inference-profile variants (us./global.) users actually invoke.
    # Opus 4.7/4.8, Fable, and gpt-5.x are intentionally EXCLUDED (R8.3).
    "amazon.nova-2-lite-v1:0",
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "amazon.nova-premier-v1:0",
    "amazon.nova-pro-v1:0",
    "amazon.titan-embed-image-v1",
    "amazon.titan-embed-text-v2:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-3-7-sonnet-20250219-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0",
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-haiku-4-5-20251001-v1:0",
    "anthropic.claude-opus-4-5-20251101-v1:0",
    "anthropic.claude-opus-4-6-v1",
    "anthropic.claude-sonnet-4-20250514-v1:0",
    "anthropic.claude-sonnet-4-5-20250929-v1:0",
    "anthropic.claude-sonnet-4-6",
    "deepseek.v3-v1:0",
    "deepseek.v3.2",
    "global.amazon.nova-premier-v1:0",
    "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "global.anthropic.claude-opus-4-5-20251101-v1:0",
    "global.anthropic.claude-opus-4-6-v1",
    "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "global.anthropic.claude-sonnet-4-6",
    "google.gemma-3-12b-it",
    "google.gemma-3-27b-it",
    "google.gemma-3-4b-it",
    "meta.llama3-1-405b-instruct-v1:0",
    "meta.llama3-1-70b-instruct-v1:0",
    "meta.llama3-1-8b-instruct-v1:0",
    "meta.llama3-2-11b-instruct-v1:0",
    "meta.llama3-2-1b-instruct-v1:0",
    "meta.llama3-2-3b-instruct-v1:0",
    "meta.llama3-2-90b-instruct-v1:0",
    "meta.llama3-3-70b-instruct-v1:0",
    "meta.llama4-maverick-17b-instruct-v1:0",
    "meta.llama4-scout-17b-instruct-v1:0",
    "minimax.minimax-m2",
    "minimax.minimax-m2.1",
    "mistral.devstral-2-123b",
    "mistral.magistral-small-2509",
    "mistral.ministral-3-14b-instruct",
    "mistral.ministral-3-3b-instruct",
    "mistral.ministral-3-8b-instruct",
    "mistral.mistral-large-2407-v1:0",
    "mistral.mistral-large-3-675b-instruct",
    "mistral.voxtral-mini-3b-2507",
    "mistral.voxtral-small-24b-2507",
    "moonshot.kimi-k2-thinking",
    "moonshotai.kimi-k2.5",
    "nvidia.nemotron-nano-12b-v2",
    "nvidia.nemotron-nano-3-30b",
    "nvidia.nemotron-nano-9b-v2",
    "openai.gpt-oss-120b-1:0",
    "openai.gpt-oss-20b-1:0",
    "openai.gpt-oss-safeguard-120b",
    "openai.gpt-oss-safeguard-20b",
    "qwen.qwen3-235b-a22b-2507-v1:0",
    "qwen.qwen3-32b-v1:0",
    "qwen.qwen3-coder-30b-a3b-v1:0",
    "qwen.qwen3-coder-480b-a35b-v1:0",
    "qwen.qwen3-next-80b-a3b",
    "qwen.qwen3-vl-235b-a22b",
    "us.amazon.nova-2-lite-v1:0",
    "us.amazon.nova-lite-v1:0",
    "us.amazon.nova-micro-v1:0",
    "us.amazon.nova-premier-v1:0",
    "us.amazon.nova-pro-v1:0",
    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "us.anthropic.claude-opus-4-5-20251101-v1:0",
    "us.anthropic.claude-opus-4-6-v1",
    "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-sonnet-4-6",
    "us.deepseek.v3-v1:0",
    "us.deepseek.v3.2",
    "us.meta.llama3-1-405b-instruct-v1:0",
    "us.meta.llama3-1-70b-instruct-v1:0",
    "us.meta.llama3-1-8b-instruct-v1:0",
    "us.meta.llama3-2-11b-instruct-v1:0",
    "us.meta.llama3-2-1b-instruct-v1:0",
    "us.meta.llama3-2-3b-instruct-v1:0",
    "us.meta.llama3-2-90b-instruct-v1:0",
    "us.meta.llama3-3-70b-instruct-v1:0",
    "us.meta.llama4-maverick-17b-instruct-v1:0",
    "us.meta.llama4-scout-17b-instruct-v1:0",
    "us.openai.gpt-oss-120b-1:0",
    "us.openai.gpt-oss-20b-1:0",
    "us.qwen.qwen3-235b-a22b-2507-v1:0",
    "us.qwen.qwen3-32b-v1:0",
    "us.qwen.qwen3-coder-30b-a3b-v1:0",
    "us.qwen.qwen3-coder-480b-a35b-v1:0",
    "zai.glm-4.7",
    "zai.glm-4.7-flash",
})

# Per-model architectural output ceiling, used ONLY as the per-record fallback
# when a record declares no output ceiling (R3.6) and as the clamp ceiling when
# it does (R12.7). Config-driven via gateway config key
# "batch_model_max_output_tokens"; conservative in-code defaults below. Any
# model not listed falls back to the "__default__" entry.
_BATCH_MODEL_MAX_OUTPUT_DEFAULT = {
    "anthropic.claude-opus-4-6-v1": 32000,
    "anthropic.claude-sonnet-4-v1": 32000,
    "anthropic.claude-sonnet-4-5-v1": 32000,
    "anthropic.claude-sonnet-4-6-v1": 32000,
    "anthropic.claude-haiku-4-5-v1": 8192,
    "openai.gpt-oss-120b": 16384,
    "openai.gpt-oss-20b": 16384,
    "us.openai.gpt-oss-120b-1:0": 16384,
    "us.openai.gpt-oss-20b-1:0": 16384,
    "__default__": 8192,
}

_BATCH_DISCOUNT = Decimal("0.5")               # R10.4, R3.2, R5.2 — 50% batch discount

# Submission bounds (config-driven — R12.6). In-code defaults match R12.2 /
# R12.4 / R12.5.
_BATCH_RECORD_COUNT_MIN_DEFAULT = 100          # R12.2 minimum Record_Count
_BATCH_RECORD_COUNT_MAX_DEFAULT = 50000        # R12.2 maximum Record_Count
_BATCH_PER_PRINCIPAL_ACTIVE_DEFAULT = 10       # R12.4 per-principal active jobs
_BATCH_GLOBAL_ACTIVE_DEFAULT = 50              # R12.5 global active jobs

_BATCH_RESERVATION_TTL_SECONDS = 48 * 3600     # R7.5 / R13.2 — > 24h max job timeout
_BATCH_TEMPLATE_OVERHEAD_TOKENS = 64           # per-record chat-template/role ceiling (§3.4)
_BATCH_SOURCE_PATH = "gateway-batch"           # Job_State / ledger discriminator (R10.2)

# Bedrock batch job terminal states (R5.1, R7). Exact strings are LIVE-VERIFY
# (Task 10.1) but are config-independent — this is the in-code terminal set.
_BATCH_TERMINAL_STATES = frozenset({
    "Completed",
    "Failed",
    "Stopped",
    "PartiallyCompleted",
    "Expired",
})


# --- Task 2.1: local exception class --------------------------------------

class BatchInputError(Exception):
    """Raised when the S3 Input_File cannot be read or parsed (R3.5).

    The submit handler maps this to HTTP 400 and SHALL NOT call
    CreateModelInvocationJob.
    """
    pass


# --- Task 2.1: batch config accessor (overlays __gateway_config__) ---------

# Batch config is read from the SAME reserved item the gateway config uses
# (principal_id = "__gateway_config__" in the principal-policy table) — NO new
# table, NO Terraform change, NO IAM change (design.md §4.6). Cached with its
# own short TTL, mirroring _get_gateway_config().
_batch_config_cache: dict = {}
_batch_config_ts: float = 0


def _batch_config() -> dict:
    """Read batch operator config overlaid on the __gateway_config__ row.

    Returns a dict with every batch key resolved to either the operator's
    configured value or the in-code default (R8 config-driven, R12.6):

      batch_allowlist:                  frozenset[str]
      batch_model_max_output_tokens:    dict[str, int]  (with "__default__")
      batch_record_count_min:           int
      batch_record_count_max:           int
      batch_per_principal_active_limit: int
      batch_global_active_limit:        int

    Falls back to the in-code defaults when a key is absent. Fail-soft: if the
    config read raises, the conservative in-code defaults are returned.
    """
    global _batch_config_cache, _batch_config_ts
    now = time.time()
    if _batch_config_cache and (now - _batch_config_ts) < GATEWAY_CONFIG_CACHE_TTL_S:
        return _batch_config_cache

    defaults = {
        "batch_allowlist": _BATCH_ALLOWLIST_DEFAULT,
        "batch_model_max_output_tokens": dict(_BATCH_MODEL_MAX_OUTPUT_DEFAULT),
        "batch_record_count_min": _BATCH_RECORD_COUNT_MIN_DEFAULT,
        "batch_record_count_max": _BATCH_RECORD_COUNT_MAX_DEFAULT,
        "batch_per_principal_active_limit": _BATCH_PER_PRINCIPAL_ACTIVE_DEFAULT,
        "batch_global_active_limit": _BATCH_GLOBAL_ACTIVE_DEFAULT,
    }

    try:
        table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
        resp = table.get_item(Key={"principal_id": GATEWAY_CONFIG_KEY})
        item = resp.get("Item") or {}

        # Allowlist override: accept any iterable of model-id strings.
        allowlist = defaults["batch_allowlist"]
        if item.get("batch_allowlist"):
            allowlist = frozenset(str(m) for m in item["batch_allowlist"])

        # Per-model max-output override: merge over the in-code defaults so a
        # partial operator map still keeps the "__default__" fallback.
        max_output = dict(_BATCH_MODEL_MAX_OUTPUT_DEFAULT)
        if item.get("batch_model_max_output_tokens"):
            for k, v in dict(item["batch_model_max_output_tokens"]).items():
                max_output[str(k)] = int(v)

        cfg = {
            "batch_allowlist": allowlist,
            "batch_model_max_output_tokens": max_output,
            "batch_record_count_min": int(
                item.get("batch_record_count_min", _BATCH_RECORD_COUNT_MIN_DEFAULT)),
            "batch_record_count_max": int(
                item.get("batch_record_count_max", _BATCH_RECORD_COUNT_MAX_DEFAULT)),
            "batch_per_principal_active_limit": int(
                item.get("batch_per_principal_active_limit",
                         _BATCH_PER_PRINCIPAL_ACTIVE_DEFAULT)),
            "batch_global_active_limit": int(
                item.get("batch_global_active_limit",
                         _BATCH_GLOBAL_ACTIVE_DEFAULT)),
        }
        _batch_config_cache = cfg
        _batch_config_ts = now
    except Exception as e:
        log_structured("error", "batch_config_read_failed", error=str(e))
        # Fail-soft: conservative in-code defaults.
        _batch_config_cache = defaults
        _batch_config_ts = now
    return _batch_config_cache


# --- Task 2.2: input-token upper bound and per-record output upper bound ---
#
# These are PURE, deterministic helpers (no mutation of module state) so the
# upper-bound and derivation properties (Tasks 2.4 / 2.5) can be property-tested
# directly. They read the S3 Input_File exactly once and derive every bound
# SOLELY from the file contents — never from a principal-supplied output field
# (R3.7, R12.1). Both the Converse record shape (modelInput.inferenceConfig.
# maxTokens) and the InvokeModel record shape (modelInput.max_tokens) are
# handled.


def _batch_input_is_multimodal(model_input) -> bool:
    """True if a record's modelInput carries an image / document / video block.

    Multimodal records are out of scope for v1 batch (design §3.4): image/
    document tokens are NOT bounded by the serialized-character count the input
    upper bound relies on, so the Reservation_Cost >= Settled_Cost guarantee
    (R3.4) could not be proven for them. Detected across both record shapes:
    Converse content blocks key the media as ``image``/``document``/``video``;
    InvokeModel (Anthropic messages) content blocks set ``type`` to
    ``image``/``document``.
    """
    if not isinstance(model_input, dict):
        return False
    messages = model_input.get("messages")
    if not isinstance(messages, list):
        return False
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if any(k in block for k in ("image", "document", "video")):
                return True
            btype = block.get("type")
            if isinstance(btype, str) and btype in ("image", "document", "video"):
                return True
    return False


def _batch_read_input_records(input_file_ref) -> list:
    """Read the S3 Input_File ONCE and parse JSONL into record dicts.

    ``input_file_ref`` is an ``s3://bucket/key`` URI. Raises BatchInputError on
    any S3/parse failure — the caller maps that to HTTP 400 and SHALL NOT call
    CreateModelInvocationJob (R3.5). Each line must be a JSON object carrying a
    ``modelInput`` object; multimodal records are rejected as out of scope for
    v1 batch (design §3.4). Uses the existing module-level ``s3_client``.
    """
    if not isinstance(input_file_ref, str) or not input_file_ref.startswith("s3://"):
        raise BatchInputError(
            "input_file_ref must be an s3:// URI")

    without = input_file_ref[len("s3://"):]
    bucket, _, key = without.partition("/")
    if not bucket or not key:
        raise BatchInputError(
            "input_file_ref must be of the form s3://bucket/key")

    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        raw = resp["Body"].read()
    except Exception as e:
        log_structured("error", "batch_input_read_failed",
                       input_file_ref=input_file_ref, error=str(e))
        raise BatchInputError(
            "cannot read input file from S3") from e

    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception as e:
        raise BatchInputError("input file is not valid UTF-8") from e

    records: list = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError) as e:
            raise BatchInputError(
                f"input file line {lineno} is not valid JSON") from e
        if not isinstance(rec, dict) or not isinstance(rec.get("modelInput"), dict):
            raise BatchInputError(
                f"input file line {lineno} is missing a modelInput object")
        if _batch_input_is_multimodal(rec["modelInput"]):
            raise BatchInputError(
                f"input file line {lineno} contains a multimodal block "
                "(image/document/video) which is out of scope for v1 batch")
        records.append(rec)

    if not records:
        raise BatchInputError("input file contains no records")
    return records


def _batch_count_input_tokens_upper(record) -> int:
    """Deterministic UPPER BOUND on the input tokens Bedrock will report for one
    record (R3.1).

        chars = len(json.dumps(record["modelInput"], ensure_ascii=False))
        return chars + _BATCH_TEMPLATE_OVERHEAD_TOKENS

    Provably >= Bedrock's reported inputTokens for text records: every BPE token
    decodes to >= 1 character of the serialized model input, so
    token_count <= char_count; chat-template/role/special tokens add no
    user-text characters and are bounded by the per-record overhead constant.
    The serialized-JSON length also over-counts (structural punctuation), making
    the bound strictly conservative. Deterministic and tokenizer-free.
    """
    if not isinstance(record, dict) or not isinstance(record.get("modelInput"), dict):
        raise BatchInputError("record is missing a modelInput object")
    chars = len(json.dumps(record["modelInput"], ensure_ascii=False))
    return chars + _BATCH_TEMPLATE_OVERHEAD_TOKENS


def _batch_record_output_upper(record, model_id, cfg=None) -> int:
    """Per-record Output_Upper_Bound contribution (R3.2, R3.6, R3.7, R12.7).

      declared = record.modelInput.max_tokens                  # InvokeModel format
               or record.modelInput.inferenceConfig.maxTokens  # Converse format
      m_max    = Model_Max_Output_Tokens(model_id, cfg)
      if declared is None: return m_max                        # R3.6 fallback
      return min(declared, m_max)                              # R12.7 clamp

    Derived SOLELY from the Input_File record; never reads a principal-supplied
    output field (R3.7, R12.1). A malformed/negative declared ceiling falls back
    to m_max so the conservative upper bound is preserved.
    """
    if not isinstance(record, dict) or not isinstance(record.get("modelInput"), dict):
        raise BatchInputError("record is missing a modelInput object")
    if cfg is None:
        cfg = _batch_config()

    model_input = record["modelInput"]
    declared = None
    if model_input.get("max_tokens") is not None:              # InvokeModel format
        declared = model_input.get("max_tokens")
    else:
        inference_config = model_input.get("inferenceConfig")  # Converse format
        if isinstance(inference_config, dict) and \
                inference_config.get("maxTokens") is not None:
            declared = inference_config.get("maxTokens")

    max_map = cfg["batch_model_max_output_tokens"]
    m_max = int(max_map.get(model_id, max_map["__default__"]))

    if declared is None:
        return m_max                                           # R3.6 fallback
    try:
        declared_int = int(declared)
    except (TypeError, ValueError):
        return m_max
    if declared_int < 0:
        return m_max
    return min(declared_int, m_max)                            # R12.7 clamp

def _batch_reservation_cost_krw(records, model_id, pricing, cfg=None):
    """Reservation cost upper bound for a batch job (R3.2, R5.2, R10.4).

    Sums the per-record input upper bound (_batch_count_input_tokens_upper) and
    the per-record output upper bound (_batch_record_output_upper) across ALL
    records, then:

        on_demand   = estimate_cost_krw(sum_input_ub, sum_output_ub, pricing)
        reservation = on_demand * _BATCH_DISCOUNT      # 50% batch discount

    The discount is applied with Decimal arithmetic (no float drift), matching
    how the async reserve path and estimate_cost_krw keep full Decimal precision
    for KRW costs — i.e. no .quantize() rounding is applied, consistent with the
    existing code. Returns (reservation_cost, sum_input_ub, sum_output_ub).

    Output_Upper_Bound is derived SOLELY from the Input_File records; no
    principal-supplied output field is read (R3.7, R12.1). Pure function: no I/O,
    no mutation, so Task 2.4's Property 1 (Reservation_Cost >= Settled_Cost) can
    test it directly. When pricing is pending (input/output price None),
    estimate_cost_krw returns Decimal(0) and the reservation is correctly 0.
    """
    if cfg is None:
        cfg = _batch_config()

    sum_input_ub = 0
    sum_output_ub = 0
    for record in records:
        sum_input_ub += _batch_count_input_tokens_upper(record)
        sum_output_ub += _batch_record_output_upper(record, model_id, cfg)

    on_demand = estimate_cost_krw(sum_input_ub, sum_output_ub, pricing)
    reservation_cost = on_demand * _BATCH_DISCOUNT
    return (reservation_cost, sum_input_ub, sum_output_ub)


# ---------------------------------------------------------------------------
# Batch_Route — reservation / job-record / concurrency / ledger helpers
# (Task 3.1; design §3.5, §4.3, §4.4). STRICTLY ADDITIVE — appended at the
# bottom of the module; no existing line is modified. These mirror the async
# /converse-jobs reserve-then-settle conventions (handle_converse_job_submit
# ~L2350/L2460) and the Fargate worker ledger shapes (worker/main.py) verbatim
# so a reviewer can diff them side by side, while keeping every DynamoDB write
# shape consistent with the in-memory fakes (ADD accumulation, PutItem,
# Select=COUNT queries) the property tests in Tasks 3.4–3.7 exercise.
# ---------------------------------------------------------------------------

# Sparse batch-active GSI on Job_State — added (additive) in Terraform Task 9.5.
# Hash key is the `gsi_batch_active` attribute, which is present ("1") ONLY on
# active batch job items and REMOVEd at settlement, so a Select=COUNT query on
# the index returns the global active-batch count without an O(table) scan
# (design §4.2, R12.5). Index name follows the existing
# "principal-created-index" convention.
_BATCH_ACTIVE_INDEX = "batch-active-index"
_BATCH_ACTIVE_MARKER = "1"

# Batch job lifecycle states counted as "active" for the concurrency limits
# (R12.4, R12.5): the gateway writes ACCEPTED; Bedrock progresses through
# SUBMITTED / IN_PROGRESS until a terminal state flips the record and removes
# the sparse marker.
_BATCH_ACTIVE_STATUSES = ("ACCEPTED", "SUBMITTED", "IN_PROGRESS")

# Job_State item TTL — 7 days after creation, identical to the async route.
_BATCH_JOB_RECORD_TTL_SECONDS = 7 * 24 * 3600


def _batch_active_counts(principal_id, cfg=None):
    """Return (per_principal_active, global_active) for batch jobs that are in
    one of the active states (ACCEPTED / SUBMITTED / IN_PROGRESS) — R12.4, R12.5.

    Per-principal: a COUNT query on the existing ``principal-created-index`` GSI
    (mirrors the PER_USER_ACTIVE_LIMIT query in handle_converse_job_submit
    ~L2350) with an added ``source_path = "gateway-batch"`` discriminator so only
    batch jobs are counted. The status set is expressed as an OR of equalities
    (rather than a DynamoDB ``IN`` list) so the filter evaluates identically
    against real DynamoDB and the in-memory test fake.

    Global: a COUNT query on the sparse batch-active GSI (``gsi_batch_active``).
    Because the index is added later (Terraform Task 9.5) the query is wrapped so
    that a missing index degrades safely to a global count of 0 — the
    per-principal limit still applies — rather than breaking submissions; the
    GSI query is always preferred when the index exists.

    Pure-read: performs only COUNT queries, no writes, so the gating property
    tests can drive it through handle_batch_submit against the fakes.
    """
    per_principal_active = 0
    global_active = 0
    if not TABLE_JOB_STATE:
        return (per_principal_active, global_active)

    job_table = dynamodb.Table(TABLE_JOB_STATE)

    # --- per-principal active batch jobs (existing principal-created-index) ---
    try:
        resp = job_table.query(
            IndexName="principal-created-index",
            KeyConditionExpression="principal_id = :pid",
            FilterExpression=(
                "source_path = :sp AND "
                "(#s = :s1 OR #s = :s2 OR #s = :s3)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":pid": principal_id,
                ":sp": _BATCH_SOURCE_PATH,
                ":s1": _BATCH_ACTIVE_STATUSES[0],
                ":s2": _BATCH_ACTIVE_STATUSES[1],
                ":s3": _BATCH_ACTIVE_STATUSES[2],
            },
            Select="COUNT",
        )
        per_principal_active = int(resp.get("Count", 0))
    except Exception as e:
        # Fail-soft to 0 (matches the existing active-count check, which logs and
        # continues): a transient index error must not block legitimate submits.
        log_structured("error", "batch_per_principal_active_count_failed",
                       principal_id=principal_id, error=str(e))

    # --- global active batch jobs (sparse batch-active GSI) ---
    try:
        gresp = job_table.query(
            IndexName=_BATCH_ACTIVE_INDEX,
            KeyConditionExpression="gsi_batch_active = :one",
            ExpressionAttributeValues={":one": _BATCH_ACTIVE_MARKER},
            Select="COUNT",
        )
        global_active = int(gresp.get("Count", 0))
    except Exception as e:
        # The sparse GSI is added in Terraform Task 9.5; tolerate it not existing
        # yet by degrading to 0 (global limit simply not enforced until the index
        # is deployed) while still preferring the GSI query when available.
        log_structured("warning", "batch_global_active_index_unavailable",
                       index=_BATCH_ACTIVE_INDEX, error=str(e))
        global_active = 0

    return (per_principal_active, global_active)


def _batch_write_reservation(principal_id, job_id, model_id, reservation_cost):
    """Write the ``__reserved__{job_id}`` upper-bound reservation row in
    MonthlyUsage (R3.3, R10.2).

    Identical convention to the async reserve at handle_converse_job_submit
    (~L2460): an ``UpdateItem ADD cost_krw`` on key
    ``principal_id_month = "<principal>#<current_month_kst()>"`` /
    ``model_id = "__reserved__{job_id}"`` with a ``ttl`` and a
    ``source_path = "gateway-batch-reserve"`` discriminator. Because ``ADD``
    accumulates, this is idempotent-safe under the fake and real DynamoDB alike.
    The TTL is 48h (``_BATCH_RESERVATION_TTL_SECONDS``), strictly greater than the
    24h max job timeout (R7.5 / R13.2) so the reservation never expires before
    settlement. ``check_quota`` already sums every row under the partition (the
    reserved row included), so no hot-path change is needed for the
    reservation-inclusive hard block (R4.1).
    """
    pk = f"{principal_id}#{current_month_kst()}"
    usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    usage_table.update_item(
        Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"},
        UpdateExpression="ADD cost_krw :c SET #t = :ttl, source_path = :sp, model_id_ref = :mid",
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues={
            ":c": reservation_cost,
            ":ttl": int(time.time()) + _BATCH_RESERVATION_TTL_SECONDS,
            ":sp": "gateway-batch-reserve",
            ":mid": model_id,
        },
    )


def _batch_delete_reservation(principal_id, job_id):
    """DeleteItem the ``__reserved__{job_id}`` MonthlyUsage row.

    Called on the Hard_Block path (R4.2) and on a CreateModelInvocationJob
    failure after the reservation was written (R4.4), so the net change to the
    principal's reserved rows is zero when a submission is not admitted.
    """
    pk = f"{principal_id}#{current_month_kst()}"
    usage_table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    usage_table.delete_item(
        Key={"principal_id_month": pk, "model_id": f"__reserved__{job_id}"})


def _batch_write_job_record(job_id, request_id, principal_id, model_id,
                            reserved_cost_krw, input_file_ref, record_count,
                            bedrock_job_arn):
    """PutItem the Job_State record for an accepted batch job (R1.4).

    Reuses the existing Job_State table with a ``source_path = "gateway-batch"``
    discriminator (design §4.1) and carries the additional batch-only attributes
    (``input_file_ref``, ``output_file_ref``, ``record_count``,
    ``bedrock_job_arn``, ``gsi_batch_active`` sparse marker). Adding attributes to
    new items is not a schema change and does not affect existing-route items.
    ``settled_cost_krw`` / ``input_tokens`` / ``output_tokens`` start at 0 and are
    set at settlement; ``gsi_batch_active = "1"`` makes the item visible in the
    sparse batch-active GSI for global counting and is REMOVEd at settlement.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    job_table = dynamodb.Table(TABLE_JOB_STATE)
    item = {
        "job_id": job_id,
        "request_id": request_id,
        "principal_id": principal_id,
        "model_id": model_id,
        "status": "ACCEPTED",
        "reserved_cost_krw": reserved_cost_krw,
        "settled_cost_krw": Decimal("0"),
        "input_file_ref": input_file_ref,
        "output_file_ref": "",
        "record_count": record_count,
        "source_path": _BATCH_SOURCE_PATH,
        "bedrock_job_arn": bedrock_job_arn,
        "gsi_batch_active": _BATCH_ACTIVE_MARKER,
        "input_tokens": 0,
        "output_tokens": 0,
        "created_at": now_iso,
        "updated_at": now_iso,
        "completed_at": "",
        "ttl": int(time.time()) + _BATCH_JOB_RECORD_TTL_SECONDS,
    }
    job_table.put_item(Item=item)


def _batch_write_ledger(event_type, request_id, job_id, principal_id, model_id,
                        decision, reserved_cost_krw=None, denial_reason="",
                        reservation_inclusive_total_krw=None,
                        input_tokens=None, output_tokens=None,
                        settled_cost_krw=None):
    """PutItem-only RequestLedger audit entry for the batch route (R11).

    Reuses the existing ``write_request_ledger`` (PutItem-only, immutable) and
    mirrors the Fargate worker's ``{request_id}#EVENT`` PK-suffix convention
    (worker/main.py). All entries carry ``source_path = "gateway-batch"``.

    Covered event types:
      * ``BATCH_ACCEPTED`` — job_id, principal_id, model_id, reserved_cost_krw,
        decision="ALLOW" (R11.1).
      * ``BATCH_DENIED_HARD_BLOCK`` — denial_reason +
        reservation_inclusive_total_krw, decision="DENY" (R11.3).
      * ``BATCH_SETTLED`` — actual input_tokens / output_tokens + settled_cost_krw,
        decision="ALLOW" (R11.2).

    Optional fields are only written when provided so each event shape stays
    minimal and matches the design's §4.4 field lists.
    """
    entry = {
        "request_id": f"{request_id}#{event_type}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principal_id": principal_id,
        "model_id": model_id,
        "event_type": event_type,
        "job_id": job_id,
        "decision": decision,
        "source_path": _BATCH_SOURCE_PATH,
    }
    if reserved_cost_krw is not None:
        entry["reserved_cost_krw"] = reserved_cost_krw
    if denial_reason:
        entry["denial_reason"] = denial_reason
    if reservation_inclusive_total_krw is not None:
        entry["reservation_inclusive_total_krw"] = reservation_inclusive_total_krw
    if input_tokens is not None:
        entry["input_tokens"] = input_tokens
    if output_tokens is not None:
        entry["output_tokens"] = output_tokens
    if settled_cost_krw is not None:
        entry["settled_cost_krw"] = settled_cost_krw
    write_request_ledger(entry)


# ---------------------------------------------------------------------------
# Batch_Route — submit orchestrator (Task 3.2; design §2.2, §3.3, §3.5).
# STRICTLY ADDITIVE — appended at the bottom of the module; no existing line is
# modified. Mirrors handle_converse_job_submit's stage order with the
# batch-specific twist that the reservation is written BEFORE the quota check so
# the hard block is reservation-inclusive (R4.1), and the reservation is DELETED
# on any downstream failure (R4.2 Hard_Block, R4.4 CreateModelInvocationJob
# failure). Batch jobs use the Bedrock CONTROL-PLANE client ("bedrock"), NOT
# bedrock-runtime; a lazy module-level accessor is used so the existing
# client-init block is left untouched and so the test suite can monkeypatch it.
# ---------------------------------------------------------------------------

_batch_bedrock_client = None


def _get_batch_bedrock_client():
    """Lazily construct the Bedrock CONTROL-PLANE client used for batch jobs.

    Batch inference (CreateModelInvocationJob / GetModelInvocationJob) lives on
    the ``bedrock`` control-plane client, NOT ``bedrock-runtime`` (which the
    real-time path uses). Created lazily and cached at module scope so this is
    additive — the existing client-init block (~L109) is never edited — and so
    tests can monkeypatch ``handler._batch_bedrock_client`` with a fake.
    """
    global _batch_bedrock_client
    if _batch_bedrock_client is None:
        _batch_bedrock_client = boto3.client(
            "bedrock", region_name=os.environ.get("AWS_REGION", "us-west-2"))
    return _batch_bedrock_client


def handle_batch_submit(principal_id: str, identity_fields: dict,
                        body: dict, request_id: str) -> dict:
    """POST /batch — Bedrock batch inference submit (R1.1).

    Stage order mirrors handle_converse_job_submit (validate → allowlist →
    policy → model access → pricing → read input → record-count bounds →
    concurrency → reserve → reservation-inclusive quota → warning → create →
    persist). Every failure path AFTER the reservation is written deletes the
    reservation so the principal's reserved rows net to zero when a submission
    is not admitted (R4.2, R4.4), and NO failure path calls
    CreateModelInvocationJob. Returns 202 + job_id on success.
    """
    # --- 1. Validate body (R1.3) — NO CreateJob ---------------------------
    model_id = body.get("model_id", "")
    input_file_ref = body.get("input_file_ref", "")
    if not model_id:
        return deny_response("model_id is required", status_code=400)
    if not input_file_ref:
        return deny_response("input_file_ref is required", status_code=400)

    cfg = _batch_config()

    # --- 2. Batch_Allowlist membership (R8.1, R8.2) — 400 naming the model -
    if model_id not in cfg["batch_allowlist"]:
        return deny_response(
            f"model {model_id} is not batch-capable", status_code=400)

    # --- 3. Policy lookup + model access (403) ----------------------------
    try:
        policy = lookup_principal_policy(principal_id)
    except Exception as e:
        log_structured("error", "batch_policy_lookup_failed",
                       principal_id=principal_id, error=str(e))
        return deny_response("policy lookup failed")
    if not policy:
        return deny_response("no policy defined for principal")
    if not check_model_access(policy, model_id):
        return deny_response(f"model {model_id} not in allowed list")

    # --- 4. Pricing lookup, fail-closed (403) -----------------------------
    pricing = lookup_model_pricing(model_id)
    if not pricing:
        return deny_response(f"no pricing defined for model {model_id}")

    # --- 5. Read S3 Input_File (BatchInputError → 400, R3.5) — NO CreateJob -
    try:
        records = _batch_read_input_records(input_file_ref)
    except BatchInputError as e:
        log_structured("warning", "batch_input_invalid",
                       principal_id=principal_id, input_file_ref=input_file_ref,
                       error=str(e))
        return deny_response(f"cannot read input file: {e}", status_code=400)
    record_count = len(records)

    # --- 6. Record_Count bounds (R12.3) — 400, NO CreateJob ---------------
    rc_min = cfg["batch_record_count_min"]
    rc_max = cfg["batch_record_count_max"]
    if record_count < rc_min or record_count > rc_max:
        return deny_response(
            f"record count {record_count} out of range "
            f"[{rc_min}, {rc_max}]", status_code=400)

    # --- 7. Concurrency limits (R12.4, R12.5) — 429, NO CreateJob ---------
    per_principal_active, global_active = _batch_active_counts(principal_id, cfg)
    per_principal_limit = cfg["batch_per_principal_active_limit"]
    global_limit = cfg["batch_global_active_limit"]
    if per_principal_active >= per_principal_limit:
        log_structured("warning", "batch_per_principal_active_limit",
                       principal_id=principal_id, active=per_principal_active)
        return _response(429, {
            "decision": "DENY",
            "denial_reason": (
                f"per-principal active batch job limit reached "
                f"({per_principal_active}/{per_principal_limit})"),
        })
    if global_active >= global_limit:
        log_structured("warning", "batch_global_active_limit",
                       principal_id=principal_id, active=global_active)
        return _response(429, {
            "decision": "DENY",
            "denial_reason": (
                f"global active batch job limit reached "
                f"({global_active}/{global_limit})"),
        })

    # --- 8. Compute upper bounds + Reservation_Cost -----------------------
    reservation_cost, sum_input_ub, sum_output_ub = _batch_reservation_cost_krw(
        records, model_id, pricing, cfg)

    job_id = f"batch-{uuid.uuid4()}"

    # --- 9. Write reservation BEFORE quota check (R3.3) -------------------
    try:
        _batch_write_reservation(principal_id, job_id, model_id, reservation_cost)
    except Exception as e:
        log_structured("error", "batch_reservation_write_failed",
                       job_id=job_id, principal_id=principal_id, error=str(e))
        return error_response("failed to reserve batch budget")

    # --- 10. Reservation-inclusive quota check (R4.1) ---------------------
    try:
        quota_result = check_quota(principal_id, policy)
    except Exception as e:
        log_structured("error", "batch_quota_check_failed",
                       job_id=job_id, principal_id=principal_id, error=str(e))
        _batch_delete_reservation(principal_id, job_id)
        return deny_response("quota check failed")

    resv_inclusive_total = quota_result["usage"]["cost_krw"]
    effective_limit = quota_result["limit"]["cost_krw"]

    if not quota_result["allowed"]:
        # Hard_Block (R4.2): delete the reservation, write a DENY ledger that
        # records the reservation-inclusive total (R11.3), and return 429.
        _batch_delete_reservation(principal_id, job_id)
        try:
            _batch_write_ledger(
                "BATCH_DENIED_HARD_BLOCK", request_id, job_id, principal_id,
                model_id, "DENY",
                denial_reason="monthly cost quota exceeded (reservation-inclusive)",
                reservation_inclusive_total_krw=Decimal(str(resv_inclusive_total)))
        except Exception as e:
            log_structured("error", "batch_denied_ledger_failed",
                           job_id=job_id, error=str(e))
        return _response(429, {
            "decision": "DENY",
            "denial_reason": "monthly cost quota exceeded",
            "reservation_inclusive_total_krw": resv_inclusive_total,
            "limit_krw": effective_limit,
        })

    # --- 11. Reservation-time 90% warning (Task 3.3) — best-effort --------
    try:
        _batch_maybe_send_warning(
            principal_id, policy,
            Decimal(str(resv_inclusive_total)),
            Decimal(str(effective_limit)))
    except Exception as e:
        # Warning is never allowed to block an admitted submission (R9 is a
        # notification, not a gate). Task 3.3 supplies the implementation.
        log_structured("warning", "batch_warning_eval_failed",
                       job_id=job_id, error=str(e))

    # --- 12. CreateModelInvocationJob (R1.2); on failure delete resv (R4.4) -
    batch_bucket = os.environ.get("BATCH_BUCKET", "")
    service_role_arn = os.environ.get("BATCH_SERVICE_ROLE_ARN", "")
    output_uri = f"s3://{batch_bucket}/output/{job_id}/"
    try:
        client = _get_batch_bedrock_client()
        create_resp = client.create_model_invocation_job(
            jobName=job_id,
            modelId=model_id,
            roleArn=service_role_arn,
            inputDataConfig={
                "s3InputDataConfig": {"s3Uri": input_file_ref},
            },
            outputDataConfig={
                "s3OutputDataConfig": {"s3Uri": output_uri},
            },
        )
        bedrock_job_arn = create_resp.get("jobArn", "")
    except Exception as e:
        log_structured("error", "batch_create_job_failed",
                       job_id=job_id, principal_id=principal_id, error=str(e))
        _batch_delete_reservation(principal_id, job_id)
        return error_response("failed to create batch inference job")

    # --- 13. Persist Job_State + ACCEPTED ledger (R1.1, R1.4, R11.1) ------
    try:
        _batch_write_job_record(
            job_id, request_id, principal_id, model_id, reservation_cost,
            input_file_ref, record_count, bedrock_job_arn)
    except Exception as e:
        log_structured("error", "batch_job_record_write_failed",
                       job_id=job_id, principal_id=principal_id, error=str(e))
        # The job has been created in Bedrock; the Reconciler (Task 5) settles
        # via GetModelInvocationJob even without a job record, so do NOT delete
        # the reservation here — keep the upper-bound hold until settlement.
        return error_response("failed to persist batch job record")

    try:
        _batch_write_ledger(
            "BATCH_ACCEPTED", request_id, job_id, principal_id, model_id,
            "ALLOW", reserved_cost_krw=reservation_cost)
    except Exception as e:
        log_structured("error", "batch_accepted_ledger_failed",
                       job_id=job_id, error=str(e))

    # --- 14. 202 Accepted -------------------------------------------------
    return _response(202, {
        "job_id": job_id,
        "status": "ACCEPTED",
        "model_id": model_id,
        "record_count": record_count,
        "reserved_cost_krw": float(reservation_cost),
        "bedrock_job_arn": bedrock_job_arn,
    })


# ---------------------------------------------------------------------------
# Batch_Route — reservation-time 90% warning (Task 3.3; design §3.5; R9).
# STRICTLY ADDITIVE — appended at the bottom of the module; no existing line is
# modified. This is the ONLY warning addition for batch: it fires the 90%
# Warning_Band at RESERVATION time using the reservation-INCLUSIVE basis, so the
# notification is not delayed by the hours a batch job runs. It DELEGATES to the
# existing _check_and_send_warning_email (which already owns the 90% threshold,
# the warning_90pct_sent_for_limit dedup, the 100% exhaustion path, and the
# direct_access_exception skip) — thresholds are NOT reimplemented here. The
# worker's post-settlement warning path (which EXCLUDES __reserved__ rows) is
# left untouched (R9.3).
# ---------------------------------------------------------------------------

def _batch_maybe_send_warning(principal_id, policy, resv_inclusive_total_krw,
                              effective_limit):
    """Reservation-time 90% Warning_Band evaluation for the batch route (R9).

    The Hard_Block and this warning share the SAME basis: the reservation-
    INCLUSIVE monthly total (settled rows + ALL ``__reserved__`` rows for the
    current KST month). ``check_quota`` already sums every row under the
    partition (reserved included), so the caller's ``resv_inclusive_total_krw``
    — taken from ``check_quota``'s ``usage.cost_krw`` — IS reservation-inclusive
    and is accepted as-is here; no separate recomputation is performed (R9.1).

    Behaviour:
      * Delegates to the existing ``_check_and_send_warning_email`` with
        ``usage_krw = float(resv_inclusive_total_krw)`` and
        ``effective_limit = int(effective_limit)``. That function owns the 90%
        threshold + ``warning_90pct_sent_for_limit`` dedup, the 100% exhaustion
        email, and the ``direct_access_exception`` skip (R9.1, R9.2). Thresholds
        are NOT reimplemented here — only the usage basis differs from the
        worker's exclusive post-settlement total (R9.3).
      * Best-effort: any failure is swallowed and logged structured so a warning
        problem can never block an already-admitted batch submission. The caller
        (``handle_batch_submit``) also wraps this in try/except, but this stays
        defensive so the contract holds regardless of call site.

    Args:
        principal_id: Principal whose monthly usage is being evaluated.
        policy: The principal policy dict (carries dedup flags + notification
            email + direct_access_exception), forwarded verbatim.
        resv_inclusive_total_krw: Reservation-inclusive monthly total, a Decimal
            (handle_batch_submit passes Decimal); converted to float for the
            existing email fn signature.
        effective_limit: The active Effective_Limit in KRW; coerced to int.
    """
    try:
        _check_and_send_warning_email(
            principal_id, policy,
            usage_krw=float(resv_inclusive_total_krw),
            effective_limit=int(effective_limit))
    except Exception as e:
        # A warning-notification failure must never propagate to the caller or
        # affect an admitted submission (R9 is a notification, not a gate).
        log_structured("warning", "batch_maybe_send_warning_failed",
                       principal_id=principal_id, error=str(e))


# ---------------------------------------------------------------------------
# Batch_Route — owner-scoped status poll (Task 4.1; design §3.3; R2.1–R2.4).
# STRICTLY ADDITIVE — appended at the bottom of the module; no existing line is
# modified. This is a NEW handler: it deliberately does NOT reuse or alter
# handle_converse_job_status, because the ownership-disclosure contract differs.
#
# The converse status handler returns 403 for a cross-principal job — which
# reveals that the job_id EXISTS. The batch requirement (R2.3) forbids that
# disclosure: a job owned by a different principal MUST be indistinguishable
# from an unknown job_id. Both cases therefore return the SAME 404 response,
# built from a single shared body constant so the status code AND the body bytes
# are identical (Property 7, Task 4.2). A job_id that resolves to a NON-batch
# job (e.g. an async /converse-jobs item) is likewise collapsed to the same 404
# so the /batch route never leaks or serves another route's jobs.
#
# This handler NEVER calls CreateModelInvocationJob (R2.4): a non-terminal job
# simply returns its last known status straight from the Job_State item.
# ---------------------------------------------------------------------------

# Single source of truth for the not-found body. handle_batch_status returns
# _response(404, _BATCH_NOT_FOUND_BODY) for BOTH the unknown-job_id case and the
# cross-principal / non-batch case; because _response is deterministic, both
# produce byte-identical output (R2.2, R2.3 — no existence disclosure).
_BATCH_NOT_FOUND_BODY = {"error": "job not found"}


def _batch_not_found_response() -> dict:
    """Return the canonical 404 used for unknown, cross-principal, AND non-batch
    job_ids so they are byte-indistinguishable (R2.2, R2.3 — Property 7)."""
    return _response(404, _BATCH_NOT_FOUND_BODY)


def handle_batch_status(principal_id: str, path: str) -> dict:
    """GET /batch/{job_id} — owner-scoped batch job status (R2.1–R2.4).

    Behaviour:
      * Parses ``job_id`` from the path ``/batch/{job_id}``.
      * ``GetItem`` Job_State by ``job_id``.
      * Owned by this principal AND a batch item → 200 with ``status`` and, when
        available, ``settled_cost_krw`` + ``output_file_ref`` (R2.1), plus the
        job metadata (model_id, record_count, reserved_cost_krw, input/output
        tokens, created_at, completed_at), Decimals cleaned to int/float.
      * Unknown ``job_id`` → 404 (R2.2).
      * Job owned by a DIFFERENT principal → 404 with a body byte-identical to
        the unknown-job_id response (R2.3 — no existence disclosure). This is the
        critical difference from handle_converse_job_status, which returns 403.
      * A ``job_id`` resolving to a NON-batch job (source_path != gateway-batch)
        is treated as not-found so /batch never serves other routes' jobs.

    NEVER calls CreateModelInvocationJob; a non-terminal job returns its last
    known status without any Bedrock create call (R2.4).
    """
    # --- Parse job_id from /batch/{job_id} --------------------------------
    parts = path.rstrip("/").split("/")
    job_id = parts[-1] if parts else ""
    if not job_id or job_id == "batch":
        # No job_id segment present — nothing can be found.
        return _batch_not_found_response()

    if not TABLE_JOB_STATE:
        return error_response("job state table not configured")

    job_table = dynamodb.Table(TABLE_JOB_STATE)
    try:
        resp = job_table.get_item(Key={"job_id": job_id})
        item = resp.get("Item")
    except Exception as e:
        log_structured("error", "batch_status_read_failed",
                       job_id=job_id, principal_id=principal_id, error=str(e))
        return error_response(f"failed to read job: {str(e)}")

    # Unknown job_id (R2.2), a job owned by a different principal (R2.3), or a
    # job_id that resolves to a non-batch job all collapse to the SAME 404 so
    # they are byte-indistinguishable (Property 7). The ownership and batch
    # checks are deliberately folded into the single not-found return.
    if not item:
        return _batch_not_found_response()
    if item.get("principal_id") != principal_id:
        return _batch_not_found_response()
    if item.get("source_path") != _BATCH_SOURCE_PATH:
        return _batch_not_found_response()

    # --- Owned batch job → 200 (R2.1) -------------------------------------
    def clean(v):
        if isinstance(v, Decimal):
            return int(v) if v == int(v) else float(v)
        return v

    return _response(200, {
        "job_id": job_id,
        "status": item.get("status", ""),
        "model_id": item.get("model_id", ""),
        "record_count": clean(item.get("record_count", 0)),
        "reserved_cost_krw": clean(item.get("reserved_cost_krw", 0)),
        "settled_cost_krw": clean(item.get("settled_cost_krw", 0)),
        "input_tokens": clean(item.get("input_tokens", 0)),
        "output_tokens": clean(item.get("output_tokens", 0)),
        "output_file_ref": item.get("output_file_ref", ""),
        "created_at": item.get("created_at", ""),
        "completed_at": item.get("completed_at", ""),
    })
