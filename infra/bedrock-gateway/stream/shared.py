"""
Bedrock Access Control Gateway — Shared Functions for Stream Handler.

Copied from handler.py for independent deployment as a separate Lambda package.
Contains: principal normalization, policy lookup, model access control,
KRW cost-based monthly quota enforcement, model pricing lookup,
cost estimation, monthly usage update, request ledger, warning emails,
and structured logging.

Does NOT contain: extract_identity (API Gateway format), lambda_handler,
invoke_bedrock (sync Converse), idempotency functions, async job functions,
response helpers, discovery/approval handlers.
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

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENV = os.environ.get("ENVIRONMENT", "dev")
TABLE_PRINCIPAL_POLICY = os.environ.get("TABLE_PRINCIPAL_POLICY", "")
TABLE_MONTHLY_USAGE = os.environ.get("TABLE_MONTHLY_USAGE", "")
TABLE_MODEL_PRICING = os.environ.get("TABLE_MODEL_PRICING", "")
TABLE_TEMPORARY_QUOTA_BOOST = os.environ.get("TABLE_TEMPORARY_QUOTA_BOOST", "")
TABLE_REQUEST_LEDGER = os.environ.get("TABLE_REQUEST_LEDGER", "")
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
ses_client = boto3.client("ses", region_name=SES_REGION)

# ---------------------------------------------------------------------------
# Gateway Config — operator-configurable controls (DynamoDB-backed)
# ---------------------------------------------------------------------------
_gateway_config_cache: dict = {}
_gateway_config_ts: float = 0
GATEWAY_CONFIG_CACHE_TTL_S = 30  # refresh every 30s

GATEWAY_CONFIG_KEY = "__gateway_config__"


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
# Principal Normalization (Candidate F)
# ---------------------------------------------------------------------------

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
# Policy Lookup
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Model Access Check
# ---------------------------------------------------------------------------

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
# Model Pricing Lookup (fail-closed if missing)
# ---------------------------------------------------------------------------

def _load_model_pricing_cache() -> dict:
    """Scan ModelPricing table and return {model_id: {input_price_per_1k, output_price_per_1k}}.

    Called once at cold start. Returns empty dict on error (fail-closed).

    Pending-pricing safety (bedrock-model-auto-sync, Property 9):
    Rows whose `pricing_status` is `"pending"` or whose `input_price_per_1k`
    / `output_price_per_1k` is missing are loaded with explicit `None` price
    values. Downstream `estimate_cost_krw` returns `Decimal(0)` and emits the
    `BedrockAutoSync/PendingPricingCostCharged` metric so a brand-new model
    is callable on the day AWS publishes it; the daily auto-sync backfill
    overwrites the zero-cost rows once Tier_1 / Tier_2 prices land.
    """
    if not TABLE_MODEL_PRICING:
        return {}
    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        resp = table.scan()
        cache = {}
        for item in resp.get("Items", []):
            mid = item.get("model_id", "")
            if not mid:
                continue
            input_raw = item.get("input_price_per_1k")
            output_raw = item.get("output_price_per_1k")
            pending = (
                input_raw is None
                or output_raw is None
                or str(item.get("pricing_status", "")).lower() == "pending"
                or str(item.get("pricing_source", "")).lower() == "pending"
            )
            cache[mid] = {
                "model_id": mid,
                "input_price_per_1k": None if pending else Decimal(str(input_raw)),
                "output_price_per_1k": None if pending else Decimal(str(output_raw)),
                "exchange_rate_krw_per_usd": item.get("exchange_rate_krw_per_usd"),
                "pricing_source": item.get("pricing_source"),
                "pricing_status": item.get("pricing_status"),
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
# Cost Estimation
# ---------------------------------------------------------------------------

def estimate_cost_krw(input_tokens: int, output_tokens: int, pricing: dict) -> Decimal:
    """Calculate estimated KRW cost for a request.

    Formula (Q1 decision): (input × input_price_per_1k / 1000) + (output × output_price_per_1k / 1000)
    Returns Decimal for DynamoDB compatibility.

    Pending-pricing safety (bedrock-model-auto-sync, Property 9):
    When either ``input_price_per_1k`` or ``output_price_per_1k`` is None
    the model is in Tier_4 Pending — the function returns ``Decimal(0)``
    and emits the ``BedrockAutoSync/PendingPricingCostCharged`` metric.
    The auto-sync backfill recomputes the real cost when Tier_1 / Tier_2
    prices arrive in DynamoDB.
    """
    input_price = pricing.get("input_price_per_1k") if isinstance(pricing, dict) else None
    output_price = pricing.get("output_price_per_1k") if isinstance(pricing, dict) else None
    if input_price is None or output_price is None:
        try:
            import boto3 as _boto3  # local import keeps cold-start lean
            cw = _boto3.client(
                "cloudwatch",
                region_name=os.environ.get("AWS_REGION", "us-west-2"),
            )
            mid = pricing.get("model_id", "") if isinstance(pricing, dict) else ""
            cw.put_metric_data(
                Namespace="BedrockAutoSync",
                MetricData=[{
                    "MetricName": "PendingPricingCostCharged",
                    "Value": 0,
                    "Unit": "Count",
                    "Dimensions": [{"Name": "model_id", "Value": str(mid) or "unknown"}],
                }],
            )
        except Exception:
            pass
        return Decimal(0)

    input_cost = Decimal(str(input_tokens)) * input_price / Decimal("1000")
    output_cost = Decimal(str(output_tokens)) * output_price / Decimal("1000")
    return input_cost + output_cost


# ---------------------------------------------------------------------------
# Gateway Config
# ---------------------------------------------------------------------------

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
# Quota Check — KRW Monthly
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


# ---------------------------------------------------------------------------
# Monthly Usage Update
# ---------------------------------------------------------------------------

def update_monthly_usage(
    principal_id: str, model_id: str,
    cost_krw: Decimal, input_tokens: int, output_tokens: int,
    pricing: dict | None = None,
) -> None:
    """Atomically ADD cost_krw, input_tokens, output_tokens to MonthlyUsage.

    PK: <principal_id>#YYYY-MM (KST). SK: model_id.
    TTL: ~35 days. Q6 decision: keep token counts alongside cost_krw.

    Pending-pricing tag (bedrock-model-auto-sync, Req 8.3 / Task 11.2):
    When ``cost_krw`` is ``Decimal(0)`` and ``pricing`` indicates a
    Pending row (either price field is ``None`` or ``pricing_source ==
    "pending"``), the persisted row is tagged with
    ``pricing_source_at_charge = "pending"`` so the daily auto-sync
    backfill can recompute it once Tier_1 / Tier_2 prices land.
    """
    month = current_month_kst()
    pk = f"{principal_id}#{month}"
    ttl_val = end_of_month_ttl_kst()

    pending_charge = (
        cost_krw == Decimal(0)
        and isinstance(pricing, dict)
        and (
            pricing.get("input_price_per_1k") is None
            or pricing.get("output_price_per_1k") is None
            or str(pricing.get("pricing_source", "")).lower() == "pending"
        )
    )

    update_expression = "ADD cost_krw :c, input_tokens :i, output_tokens :o SET #t = :ttl"
    expr_values = {
        ":c": cost_krw,
        ":i": input_tokens,
        ":o": output_tokens,
        ":ttl": ttl_val,
    }
    if pending_charge:
        update_expression += ", pricing_source_at_charge = :psac"
        expr_values[":psac"] = "pending"

    table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    table.update_item(
        Key={"principal_id_month": pk, "model_id": model_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues=expr_values,
    )


# ---------------------------------------------------------------------------
# Request Ledger
# ---------------------------------------------------------------------------

def write_request_ledger(entry: dict) -> None:
    """Append immutable audit entry to RequestLedger.

    PutItem only — no UpdateItem/DeleteItem. Locked decision #9.
    Req 8.1-8.3: immutable audit, request_id PK, includes decision/tokens/duration.
    Raises on failure (caller must deny + alarm). Req 12.4.
    """
    table = dynamodb.Table(TABLE_REQUEST_LEDGER)
    table.put_item(Item=entry)


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
# Warning & Exhaustion Emails
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
