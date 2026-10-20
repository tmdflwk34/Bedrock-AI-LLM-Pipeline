"""
Bedrock Gateway — Usage & Policy Read Routes (Phase 4 Scope A + Exception User Monitoring).

Admin-plane read-only endpoints for operator monitoring:
  - GET /api/gateway/pricing       — model pricing reference
  - GET /api/gateway/users         — managed user overview with monthly KRW totals
  - GET /api/gateway/users/<pid>/usage  — per-model monthly breakdown
  - GET /api/gateway/users/<pid>/policy — policy detail with boosts and band
  - GET /api/gateway/exception-usage    — direct-use exception user usage from CloudWatch Logs

All endpoints require admin JWT auth via @admin_required.
Req 11 (Admin Portal), Req 4 (Quota), Req 5 (Approval Ladder).
"""

import os
import hashlib
import time
import logging
from functools import wraps
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from urllib.parse import unquote

import jwt
import boto3
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

gateway_usage_bp = Blueprint('gateway_usage', __name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
ENVIRONMENT = os.environ.get('BEDROCK_GW_ENV', 'dev')
TABLE_PREFIX = f'bedrock-gw-{ENVIRONMENT}-{AWS_REGION}'

TABLE_PRINCIPAL_POLICY = f'{TABLE_PREFIX}-principal-policy'
TABLE_MONTHLY_USAGE = f'{TABLE_PREFIX}-monthly-usage'
TABLE_MODEL_PRICING = f'{TABLE_PREFIX}-model-pricing'
TABLE_TEMPORARY_QUOTA_BOOST = f'{TABLE_PREFIX}-temporary-quota-boost'
TABLE_APPROVAL_PENDING_LOCK = f'{TABLE_PREFIX}-approval-pending-lock'

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if (
    not JWT_SECRET_KEY
    or not JWT_SECRET_KEY.strip()
    or hashlib.sha256(JWT_SECRET_KEY.encode("utf-8")).hexdigest()
    == "cd10b8a868cf4a650ae2e5022ce51ba95e01161e2a13f4140d3263f83a8d74bb"
):
    raise RuntimeError("JWT_SECRET_KEY must be set to a non-empty, unexposed secret")
HARD_CAP_KRW = 2000000
BOOST_INCREMENT_KRW = 500000

# KST timezone (Q3/Q4: KST for all monthly boundaries)
KST = timezone(timedelta(hours=9))

# Username → email mapping (authoritative source for notification_email)
USER_EMAIL_MAP = {
    'admin': '<EMAIL>',
    'user20': '<EMAIL>',
    'user05': '<EMAIL>',
    'user12': '<EMAIL>',
    'user13': '<EMAIL>',
    'user22': '<EMAIL>',
    'user11': '<EMAIL>',
    'user08': '<EMAIL>',
    'user19': '<EMAIL>',
    'user10': '<EMAIL>',
    'user17': '<EMAIL>',
    'user21': '<EMAIL>',
    'user15': '<EMAIL>',
    'user01': '<EMAIL>',
    'user09': '<EMAIL>',
    'user07': '<EMAIL>',
    'user14': '<EMAIL>',
    'user02': '<EMAIL>',
    'user18': '<EMAIL>',
    'user16': '<EMAIL>',
    'user04': '<EMAIL>',
}

ACCOUNT_ID = '<ACCOUNT_ID>'

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
logs_client = boto3.client('logs', region_name=AWS_REGION)

CW_LOG_GROUP = '/aws/bedrock/modelinvocations'
# Cache for exception user usage (avoid hammering CloudWatch Logs Insights on every poll)
_exception_usage_cache = {'data': None, 'ts': 0}
EXCEPTION_CACHE_TTL_S = 30  # 30s cache — balances near-real-time with CW Logs query cost


# ---------------------------------------------------------------------------
# Auth decorator (M1) — reuses JWT pattern from auth.py
# ---------------------------------------------------------------------------

def admin_required(f):
    """Reject requests without a valid admin JWT. 401 for missing/invalid, 403 for non-admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'missing or malformed Authorization header'}), 401
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'invalid token'}), 401
        if payload.get('role') != 'admin':
            return jsonify({'error': 'admin role required'}), 403
        request.admin_user = payload
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decimal_to_number(val):
    """Convert DynamoDB Decimal to int or float for JSON serialization."""
    if isinstance(val, Decimal):
        if val == int(val):
            return int(val)
        return float(val)
    return val


def _clean_item(item: dict) -> dict:
    """Recursively convert Decimal values in a DynamoDB item."""
    cleaned = {}
    for k, v in item.items():
        if isinstance(v, Decimal):
            cleaned[k] = _decimal_to_number(v)
        elif isinstance(v, dict):
            cleaned[k] = _clean_item(v)
        elif isinstance(v, list):
            cleaned[k] = [_decimal_to_number(i) if isinstance(i, Decimal) else i for i in v]
        else:
            cleaned[k] = v
    return cleaned


def _is_exception_user(principal_id: str) -> bool:
    """Check if a principal is a direct-access exception user via DynamoDB attribute."""
    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        resp = policy_table.get_item(Key={'principal_id': principal_id})
        item = resp.get('Item')
        if not item:
            return False
        return bool(item.get('direct_access_exception', False))
    except Exception:
        return False


def _get_exception_users_from_db() -> dict:
    """Scan principal_policy for users with direct_access_exception=true.

    Returns dict keyed by principal_id with metadata for API responses.
    """
    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        resp = policy_table.scan()
    except Exception as e:
        logger.error(f'Failed to scan principal_policy for exception users: {e}')
        return {}

    result = {}
    for item in resp.get('Items', []):
        pid = item.get('principal_id', '')
        if pid == GATEWAY_CONFIG_KEY:
            continue
        if not item.get('direct_access_exception', False):
            continue
        result[pid] = {
            'principal_id': pid,
            'status': 'direct-use exception',
            'gateway_managed': False,
            'note': 'Usage tracked via /aws/bedrock/modelinvocations only',
        }
    return result


def _current_kst_month() -> str:
    """Return current month as YYYY-MM in KST."""
    return datetime.now(KST).strftime('%Y-%m')


def _get_effective_limit_and_band(principal_id: str):
    """Return (effective_limit_krw, approval_band, active_boosts_list).

    Replicates the logic from gateway_approval.py._get_effective_limit()
    but also returns band count and boost details for the policy endpoint.
    """
    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    resp = policy_table.get_item(Key={'principal_id': principal_id})
    policy = resp.get('Item')
    if not policy:
        return 0, 0, []

    base_limit = int(policy.get('monthly_cost_limit_krw', 500000))
    max_limit = int(policy.get('max_monthly_cost_limit_krw', HARD_CAP_KRW))

    boost_table = dynamodb.Table(TABLE_TEMPORARY_QUOTA_BOOST)
    boost_resp = boost_table.query(
        KeyConditionExpression='principal_id = :pid',
        ExpressionAttributeValues={':pid': principal_id},
    )

    now_epoch = int(time.time())
    active_boosts = []
    boost_total = 0
    for item in boost_resp.get('Items', []):
        ttl_val = int(item.get('ttl', 0))
        if ttl_val > now_epoch:
            boost_total += int(item.get('extra_cost_krw', 0))
            active_boosts.append(_clean_item(item))

    effective = min(base_limit + boost_total, max_limit)
    band = len(active_boosts)
    return effective, band, active_boosts


def _has_pending_approval(principal_id: str) -> bool:
    """Check if principal has an active approval pending lock."""
    lock_table = dynamodb.Table(TABLE_APPROVAL_PENDING_LOCK)
    try:
        resp = lock_table.get_item(Key={'principal_id': principal_id})
        item = resp.get('Item')
        if not item:
            return False
        ttl_val = int(item.get('ttl', 0))
        return ttl_val > int(time.time())
    except Exception:
        return False


def _get_monthly_usage(principal_id: str, month: str):
    """Query monthly_usage for a principal+month. Returns list of per-model items."""
    table = dynamodb.Table(TABLE_MONTHLY_USAGE)
    pk = f'{principal_id}#{month}'
    resp = table.query(
        KeyConditionExpression='principal_id_month = :pk',
        ExpressionAttributeValues={':pk': pk},
    )
    return resp.get('Items', [])


# ---------------------------------------------------------------------------
# Gateway Config — operator-configurable controls
# ---------------------------------------------------------------------------
# Stored as a reserved item in principal-policy table:
#   principal_id = "__gateway_config__"
# ---------------------------------------------------------------------------

GATEWAY_CONFIG_KEY = '__gateway_config__'


@gateway_usage_bp.route('/api/gateway/config', methods=['GET'])
@admin_required
def get_gateway_config():
    """Return operator-configurable gateway settings."""
    table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        resp = table.get_item(Key={'principal_id': GATEWAY_CONFIG_KEY})
        item = resp.get('Item')
        if not item:
            # Return defaults
            return jsonify({
                'quota_enforcement_enabled': True,
            }), 200
        return jsonify({
            'quota_enforcement_enabled': bool(item.get('quota_enforcement_enabled', True)),
        }), 200
    except Exception as e:
        logger.error(f'Failed to read gateway config: {e}')
        return jsonify({'error': 'failed to read gateway config'}), 500


@gateway_usage_bp.route('/api/gateway/config', methods=['PUT'])
@admin_required
def update_gateway_config():
    """Update operator-configurable gateway settings.

    Body: {"quota_enforcement_enabled": true|false}
    """
    body = request.get_json(silent=True) or {}
    quota_enforcement = body.get('quota_enforcement_enabled')
    if quota_enforcement is None:
        return jsonify({'error': 'quota_enforcement_enabled is required'}), 400
    if not isinstance(quota_enforcement, bool):
        return jsonify({'error': 'quota_enforcement_enabled must be a boolean'}), 400

    table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        table.put_item(Item={
            'principal_id': GATEWAY_CONFIG_KEY,
            'quota_enforcement_enabled': quota_enforcement,
            'updated_at': datetime.now(KST).isoformat(),
            'updated_by': request.admin_user.get('user_id', 'unknown'),
        })
        logger.info(f'Gateway config updated: quota_enforcement_enabled={quota_enforcement} by {request.admin_user.get("user_id")}')
        return jsonify({
            'quota_enforcement_enabled': quota_enforcement,
            'message': 'gateway config updated',
        }), 200
    except Exception as e:
        logger.error(f'Failed to update gateway config: {e}')
        return jsonify({'error': 'failed to update gateway config'}), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# --- M8: GET /api/gateway/pricing -------------------------------------------

@gateway_usage_bp.route('/api/gateway/pricing', methods=['GET'])
@admin_required
def get_pricing():
    """Return model pricing reference data from model_pricing table."""
    table = dynamodb.Table(TABLE_MODEL_PRICING)
    try:
        resp = table.scan()
        models = [_clean_item(item) for item in resp.get('Items', [])]
        return jsonify({'models': models}), 200
    except Exception as e:
        logger.error(f'Failed to scan model_pricing: {e}')
        return jsonify({'error': 'failed to fetch pricing data'}), 500


# --- M4: GET /api/gateway/users ---------------------------------------------

@gateway_usage_bp.route('/api/gateway/users', methods=['GET'])
@admin_required
def list_users():
    """Return gateway-managed user overview with monthly KRW totals.

    Query params:
      month — YYYY-MM, default current KST month
    """
    month = request.args.get('month', _current_kst_month())

    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        policy_resp = policy_table.scan()
    except Exception as e:
        logger.error(f'Failed to scan principal_policy: {e}')
        return jsonify({'error': 'failed to fetch user policies'}), 500

    managed_users = []
    exception_users_list = []
    for policy in policy_resp.get('Items', []):
        pid = policy.get('principal_id', '')
        if pid == GATEWAY_CONFIG_KEY:
            continue

        # Check if this is a direct-access exception user
        if policy.get('direct_access_exception', False):
            exception_users_list.append({
                'principal_id': pid,
                'status': 'direct-use exception',
                'gateway_managed': False,
                'note': 'Usage tracked via /aws/bedrock/modelinvocations only',
            })
            continue

        # Monthly usage aggregation
        usage_items = _get_monthly_usage(pid, month)
        total_cost = sum(float(item.get('cost_krw', 0)) for item in usage_items)
        total_input = sum(int(item.get('input_tokens', 0)) for item in usage_items)
        total_output = sum(int(item.get('output_tokens', 0)) for item in usage_items)

        effective_limit, band, _ = _get_effective_limit_and_band(pid)
        pending = _has_pending_approval(pid)

        allowed_models = policy.get('allowed_models', [])
        if isinstance(allowed_models, set):
            allowed_models = list(allowed_models)

        managed_users.append({
            'principal_id': pid,
            'monthly_cost_limit_krw': int(policy.get('monthly_cost_limit_krw', 500000)),
            'max_monthly_cost_limit_krw': int(policy.get('max_monthly_cost_limit_krw', HARD_CAP_KRW)),
            'effective_limit_krw': effective_limit,
            'approval_band': band,
            'has_pending_approval': pending,
            'current_month_cost_krw': round(total_cost, 4),
            'current_month_input_tokens': total_input,
            'current_month_output_tokens': total_output,
            'allowed_models': allowed_models,
        })

    return jsonify({
        'month': month,
        'managed_users': managed_users,
        'exception_users': exception_users_list,
    }), 200


# --- M5: GET /api/gateway/users/<pid>/usage ---------------------------------

@gateway_usage_bp.route('/api/gateway/users/<path:principal_id>/usage', methods=['GET'])
@admin_required
def get_user_usage(principal_id):
    """Return per-model monthly usage breakdown for a managed user.

    Query params:
      month — YYYY-MM, default current KST month
    """
    principal_id = unquote(principal_id)

    if _is_exception_user(principal_id):
        return jsonify({'error': 'exception user — no gateway usage data'}), 404

    # Verify user exists in principal_policy
    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    policy_resp = policy_table.get_item(Key={'principal_id': principal_id})
    if not policy_resp.get('Item'):
        return jsonify({'error': 'principal not found'}), 404

    month = request.args.get('month', _current_kst_month())
    usage_items = _get_monthly_usage(principal_id, month)

    effective_limit, _, _ = _get_effective_limit_and_band(principal_id)

    # Join with model_pricing for rates
    pricing_table = dynamodb.Table(TABLE_MODEL_PRICING)
    pricing_cache = {}

    models = []
    total_cost = 0.0
    total_input = 0
    total_output = 0

    for item in usage_items:
        model_id = item.get('model_id', '')
        cost = float(item.get('cost_krw', 0))
        inp = int(item.get('input_tokens', 0))
        out = int(item.get('output_tokens', 0))

        total_cost += cost
        total_input += inp
        total_output += out

        # Fetch pricing if not cached
        if model_id not in pricing_cache:
            try:
                pr = pricing_table.get_item(Key={'model_id': model_id})
                pricing_cache[model_id] = pr.get('Item', {})
            except Exception:
                pricing_cache[model_id] = {}

        pricing = pricing_cache[model_id]
        models.append({
            'model_id': model_id,
            'cost_krw': round(cost, 4),
            'input_tokens': inp,
            'output_tokens': out,
            'price_per_1k_input_krw': float(pricing.get('input_price_per_1k', 0)),
            'price_per_1k_output_krw': float(pricing.get('output_price_per_1k', 0)),
        })

    return jsonify({
        'principal_id': principal_id,
        'month': month,
        'effective_limit_krw': effective_limit,
        'total_cost_krw': round(total_cost, 4),
        'total_input_tokens': total_input,
        'total_output_tokens': total_output,
        'models': models,
    }), 200


# --- M7: GET /api/gateway/users/<pid>/policy --------------------------------

@gateway_usage_bp.route('/api/gateway/users/<path:principal_id>/policy', methods=['GET'])
@admin_required
def get_user_policy(principal_id):
    """Return policy detail for a managed user: limits, boosts, pending state."""
    principal_id = unquote(principal_id)

    if _is_exception_user(principal_id):
        return jsonify({'error': 'exception user — no gateway policy'}), 404

    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    policy_resp = policy_table.get_item(Key={'principal_id': principal_id})
    policy = policy_resp.get('Item')
    if not policy:
        return jsonify({'error': 'principal not found'}), 404

    effective_limit, band, active_boosts = _get_effective_limit_and_band(principal_id)
    pending = _has_pending_approval(principal_id)

    allowed_models = policy.get('allowed_models', [])
    if isinstance(allowed_models, set):
        allowed_models = list(allowed_models)

    return jsonify({
        'principal_id': principal_id,
        'monthly_cost_limit_krw': int(policy.get('monthly_cost_limit_krw', 500000)),
        'max_monthly_cost_limit_krw': int(policy.get('max_monthly_cost_limit_krw', HARD_CAP_KRW)),
        'allowed_models': allowed_models,
        'effective_limit_krw': effective_limit,
        'approval_band': band,
        'active_boosts': active_boosts,
        'has_pending_approval': pending,
    }), 200


# ---------------------------------------------------------------------------
# Daily Breakdown (KST date grouping from RequestLedger)
# ---------------------------------------------------------------------------

TABLE_REQUEST_LEDGER = f'{TABLE_PREFIX}-request-ledger'

@gateway_usage_bp.route('/api/gateway/users/<path:principal_id>/daily', methods=['GET'])
@admin_required
def get_user_daily(principal_id):
    """Return daily KST breakdown from request ledger.

    Query params:
      month — YYYY-MM, default current KST month

    Returns per-day, per-model breakdown with region, tokens, cost.
    Day boundary: KST 00:00:00.
    """
    principal_id = unquote(principal_id)
    month = request.args.get('month', _current_kst_month())

    # Scan ledger for this principal + month
    ledger_table = dynamodb.Table(TABLE_REQUEST_LEDGER)

    # Ledger has request_id as PK. We need to scan with filter.
    # For production scale, a GSI on principal_id would be better.
    # MVP: scan with filter (acceptable for current user count).
    items = []
    scan_kwargs = {
        'FilterExpression': 'principal_id = :pid AND begins_with(#ts, :month)',
        'ExpressionAttributeNames': {'#ts': 'timestamp'},
        'ExpressionAttributeValues': {
            ':pid': principal_id,
            ':month': month,
        },
    }
    while True:
        resp = ledger_table.scan(**scan_kwargs)
        items.extend(resp.get('Items', []))
        if 'LastEvaluatedKey' not in resp:
            break
        scan_kwargs['ExclusiveStartKey'] = resp['LastEvaluatedKey']

    # Group by KST date + model
    from collections import defaultdict
    daily = defaultdict(lambda: defaultdict(lambda: {
        'request_count': 0, 'input_tokens': 0, 'output_tokens': 0,
        'cache_read_tokens': 0, 'cache_write_tokens': 0, 'cost_krw': 0.0,
        'region': 'us-west-2',
    }))

    for item in items:
        if item.get('decision') != 'ALLOW':
            continue
        # Parse timestamp to KST date
        created = item.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            kst_date = (dt + timedelta(hours=9)).strftime('%Y-%m-%d')
        except Exception:
            continue

        model_id = item.get('model_id', 'unknown')
        region = item.get('region', 'us-west-2')
        d = daily[kst_date][model_id]
        d['request_count'] += 1
        d['input_tokens'] += int(item.get('input_tokens', 0))
        d['output_tokens'] += int(item.get('output_tokens', 0))
        d['cache_read_tokens'] += int(item.get('cache_read_tokens', 0))
        d['cache_write_tokens'] += int(item.get('cache_write_tokens', 0))
        d['cost_krw'] += float(item.get('estimated_cost_krw', 0))
        d['region'] = region

    # Format response
    days = []
    for date_str in sorted(daily.keys()):
        models = []
        day_total = 0.0
        for model_id, stats in sorted(daily[date_str].items()):
            stats['cost_krw'] = round(stats['cost_krw'], 4)
            day_total += stats['cost_krw']
            models.append({'model_id': model_id, **stats})
        days.append({
            'date': date_str,
            'total_cost_krw': round(day_total, 4),
            'models': models,
        })

    return jsonify({
        'principal_id': principal_id,
        'month': month,
        'days': days,
        'total_requests': sum(d['total_cost_krw'] for d in days),
    })


# ---------------------------------------------------------------------------
# Exception User Usage via CloudWatch Logs (direct Bedrock invocations)
# ---------------------------------------------------------------------------

def _extract_username_from_arn_filter(principal_id: str) -> str:
    """Extract the IAM role name suffix for CloudWatch Logs filter.
    e.g. '<ACCOUNT_ID>#BedrockUser-user05' -> 'BedrockUser-user05'
    """
    if '#' in principal_id:
        return principal_id.split('#', 1)[1]
    return principal_id


def _query_exception_user_usage(username_filter: str, start_epoch: int, end_epoch: int):
    """Run CloudWatch Logs Insights query for a specific user's Bedrock usage.
    Returns list of per-model aggregates or None on error.
    """
    query = f'''
stats sum(input.inputTokenCount) as total_input,
      sum(output.outputTokenCount) as total_output,
      count(*) as invocation_count,
      max(@timestamp) as last_activity
by modelId
| filter identity.arn like /{username_filter}/
'''
    try:
        resp = logs_client.start_query(
            logGroupName=CW_LOG_GROUP,
            startTime=start_epoch,
            endTime=end_epoch,
            queryString=query,
        )
        query_id = resp['queryId']

        # Poll for results (max ~20s)
        for _ in range(10):
            time.sleep(2)
            result = logs_client.get_query_results(queryId=query_id)
            if result['status'] in ('Complete', 'Failed', 'Cancelled'):
                break

        if result['status'] != 'Complete':
            logger.warning(f'CW Logs query did not complete: {result["status"]}')
            return None

        models = []
        for row_fields in result.get('results', []):
            row = {f['field']: f['value'] for f in row_fields}
            model_id = row.get('modelId', '')
            if not model_id:
                continue
            models.append({
                'model_id': model_id,
                'input_tokens': int(row.get('total_input', 0) or 0),
                'output_tokens': int(row.get('total_output', 0) or 0),
                'invocation_count': int(row.get('invocation_count', 0) or 0),
                'last_activity': row.get('last_activity', ''),
            })
        return models

    except Exception as e:
        logger.error(f'CloudWatch Logs query failed for {username_filter}: {e}')
        return None


def _get_exception_usage_cached():
    """Return cached exception user usage data, refreshing if stale."""
    now_epoch = int(time.time())
    if (_exception_usage_cache['data'] is not None
            and now_epoch - _exception_usage_cache['ts'] < EXCEPTION_CACHE_TTL_S):
        return _exception_usage_cache['data']

    now_kst = datetime.now(KST)
    month_start = now_kst.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_epoch = int(month_start.timestamp())
    end_epoch = int(now_kst.timestamp())

    # Load model pricing for cost estimation
    pricing_table = dynamodb.Table(TABLE_MODEL_PRICING)
    try:
        pricing_resp = pricing_table.scan()
        pricing_map = {}
        for item in pricing_resp.get('Items', []):
            mid = item.get('model_id', '')
            pricing_map[mid] = {
                'input_price_per_1k': float(item.get('input_price_per_1k', 0)),
                'output_price_per_1k': float(item.get('output_price_per_1k', 0)),
            }
    except Exception:
        pricing_map = {}

    result = {}
    exception_users = _get_exception_users_from_db()
    for pid, info in exception_users.items():
        username_filter = _extract_username_from_arn_filter(pid)
        models = _query_exception_user_usage(username_filter, start_epoch, end_epoch)

        if models is None:
            result[pid] = {
                'principal_id': pid,
                'data_source': 'cloudwatch_logs',
                'data_source_label': 'CloudWatch Logs (/aws/bedrock/modelinvocations)',
                'status': info.get('status', 'direct-use exception'),
                'note': info.get('note', ''),
                'error': 'CloudWatch Logs query failed',
                'models': [],
                'total_input_tokens': 0,
                'total_output_tokens': 0,
                'total_invocations': 0,
                'estimated_cost_krw': None,
                'last_activity': None,
            }
            continue

        total_input = sum(m['input_tokens'] for m in models)
        total_output = sum(m['output_tokens'] for m in models)
        total_invocations = sum(m['invocation_count'] for m in models)

        # Estimate cost using model_pricing where available
        total_cost = 0.0
        has_unpriced = False
        for m in models:
            pricing = pricing_map.get(m['model_id'])
            if pricing:
                cost = (m['input_tokens'] / 1000.0 * pricing['input_price_per_1k']
                        + m['output_tokens'] / 1000.0 * pricing['output_price_per_1k'])
                m['estimated_cost_krw'] = round(cost, 2)
                m['cost_source'] = 'model_pricing'
                total_cost += cost
            else:
                m['estimated_cost_krw'] = None
                m['cost_source'] = 'unavailable'
                has_unpriced = True

        # Find latest activity across all models
        last_activity = None
        for m in models:
            la = m.get('last_activity', '')
            if la and (last_activity is None or la > last_activity):
                last_activity = la

        result[pid] = {
            'principal_id': pid,
            'data_source': 'cloudwatch_logs',
            'data_source_label': 'CloudWatch Logs (/aws/bedrock/modelinvocations)',
            'status': info.get('status', 'direct-use exception'),
            'note': info.get('note', ''),
            'models': sorted(models, key=lambda x: x.get('input_tokens', 0), reverse=True),
            'total_input_tokens': total_input,
            'total_output_tokens': total_output,
            'total_invocations': total_invocations,
            'estimated_cost_krw': round(total_cost, 2) if not has_unpriced else None,
            'partial_cost_krw': round(total_cost, 2) if has_unpriced else None,
            'has_unpriced_models': has_unpriced,
            'last_activity': last_activity,
        }

    _exception_usage_cache['data'] = result
    _exception_usage_cache['ts'] = now_epoch
    return result


# --- GET /api/gateway/exception-usage ----------------------------------------

@gateway_usage_bp.route('/api/gateway/exception-usage', methods=['GET'])
@admin_required
def get_exception_usage():
    """Return usage data for direct-use exception users from CloudWatch Logs.

    Data source: /aws/bedrock/modelinvocations (NOT gateway DynamoDB).
    Cached for 30s to avoid excessive CloudWatch Logs Insights queries.
    """
    month = _current_kst_month()
    try:
        usage_data = _get_exception_usage_cached()
        return jsonify({
            'month': month,
            'data_source': 'cloudwatch_logs',
            'cache_ttl_seconds': EXCEPTION_CACHE_TTL_S,
            'exception_users': list(usage_data.values()),
        }), 200
    except Exception as e:
        logger.error(f'Failed to fetch exception user usage: {e}')
        return jsonify({'error': 'failed to fetch exception user usage'}), 500


# --- POST /api/gateway/seed-emails ------------------------------------------

@gateway_usage_bp.route('/api/gateway/seed-emails', methods=['POST'])
@admin_required
def seed_emails():
    """Populate notification_email for all existing principal_policy records
    using USER_EMAIL_MAP. Idempotent — only updates records missing the field
    or with a different email than the map.
    """
    policy_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    try:
        resp = policy_table.scan()
    except Exception as e:
        logger.error(f'Failed to scan principal_policy for email seed: {e}')
        return jsonify({'error': 'scan failed'}), 500

    updated = []
    skipped = []
    for item in resp.get('Items', []):
        pid = item.get('principal_id', '')
        if pid == GATEWAY_CONFIG_KEY:
            continue
        # Extract username from principal_id
        username = pid.split('#')[-1].replace('BedrockUser-', '') if '#' in pid else ''
        if not username:
            continue
        email = USER_EMAIL_MAP.get(username, '')
        if not email:
            skipped.append(username)
            continue
        current_email = item.get('notification_email', '')
        if current_email == email:
            skipped.append(username)
            continue
        policy_table.update_item(
            Key={'principal_id': pid},
            UpdateExpression='SET notification_email = :e',
            ExpressionAttributeValues={':e': email},
        )
        updated.append({'username': username, 'email': email})

    return jsonify({'updated': updated, 'skipped': skipped}), 200
