"""
Bedrock Gateway — Team/Admin/User Governance Routes.

Admin-plane endpoints for managing team structure:
  - GET    /api/gateway/teams              — list all teams
  - GET    /api/gateway/teams/<team_id>    — get team detail
  - POST   /api/gateway/teams              — create team
  - PUT    /api/gateway/teams/<team_id>    — update team
  - DELETE /api/gateway/teams/<team_id>    — delete team
  - GET    /api/gateway/audit-log          — governance audit log

All changes go through admin API only. Portal never writes DynamoDB directly.
"""
import os, time, uuid, json, logging
from datetime import datetime, timezone
from decimal import Decimal
from functools import wraps

import boto3
from flask import Blueprint, request, jsonify
from routes.gateway_usage import admin_required

logger = logging.getLogger(__name__)
gateway_teams_bp = Blueprint('gateway_teams', __name__)

AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
ENVIRONMENT = os.environ.get('BEDROCK_GW_ENV', 'dev')
TABLE_PREFIX = f'bedrock-gw-{ENVIRONMENT}-{AWS_REGION}'
TABLE_TEAM_CONFIG = f'{TABLE_PREFIX}-team-config'
TABLE_AUDIT_LOG = f'{TABLE_PREFIX}-governance-audit'
TABLE_PRINCIPAL_POLICY = f'{TABLE_PREFIX}-principal-policy'

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)


def _clean(item):
    if not item:
        return item
    cleaned = {}
    for k, v in item.items():
        if isinstance(v, Decimal):
            cleaned[k] = int(v) if v == int(v) else float(v)
        elif isinstance(v, set):
            cleaned[k] = list(v)
        else:
            cleaned[k] = v
    return cleaned


def _write_audit(action, target, details, actor="admin"):
    """Write governance audit log entry."""
    try:
        table = dynamodb.Table(TABLE_AUDIT_LOG)
        table.put_item(Item={
            'audit_id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'target': target,
            'details': json.dumps(details, default=str),
            'actor': actor,
            'ttl': int(time.time()) + 365 * 24 * 3600,
        })
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")


@gateway_teams_bp.route('/api/gateway/teams', methods=['GET'])
@admin_required
def list_teams():
    table = dynamodb.Table(TABLE_TEAM_CONFIG)
    resp = table.scan()
    teams = [_clean(i) for i in resp.get('Items', [])]
    return jsonify({'teams': teams})


@gateway_teams_bp.route('/api/gateway/teams/<team_id>', methods=['GET'])
@admin_required
def get_team(team_id):
    table = dynamodb.Table(TABLE_TEAM_CONFIG)
    resp = table.get_item(Key={'team_id': team_id})
    item = resp.get('Item')
    if not item:
        return jsonify({'error': 'team not found'}), 404
    return jsonify(_clean(item))


@gateway_teams_bp.route('/api/gateway/teams', methods=['POST'])
@admin_required
def create_team():
    data = request.get_json(silent=True) or {}
    team_id = data.get('team_id', '').strip()
    team_name = data.get('team_name', '').strip()
    if not team_id or not team_name:
        return jsonify({'error': 'team_id and team_name required'}), 400

    table = dynamodb.Table(TABLE_TEAM_CONFIG)
    existing = table.get_item(Key={'team_id': team_id}).get('Item')
    if existing:
        return jsonify({'error': 'team already exists'}), 409

    item = {
        'team_id': team_id,
        'team_name': team_name,
        'admins': data.get('admins', []),
        'users': data.get('users', []),
        'notification_admin_emails': data.get('notification_admin_emails', []),
        'direct_access_users': data.get('direct_access_users', []),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }
    table.put_item(Item=item)
    _write_audit('team_create', team_id, item)
    return jsonify(_clean(item)), 201


ACCOUNT_ID = '<ACCOUNT_ID>'
GATEWAY_API_ID = '<GATEWAY_API_ID>'
DISCOVERY_API_ID = '<DISCOVERY_API_ID>'

# Username → email mapping (authoritative, shared with gateway_usage.py)
from routes.gateway_usage import USER_EMAIL_MAP

iam_client = boto3.client('iam', region_name=AWS_REGION)

# IAM policy templates for BedrockUser roles
_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": [
            f"arn:aws:iam::{ACCOUNT_ID}:role/acme-ora-RoleHeadNode-NoBedrock",
            f"arn:aws:iam::{ACCOUNT_ID}:role/parallelcluster/acme-ora/acme-ora-RoleHeadNode-EXAMPLE",
        ]},
        "Action": "sts:AssumeRole"
    }]
})

_BEDROCK_ACCESS_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse", "bedrock:ConverseStream"],
         "Resource": [f"arn:aws:bedrock:*::foundation-model/anthropic.claude*", f"arn:aws:bedrock:*::foundation-model/amazon.*", f"arn:aws:bedrock:*:{ACCOUNT_ID}:inference-profile/*"]},
        {"Effect": "Allow", "Action": ["bedrock:ListFoundationModels", "bedrock:GetFoundationModel", "bedrock:ListInferenceProfiles", "bedrock:GetInferenceProfile", "bedrock:InvokeAgent"], "Resource": "*"},
    ]
})

_DENY_DIRECT_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Sid": "DenyDirectBedrockAccess", "Effect": "Deny",
        "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse", "bedrock:ConverseStream"], "Resource": "*"}]
})

_DENY_DIRECT_ECS_SFN_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Sid": "DenyDirectECSAndSFN", "Effect": "Deny",
        "Action": ["ecs:RunTask", "ecs:ExecuteCommand", "ecs:StartTask", "states:StartExecution", "states:StartSyncExecution"], "Resource": "*"}]
})

_S3_DATA_ACCESS_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation"],
        "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]}]
})

def _gateway_invoke_policy(path):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "execute-api:Invoke",
         "Resource": [f"arn:aws:execute-api:us-west-2:{ACCOUNT_ID}:{GATEWAY_API_ID}/v1/{path}"]}
    ]})


def _gateway_invoke_policy_wildcard(paths):
    """Like _gateway_invoke_policy but accepts a list of paths (supports wildcards)."""
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "execute-api:Invoke",
         "Resource": [f"arn:aws:execute-api:us-west-2:{ACCOUNT_ID}:{GATEWAY_API_ID}/v1/{p}" for p in paths]}
    ]})


def _ensure_iam_role(username):
    """Create BedrockUser-{username} IAM role with gateway policies if it doesn't exist.
    If role exists, ensure DenyDirectBedrockInference is applied.
    Returns (created: bool, errors: list).
    """
    role_name = f'BedrockUser-{username}'
    errors = []
    created = False

    # Check if role exists
    try:
        iam_client.get_role(RoleName=role_name)
        logger.info(f"IAM role {role_name} already exists")
    except iam_client.exceptions.NoSuchEntityException:
        # Create role
        try:
            iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY,
                                   MaxSessionDuration=3600, Description=f'Bedrock gateway user role for {username}')
            created = True
            logger.info(f"Created IAM role {role_name}")
        except Exception as e:
            errors.append(f"create_role failed: {e}")
            return created, errors

    # Apply inline policies (idempotent — put_role_policy overwrites if exists)
    policies = {
        'BedrockAccess': _BEDROCK_ACCESS_POLICY,
        'DenyDirectBedrockInference': _DENY_DIRECT_POLICY,
        'DenyDirectECSAndSFN': _DENY_DIRECT_ECS_SFN_POLICY,
        'AllowDevGatewayConverse': _gateway_invoke_policy('POST/converse'),
        'AllowDevGatewayConverseJobs': _gateway_invoke_policy_wildcard(['POST/converse-jobs', 'GET/converse-jobs/*', 'POST/converse-jobs/*']),
        'AllowDevGatewayApprovalRequest': _gateway_invoke_policy('POST/approval/request'),
        'AllowDevGatewayQuotaStatus': _gateway_invoke_policy('GET/quota/status'),
        'AllowDevGatewayJobCancel': _gateway_invoke_policy('POST/converse-jobs/*'),
        'AllowDevGatewayJobStatus': _gateway_invoke_policy('GET/converse-jobs/*'),
        'AllowDevGatewayLongrun': _gateway_invoke_policy('POST/longrun/*'),
        'AllowDiscoveryGatewayInvoke': json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "AllowDiscoveryGatewayInvoke", "Effect": "Allow", "Action": "execute-api:Invoke", "Resource": [f"arn:aws:execute-api:us-west-2:{ACCOUNT_ID}:{DISCOVERY_API_ID}/v1/*/*"]}]}),
        'S3DataAccess': _S3_DATA_ACCESS_POLICY,
    }
    for policy_name, policy_doc in policies.items():
        try:
            iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
        except Exception as e:
            errors.append(f"put_role_policy {policy_name} failed: {e}")

    return created, errors


def _remove_gateway_enforcement(username):
    """Remove DenyDirectBedrockInference and upgrade BedrockAccess with InvokeTool for direct access.
    Returns (success: bool, error: str or None).
    """
    role_name = f'BedrockUser-{username}'
    try:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName='DenyDirectBedrockInference')
        logger.info(f"Removed DenyDirectBedrockInference from {role_name}")
    except iam_client.exceptions.NoSuchEntityException:
        pass  # already removed
    except Exception as e:
        return False, str(e)

    # Upgrade BedrockAccess to include InvokeTool for direct-access users (web grounding etc.)
    direct_access_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse", "bedrock:ConverseStream"],
             "Resource": [f"arn:aws:bedrock:*::foundation-model/anthropic.claude*", f"arn:aws:bedrock:*::foundation-model/amazon.*", f"arn:aws:bedrock:*:{ACCOUNT_ID}:inference-profile/*"]},
            {"Effect": "Allow", "Action": ["bedrock:ListFoundationModels", "bedrock:GetFoundationModel", "bedrock:ListInferenceProfiles", "bedrock:GetInferenceProfile", "bedrock:InvokeAgent", "bedrock:InvokeTool"], "Resource": "*"},
        ]
    })
    try:
        iam_client.put_role_policy(RoleName=role_name, PolicyName='BedrockAccess', PolicyDocument=direct_access_policy)
        logger.info(f"Upgraded BedrockAccess with InvokeTool for {role_name}")
    except Exception as e:
        logger.error(f"Failed to upgrade BedrockAccess for {role_name}: {e}")

    return True, None

# Default principal-policy template for new gateway users
# allowed_models is populated dynamically from model_pricing table at provision time.
_DEFAULT_PRINCIPAL_POLICY_BASE = {
    'daily_input_token_limit': 100000,
    'daily_output_token_limit': 50000,
    'max_monthly_cost_limit_krw': 2000000,
    'monthly_cost_limit_krw': 500000,
}

TABLE_MODEL_PRICING = f'{TABLE_PREFIX}-model-pricing'


def _get_all_model_ids():
    """Fetch all model_id values from model_pricing table."""
    try:
        table = dynamodb.Table(TABLE_MODEL_PRICING)
        resp = table.scan(ProjectionExpression='model_id')
        return sorted([item['model_id'] for item in resp.get('Items', []) if 'model_id' in item])
    except Exception as e:
        logger.error(f"Failed to scan model_pricing for allowed_models: {e}")
        return []


def _ensure_principal_policy(username, email=''):
    """Create principal-policy record + IAM role if they don't exist.

    1. Creates/updates BedrockUser-{username} IAM role with gateway policies
    2. Creates principal-policy DynamoDB record with all models allowed
    Email priority: explicit param > USER_EMAIL_MAP > empty.
    """
    # Step 1: IAM role
    iam_created, iam_errors = _ensure_iam_role(username)
    if iam_errors:
        logger.error(f"IAM provisioning errors for {username}: {iam_errors}")

    # Step 2: DynamoDB principal-policy
    pp_table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    pid = f'{ACCOUNT_ID}#BedrockUser-{username}'
    existing = pp_table.get_item(Key={'principal_id': pid}).get('Item')
    if existing:
        # Update email if provided and different
        if email and existing.get('notification_email') != email:
            pp_table.update_item(Key={'principal_id': pid},
                UpdateExpression='SET notification_email = :e',
                ExpressionAttributeValues={':e': email})
        return False  # already exists
    all_models = _get_all_model_ids()
    item = {'principal_id': pid, 'allowed_models': all_models, **_DEFAULT_PRINCIPAL_POLICY_BASE}
    resolved_email = email or USER_EMAIL_MAP.get(username, '')
    if resolved_email:
        item['notification_email'] = resolved_email
    pp_table.put_item(Item=item)
    logger.info(f"Auto-provisioned principal-policy for {pid} with {len(all_models)} models, IAM created={iam_created}")
    _write_audit('principal_auto_provision', pid, {
        'source': 'team_add', 'notification_email': resolved_email,
        'model_count': len(all_models), 'iam_role_created': iam_created,
        'iam_errors': iam_errors if iam_errors else None,
    })
    return True


@gateway_teams_bp.route('/api/gateway/teams/<team_id>', methods=['PUT'])
@admin_required
def update_team(team_id):
    data = request.get_json(silent=True) or {}
    table = dynamodb.Table(TABLE_TEAM_CONFIG)
    existing = table.get_item(Key={'team_id': team_id}).get('Item')
    if not existing:
        return jsonify({'error': 'team not found'}), 404

    old_users = set(existing.get('users', []))
    new_users = set(data.get('users', [])) if 'users' in data else old_users

    # Auto-provision principal-policy + IAM role for newly added users
    added_users = new_users - old_users
    provisioned = []
    new_user_email = data.get('new_user_email', '')  # Email from portal for new user
    for username in added_users:
        if _ensure_principal_policy(username, email=new_user_email):
            provisioned.append(username)

    # Handle removed users — only switch to direct access if not in any other team
    removed_users = old_users - new_users
    removed_to_direct = []
    for username in removed_users:
        # Check if user is in another team
        in_other_team = False
        try:
            all_teams = dynamodb.Table(TABLE_TEAM_CONFIG).scan().get('Items', [])
            for other_team in all_teams:
                if other_team.get('team_id') == team_id:
                    continue  # skip current team
                if username in (other_team.get('users') or []):
                    in_other_team = True
                    break
        except Exception:
            pass

        if in_other_team:
            logger.info(f"{username} removed from {team_id} but still in another team — keeping gateway enforcement")
            continue

        ok, err = _remove_gateway_enforcement(username)
        if ok:
            removed_to_direct.append(username)
        pid = f'{ACCOUNT_ID}#BedrockUser-{username}'
        try:
            dynamodb.Table(TABLE_PRINCIPAL_POLICY).update_item(
                Key={'principal_id': pid},
                UpdateExpression='SET direct_access_exception = :da, gateway_managed = :gm, updated_at = :t',
                ExpressionAttributeValues={':da': True, ':gm': False, ':t': datetime.now(timezone.utc).isoformat()},
            )
        except Exception as e:
            logger.error(f"Failed to mark {pid} as direct_access: {e}")

    update_fields = {}
    for field in ['team_name', 'admins', 'users', 'notification_admin_emails', 'direct_access_users']:
        if field in data:
            update_fields[field] = data[field]

    # Auto-sync notification_admin_emails when admins change
    if 'admins' in update_fields and 'notification_admin_emails' not in update_fields:
        admin_emails = [USER_EMAIL_MAP.get(a, '') for a in update_fields['admins']]
        update_fields['notification_admin_emails'] = [e for e in admin_emails if e]

    update_fields['updated_at'] = datetime.now(timezone.utc).isoformat()

    expr_parts = []
    expr_names = {}
    expr_values = {}
    for i, (k, v) in enumerate(update_fields.items()):
        alias = f'#f{i}'
        val_alias = f':v{i}'
        expr_parts.append(f'{alias} = {val_alias}')
        expr_names[alias] = k
        expr_values[val_alias] = v

    table.update_item(
        Key={'team_id': team_id},
        UpdateExpression='SET ' + ', '.join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    audit_details = {'changes': update_fields}
    if provisioned:
        audit_details['auto_provisioned_principals'] = provisioned
    if removed_to_direct:
        audit_details['removed_to_direct_access'] = removed_to_direct
    _write_audit('team_update', team_id, audit_details)
    updated = table.get_item(Key={'team_id': team_id}).get('Item', {})
    return jsonify(_clean(updated))


@gateway_teams_bp.route('/api/gateway/teams/<team_id>', methods=['DELETE'])
@admin_required
def delete_team(team_id):
    table = dynamodb.Table(TABLE_TEAM_CONFIG)
    existing = table.get_item(Key={'team_id': team_id}).get('Item')
    if not existing:
        return jsonify({'error': 'team not found'}), 404
    table.delete_item(Key={'team_id': team_id})
    _write_audit('team_delete', team_id, {'deleted': _clean(existing)})
    return jsonify({'deleted': team_id})


@gateway_teams_bp.route('/api/gateway/audit-log', methods=['GET'])
@admin_required
def get_audit_log():
    table = dynamodb.Table(TABLE_AUDIT_LOG)
    resp = table.scan()
    items = sorted([_clean(i) for i in resp.get('Items', [])],
                   key=lambda x: x.get('timestamp', ''), reverse=True)
    limit = request.args.get('limit', 50, type=int)
    return jsonify({'audit_log': items[:limit]})


@gateway_teams_bp.route('/api/gateway/users/<path:principal_id>/direct-access', methods=['PUT'])
@admin_required
def set_direct_access(principal_id):
    """Set or unset direct_access_exception on a principal policy.

    When enabling direct access (removing from gateway):
      - Removes DenyDirectBedrockInference from IAM role
      - Sets direct_access_exception=true in DynamoDB
    When disabling direct access (adding back to gateway):
      - Re-applies DenyDirectBedrockInference to IAM role
      - Sets direct_access_exception=false in DynamoDB
    """
    from urllib.parse import unquote
    pid = unquote(principal_id)
    data = request.get_json(silent=True) or {}
    enabled = data.get('direct_access_exception', False)

    table = dynamodb.Table(TABLE_PRINCIPAL_POLICY)
    existing = table.get_item(Key={'principal_id': pid}).get('Item')
    if not existing:
        return jsonify({'error': 'principal not found'}), 404

    # Extract username from principal_id
    username = pid.split('#')[-1].replace('BedrockUser-', '') if '#' in pid else pid

    iam_result = None
    if enabled:
        # Switching to direct access — remove deny
        ok, err = _remove_gateway_enforcement(username)
        iam_result = {'action': 'remove_deny', 'success': ok, 'error': err}
    else:
        # Switching back to gateway — re-apply deny
        role_name = f'BedrockUser-{username}'
        try:
            iam_client.put_role_policy(RoleName=role_name, PolicyName='DenyDirectBedrockInference',
                                       PolicyDocument=_DENY_DIRECT_POLICY)
            iam_result = {'action': 'apply_deny', 'success': True, 'error': None}
        except Exception as e:
            iam_result = {'action': 'apply_deny', 'success': False, 'error': str(e)}

    table.update_item(
        Key={'principal_id': pid},
        UpdateExpression='SET gateway_managed = :gm, direct_access_exception = :da, updated_at = :t',
        ExpressionAttributeValues={
            ':gm': not enabled,
            ':da': enabled,
            ':t': datetime.now(timezone.utc).isoformat(),
        },
    )
    _write_audit('direct_access_toggle', pid, {'direct_access_exception': enabled, 'iam': iam_result})
    return jsonify({'principal_id': pid, 'direct_access_exception': enabled, 'gateway_managed': not enabled, 'iam': iam_result})
