# =============================================================================
# BedrockUser IAM Roles — per-user gateway access
# =============================================================================

variable "bedrock_users" {
  description = "List of usernames for BedrockUser IAM roles"
  type        = list(string)
  default = [
    "user01", "bk86", "user10", "admin", "user18", "user07", "user14", "user08",
    "user12", "user11", "hssim", "ihkim", "intern", "user16", "user02", "user19", "user05",
    "user04", "user21", "user09", "user22", "user15", "user17", "user13", "user20",
  ]
}

variable "cluster_assume_role_arns" {
  description = "ParallelCluster role ARNs allowed to assume BedrockUser roles"
  type        = list(string)
  default = [
    "arn:aws:iam::123456789012:role/acme-ora-RoleHeadNode-NoBedrock",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-RoleHeadNode-EXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleEXAMPLE",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleD4a04feab6af0c39-NQldLulTWEGn",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleE023cc478a73ac4b-t59JrlvQNSsR",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleE9d20843b98a0ad6-9o5EnlM6C07N",
    "arn:aws:iam::123456789012:role/parallelcluster/acme-ora/acme-ora-ComputeFleetQueuesNe-RoleFddf5a48e958cde0-PnbZiKu1235l",
  ]
}

variable "discovery_api_id" {
  description = "Discovery API Gateway ID"
  type        = string
  default     = "ugpt5xi8b7"
}

# --- Role ---
resource "aws_iam_role" "bedrock_user" {
  for_each = toset(var.bedrock_users)
  name     = "BedrockUser-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect    = "Allow"
        Principal = { AWS = var.cluster_assume_role_arns }
        Action    = "sts:AssumeRole"
      }],
      # SSO trust — allows IAM Identity Center users to assume their own role
      [{
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          ArnLike = {
            "aws:PrincipalArn" = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_*"
          }
        }
      }],
      # Add IAM Roles Anywhere statement for DGX pilot users only
      var.enable_dgx_onprem_access && contains(var.dgx_pilot_users, each.key) ? [{
        Effect    = "Allow"
        Principal = { Service = "rolesanywhere.amazonaws.com" }
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_rolesanywhere_trust_anchor.dgx[0].arn
          }
        }
      }] : []
    )
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# --- BedrockAccess ---
resource "aws_iam_role_policy" "bedrock_user_access" {
  for_each = toset(var.bedrock_users)
  name     = "BedrockAccess"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse", "bedrock:ConverseStream"]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.claude*",
          "arn:aws:bedrock:*::foundation-model/amazon.*",
          "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:ListFoundationModels", "bedrock:GetFoundationModel", "bedrock:ListInferenceProfiles", "bedrock:GetInferenceProfile", "bedrock:InvokeTool"]
        Resource = "*"
      },
    ]
  })
}

# --- DenyDirectBedrockInference ---
resource "aws_iam_role_policy" "bedrock_user_deny_direct" {
  for_each = toset(var.bedrock_users)
  name     = "DenyDirectBedrockInference"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDirectBedrockAccess"
      Effect = "Deny"
      Action = [
        "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
        "bedrock:Converse", "bedrock:ConverseStream",
        "bedrock:InvokeAgent", "bedrock:InvokeInlineAgent", "bedrock:InvokeFlow",
      ]
      Resource = "*"
    }]
  })
}

# --- DenyDirectECSAndSFN ---
resource "aws_iam_role_policy" "bedrock_user_deny_ecs_sfn" {
  for_each = toset(var.bedrock_users)
  name     = "DenyDirectECSAndSFN"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDirectECSAndSFN"
      Effect = "Deny"
      Action = ["ecs:RunTask", "ecs:ExecuteCommand", "ecs:StartTask", "states:StartExecution", "states:StartSyncExecution"]
      Resource = "*"
    }]
  })
}

# --- Gateway execute-api policies ---
resource "aws_iam_role_policy" "bedrock_user_gw_converse" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayConverse"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/converse"
    }]
  })
}

# /invoke route — InvokeModel passthrough for image / embedding / rerank.
# Synchronous only; allowlist enforced at the gateway Lambda.
resource "aws_iam_role_policy" "bedrock_user_gw_invoke" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayInvoke"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/invoke"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_converse_jobs" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayConverseJobs"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = [
        "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/converse-jobs",
        "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/GET/converse-jobs/*",
        "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/converse-jobs/*",
      ]
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_approval" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayApprovalRequest"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/approval/request"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_quota" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayQuotaStatus"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/GET/quota/status"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_job_cancel" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayJobCancel"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/converse-jobs/*"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_job_status" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayJobStatus"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/GET/converse-jobs/*"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_longrun" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDevGatewayLongrun"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.gateway.id}/${var.api_gateway_stage_name}/POST/longrun/*"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_stream" {
  for_each = toset(var.bedrock_users)
  name     = "AllowStreamFunctionUrl"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunctionUrl"
      Resource = aws_lambda_function.stream_handler.arn
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_user_gw_discovery" {
  for_each = toset(var.bedrock_users)
  name     = "AllowDiscoveryGatewayInvoke"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowDiscoveryGatewayInvoke"
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.discovery_api_id}/${var.api_gateway_stage_name}/*/*"
    }]
  })
}

# --- S3DataAccess ---
resource "aws_iam_role_policy" "bedrock_user_s3" {
  for_each = toset(var.bedrock_users)
  name     = "S3DataAccess"
  role     = aws_iam_role.bedrock_user[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation"]
      Resource = ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
    }]
  })
}
