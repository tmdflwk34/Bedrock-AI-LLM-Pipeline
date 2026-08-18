# =============================================================================
# Lambda Execution Role + Policies
# =============================================================================

resource "aws_iam_role" "lambda_exec" {
  name = "${local.prefix}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# CloudWatch Logs — basic Lambda logging
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Bedrock inference — Converse API requires bedrock:InvokeModel at IAM level.
# bedrock:Converse is NOT a valid IAM action; AWS maps Converse → InvokeModel,
# ConverseStream → InvokeModelWithResponseStream.
# v1: Converse only. InvokeModelWithResponseStream added for v2 streaming readiness.
resource "aws_iam_role_policy" "bedrock" {
  name = "${local.prefix}-bedrock"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "BedrockInference"
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      Resource = ["*"]
      },
      # Additive grant for the bedrock-mantle OpenAI Responses endpoint.
      # LIVE-CONFIRMED (2026-06): the mantle Responses API authorizes via the
      # NEW service namespace action `bedrock-mantle:CreateInference` on the
      # account's mantle project resource — NOT bedrock:InvokeModel. The 25
      # BedrockUser roles ALSO get a per-path execute-api:Invoke grant for
      # POST /openai/responses (see bedrock_users.tf — execute-api perms are
      # per-method/path, not wildcard). No static credential / per-user secret.
      #
      # ADDITIVE CHANGE — requires a TARGETED apply only (NEVER a full apply):
      #   AWS_PROFILE=bedrock-gw terraform apply \
      #     -target=aws_iam_role_policy.bedrock \
      #     -target=aws_lambda_function.gateway \
      #     -var-file=env/dev.tfvars -lock=false
      {
        Sid    = "BedrockMantleResponses"
        Effect = "Allow"
        Action = ["bedrock-mantle:CreateInference"]
        Resource = [
          "arn:aws:bedrock-mantle:us-west-2:123456789012:project/default",
          "arn:aws:bedrock-mantle:us-east-2:123456789012:project/default",
        ]
    }]
  })
}

# DynamoDB — full access to gateway tables EXCEPT RequestLedger mutation
# RequestLedger: PutItem only (immutable audit). No UpdateItem/DeleteItem.
resource "aws_iam_role_policy" "dynamodb" {
  name = "${local.prefix}-dynamodb"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadWriteNonLedger"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
        ]
        Resource = [
          aws_dynamodb_table.principal_policy.arn,
          aws_dynamodb_table.daily_usage.arn,
          aws_dynamodb_table.monthly_usage.arn,
          aws_dynamodb_table.temporary_quota_boost.arn,
          aws_dynamodb_table.approval_request.arn,
          "${aws_dynamodb_table.approval_request.arn}/index/*",
          aws_dynamodb_table.session_metadata.arn,
          aws_dynamodb_table.idempotency_record.arn,
          aws_dynamodb_table.approval_pending_lock.arn,
          aws_dynamodb_table.longrun_request.arn,
          aws_dynamodb_table.job_state.arn,
          "${aws_dynamodb_table.job_state.arn}/index/*",
          aws_dynamodb_table.concurrency_semaphore.arn,
        ]
      },
      {
        Sid      = "RequestLedgerPutOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid    = "RequestLedgerDenyMutation"
        Effect = "Deny"
        Action = [
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
        ]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid    = "ModelPricingReadOnly"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ]
        Resource = [aws_dynamodb_table.model_pricing.arn]
      },
      {
        Sid    = "TeamConfigReadOnly"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:GetItem",
        ]
        Resource = [aws_dynamodb_table.team_config.arn]
      },
    ]
  })
}

# SES — send approval notification emails
resource "aws_iam_role_policy" "ses" {
  name = "${local.prefix}-ses"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SESSendEmail"
      Effect   = "Allow"
      Action   = ["ses:SendEmail", "ses:SendRawEmail"]
      Resource = ["*"]
    }]
  })
}


# Step Functions — start async job executions, and stop them when cancelled.
#
# StopExecution is what delivers the SIGTERM the worker's cancel handler runs on
# (long-output-streaming task 5.3). Without it `handle_converse_job_cancel` still
# answered 200 and still released the `__reserved__` hold, while the generation
# ran to completion and settled against a hold that no longer existed — observed
# live on job-542e9f20-ddb3-454a-86d0-3157f99eea3b (scenario 9.4, R9.1/R9.2/R7.5).
# The leak window is the single-generation ceiling, so raising that 1800s → 7200s
# made the same missing grant four times as expensive.
#
# Two statements, because the two actions authorize on different resource types
# and one combined statement would have to widen both to cover either:
#   StartExecution -> the state machine   arn:...:stateMachine:<name>
#   StopExecution  -> an execution of it  arn:...:execution:<name>:<execution-id>
# StopExecution granted on the state machine ARN is an AccessDenied at call time;
# granted on "*" it would let this role stop any execution in the account. The
# execution name is the job_id, hence the trailing `*`.
#
# The resource label and the policy `name` stay `sfn_start` on purpose: renaming
# either would destroy and recreate the inline policy, and this change is meant
# to be a pure action addition on the existing one.
resource "aws_iam_role_policy" "sfn_start" {
  name = "${local.prefix}-sfn-start"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartJobExecution"
        Effect   = "Allow"
        Action   = ["states:StartExecution"]
        Resource = [aws_sfn_state_machine.job_orchestrator.arn]
      },
      {
        Sid    = "StopJobExecution"
        Effect = "Allow"
        Action = ["states:StopExecution"]
        Resource = [
          "arn:aws:states:${var.aws_region}:${data.aws_caller_identity.current.account_id}:execution:${aws_sfn_state_machine.job_orchestrator.name}:*",
        ]
      },
    ]
  })
}

# S3 — store/retrieve job payloads
resource "aws_iam_role_policy" "s3_payload" {
  name = "${local.prefix}-s3-payload"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PayloadBucketAccess"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = ["${aws_s3_bucket.payload.arn}/*"]
    }]
  })
}

# SQS — enqueue job messages
resource "aws_iam_role_policy" "sqs_enqueue" {
  name = "${local.prefix}-sqs-enqueue"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SQSEnqueue"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.job_queue.arn]
    }]
  })
}

# =============================================================================
# Fargate Task — Lambda Invoke (warning check after async settlement)
# =============================================================================

resource "aws_iam_role_policy" "fargate_task_lambda_invoke" {
  name = "${local.prefix}-fargate-lambda-invoke"
  role = aws_iam_role.fargate_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "InvokeWarningCheckLambda"
      Effect = "Allow"
      Action = ["lambda:InvokeFunction"]
      Resource = [
        "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.prefix}-gateway",
        "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.prefix}-gateway:live",
      ]
    }]
  })
}
