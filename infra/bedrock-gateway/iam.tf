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


# Step Functions — start async job executions
resource "aws_iam_role_policy" "sfn_start" {
  name = "${local.prefix}-sfn-start"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "StartJobExecution"
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [aws_sfn_state_machine.job_orchestrator.arn]
    }]
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
