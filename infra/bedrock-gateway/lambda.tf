# =============================================================================
# Gateway Lambda Function + Alias
# =============================================================================

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.build/lambda.zip"
}

resource "aws_lambda_function" "gateway" {
  function_name    = "${local.prefix}-gateway"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT                 = var.environment
      TABLE_PRINCIPAL_POLICY      = aws_dynamodb_table.principal_policy.name
      TABLE_DAILY_USAGE           = aws_dynamodb_table.daily_usage.name
      TABLE_MONTHLY_USAGE         = aws_dynamodb_table.monthly_usage.name
      TABLE_MODEL_PRICING         = aws_dynamodb_table.model_pricing.name
      TABLE_TEMPORARY_QUOTA_BOOST = aws_dynamodb_table.temporary_quota_boost.name
      TABLE_APPROVAL_REQUEST      = aws_dynamodb_table.approval_request.name
      TABLE_REQUEST_LEDGER        = aws_dynamodb_table.request_ledger.name
      TABLE_SESSION_METADATA      = aws_dynamodb_table.session_metadata.name
      TABLE_IDEMPOTENCY_RECORD    = aws_dynamodb_table.idempotency_record.name
      TABLE_APPROVAL_PENDING_LOCK = aws_dynamodb_table.approval_pending_lock.name
      TABLE_LONGRUN_REQUEST       = aws_dynamodb_table.longrun_request.name
      TABLE_JOB_STATE             = aws_dynamodb_table.job_state.name
      TABLE_CONCURRENCY_SEMAPHORE = aws_dynamodb_table.concurrency_semaphore.name
      PAYLOAD_BUCKET              = aws_s3_bucket.payload.id
      SFN_STATE_MACHINE_ARN       = aws_sfn_state_machine.job_orchestrator.arn
      SQS_JOB_QUEUE_URL           = aws_sqs_queue.job_queue.url
      GLOBAL_QUEUE_LIMIT          = tostring(var.global_queue_limit)
      PER_USER_QUEUE_LIMIT        = tostring(var.per_user_queue_limit)
      SES_SENDER_EMAIL            = var.ses_sender_email
      SES_ADMIN_GROUP_EMAIL       = var.ses_admin_group_email
      DISCOVERY_MODE              = tostring(var.discovery_mode)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.dynamodb,
    aws_iam_role_policy.bedrock,
  ]

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Published version — required for alias
resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.gateway.function_name
  function_version = aws_lambda_function.gateway.version
}
