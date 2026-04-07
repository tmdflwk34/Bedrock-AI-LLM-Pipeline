# =============================================================================
# v3: Dispatcher Lambda — SQS → check limits → start SFN
# =============================================================================

data "archive_file" "dispatcher_zip" {
  type        = "zip"
  source_dir  = "${path.module}/dispatcher"
  output_path = "${path.module}/.build/dispatcher.zip"
}

resource "aws_lambda_function" "dispatcher" {
  function_name    = "${local.prefix}-dispatcher"
  role             = aws_iam_role.dispatcher_exec.arn
  handler          = "handler.handler"
  runtime          = var.lambda_runtime
  timeout          = 60
  memory_size      = 128
  filename         = data.archive_file.dispatcher_zip.output_path
  source_code_hash = data.archive_file.dispatcher_zip.output_base64sha256

  environment {
    variables = {
      TABLE_JOB_STATE      = aws_dynamodb_table.job_state.name
      SFN_STATE_MACHINE_ARN = aws_sfn_state_machine.job_orchestrator.arn
      GLOBAL_ACTIVE_LIMIT  = tostring(var.global_active_limit)
      PER_USER_ACTIVE_LIMIT = tostring(var.per_user_active_limit)
      BEDROCK_REGION       = var.aws_region
      SQS_QUEUE_URL         = aws_sqs_queue.job_queue.url
    }
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# SQS event source mapping
resource "aws_lambda_event_source_mapping" "dispatcher_sqs" {
  event_source_arn                   = aws_sqs_queue.job_queue.arn
  function_name                      = aws_lambda_function.dispatcher.arn
  batch_size                         = 5
  maximum_batching_window_in_seconds = 2
  function_response_types            = ["ReportBatchItemFailures"]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "dispatcher" {
  name              = "/aws/lambda/${local.prefix}-dispatcher"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# IAM role for dispatcher
resource "aws_iam_role" "dispatcher_exec" {
  name = "${local.prefix}-dispatcher-exec"

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

resource "aws_iam_role_policy_attachment" "dispatcher_basic" {
  role       = aws_iam_role.dispatcher_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "dispatcher_sqs" {
  name = "${local.prefix}-dispatcher-sqs"
  role = aws_iam_role.dispatcher_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:SendMessage",
        "sqs:ChangeMessageVisibility",
      ]
      Resource = [aws_sqs_queue.job_queue.arn]
    }]
  })
}

resource "aws_iam_role_policy" "dispatcher_sfn" {
  name = "${local.prefix}-dispatcher-sfn"
  role = aws_iam_role.dispatcher_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [aws_sfn_state_machine.job_orchestrator.arn]
    }]
  })
}

resource "aws_iam_role_policy" "dispatcher_dynamodb" {
  name = "${local.prefix}-dispatcher-dynamodb"
  role = aws_iam_role.dispatcher_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:UpdateItem"]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          "${aws_dynamodb_table.job_state.arn}/index/*",
        ]
      },
    ]
  })
}
