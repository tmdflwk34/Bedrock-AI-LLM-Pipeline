# =============================================================================
# v3: SQS Job Queue + Dead Letter Queue
# =============================================================================

resource "aws_sqs_queue" "job_dlq" {
  name                      = "${local.prefix}-job-dlq"
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_sqs_queue" "job_queue" {
  name                       = "${local.prefix}-job-queue"
  visibility_timeout_seconds = 120
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 5

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.job_dlq.arn
    maxReceiveCount     = 10
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
