# =============================================================================
# v2: ECS Cluster + Fargate Task Definition for Long-Running Bedrock Calls
# =============================================================================

resource "aws_ecs_cluster" "gateway" {
  name = "${local.prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Fargate task execution role (ECR pull + CloudWatch Logs)
resource "aws_iam_role" "fargate_execution" {
  name = "${local.prefix}-fargate-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "fargate_execution" {
  role       = aws_iam_role.fargate_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Fargate task role (Bedrock + DynamoDB + S3 — least privilege)
resource "aws_iam_role" "fargate_task" {
  name = "${local.prefix}-fargate-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_iam_role_policy" "fargate_task_bedrock" {
  name = "${local.prefix}-fargate-bedrock"
  role = aws_iam_role.fargate_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BedrockInvoke"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:Converse"]
        Resource = ["*"]
      },
      {
        Sid      = "MarketplaceAccess"
        Effect   = "Allow"
        Action   = ["aws-marketplace:ViewSubscriptions", "aws-marketplace:Subscribe"]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role_policy" "fargate_task_dynamodb" {
  name = "${local.prefix}-fargate-dynamodb"
  role = aws_iam_role.fargate_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "JobStateReadWrite"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          aws_dynamodb_table.monthly_usage.arn,
        ]
      },
      {
        Sid    = "SemaphoreRelease"
        Effect = "Allow"
        Action = ["dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.concurrency_semaphore.arn]
      },
      {
        Sid    = "LedgerPutOnly"
        Effect = "Allow"
        Action = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid    = "PricingRead"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:Scan"]
        Resource = [aws_dynamodb_table.model_pricing.arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "fargate_task_s3" {
  name = "${local.prefix}-fargate-s3"
  role = aws_iam_role.fargate_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PayloadBucket"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["${aws_s3_bucket.payload.arn}/*"]
    }]
  })
}

# CloudWatch log group for Fargate worker
resource "aws_cloudwatch_log_group" "fargate_worker" {
  name              = "/aws/ecs/${local.prefix}-worker"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Task definition — single container, all models
resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.prefix}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.fargate_execution.arn
  task_role_arn            = aws_iam_role.fargate_task.arn

  container_definitions = jsonencode([{
    name      = "worker"
    image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${local.prefix}-worker:latest"
    essential = true

    environment = [
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
      { name = "TABLE_JOB_STATE", value = aws_dynamodb_table.job_state.name },
      { name = "TABLE_MONTHLY_USAGE", value = aws_dynamodb_table.monthly_usage.name },
      { name = "TABLE_MODEL_PRICING", value = aws_dynamodb_table.model_pricing.name },
      { name = "TABLE_REQUEST_LEDGER", value = aws_dynamodb_table.request_ledger.name },
      { name = "PAYLOAD_BUCKET", value = aws_s3_bucket.payload.id },
      { name = "TABLE_CONCURRENCY_SEMAPHORE", value = aws_dynamodb_table.concurrency_semaphore.name },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.fargate_worker.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "worker"
      }
    }
  }])

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
