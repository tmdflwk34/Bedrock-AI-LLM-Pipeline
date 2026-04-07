# =============================================================================
# v2: Step Functions Standard — Job Orchestrator
# =============================================================================

resource "aws_iam_role" "sfn_execution" {
  name = "${local.prefix}-sfn-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_iam_role_policy" "sfn_ecs" {
  name = "${local.prefix}-sfn-ecs"
  role = aws_iam_role.sfn_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RunFargateTask"
        Effect = "Allow"
        Action = ["ecs:RunTask", "ecs:StopTask", "ecs:DescribeTasks"]
        Resource = ["*"]
        Condition = {
          ArnEquals = {
            "ecs:cluster" = aws_ecs_cluster.gateway.arn
          }
        }
      },
      {
        Sid    = "PassRoles"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.fargate_execution.arn,
          aws_iam_role.fargate_task.arn,
        ]
      },
      {
        Sid    = "DynamoDBJobState"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          aws_dynamodb_table.concurrency_semaphore.arn,
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = ["*"]
      },
      {
        Sid    = "EventBridge"
        Effect = "Allow"
        Action = [
          "events:PutTargets",
          "events:PutRule",
          "events:DescribeRule",
        ]
        Resource = ["*"]
      },
    ]
  })
}

# State machine log group
resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/states/${local.prefix}-job-orchestrator"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# The state machine definition
resource "aws_sfn_state_machine" "job_orchestrator" {
  name     = "${local.prefix}-job-orchestrator"
  role_arn = aws_iam_role.sfn_execution.arn

  definition = jsonencode({
    Comment = "Bedrock Gateway async job orchestrator"
    StartAt = "UpdateJobQueued"
    TimeoutSeconds = 3600
    States = {
      UpdateJobQueued = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression    = "SET #s = :status, updated_at = :ts"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status" = { "S" = "QUEUED" }
            ":ts"     = { "S.$" = "$$.State.EnteredTime" }
          }
        }
        ResultPath = null
        Next       = "RunFargateTask"
      }
      RunFargateTask = {
        Type     = "Task"
        Resource = "arn:aws:states:::ecs:runTask.sync"
        Parameters = {
          Cluster        = aws_ecs_cluster.gateway.arn
          TaskDefinition = aws_ecs_task_definition.worker.arn
          LaunchType     = "FARGATE"
          NetworkConfiguration = {
            AwsvpcConfiguration = {
              Subnets        = var.private_subnet_ids
              SecurityGroups = var.fargate_security_group_ids
              AssignPublicIp = "DISABLED"
            }
          }
          Overrides = {
            ContainerOverrides = [{
              Name = "worker"
              Environment = [
                { "Name" = "JOB_ID", "Value.$" = "$.job_id" },
                { "Name" = "REQUEST_ID", "Value.$" = "$.request_id" },
                { "Name" = "PRINCIPAL_ID", "Value.$" = "$.principal_id" },
                { "Name" = "MODEL_ID", "Value.$" = "$.model_id" },
                { "Name" = "REGION", "Value.$" = "$.region" },
                { "Name" = "PRICING_VERSION", "Value.$" = "$.pricing_version" },
                { "Name" = "PAYLOAD_REF", "Value.$" = "$.payload_ref" },
              ]
            }]
          }
        }
        TimeoutSeconds = 3600
        ResultPath     = "$.taskResult"
        Next           = "UpdateJobSucceeded"
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.error"
          Next        = "UpdateJobFailed"
        }]
      }
      UpdateJobSucceeded = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression    = "SET #s = :status, updated_at = :ts, completed_at = :ts"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status" = { "S" = "SUCCEEDED" }
            ":ts"     = { "S.$" = "$$.State.EnteredTime" }
          }
        }
        End = true
      }
      UpdateJobFailed = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression    = "SET #s = :status, updated_at = :ts, completed_at = :ts, error_message = :err"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status" = { "S" = "FAILED" }
            ":ts"     = { "S.$" = "$$.State.EnteredTime" }
            ":err"    = { "S.$" = "States.Format('{}', $.error)" }
          }
        }
        End = true
      }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
