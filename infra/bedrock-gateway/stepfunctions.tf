# =============================================================================
# v2: Step Functions Standard — Job Orchestrator
# =============================================================================

locals {
  # Error names for "the ConditionExpression declined the write" (task 5.4).
  #
  # This state machine uses the *optimized* DynamoDB integration
  # (`arn:aws:states:::dynamodb:updateItem`), whose exceptions are prefixed
  # `DynamoDB.` — the AWS integration docs call out that the SDK-style
  # ("standard connection") prefix is the mixed-case `DynamoDb.` instead. Both
  # spellings are listed because the cost of the extra string is nothing and the
  # cost of guessing wrong is an execution that ends FAILED on a normal path.
  # An error name that never matches is inert in ASL.
  sfn_conditional_check_failed = [
    "DynamoDB.ConditionalCheckFailedException",
    "DynamoDb.ConditionalCheckFailedException",
  ]
}

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

  # Timeout nesting (task 5.4, D1, R1.3) — the two values below must stay
  # ordered `state machine > RunTask`, and the gap must be wide enough for the
  # catch branch to run.
  #
  # Before: both were 3600. `UpdateJobQueued` starts the execution clock first,
  # so the *top-level* timeout always fired first, and AWS documents the
  # top-level state-machine timeout as **not catchable** — `UpdateJobFailed`
  # never ran and the job row sat at `RUNNING` until its 7-day TTL. The leak was
  # invisible only because the worker's 1800s read timeout always ended things
  # earlier; raising the ceiling is what makes D1 fire for the first time, which
  # is why this wiring lands *before* any ceiling change.
  #
  # After: 8100 / 7800. The 300s gap is for the catch branch (one DynamoDB
  # UpdateItem), not for the task, so the Task-level timeout is now the one that
  # fires and it is catchable.
  #
  # This does NOT depend on `States.Timeout` actually stopping the Fargate task
  # (U3 — unverified). The primary stopper is the worker's own total deadline
  # (task 4.2, 2100s today), backed by SIGTERM + `stopTimeout = 120` (task 5.3).
  # `States.Timeout` here is the *record-keeping* backstop: whatever happens to
  # the container, the job row reaches a terminal state.
  #
  # Actual run time does not change with this task: the task definition is still
  # per-attempt 1800 / total deadline 2100. Only the wiring moves.
  definition = jsonencode({
    Comment = "Bedrock Gateway async job orchestrator"
    StartAt = "UpdateJobQueued"
    TimeoutSeconds = 8100
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
        TimeoutSeconds = 7800
        ResultPath     = "$.taskResult"
        Next           = "UpdateJobSucceeded"
        # ORDER IS LOAD-BEARING. Catchers are evaluated top to bottom and the
        # first match wins, so `States.ALL` must come last: put it first and the
        # specific catcher below it is dead code, silently — the definition still
        # validates, still deploys, and every timeout records FAILED with no
        # reason. Task 5.7 pins this ordering as a configuration check for
        # exactly that reason.
        Catch = [
          {
            ErrorEquals = ["States.Timeout"]
            ResultPath  = "$.error"
            Next        = "UpdateJobTimedOut"
          },
          {
            ErrorEquals = ["States.ALL"]
            ResultPath  = "$.error"
            Next        = "UpdateJobFailed"
          },
        ]
      }
      # ---------------------------------------------------------------------
      # The terminal-status guard shared by the three writers below (task 5.4)
      # ---------------------------------------------------------------------
      #
      # Every one of these states used to write `#s = :status` unconditionally,
      # which made the *last* writer win instead of the *best-informed* one. The
      # worker classifies its own ending (task 4.3/4.4) and then exits non-zero,
      # so the state machine always writes after it:
      #
      #   worker writes TIMED_OUT + `termination_reason = duration_limit`,
      #   exits 1  ->  `States.TaskFailed`  ->  UpdateJobFailed writes FAILED
      #   over it  ->  `status = FAILED` with `termination_reason =
      #   duration_limit`, which R5.3 (duration_limit => TIMED_OUT) forbids.
      #
      #   worker handles SIGTERM, writes CANCELED, exits 143  ->  same route,
      #   CANCELED becomes FAILED, breaking R9.1. Task 5.3 called this out and
      #   accepted it *because this guard did not exist yet* (see the
      #   `EXIT_CODE_SIGTERM` comment in worker/main.py).
      #
      # The rule, one line: **a writer may set its own status or overwrite a
      # non-terminal one; it may not overwrite somebody else's terminal status.**
      #
      #   ConditionExpression = attribute_not_exists(#s)
      #                         OR NOT #s IN (<the other terminal statuses>)
      #
      # `attribute_not_exists(#s)` is what keeps the original purpose intact: a
      # missing row (or a row that never got a status) is still driven to a
      # terminal state, so the leak this branch exists to stop is still stopped.
      # Plain `if_not_exists(#s, :status)` would NOT do — it also declines to
      # write over `RUNNING`, which is precisely the row that leaks.
      #
      # Each writer omits its *own* status from the list on purpose, so the
      # write stays idempotent and the additive fields (`orchestration_error`,
      # `termination_reason`) still land when the worker reached the same verdict
      # by itself. That is not a status change, so nothing is overwritten.
      #
      # Condition failure is a NORMAL outcome here, not an error: it means a
      # better-informed writer got there first. Step Functions surfaces it as a
      # task failure, so each state catches it and ends the execution at
      # `TerminalRecordPreserved`. Without that catch this fix would trade a
      # wrong job status for a failed execution, and the alarm on failed
      # executions would make the correct behaviour look broken.
      #
      # Mirrors worker/main.py `_FOREIGN_TERMINAL_STATUSES` (task 5.3); this side
      # adds CANCELED, which the worker's SIGTERM path deliberately excludes
      # because it is the writer of that value.
      UpdateJobSucceeded = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression = "SET #s = :status, updated_at = :ts, completed_at = :ts"
          # Reached only on container exit 0, which today means the worker wrote
          # SUCCEEDED itself — so the guard is normally satisfied trivially. It
          # is here for the case that is not normal: a cancel that lands while
          # the worker is finishing, where writing SUCCEEDED over CANCELED would
          # be a false accounting statement (R9.1) rather than a lost detail.
          ConditionExpression      = "attribute_not_exists(#s) OR NOT #s IN (:fin_failed, :fin_timed_out, :fin_canceled)"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status"        = { "S" = "SUCCEEDED" }
            ":ts"            = { "S.$" = "$$.State.EnteredTime" }
            ":fin_failed"    = { "S" = "FAILED" }
            ":fin_timed_out" = { "S" = "TIMED_OUT" }
            ":fin_canceled"  = { "S" = "CANCELED" }
          }
        }
        Catch = [{
          ErrorEquals = local.sfn_conditional_check_failed
          ResultPath  = null
          Next        = "TerminalRecordPreserved"
        }]
        End = true
      }
      # Task 5.4: the `States.Timeout` branch. This is the state that closes D1 —
      # a Task-level timeout is catchable, so an over-running job now reaches a
      # terminal status instead of sitting at `RUNNING` for seven days.
      #
      # `termination_reason = duration_limit` is written here and NOT in
      # `UpdateJobFailed` for one reason: this catcher knows the cause. R5.3
      # pairs `duration_limit` with `TIMED_OUT`, and both are set in the same
      # UpdateItem, so the pair cannot come apart.
      #
      # `error_message` follows task 5.2 exactly: fill only when absent, and put
      # the orchestration event in its own field. If the worker managed to write
      # a cause before it was stopped, that cause is what a user sees.
      UpdateJobTimedOut = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression         = "SET #s = :status, updated_at = :ts, completed_at = :ts, termination_reason = :reason, error_message = if_not_exists(error_message, :err), orchestration_error = :err"
          ConditionExpression      = "attribute_not_exists(#s) OR NOT #s IN (:fin_succeeded, :fin_failed, :fin_canceled)"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status"        = { "S" = "TIMED_OUT" }
            ":reason"        = { "S" = "duration_limit" }
            ":ts"            = { "S.$" = "$$.State.EnteredTime" }
            ":err"           = { "S.$" = "States.Format('{}', $.error)" }
            ":fin_succeeded" = { "S" = "SUCCEEDED" }
            ":fin_failed"    = { "S" = "FAILED" }
            ":fin_canceled"  = { "S" = "CANCELED" }
          }
        }
        Catch = [{
          ErrorEquals = local.sfn_conditional_check_failed
          ResultPath  = null
          Next        = "TerminalRecordPreserved"
        }]
        End = true
      }
      # D13 fix (task 5.2): this state used to overwrite `error_message` with the
      # ECS event JSON, destroying the exception string the worker had just
      # written. The 54 FAILED rows audited in task 9.1 are 54/54
      # `ecs_event_json` (2,755–2,758 chars) for exactly this reason: the audit
      # could only date the 1800s read-timeout cluster by timestamp arithmetic
      # because no cause string survived.
      #
      # Two changes, both additive in information terms:
      #   - `error_message` is filled only when absent (`if_not_exists`). The
      #     worker's value wins; the state machine covers the case where the
      #     worker never got to write one (task failed to start, container
      #     killed).
      #   - the orchestration event goes to its own field, `orchestration_error`,
      #     so nothing is discarded.
      #
      # `termination_reason` is deliberately NOT written here. See the report /
      # design D13: a `States.ALL` catch does not know the cause, and R5.1's six
      # values contain no orchestration-failure member. Worker task 4.3 already
      # established the rule — request errors and unknown exceptions record
      # FAILED with no reason rather than a fabricated `server_error`. The
      # reasons the orchestrator does know are written by the states that know
      # them: `UpdateJobTimedOut` (task 5.4, `duration_limit`) and the watchdog.
      UpdateJobFailed = {
        Type     = "Task"
        Resource = "arn:aws:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.job_state.name
          Key = {
            "job_id" = { "S.$" = "$.job_id" }
          }
          UpdateExpression = "SET #s = :status, updated_at = :ts, completed_at = :ts, error_message = if_not_exists(error_message, :err), orchestration_error = :err"
          # Task 5.4. FAILED is absent from the guard list on purpose: the
          # dominant real case is a worker that already wrote FAILED and exited
          # non-zero, and FAILED-over-FAILED is not a status change, so letting
          # it through is what keeps `orchestration_error` (the ECS stop reason,
          # the exit code) landing on the row that needs it — the whole point of
          # task 5.2. The three statuses that ARE listed are the ones this state
          # would be lying about.
          ConditionExpression      = "attribute_not_exists(#s) OR NOT #s IN (:fin_succeeded, :fin_timed_out, :fin_canceled)"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":status" = { "S" = "FAILED" }
            ":ts"     = { "S.$" = "$$.State.EnteredTime" }
            # Not truncated: JSONPath intrinsics have no substring/length
            # operation (the only string intrinsic is delimiter-based
            # `States.StringSplit`), so there is no in-definition equivalent of
            # the worker's `error_msg[:500]`. Item-size delta versus today is
            # bounded — the same string was already being stored, just in
            # `error_message`.
            ":err"           = { "S.$" = "States.Format('{}', $.error)" }
            ":fin_succeeded" = { "S" = "SUCCEEDED" }
            ":fin_timed_out" = { "S" = "TIMED_OUT" }
            ":fin_canceled"  = { "S" = "CANCELED" }
          }
        }
        Catch = [{
          ErrorEquals = local.sfn_conditional_check_failed
          ResultPath  = null
          Next        = "TerminalRecordPreserved"
        }]
        End = true
      }
      # Where a failed terminal-status guard lands (task 5.4). A `Succeed` state,
      # because nothing went wrong: the row already carries a terminal status
      # written by whoever knew more, so there is nothing left to record and no
      # resource left held. Routing this to a failure instead would fire the
      # failed-execution alarm on the code path working as designed.
      #
      # No DynamoDB write here: the point of arriving is that the record is
      # already correct.
      TerminalRecordPreserved = {
        Type    = "Succeed"
        Comment = "JobState already held a terminal status written by a better-informed writer; guard declined the overwrite (task 5.4)."
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
