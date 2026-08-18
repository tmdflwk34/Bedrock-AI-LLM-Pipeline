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
        # long-output-streaming 13.1. `bedrock:Converse` was here and granted
        # nothing: it is not an IAM action. AWS authorizes the Converse API on
        # the *base* inference actions — Converse -> bedrock:InvokeModel,
        # ConverseStream -> bedrock:InvokeModelWithResponseStream
        # (docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference-call).
        # So the worker's Converse calls have always been authorized by the
        # InvokeModel entry beside it, and removing the invalid one changes no
        # effective permission. iam.tf already carried this note for the Lambda
        # role; this file had not caught up.
        #
        # `InvokeModelWithResponseStream` is the *new* grant, and it is additive:
        # nothing in the shipped worker calls ConverseStream today
        # (worker/main.py uses buffered `converse`). It exists so the A3
        # experiment (task 12.3, scripts/long_output_verify/s8_a3_chunk_reset.py)
        # can run on this same task role, and so a later switch to streaming is
        # not blocked on an IAM change. Without it ConverseStream is an
        # AccessDeniedException, which would read as "streaming does not work"
        # rather than "streaming was not permitted".
        Sid      = "BedrockInvoke"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = ["*"]
      },
      {
        # Async OpenAI Responses (gpt-5.4/5.5/gpt-oss) via bedrock-mantle.
        # us-west-2 + us-east-2 (gpt-5.5 is published only in us-east-2).
        Sid    = "BedrockMantleResponses"
        Effect = "Allow"
        Action = ["bedrock-mantle:CreateInference"]
        Resource = [
          "arn:aws:bedrock-mantle:us-west-2:${data.aws_caller_identity.current.account_id}:project/default",
          "arn:aws:bedrock-mantle:us-east-2:${data.aws_caller_identity.current.account_id}:project/default",
        ]
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
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          aws_dynamodb_table.monthly_usage.arn,
        ]
      },
      {
        Sid      = "SemaphoreRelease"
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.concurrency_semaphore.arn]
      },
      {
        Sid      = "LedgerPutOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid      = "PricingRead"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:Scan"]
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
    name = "worker"

    # Pinned by digest, not by `:latest` (long-output-streaming 5.5, design.md
    # U4). A tag is a mutable pointer: with `:latest` the question "which image
    # does task definition revision N run?" has no answer, so **no rollback is
    # decisive** — reverting to an earlier revision reverts the declared values
    # and silently keeps whatever `:latest` happens to point at today.
    #
    # The digest currently pinned is the one `:latest` resolved to when this
    # pin was made, so the code that runs does not change. Evidence and method
    # are recorded on var.worker_image_digest in variables.tf.
    #
    # Consequence, stated so it is not discovered later: pushing a new image no
    # longer reaches running tasks. A worker code change now takes a build, a
    # push, a digest bump here (a new revision), and an apply. That is the cost
    # of determinism and it is the point of this pin.
    image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${local.prefix}-worker@${var.worker_image_digest}"
    essential = true

    # Provenance of the image above, readable from a running container. The OCI
    # key is the conventional one for "which source revision is this".
    dockerLabels = {
      "org.opencontainers.image.revision" = var.worker_source_commit
    }

    # Stop grace for the worker's SIGTERM handler (long-output-streaming 5.3,
    # design.md C4-a). 120 is the Fargate maximum.
    #
    # **This 120 is the real grace, and it is NOT the 7800 - 7500 = 300 headroom
    # between the RunTask timeout and the worker's own deadline.** Those 300s are
    # provisioning and polling slack in the orchestration layer; they buy the
    # handler nothing. What the handler actually gets is this value: SIGTERM
    # arrives, and SIGKILL follows 120s later no matter what else is true.
    #
    # Why the default 30 is not enough: the handler has to fit 3 DynamoDB writes
    # (reservation delete, JobState record, semaphore release — the release
    # itself walks slots until its conditional write lands) plus 1 ledger write,
    # each of which can be retried by botocore against a cold connection. 30s
    # leaves no margin for a throttled table, and a truncated cleanup is exactly
    # the leak this task closes: a RUNNING row and a budget hold per cancel.
    stopTimeout = 120

    environment = [
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
      { name = "TABLE_JOB_STATE", value = aws_dynamodb_table.job_state.name },
      { name = "TABLE_MONTHLY_USAGE", value = aws_dynamodb_table.monthly_usage.name },
      { name = "TABLE_MODEL_PRICING", value = aws_dynamodb_table.model_pricing.name },
      { name = "TABLE_REQUEST_LEDGER", value = aws_dynamodb_table.request_ledger.name },
      { name = "PAYLOAD_BUCKET", value = aws_s3_bucket.payload.id },
      { name = "TABLE_CONCURRENCY_SEMAPHORE", value = aws_dynamodb_table.concurrency_semaphore.name },
      { name = "WARNING_CHECK_FUNCTION_NAME", value = "${local.prefix}-gateway:live" },

      # ---------------------------------------------------------------------
      # Deadline budget (long-output-streaming 5.5, design.md §C4 "폭발 반경")
      #
      # These four are the worker's time budget, and they live here rather than
      # in the image on purpose: **the image is deployed once, the limits move
      # by task-definition revision.** Raising a ceiling must not require a
      # rebuild, and rolling one back must not require finding the old image.
      #
      # Task 5.5 injected these four at the values already compiled into
      # worker/main.py, so that revision moved the values' home without moving
      # the values. **Task 7.2 is the revision that moves two of them** — the
      # total deadline to 7500 and the per-attempt cap to 7200 — and it is
      # therefore the first revision that changes how long a generation may
      # run. The two that stay (reserve 300, floor 300) still match the image
      # defaults; the two that move no longer do, which is exactly why they
      # live here and not in the image.
      #
      # Values are strings because a container `environment` value is a string
      # in the ECS API. worker/main.py `_env_seconds` parses them and falls back
      # to its own default (with a log line) on anything unparseable, so a typo
      # here degrades to the pre-7.2 behaviour instead of killing every job.
      #
      # The nesting these must respect, whole chain, after this task:
      #   job_state TTL 604800 > reservation 10800 = semaphore 10800
      #     > state machine 8100 > RunTask 7800 > total deadline 7500
      #     > per-attempt 7200
      # i.e. 604800 > 10800 = 10800 > 8100 > 7800 > 7500 > 7200. Inner layers
      # expire first so the code that *owns* the job writes its own termination
      # record and releases the reservation and the slot; if an outer layer went
      # first, nobody would clean up (design.md §타임아웃 중첩). The state
      # machine and RunTask ends of the chain were placed by task 5.4 and the
      # TTLs by 7.3, so this edit is the link that completes it. Checked against
      # the plan by tasks 2.4 / 5.7 / 7.8 rather than asserted here.

      # Wall-clock budget for the whole process, fixed on entry.
      # Raised 2100 -> 7500 by task 7.2. **HC2 is met here**: a single
      # generation may now exceed one hour.
      #
      # Why 7500: 7200 of generation + 300 held back for settlement and cleanup
      # (SETTLEMENT_RESERVE_SECONDS below). It is not a guess with headroom —
      # 7500 - 300 is exactly the per-attempt cap, so a fresh process grants its
      # first attempt the full 7200 and nothing is left over to give away.
      #
      # **Worst-case process runtime is now 7500s, not 11 x 7200 + 1305 =
      # 80,505s.** That second number is what raising the per-attempt ceiling
      # would have cost *without* a total deadline: MAX_RETRIES = 10 means up to
      # 11 attempts, each able to burn the full read timeout, plus at most 1305s
      # of backoff — roughly 22 hours holding a slot and a budget hold. Task 4.2
      # put the deadline in first precisely so this raise could not produce that
      # number: every attempt is granted min(ceiling, remaining budget), so the
      # attempts cannot sum past the deadline, and an attempt that consumes the
      # full 7200 leaves 0 < 300 (MIN_VIABLE_ATTEMPT_SECONDS) and is not retried.
      # The pathological chain is arithmetically unreachable, which is why the
      # total deadline was a precondition of this raise rather than a companion
      # to it.
      #
      # Rollback: revert this line to "2100" (with PER_ATTEMPT_TIMEOUT_SECONDS
      # back to "1800") and apply — a new task-definition revision, new tasks
      # only, in-flight tasks unaffected. No rebuild: the image reads both from
      # the environment. Do NOT roll the TTLs (10800) back with it; a shorter
      # TTL would expire the reservations of jobs already running.
      { name = "WORKER_TOTAL_DEADLINE_SECONDS", value = "7500" },

      # Ceiling for a single Bedrock attempt (the botocore read timeout).
      # Raised 1800 -> 7200 by task 7.2. This is the value that removes the
      # observed wall: the 56 audited failures clustered at ~1800s of container
      # time were this timeout firing, not a Fargate or Step Functions limit.
      #
      # **This is a cap, not an override** (task 7.1, worker/main.py
      # `attempt_ceiling_seconds`): the granted timeout is
      # min(model Duration_Ceiling, this cap, remaining budget). Raising it to
      # 7200 therefore lands per family, and the model declaration keeps
      # binding where it is lower:
      #
      #   Claude (us.anthropic.*)      min(7200, 7200) = 7200
      #   OpenAI (openai.gpt-5.6-*)    min(7200, 7200) = 7200   (Converse path;
      #                                  the mantle HTTP path still carries its
      #                                  own 1800 until task 7.4 folds it into
      #                                  the same budget rule)
      #   Nova   (amazon.nova*, nova)  min(3600, 7200) = 3600   — the model
      #                                  declaration wins. AWS published a
      #                                  60-minute per-request model timeout for
      #                                  Nova alone; granting 7200 would only
      #                                  buy a 408 ModelTimeoutException we
      #                                  could have predicted.
      #   anything unmatched           min(1800, 7200) = 1800   — the
      #                                  DEFAULT_DURATION_CEILING_SECONDS
      #                                  fallback, deliberately left at today's
      #                                  value. Not hypothetical: the image
      #                                  models (stability.*,
      #                                  amazon.titan-image-generator-v2:0)
      #                                  match no family marker, and R1.1 wants
      #                                  a declared ceiling to be true rather
      #                                  than generous.
      #
      # So this line raises the ceiling for the models that were hitting the
      # wall and leaves every other family exactly where it was. Because the cap
      # can only lower the model's own number, no revision of this file can hand
      # out more time than a model declares.
      #
      # Rollback: revert to "1800". The cap alone restores today's effective
      # ceiling for every family without touching the image.
      { name = "PER_ATTEMPT_TIMEOUT_SECONDS", value = "7200" },

      # Tail held back from generation for terminating honestly: termination
      # record, settlement, reservation delete, result write, semaphore release.
      # worker/main.py DEFAULT_SETTLEMENT_RESERVE_SECONDS.
      #
      # Unchanged by task 7.2, and that is the whole of the 7500 arithmetic:
      # 7200 + this 300 = 7500. The writes it pays for do not get slower because
      # the generation got longer, so scaling it with the deadline would only
      # take time away from generation. (Distinct from `stopTimeout` above: this
      # reserve is the worker budgeting for its own shutdown, that one is how
      # long ECS waits after SIGTERM.)
      { name = "SETTLEMENT_RESERVE_SECONDS", value = "300" },

      # Floor under which a retry is not started — the retry budget is bounded
      # by time, not by a count. worker/main.py MIN_VIABLE_ATTEMPT_SECONDS.
      #
      # Unchanged by task 7.2. It is what makes the raise safe: with the cap at
      # 7200 and the deadline at 7500, an attempt that burns its full grant
      # leaves nothing above this floor, so no retry follows and the worst case
      # stays one generation long. Raising this floor alongside the ceiling
      # would not buy anything; lowering it would let a doomed second attempt
      # start inside the settlement reserve.
      { name = "MIN_VIABLE_ATTEMPT_SECONDS", value = "300" },
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

    # Provenance, queryable per revision without parsing the container
    # definition: `aws ecs describe-task-definition --include TAGS` answers
    # "which source produced the image this revision runs?" (design.md U4).
    # The digest itself is not duplicated here — it is already unambiguous in
    # the image reference, and a second copy could only ever drift from it.
    SourceCommit = var.worker_source_commit
  }
}
