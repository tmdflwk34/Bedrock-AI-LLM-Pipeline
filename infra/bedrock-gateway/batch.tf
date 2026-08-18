# =============================================================================
# bedrock-batch-inference-gateway — Batch S3 bucket (design §4.5, R13.1)
# =============================================================================
# STRICTLY ADDITIVE: this file introduces ONLY new resources. No existing .tf
# file is modified by this feature.
#
# APPLY POLICY: targeted-apply ONLY, e.g.
#   terraform apply \
#     -target=aws_s3_bucket.batch \
#     -target=aws_s3_bucket_server_side_encryption_configuration.batch \
#     -target=aws_s3_bucket_lifecycle_configuration.batch \
#     -target=aws_s3_bucket_public_access_block.batch \
#     -target=aws_iam_role_policy.batch_gateway \
#     -target=aws_iam_role.batch_service \
#     -target=aws_iam_role_policy.batch_service \
#     -target=aws_iam_role.batch_settlement \
#     -target=aws_iam_role_policy_attachment.batch_settlement_basic \
#     -target=aws_iam_role_policy.batch_settlement \
#     -target=aws_lambda_function.batch_settlement \
#     -target=aws_iam_role.batch_reconciler \
#     -target=aws_iam_role_policy_attachment.batch_reconciler_basic \
#     -target=aws_iam_role_policy.batch_reconciler \
#     -target=aws_lambda_function.batch_reconciler \
#     -target=aws_cloudwatch_event_rule.batch_settlement \
#     -target=aws_cloudwatch_event_target.batch_settlement \
#     -target=aws_lambda_permission.allow_eventbridge_invoke_batch_settlement \
#     -target=aws_cloudwatch_event_rule.batch_reconciler \
#     -target=aws_cloudwatch_event_target.batch_reconciler \
#     -target=aws_lambda_permission.allow_eventbridge_invoke_batch_reconciler \
#     -var-file=env/dev.tfvars -lock=false
# NEVER run a full `terraform apply` / `terraform plan` for this feature.
#
# Naming + env/account_id sourcing mirror the existing payload bucket (s3.tf):
#   env        -> var.environment
#   account_id -> data.aws_caller_identity.current.account_id  (declared in s3.tf;
#                 reused here, NOT redeclared, to avoid a duplicate data source)
# =============================================================================

resource "aws_s3_bucket" "batch" {
  bucket = "bedrock-gw-${var.environment}-batch-${data.aws_caller_identity.current.account_id}"

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "batch" {
  bucket = aws_s3_bucket.batch.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Expire input/ and output/ JSONL objects 30 days after creation (R13.1).
resource "aws_s3_bucket_lifecycle_configuration" "batch" {
  bucket = aws_s3_bucket.batch.id

  rule {
    id     = "expire-batch-objects"
    status = "Enabled"

    # Apply to all objects in the bucket (both input/ and output/ prefixes).
    # An explicit empty filter is required by aws provider v5 (avoids the
    # "one of filter/prefix is required" deprecation warning).
    filter {}

    expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "batch" {
  bucket = aws_s3_bucket.batch.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# IAM — additive grants for the Bedrock batch inference route
# (design §"IAM and Infrastructure", §4.5; R10.1)
# =============================================================================
# STRICTLY ADDITIVE: the gateway exec role used by aws_lambda_function.gateway is
# `aws_iam_role.lambda_exec` (declared in iam.tf, role attribute
# `aws_iam_role.lambda_exec.arn`). We attach a SEPARATE, NEW aws_iam_role_policy
# to that existing role via `role = aws_iam_role.lambda_exec.id` — we do NOT edit
# the existing inline policies (aws_iam_role_policy.bedrock / .dynamodb / .s3_payload
# / etc.) so this grant is purely additive and independently target-appliable.
# -----------------------------------------------------------------------------

# Additive batch grant on the EXISTING gateway Lambda exec role.
resource "aws_iam_role_policy" "batch_gateway" {
  name = "${local.prefix}-batch-gateway"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # LIVE-VERIFY (Task 10.3): the exact Bedrock batch IAM action namespace
      # (`bedrock:CreateModelInvocationJob` / `:GetModelInvocationJob` /
      # `:ListModelInvocationJobs`) must be confirmed against the deployed account
      # before enabling the route. Resource is "*" pending that confirmation; Task
      # 10.3 may scope it to a model-invocation-job ARN pattern.
      {
        Sid    = "BedrockBatchJobs"
        Effect = "Allow"
        Action = [
          "bedrock:CreateModelInvocationJob",
          "bedrock:GetModelInvocationJob",
          "bedrock:ListModelInvocationJobs",
        ]
        Resource = ["*"]
      },
      # Scoped read/write on the batch bucket (input/ upload + output/ read-back).
      {
        Sid    = "BatchBucketObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.batch.arn,
          "${aws_s3_bucket.batch.arn}/*",
        ]
      },
      # PassRole so the gateway can hand the Bedrock batch service role to the
      # CreateModelInvocationJob call. LIVE-VERIFY (Task 10.3): the exact PassRole
      # shape / condition key may need refinement against the live API.
      {
        Sid      = "PassBatchServiceRole"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.batch_service.arn]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "bedrock.amazonaws.com"
          }
        }
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# Bedrock batch service role — assumed by Amazon Bedrock to read the input/ JSONL
# and write the output/ JSONL on behalf of a CreateModelInvocationJob (design §4.5).
# -----------------------------------------------------------------------------
resource "aws_iam_role" "batch_service" {
  name = "${local.prefix}-batch-service"

  # LIVE-VERIFY (Task 10.3): the batch service role trust/permissions required by
  # CreateModelInvocationJob must be confirmed against the deployed account.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
    }]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Scoped bucket access for the batch service role: READ on input/, WRITE on output/.
resource "aws_iam_role_policy" "batch_service" {
  name = "${local.prefix}-batch-service"
  role = aws_iam_role.batch_service.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadBatchInput"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.batch.arn}/input/*"]
      },
      {
        Sid      = "WriteBatchOutput"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.batch.arn}/output/*"]
      },
      # ListBucket scoped (via prefix conditions) so the service can enumerate the
      # input/ and output/ prefixes without bucket-wide listing.
      {
        Sid      = "ListBatchPrefixes"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.batch.arn]
        Condition = {
          StringLike = {
            "s3:prefix" = ["input/*", "output/*"]
          }
        }
      },
      # LIVE-VERIFIED (2026-06, Task 10): Amazon Bedrock batch REQUIRES the
      # service role to hold bedrock:InvokeModel on the model it runs — a job
      # without it fails with "Customer doesn't have permissions to invokeModel"
      # (observed on job bldx5ozqo8rq). Per the official batch service-role doc
      # (batch-iam-sr.html "Permissions to run batch inference with inference
      # profiles"), cross-region (us./global.) profile jobs need InvokeModel on
      # BOTH the inference-profile AND the underlying foundation-model in every
      # region of the profile. Foundation models are AWS-owned, so they are
      # granted by ARN pattern (NO org/ownership conditions — the doc warns those
      # break FM access). The gateway's allowlist + per-principal policy remain
      # the authorization gate for WHICH model a user may submit; this role just
      # needs to invoke whatever the gateway already authorized and created.
      {
        Sid    = "InvokeModelForBatch"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/*",
          "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/*",
          "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:application-inference-profile/*",
        ]
      },
    ]
  })
}

# =============================================================================
# Settlement_Lambda + Reconciler Lambda (design §3.6, §3.7, §"IAM and
# Infrastructure"). STRICTLY ADDITIVE — new resources only.
# =============================================================================
# Packaging mirrors the model_sync Lambda (auto_sync.tf): archive_file does not
# support multiple source_dir entries, so we bundle individual `source` blocks.
# Both Lambdas package BOTH lambda/batch_settlement.py and
# lambda/batch_reconciler.py at the zip root, because batch_reconciler.py does a
# top-level `import batch_settlement` and shares its _settle_batch_job() path.
# Runtime is python3.12 for both functions.
# -----------------------------------------------------------------------------

data "archive_file" "batch_settlement_zip" {
  type        = "zip"
  output_path = "${path.module}/.build/batch_settlement.zip"

  source {
    content  = file("${path.module}/lambda/batch_settlement.py")
    filename = "batch_settlement.py"
  }
  source {
    content  = file("${path.module}/lambda/batch_reconciler.py")
    filename = "batch_reconciler.py"
  }
}

data "archive_file" "batch_reconciler_zip" {
  type        = "zip"
  output_path = "${path.module}/.build/batch_reconciler.zip"

  source {
    content  = file("${path.module}/lambda/batch_settlement.py")
    filename = "batch_settlement.py"
  }
  source {
    content  = file("${path.module}/lambda/batch_reconciler.py")
    filename = "batch_reconciler.py"
  }
}

# -----------------------------------------------------------------------------
# Settlement_Lambda exec role (scoped)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "batch_settlement" {
  name = "${local.prefix}-batch-settlement"

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

# CloudWatch Logs basic — mirrors aws_iam_role_policy_attachment.lambda_basic
# (iam.tf) and aws_iam_role_policy_attachment.model_sync_basic (auto_sync.tf).
resource "aws_iam_role_policy_attachment" "batch_settlement_basic" {
  role       = aws_iam_role.batch_settlement.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "batch_settlement" {
  name = "${local.prefix}-batch-settlement"
  role = aws_iam_role.batch_settlement.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "JobStateAndMonthlyUsage"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:TransactWriteItems",
        ]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          "${aws_dynamodb_table.job_state.arn}/index/*",
          aws_dynamodb_table.monthly_usage.arn,
          "${aws_dynamodb_table.monthly_usage.arn}/index/*",
        ]
      },
      {
        Sid      = "RequestLedgerPut"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid      = "ModelPricingRead"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.model_pricing.arn]
      },
      {
        Sid    = "BatchBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.batch.arn,
          "${aws_s3_bucket.batch.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_lambda_function" "batch_settlement" {
  function_name    = "${local.prefix}-batch-settlement"
  role             = aws_iam_role.batch_settlement.arn
  handler          = "batch_settlement.lambda_handler"
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 512
  filename         = data.archive_file.batch_settlement_zip.output_path
  source_code_hash = data.archive_file.batch_settlement_zip.output_base64sha256

  environment {
    variables = {
      TABLE_JOB_STATE      = aws_dynamodb_table.job_state.name
      TABLE_MONTHLY_USAGE  = aws_dynamodb_table.monthly_usage.name
      TABLE_MODEL_PRICING  = aws_dynamodb_table.model_pricing.name
      TABLE_REQUEST_LEDGER = aws_dynamodb_table.request_ledger.name
      BATCH_BUCKET         = aws_s3_bucket.batch.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.batch_settlement_basic,
    aws_iam_role_policy.batch_settlement,
  ]

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# -----------------------------------------------------------------------------
# Reconciler Lambda exec role (scoped) — same DynamoDB/S3 grants as the
# Settlement_Lambda PLUS bedrock Get/List for terminal-state reconciliation.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "batch_reconciler" {
  name = "${local.prefix}-batch-reconciler"

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

resource "aws_iam_role_policy_attachment" "batch_reconciler_basic" {
  role       = aws_iam_role.batch_reconciler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "batch_reconciler" {
  name = "${local.prefix}-batch-reconciler"
  role = aws_iam_role.batch_reconciler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "JobStateAndMonthlyUsage"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:TransactWriteItems",
        ]
        Resource = [
          aws_dynamodb_table.job_state.arn,
          "${aws_dynamodb_table.job_state.arn}/index/*",
          aws_dynamodb_table.monthly_usage.arn,
          "${aws_dynamodb_table.monthly_usage.arn}/index/*",
        ]
      },
      {
        Sid      = "RequestLedgerPut"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.request_ledger.arn]
      },
      {
        Sid      = "ModelPricingRead"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.model_pricing.arn]
      },
      {
        Sid    = "BatchBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.batch.arn,
          "${aws_s3_bucket.batch.arn}/*",
        ]
      },
      # Reconciler-only: poll Bedrock for terminal-but-unsettled jobs (design §3.7).
      # LIVE-VERIFY (Task 10.3): confirm the exact Bedrock batch action namespace.
      {
        Sid    = "BedrockBatchJobRead"
        Effect = "Allow"
        Action = [
          "bedrock:GetModelInvocationJob",
          "bedrock:ListModelInvocationJobs",
        ]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_lambda_function" "batch_reconciler" {
  function_name    = "${local.prefix}-batch-reconciler"
  role             = aws_iam_role.batch_reconciler.arn
  handler          = "batch_reconciler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 512
  filename         = data.archive_file.batch_reconciler_zip.output_path
  source_code_hash = data.archive_file.batch_reconciler_zip.output_base64sha256

  environment {
    variables = {
      TABLE_JOB_STATE      = aws_dynamodb_table.job_state.name
      TABLE_MONTHLY_USAGE  = aws_dynamodb_table.monthly_usage.name
      TABLE_MODEL_PRICING  = aws_dynamodb_table.model_pricing.name
      TABLE_REQUEST_LEDGER = aws_dynamodb_table.request_ledger.name
      BATCH_BUCKET         = aws_s3_bucket.batch.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.batch_reconciler_basic,
    aws_iam_role_policy.batch_reconciler,
  ]

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
# =============================================================================
# EventBridge wiring (design §"IAM and Infrastructure"; R7.1, R7.5)
# STRICTLY ADDITIVE — new resources only.
# =============================================================================
# Enable/disable attribute style: this repo pins aws provider `~> 5.0`
# (providers.tf) and the existing rule aws_cloudwatch_event_rule.model_sync_daily
# (auto_sync.tf) uses the `state = "ENABLED"|"DISABLED"` attribute, so we use the
# same `state` attribute here. (Older providers (<5.x) use `is_enabled = false`
# instead — that is the equivalent attribute if this is ever back-ported.)
# -----------------------------------------------------------------------------

# Settlement rule — fires the Settlement_Lambda on a Bedrock batch job
# state-change event (design §2.3, R7.1).
#
# Created DISABLED — enable only after the Task 10.1-10.3 live-verification
# checklist passes. Task 10.5 flips this to "ENABLED".
resource "aws_cloudwatch_event_rule" "batch_settlement" {
  name        = "${local.prefix}-batch-settlement"
  description = "Bedrock batch job state-change → Settlement_Lambda"
  # ENABLED (Task 10.5): LIVE-VERIFY checklist passed — source/detail-type
  # confirmed against the deployed account (10.1), IAM/PassRole + real
  # CreateModelInvocationJob confirmed (10.3/10.4). Settlement is idempotent
  # with the Reconciler (TransactWriteItems + attribute_not_exists(settled)),
  # so event-driven + scheduled settlement apply the cost exactly once.
  state = "ENABLED"

  # LIVE-VERIFY (Task 10.1): the exact EventBridge `source` and `detail-type` for
  # the Bedrock batch job state-change event MUST be confirmed against the deployed
  # account before this rule is enabled. The source/detail-type below are the
  # documented values pending that confirmation; Task 10.1 may refine them (and the
  # `detail` filter carrying job ARN/status + S3 output URI).
  event_pattern = jsonencode({
    source        = ["aws.bedrock"]
    "detail-type" = ["Batch Inference Job State Change"]
  })

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_cloudwatch_event_target" "batch_settlement" {
  rule      = aws_cloudwatch_event_rule.batch_settlement.name
  target_id = "BatchSettlementLambda"
  arn       = aws_lambda_function.batch_settlement.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_batch_settlement" {
  statement_id  = "AllowEventBridgeInvokeBatchSettlement"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.batch_settlement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.batch_settlement.arn
}

# -----------------------------------------------------------------------------
# Reconciler schedule — fixed rate(15 minutes) (design §2.4, R7.1, R7.5).
# ENABLED is safe: the Reconciler only settles terminal-but-unsettled jobs through
# the same exactly-once settlement path, and is a no-op when there is nothing to
# reconcile.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "batch_reconciler" {
  name                = "${local.prefix}-batch-reconciler"
  description         = "Every 15 min — reconcile terminal-but-unsettled Bedrock batch jobs"
  schedule_expression = "rate(15 minutes)"
  state               = "ENABLED"

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_cloudwatch_event_target" "batch_reconciler" {
  rule      = aws_cloudwatch_event_rule.batch_reconciler.name
  target_id = "BatchReconcilerLambda"
  arn       = aws_lambda_function.batch_reconciler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_batch_reconciler" {
  statement_id  = "AllowEventBridgeInvokeBatchReconciler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.batch_reconciler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.batch_reconciler.arn
}
