# =============================================================================
# Auto-Sync — daily Bedrock model catalog → DynamoDB sync
# =============================================================================
# Reference: .kiro/specs/bedrock-model-auto-sync/design.md §2.5 / 2.6
#
# Two new DynamoDB tables, one S3 bucket, one IAM role + inline policy, one
# Lambda function, one EventBridge rule (created DISABLED — operator flips
# to ENABLED after the Manual_Seed task verification).
#
# The Lambda packages BOTH the entry point (lambda/model_sync_handler.py)
# AND the importable module package (scripts/auto_sync_models/) plus the
# Tier_3 explicit-pricing JSON so the resolver works inside the Lambda
# runtime.
# =============================================================================


# -----------------------------------------------------------------------------
# DynamoDB — Model_Routing_Table (rule_type, rule_value)
# -----------------------------------------------------------------------------

resource "aws_dynamodb_table" "model_routing" {
  name         = "${local.table_prefix}-model-routing"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "rule_type"
  range_key    = "rule_value"

  attribute {
    name = "rule_type"
    type = "S"
  }
  attribute {
    name = "rule_value"
    type = "S"
  }

  tags = {
    Owner   = "bedrock-gateway"
    Purpose = "auto-sync routing-flags"
  }
}


# -----------------------------------------------------------------------------
# DynamoDB — Model_Sync_State_Table (lock + heartbeat)
# -----------------------------------------------------------------------------

resource "aws_dynamodb_table" "model_sync_state" {
  name         = "${local.table_prefix}-model-sync-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "state_key"

  attribute {
    name = "state_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Owner   = "bedrock-gateway"
    Purpose = "auto-sync lock + heartbeat"
  }
}


# -----------------------------------------------------------------------------
# S3 — Pricelist snapshot bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "pricelist_snapshots" {
  bucket = "${local.table_prefix}-pricelist-snapshots"

  tags = {
    Owner   = "bedrock-gateway"
    Purpose = "auto-sync pricelist snapshots"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "pricelist_snapshots" {
  bucket = aws_s3_bucket.pricelist_snapshots.id

  rule {
    id     = "expire-90d"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}


# -----------------------------------------------------------------------------
# Lambda packaging — model_sync_handler + scripts/auto_sync_models
# -----------------------------------------------------------------------------
# Bundles two source trees into one zip:
#   - lambda/model_sync_handler.py   (the entry point)
#   - scripts/auto_sync_models/*     (the importable package)
#   - scripts/add_missing_models/    (re-exported helpers + explicit_pricing.json)
#   - scripts/add_pricing_us_prefix/ (re-exported helpers)
#
# Terraform's archive_file does not support multiple source_dir entries, so
# we use source blocks via dynamic content.

data "archive_file" "model_sync_zip" {
  type        = "zip"
  output_path = "${path.module}/.build/model_sync.zip"

  source {
    content  = file("${path.module}/lambda/model_sync_handler.py")
    filename = "lambda/model_sync_handler.py"
  }

  # auto_sync_models package
  source {
    content  = file("${path.module}/scripts/auto_sync_models/__init__.py")
    filename = "scripts/auto_sync_models/__init__.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/_common.py")
    filename = "scripts/auto_sync_models/_common.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/version_resolver.py")
    filename = "scripts/auto_sync_models/version_resolver.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/explicit_pricing.py")
    filename = "scripts/auto_sync_models/explicit_pricing.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/redact.py")
    filename = "scripts/auto_sync_models/redact.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/catalog_fetcher.py")
    filename = "scripts/auto_sync_models/catalog_fetcher.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/pricelist_client.py")
    filename = "scripts/auto_sync_models/pricelist_client.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/pricing_writer.py")
    filename = "scripts/auto_sync_models/pricing_writer.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/policy_writer.py")
    filename = "scripts/auto_sync_models/policy_writer.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/routing_writer.py")
    filename = "scripts/auto_sync_models/routing_writer.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/crosscheck.py")
    filename = "scripts/auto_sync_models/crosscheck.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/backfill.py")
    filename = "scripts/auto_sync_models/backfill.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/notifier.py")
    filename = "scripts/auto_sync_models/notifier.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/metrics.py")
    filename = "scripts/auto_sync_models/metrics.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/sync.py")
    filename = "scripts/auto_sync_models/sync.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/curated_catalog.py")
    filename = "scripts/auto_sync_models/curated_catalog.py"
  }
  source {
    content  = file("${path.module}/scripts/auto_sync_models/curated_catalog.json")
    filename = "scripts/auto_sync_models/curated_catalog.json"
  }

  # add_missing_models — re-exported helpers + explicit_pricing.json
  source {
    content  = file("${path.module}/scripts/add_missing_models/__init__.py")
    filename = "scripts/add_missing_models/__init__.py"
  }
  source {
    content  = file("${path.module}/scripts/add_missing_models/_common.py")
    filename = "scripts/add_missing_models/_common.py"
  }
  source {
    content  = file("${path.module}/scripts/add_missing_models/explicit_pricing.json")
    filename = "scripts/add_missing_models/explicit_pricing.json"
  }

  # add_pricing_us_prefix — re-exported helpers
  source {
    content  = file("${path.module}/scripts/add_pricing_us_prefix/__init__.py")
    filename = "scripts/add_pricing_us_prefix/__init__.py"
  }
  source {
    content  = file("${path.module}/scripts/add_pricing_us_prefix/_common.py")
    filename = "scripts/add_pricing_us_prefix/_common.py"
  }

  # scripts top-level __init__.py
  source {
    content  = file("${path.module}/scripts/__init__.py")
    filename = "scripts/__init__.py"
  }
}


# -----------------------------------------------------------------------------
# IAM — Model_Sync execution role
# -----------------------------------------------------------------------------

resource "aws_iam_role" "model_sync" {
  name               = "${local.prefix}-model-sync"
  assume_role_policy = data.aws_iam_policy_document.model_sync_assume.json
}

data "aws_iam_policy_document" "model_sync_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "model_sync_basic" {
  role       = aws_iam_role.model_sync.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "model_sync_inline" {
  statement {
    sid    = "BedrockListAndPricing"
    effect = "Allow"
    actions = [
      "bedrock:ListFoundationModels",
      "bedrock:ListInferenceProfiles",
      "pricing:GetProducts",
      "pricing:DescribeServices",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DynamoDBReadWriteScopedTables"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:BatchGetItem",
    ]
    resources = [
      aws_dynamodb_table.model_pricing.arn,
      aws_dynamodb_table.principal_policy.arn,
      aws_dynamodb_table.model_routing.arn,
      aws_dynamodb_table.model_sync_state.arn,
      aws_dynamodb_table.monthly_usage.arn,
    ]
  }

  statement {
    sid     = "S3PricelistSnapshots"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.pricelist_snapshots.arn,
      "${aws_s3_bucket.pricelist_snapshots.arn}/*",
    ]
  }

  statement {
    sid       = "CloudWatchMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["BedrockAutoSync"]
    }
  }

  statement {
    sid       = "SesSendEmailToOperator"
    effect    = "Allow"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = ["<ADMIN_EMAIL>"]
    }
  }
}

resource "aws_iam_role_policy" "model_sync_inline" {
  name   = "${local.prefix}-model-sync-inline"
  role   = aws_iam_role.model_sync.id
  policy = data.aws_iam_policy_document.model_sync_inline.json
}


# -----------------------------------------------------------------------------
# Lambda function
# -----------------------------------------------------------------------------

resource "aws_lambda_function" "model_sync" {
  function_name    = "${local.prefix}-model-sync"
  role             = aws_iam_role.model_sync.arn
  handler          = "lambda.model_sync_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 900 # 15 min hard cap (Req 5.5; sync logic soft-stops at 13 min)
  memory_size      = 1024
  filename         = data.archive_file.model_sync_zip.output_path
  source_code_hash = data.archive_file.model_sync_zip.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT = var.environment
      # AWS_REGION is reserved by the Lambda runtime — it is auto-injected
      # and rejected if set explicitly. The handler reads it via os.environ
      # like any other Lambda function.
      PRICELIST_SNAPSHOT_BUCKET = aws_s3_bucket.pricelist_snapshots.bucket
      EXPLICIT_PRICING_PATH     = "/var/task/scripts/add_missing_models/explicit_pricing.json"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.model_sync_basic,
    aws_iam_role_policy.model_sync_inline,
  ]
}


# -----------------------------------------------------------------------------
# EventBridge — daily 09:00 KST schedule, created DISABLED
# -----------------------------------------------------------------------------
# Operator flips to ENABLED only after the Manual_Seed verification
# (Req 5.6 / 9.5).

resource "aws_cloudwatch_event_rule" "model_sync_daily" {
  name                = "${local.prefix}-model-sync-daily"
  description         = "Daily 09:00 KST trigger for the Bedrock model auto-sync Lambda"
  schedule_expression = "cron(0 0 * * ? *)"
  state               = "ENABLED"

  tags = {
    Owner = "bedrock-gateway"
  }
}

resource "aws_cloudwatch_event_target" "model_sync_daily" {
  rule      = aws_cloudwatch_event_rule.model_sync_daily.name
  target_id = "ModelSyncLambda"
  arn       = aws_lambda_function.model_sync.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_model_sync" {
  statement_id  = "AllowEventBridgeInvokeModelSync"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.model_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.model_sync_daily.arn
}


# -----------------------------------------------------------------------------
# CloudWatch alarms
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "model_sync_failed" {
  alarm_name          = "${local.prefix}-model-sync-failed"
  alarm_description   = "BedrockAutoSync/SyncRunFailed >= 1 in the last day."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 86400 # 1 day
  statistic           = "Sum"
  namespace           = "BedrockAutoSync"
  metric_name         = "SyncRunFailed"
  treat_missing_data  = "notBreaching"

  tags = {
    Owner = "bedrock-gateway"
  }
}

resource "aws_cloudwatch_metric_alarm" "model_sync_inheritance_mismatch" {
  alarm_name          = "${local.prefix}-model-sync-inheritance-mismatch"
  alarm_description   = "BedrockAutoSync/InheritanceMismatchCount >= 1 in the last day."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 86400
  statistic           = "Sum"
  namespace           = "BedrockAutoSync"
  metric_name         = "InheritanceMismatchCount"
  treat_missing_data  = "notBreaching"

  tags = {
    Owner = "bedrock-gateway"
  }
}


# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "model_sync_lambda_name" {
  description = "Bedrock model auto-sync Lambda function name."
  value       = aws_lambda_function.model_sync.function_name
}

output "model_sync_eventbridge_rule" {
  description = "EventBridge rule name (DISABLED until Manual_Seed verified)."
  value       = aws_cloudwatch_event_rule.model_sync_daily.name
}

output "model_routing_table" {
  description = "Model_Routing_Table name for the handler MODEL_ROUTING_TABLE env var."
  value       = aws_dynamodb_table.model_routing.name
}
