# =============================================================================
# DynamoDB Tables (10 tables)
# Naming: bedrock-gw-${env}-${region}-${table}  (Locked decision #7)
#
# Race-safe pending-one-per-principal enforcement:
#   ApprovalRequest stores requests (PK: request_id).
#   ApprovalPendingLock (PK: principal_id) enforces at most one pending
#   approval per principal via conditional PutItem (attribute_not_exists).
#   GSI query on ApprovalRequest is NOT atomic with PutItem — the separate
#   lock table is required.  (Locked decision #10)
#
# Audit immutability:
#   RequestLedger is append-only (PutItem). Lambda IAM explicitly denies
#   UpdateItem/DeleteItem.  (Locked decision #9)
#
# IdempotencyRecord is separate from RequestLedger — duplicate replay
# state must not pollute the immutable audit log.  (Locked decision #9)
# =============================================================================

resource "aws_dynamodb_table" "principal_policy" {
  name         = "${local.table_prefix}-principal-policy"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_dynamodb_table" "daily_usage" {
  name         = "${local.table_prefix}-daily-usage"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id_date"
  range_key    = "model_id"

  attribute {
    name = "principal_id_date"
    type = "S"
  }

  attribute {
    name = "model_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_dynamodb_table" "temporary_quota_boost" {
  name         = "${local.table_prefix}-temporary-quota-boost"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"
  range_key    = "boost_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "boost_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# ApprovalRequest: stores approval requests.
# Race-safe pending-one enforcement is NOT done via GSI query here —
# it is handled by the separate ApprovalPendingLock table (Locked decision #10).
resource "aws_dynamodb_table" "approval_request" {
  name         = "${local.table_prefix}-approval-request"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name            = "principal-status-index"
    hash_key        = "principal_id"
    range_key       = "status"
    projection_type = "ALL"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# RequestLedger: immutable audit log (append-only).
# Lambda IAM allows PutItem only — UpdateItem/DeleteItem explicitly denied.
# (Locked decision #9)
resource "aws_dynamodb_table" "request_ledger" {
  name         = "${local.table_prefix}-request-ledger"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_dynamodb_table" "session_metadata" {
  name         = "${local.table_prefix}-session-metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_dynamodb_table" "idempotency_record" {
  name         = "${local.table_prefix}-idempotency-record"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# ApprovalPendingLock: race-safe pending-one-per-principal enforcement.
# PK: principal_id. Lambda uses conditional PutItem (attribute_not_exists)
# to atomically acquire the lock. Admin API deletes the lock on
# approval or rejection.  (Locked decision #10)
#
# TTL: safety net for orphan locks. If admin never acts on an approval
# request (crash, oversight), the lock auto-expires so the principal
# is not permanently blocked from submitting new requests.
# Default TTL should be set by Lambda at write time (e.g. 7 days).
resource "aws_dynamodb_table" "approval_pending_lock" {
  name         = "${local.table_prefix}-approval-pending-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# =============================================================================
# Phase 1 additive tables (KRW cost-based quota migration)
# These tables are unused by the current runtime. They will be referenced
# by handler.py after Phase 2 (Lambda quota logic rewrite).
# daily_usage is intentionally preserved — current runtime depends on it.
# Removal: post-Phase-2 validation cleanup only.
# =============================================================================

# ModelPricing: admin-managed KRW pricing per model.
# Lambda reads at cold start and caches. No TTL (persistent, admin-managed).
# Q1 decision (2026-03-18): fixed KRW rates, no real-time FX.
resource "aws_dynamodb_table" "model_pricing" {
  name         = "${local.table_prefix}-model-pricing"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "model_id"

  attribute {
    name = "model_id"
    type = "S"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# MonthlyUsage: KRW cost-based monthly usage tracking.
# PK: <principal_id>#YYYY-MM (KST month boundary — Q3 decision).
# SK: model_id. Fields: cost_krw, input_tokens, output_tokens (Q6 decision).
# TTL: ~35 days (auto-expire old month records).
resource "aws_dynamodb_table" "monthly_usage" {
  name         = "${local.table_prefix}-monthly-usage"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id_month"
  range_key    = "model_id"

  attribute {
    name = "principal_id_month"
    type = "S"
  }

  attribute {
    name = "model_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}


# =============================================================================
# Team Configuration (governance)
# =============================================================================
resource "aws_dynamodb_table" "team_config" {
  name         = "${local.table_prefix}-team-config"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "team_id"

  attribute {
    name = "team_id"
    type = "S"
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# =============================================================================
# Governance Audit Log
# =============================================================================
resource "aws_dynamodb_table" "governance_audit" {
  name         = "${local.table_prefix}-governance-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "audit_id"

  attribute {
    name = "audit_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# =============================================================================
# Long-Running Request Tracking
# =============================================================================
# Tracks gateway-mediated direct Bedrock calls (Tier 3 / long path).
# Gateway issues authorization + budget reservation, client executes
# Bedrock call directly, then settles actual usage back to gateway.
# PK: request_id (UUID issued by /longrun/authorize)
# States: authorized → running → settled | failed | expired
resource "aws_dynamodb_table" "longrun_request" {
  name         = "${local.table_prefix}-longrun-request"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "request_id"

  attribute {
    name = "request_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# =============================================================================
# v2: Async Job State
# =============================================================================
resource "aws_dynamodb_table" "job_state" {
  name         = "${local.table_prefix}-job-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  global_secondary_index {
    name            = "principal-created-index"
    hash_key        = "principal_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# =============================================================================
# v2: Concurrency Semaphore
# =============================================================================
resource "aws_dynamodb_table" "concurrency_semaphore" {
  name         = "${local.table_prefix}-concurrency-semaphore"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "slot_id"

  attribute {
    name = "slot_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
