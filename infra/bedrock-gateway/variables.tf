variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "lambda_runtime" {
  description = "Lambda runtime"
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 900
}

variable "lambda_memory_size" {
  description = "Lambda memory in MB"
  type        = number
  default     = 256
}

variable "api_gateway_stage_name" {
  description = "API Gateway deployment stage name"
  type        = string
  default     = "v1"
}

variable "api_throttle_rate_limit" {
  description = "API Gateway stage-level rate limit (requests/sec)"
  type        = number
  default     = 50
}

variable "api_throttle_burst_limit" {
  description = "API Gateway stage-level burst limit"
  type        = number
  default     = 100
}

variable "ses_sender_email" {
  description = "SES verified sender email address"
  type        = string
}

variable "ses_admin_group_email" {
  description = "Admin group email alias for approval notifications"
  type        = string
}

variable "bedrock_invocation_log_group_name" {
  description = "CloudWatch log group name for Bedrock model invocation logging"
  type        = string
  default     = ""
}

variable "discovery_mode" {
  description = "Enable ry mode for Task 3 principal normalization capture. Disable after discovery."
  type        = bool
  default     = false
}

variable "fx_rate_krw_per_usd" {
  description = "Fixed reference exchange rate (KRW per USD) used to derive KRW prices from USD source rates. Centralized single source of truth (R6.5)."
  type        = string
  default     = "1482.5"
}

variable "manage_api_gateway_account_cloudwatch_role" {
  description = "Whether this stack is allowed to manage the account-level API Gateway CloudWatch logging role."
  type        = bool
  default     = false
}

variable "api_gateway_execution_logging_level" {
  description = "API Gateway execution logging level. Use ERROR by default in non-dev environments."
  type        = string
  default     = "ERROR"

  validation {
    condition     = contains(["OFF", "ERROR", "INFO"], var.api_gateway_execution_logging_level)
    error_message = "api_gateway_execution_logging_level must be one of: OFF, ERROR, INFO."
  }
}

variable "api_gateway_data_trace_enabled" {
  description = "Whether API Gateway execution data trace is enabled. Keep false by default to avoid prompt/response payload leakage."
  type        = bool
  default     = false
}

# =============================================================================
# v2: Fargate Networking
# =============================================================================

variable "private_subnet_ids" {
  description = "Private subnet IDs for Fargate tasks"
  type        = list(string)
  default     = []
}

variable "fargate_security_group_ids" {
  description = "Security group IDs for Fargate tasks (outbound only)"
  type        = list(string)
  default     = []
}

# =============================================================================
# Worker Image Pinning (long-output-streaming 5.5, design.md U4)
# =============================================================================
#
# Neither variable has a default, on purpose. A default would be the *dev*
# registry's digest, and inheriting it in another environment produces a task
# definition that cannot pull — discovered at the first job launch, not at plan
# time. No default means terraform refuses to plan until the pin is stated for
# the environment being deployed, which is the same fail-closed shape as
# `ses_sender_email`. Both are set in `env/<environment>.tfvars`.

variable "worker_image_digest" {
  description = "Immutable digest of the worker container image, `sha256:<64 hex>`. Replaces the `:latest` tag so a task-definition revision identifies exactly one image (U4). Bump together with worker_source_commit."
  type        = string

  # A truncated or mistyped digest is otherwise only caught when a task tries
  # to start (CannotPullContainerError), which is long after apply.
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.worker_image_digest))
    error_message = "worker_image_digest must be a full digest of the form sha256:<64 lowercase hex chars>."
  }
}

variable "worker_source_commit" {
  description = "Full 40-char git SHA of the source the pinned worker image was built from. Recorded as the task-definition `SourceCommit` tag and the container's `org.opencontainers.image.revision` label so a rollback target is identifiable (U4)."
  type        = string

  # Full SHA only: an abbreviated or placeholder value ('unknown', 'HEAD') would
  # reintroduce exactly the provenance gap U4 describes.
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.worker_source_commit))
    error_message = "worker_source_commit must be a full 40-character lowercase git SHA."
  }
}

# =============================================================================
# v3: Queue/Scheduler Limits
# =============================================================================

variable "global_active_limit" {
  description = "Maximum concurrent active long-running jobs globally. 배포 실측값과 일치. 변경 시 HC1(≥50) 검증 필요"
  type        = number
  default     = 1000
}

variable "per_user_active_limit" {
  description = "Maximum concurrent active long-running jobs per user"
  type        = number
  default     = 50
}

variable "global_queue_limit" {
  description = "Maximum queued jobs globally before rejecting new submissions"
  type        = number
  default     = 500
}

variable "per_user_queue_limit" {
  description = "Maximum queued jobs per user before rejecting new submissions"
  type        = number
  default     = 100
}

# =============================================================================
# DGX On-Prem Gateway Access (IAM Roles Anywhere)
# =============================================================================

variable "enable_dgx_onprem_access" {
  description = "Enable IAM Roles Anywhere resources for DGX on-prem gateway access"
  type        = bool
  default     = false
}

variable "dgx_ca_certificate_pem" {
  description = "PEM-encoded CA certificate for the DGX gateway Trust Anchor"
  type        = string
  default     = ""
  sensitive   = true
}

variable "dgx_pilot_users" {
  description = "List of pilot usernames for DGX on-prem access (maps to BedrockUser-{username} roles)"
  type        = list(string)
  default     = ["user08"]
}
