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
  description = "Enable discovery mode for Task 3 principal normalization capture. Disable after discovery."
  type        = bool
  default     = false
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
# v3: Queue/Scheduler Limits
# =============================================================================

variable "global_active_limit" {
  description = "Maximum concurrent active long-running jobs globally"
  type        = number
  default     = 20
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
