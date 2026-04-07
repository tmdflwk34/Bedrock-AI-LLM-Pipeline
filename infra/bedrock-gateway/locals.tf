# =============================================================================
# Locals
# =============================================================================

locals {
  prefix       = "bedrock-gw-${var.environment}"
  table_prefix = "bedrock-gw-${var.environment}-${var.aws_region}"
}
