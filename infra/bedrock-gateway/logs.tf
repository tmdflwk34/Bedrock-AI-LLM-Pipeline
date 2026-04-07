# =============================================================================
# CloudWatch Log Groups
# =============================================================================

resource "aws_cloudwatch_log_group" "api_gw_access" {
  name              = "/aws/apigateway/${local.prefix}-api/access"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.prefix}-gateway"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
