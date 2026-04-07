# =============================================================================
# API Gateway — REST API (Regional, AWS_IAM auth)
# =============================================================================
# Regional REST API with AWS_IAM authorization.
# Default integration timeout: 29s. Can be increased via Service Quotas
# for Regional APIs (announced June 2024).
# Lambda max: 15 minutes (900s).
#
# NOTE: HTTP API was evaluated and rejected. HTTP API max integration
# timeout is 30 seconds (hard limit, not increasable). REST API Regional
# can request timeout increase beyond 29s via Service Quotas.
# See docs/ai/long-running-bedrock-architecture-final.md for full analysis.

resource "aws_api_gateway_rest_api" "gateway" {
  name        = "${local.prefix}-api"
  description = "Bedrock Access Control Gateway (v1, non-streaming)"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Proxy resource: {proxy+} catches all paths
resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.gateway.id
  parent_id   = aws_api_gateway_rest_api.gateway.root_resource_id
  path_part   = "{proxy+}"
}

# ANY method on proxy resource — AWS_IAM auth
resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.gateway.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "AWS_IAM"
}

# Lambda proxy integration for {proxy+}
resource "aws_api_gateway_integration" "proxy" {
  rest_api_id             = aws_api_gateway_rest_api.gateway.id
  resource_id             = aws_api_gateway_resource.proxy.id
  http_method             = aws_api_gateway_method.proxy.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_alias.live.invoke_arn
}

# Root resource method (for POST / without path)
resource "aws_api_gateway_method" "root" {
  rest_api_id   = aws_api_gateway_rest_api.gateway.id
  resource_id   = aws_api_gateway_rest_api.gateway.root_resource_id
  http_method   = "ANY"
  authorization = "AWS_IAM"
}

# Lambda proxy integration for root
resource "aws_api_gateway_integration" "root" {
  rest_api_id             = aws_api_gateway_rest_api.gateway.id
  resource_id             = aws_api_gateway_rest_api.gateway.root_resource_id
  http_method             = aws_api_gateway_method.root.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_alias.live.invoke_arn
}

# Deployment — triggers on any API change
resource "aws_api_gateway_deployment" "gateway" {
  rest_api_id = aws_api_gateway_rest_api.gateway.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.proxy.id,
      aws_api_gateway_method.proxy.id,
      aws_api_gateway_integration.proxy.id,
      aws_api_gateway_method.root.id,
      aws_api_gateway_integration.root.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Stage
resource "aws_api_gateway_stage" "gateway" {
  deployment_id = aws_api_gateway_deployment.gateway.id
  rest_api_id   = aws_api_gateway_rest_api.gateway.id
  stage_name    = var.api_gateway_stage_name

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      userArn        = "$context.identity.userArn"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Method settings — logging, throttling, metrics
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.gateway.id
  stage_name  = aws_api_gateway_stage.gateway.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    logging_level          = var.api_gateway_execution_logging_level
    data_trace_enabled     = var.api_gateway_data_trace_enabled
    throttling_rate_limit  = var.api_throttle_rate_limit
    throttling_burst_limit = var.api_throttle_burst_limit
  }
}

# Lambda permission for REST API invocation
resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gateway.function_name
  qualifier     = aws_lambda_alias.live.name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.gateway.execution_arn}/*/*"
}

# Optional: manage the account-level API Gateway CloudWatch logging role.
resource "aws_iam_role" "api_gw_cloudwatch" {
  count = var.manage_api_gateway_account_cloudwatch_role ? 1 : 0
  name  = "${local.prefix}-apigw-cw"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "api_gw_cloudwatch" {
  count      = var.manage_api_gateway_account_cloudwatch_role ? 1 : 0
  role       = aws_iam_role.api_gw_cloudwatch[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "main" {
  count               = var.manage_api_gateway_account_cloudwatch_role ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.api_gw_cloudwatch[0].arn
}
