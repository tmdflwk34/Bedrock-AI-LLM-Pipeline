output "api_gateway_invoke_url" {
  description = "API Gateway REST API invoke URL"
  value       = aws_api_gateway_stage.gateway.invoke_url
}

output "api_gateway_id" {
  description = "API Gateway REST API ID"
  value       = aws_api_gateway_rest_api.gateway.id
}

output "lambda_function_arn" {
  description = "Gateway Lambda function ARN"
  value       = aws_lambda_function.gateway.arn
}

output "lambda_role_arn" {
  description = "Gateway Lambda execution role ARN"
  value       = aws_iam_role.lambda_exec.arn
}

output "dynamodb_table_arns" {
  description = "Map of DynamoDB table names to ARNs"
  value = {
    principal_policy      = aws_dynamodb_table.principal_policy.arn
    daily_usage           = aws_dynamodb_table.daily_usage.arn
    monthly_usage         = aws_dynamodb_table.monthly_usage.arn
    model_pricing         = aws_dynamodb_table.model_pricing.arn
    temporary_quota_boost = aws_dynamodb_table.temporary_quota_boost.arn
    approval_request      = aws_dynamodb_table.approval_request.arn
    request_ledger        = aws_dynamodb_table.request_ledger.arn
    session_metadata      = aws_dynamodb_table.session_metadata.arn
    idempotency_record    = aws_dynamodb_table.idempotency_record.arn
    approval_pending_lock = aws_dynamodb_table.approval_pending_lock.arn
  }
}
