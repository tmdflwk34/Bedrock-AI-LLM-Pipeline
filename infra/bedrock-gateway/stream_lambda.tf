# =============================================================================
# Stream Lambda Function + Function URL (Lambda Web Adapter + FastAPI)
# =============================================================================

# Build the streaming Lambda package WITH its Python dependencies vendored.
# The runtime needs fastapi + uvicorn (run.sh launches uvicorn). A plain
# archive of the source dir omits them, which makes the adapter boot fail
# with "No module named uvicorn" and every request 502s. This null_resource
# pip-installs requirements.txt into a build dir and copies the source in;
# archive_file then zips that complete dir. The trigger hashes the source
# files + requirements so the package rebuilds whenever any of them change.
resource "null_resource" "stream_build" {
  triggers = {
    handler      = filesha256("${path.module}/stream/stream_handler.py")
    shared       = filesha256("${path.module}/stream/shared.py")
    run_sh       = filesha256("${path.module}/stream/run.sh")
    requirements = filesha256("${path.module}/stream/requirements.txt")
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      BUILD_DIR="${path.module}/.build/stream_pkg"
      rm -rf "$BUILD_DIR"
      mkdir -p "$BUILD_DIR"
      # Vendor dependencies for the Lambda runtime (python3.12, x86_64).
      python3 -m pip install \
        --platform manylinux2014_x86_64 \
        --implementation cp \
        --python-version 3.12 \
        --only-binary=:all: \
        --target "$BUILD_DIR" \
        -r "${path.module}/stream/requirements.txt"
      # Copy application source (overwrites any same-named dep files).
      cp "${path.module}/stream/stream_handler.py" "$BUILD_DIR/"
      cp "${path.module}/stream/shared.py" "$BUILD_DIR/"
      cp "${path.module}/stream/run.sh" "$BUILD_DIR/"
      cp "${path.module}/stream/requirements.txt" "$BUILD_DIR/"
    EOT
  }
}

data "archive_file" "stream_zip" {
  type        = "zip"
  source_dir  = "${path.module}/.build/stream_pkg"
  output_path = "${path.module}/.build/stream.zip"

  depends_on = [null_resource.stream_build]
}

resource "aws_lambda_function" "stream_handler" {
  function_name    = "${local.prefix}-stream"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "run.sh"
  runtime          = "python3.12"
  timeout          = 900
  memory_size      = 256
  filename         = data.archive_file.stream_zip.output_path
  source_code_hash = data.archive_file.stream_zip.output_base64sha256

  layers = [
    "arn:aws:lambda:${var.aws_region}:753240598075:layer:LambdaAdapterLayerX86:27"
  ]

  environment {
    variables = {
      # Lambda Web Adapter config
      # AWS_LAMBDA_EXEC_WRAPPER activates the adapter layer's bootstrap so
      # the runtime launches run.sh (uvicorn) instead of trying to import
      # a Python module named "run". Without it the function fails at init
      # with Runtime.ImportModuleError: No module named 'run' and every
      # request returns 502. This MUST stay in IaC so a redeploy can never
      # silently drop it again.
      AWS_LAMBDA_EXEC_WRAPPER     = "/opt/bootstrap"
      AWS_LWA_INVOKE_MODE         = "response_stream"
      AWS_LWA_PORT                = "8080"
      # Gateway config (same env vars as existing Lambda)
      ENVIRONMENT                 = var.environment
      TABLE_PRINCIPAL_POLICY      = aws_dynamodb_table.principal_policy.name
      TABLE_MONTHLY_USAGE         = aws_dynamodb_table.monthly_usage.name
      TABLE_MODEL_PRICING         = aws_dynamodb_table.model_pricing.name
      TABLE_TEMPORARY_QUOTA_BOOST = aws_dynamodb_table.temporary_quota_boost.name
      TABLE_REQUEST_LEDGER        = aws_dynamodb_table.request_ledger.name
      SES_SENDER_EMAIL            = var.ses_sender_email
      SES_ADMIN_GROUP_EMAIL       = var.ses_admin_group_email
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.stream_lambda,
    aws_iam_role_policy.dynamodb,
    aws_iam_role_policy.bedrock,
  ]

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

# Function URL with response streaming and IAM auth
resource "aws_lambda_function_url" "stream" {
  function_name      = aws_lambda_function.stream_handler.function_name
  authorization_type = "AWS_IAM"
  invoke_mode        = "RESPONSE_STREAM"
}

# Dedicated CloudWatch log group
resource "aws_cloudwatch_log_group" "stream_lambda" {
  name              = "/aws/lambda/${local.prefix}-stream"
  retention_in_days = 90

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}
