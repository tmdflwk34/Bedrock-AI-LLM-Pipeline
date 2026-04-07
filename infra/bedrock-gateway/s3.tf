# =============================================================================
# v2: Payload/Result Storage Bucket
# =============================================================================

resource "aws_s3_bucket" "payload" {
  bucket = "bedrock-gw-${var.environment}-payload-${data.aws_caller_identity.current.account_id}"

  tags = {
    Service = "bedrock-access-gateway"
    Env     = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payload" {
  bucket = aws_s3_bucket.payload.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "payload" {
  bucket = aws_s3_bucket.payload.id

  rule {
    id     = "cleanup-old-payloads"
    status = "Enabled"

    expiration {
      days = 7
    }
  }
}

resource "aws_s3_bucket_public_access_block" "payload" {
  bucket = aws_s3_bucket.payload.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}
