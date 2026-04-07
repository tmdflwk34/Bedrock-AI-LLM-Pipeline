# S3 backend — uncomment and configure before first apply.
# terraform {
#   backend "s3" {
#     bucket         = "REPLACE-terraform-state-bucket"
#     key            = "bedrock-gateway/terraform.tfstate"
#     region         = "us-west-2"
#     dynamodb_table = "REPLACE-terraform-lock-table"
#     encrypt        = true
#   }
# }
