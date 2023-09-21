###############################################################################
# Versions
###############################################################################

terraform {
  # Terraform version
  required_version = ">= 1.0.4"
  required_providers {
    # AWS version
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.6.2"
    }
  }
  # S3 bucket being used as a  remote backend for AWS deployment, needs to be created before any terraform operations
  backend "s3" {
    bucket  = "dvt-acloud-kubernetes-terraform"
    region  = "eu-west-2"
    key     = "cp/e2e-ecs-fargate/terraform.tfstate"
    encrypt = true
  }
}