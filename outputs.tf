###############################################################################
# General variables
###############################################################################

output "region" {
  description = "AWS region in which the AWS infrastructure has been deployed"
  value       = local.region
}

###############################################################################
# VPC
###############################################################################

output "azs" {
  description = "A list of availability zones specified as argument to this module"
  value       = local.azs
}

output "vpc_name" {
  description = "The name of the VPC specified as argument to this module"
  value       = local.name
}

output "vpc_id" {
  description = "The ID of the VPC"
  value       = try(module.vpc.vpc_id, null)
}

output "vpc_arn" {
  description = "The ARN of the VPC"
  value       = try(module.vpc.vpc_arn, null)
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = try(module.vpc.vpc_cidr_block, null)
}

output "vpc_main_route_table_id" {
  description = "The ID of the main route table associated with this VPC"
  value       = try(module.vpc.vpc_main_route_table_id, null)
}

output "vpc_owner_id" {
  description = "The ID of the AWS account that owns the VPC"
  value       = try(module.vpc.vpc_owner_id, null)
}

###############################################################################
# Internet Gateway
###############################################################################

output "igw_id" {
  description = "The ID of the Internet Gateway"
  value       = try(module.vpc.igw_id, null)
}

output "igw_arn" {
  description = "The ARN of the Internet Gateway"
  value       = try(module.vpc.igw_arn, null)
}

###############################################################################
# Publiс Subnets
###############################################################################

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = try(module.vpc.public_subnets, null)
}

output "public_subnet_arns" {
  description = "List of ARNs of public subnets"
  value       = try(module.vpc.public_subnet_arns, null)
}

output "public_subnets_cidr_blocks" {
  description = "List of cidr_blocks of public subnets"
  value       = try(module.vpc.public_subnets_cidr_blocks, null)
}

output "public_route_table_ids" {
  description = "List of IDs of public route tables"
  value       = try(module.vpc.public_route_table_ids, null)
}

output "public_internet_gateway_route_id" {
  description = "ID of the internet gateway route"
  value       = try(module.vpc.public_internet_gateway_route_id, null)
}

output "public_route_table_association_ids" {
  description = "List of IDs of the public route table association"
  value       = try(module.vpc.public_route_table_association_ids, null)
}

output "public_network_acl_id" {
  description = "ID of the public network ACL"
  value       = try(module.vpc.public_network_acl_id, null)
}

output "public_network_acl_arn" {
  description = "ARN of the public network ACL"
  value       = try(module.vpc.public_network_acl_arn, null)
}

###############################################################################
# Private Subnets
###############################################################################

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = try(module.vpc.private_subnets, null)
}

output "private_subnet_arns" {
  description = "List of ARNs of private subnets"
  value       = try(module.vpc.private_subnet_arns, null)
}

output "private_subnets_cidr_blocks" {
  description = "List of cidr_blocks of private subnets"
  value       = try(module.vpc.private_subnets_cidr_blocks, null)
}

output "private_route_table_ids" {
  description = "List of IDs of private route tables"
  value       = try(module.vpc.private_route_table_ids, null)
}

output "private_nat_gateway_route_ids" {
  description = "List of IDs of the private nat gateway route"
  value       = try(module.vpc.private_nat_gateway_route_ids, null)
}

output "private_route_table_association_ids" {
  description = "List of IDs of the private route table association"
  value       = try(module.vpc.private_route_table_association_ids, null)
}

output "private_network_acl_id" {
  description = "ID of the private network ACL"
  value       = try(module.vpc.private_network_acl_id, null)
}

output "private_network_acl_arn" {
  description = "ARN of the private network ACL"
  value       = try(module.vpc.private_network_acl_arn, null)
}

###############################################################################
# NAT Gateway
###############################################################################

output "nat_ids" {
  description = "List of allocation ID of Elastic IPs created for AWS NAT Gateway"
  value       = try(module.vpc.nat_ids, null)
}

output "nat_public_ips" {
  description = "List of public Elastic IPs created for AWS NAT Gateway"
  value       = try(module.vpc.nat_public_ips, null)
}

output "natgw_ids" {
  description = "List of NAT Gateway IDs"
  value       = try(module.vpc.natgw_ids, null)
}

###############################################################################
# VPC Flow Log
###############################################################################

output "vpc_flow_log_id" {
  description = "The ID of the Flow Log resource"
  value       = try(module.vpc.vpc_flow_log_id, null)
}

output "vpc_flow_log_destination_arn" {
  description = "The ARN of the destination for VPC Flow Logs"
  value       = try(module.vpc.vpc_flow_log_destination_arn, null)
}

output "vpc_flow_log_cloudwatch_iam_role_arn" {
  description = "The ARN of the IAM role used when pushing logs to Cloudwatch log group"
  value       = try(module.vpc.vpc_flow_log_cloudwatch_iam_role_arn, null)
}

###############################################################################
#  KMS key for CloudWatch log groups for VPC flow logs
###############################################################################

output "vpc_flow_log_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.vpc_flow_log_kms_key.key_arn, null)
}

output "vpc_flow_log_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.vpc_flow_log_kms_key.key_id, null)
}

output "vpc_flow_log_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.vpc_flow_log_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for VPC flow logs
###############################################################################

output "vpc_flow_log_kms_key_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.vpc_flow_log_kms_key.aliases
}

###############################################################################
# VPC endpoints SG
###############################################################################
output "security_group_arn" {
  description = "The ARN of the security group"
  value       = try(module.vpc_endpoints_sg.security_group_arn, null)
}

output "security_group_id" {
  description = "The ID of the security group"
  value       = try(module.vpc_endpoints_sg.security_group_id, null)
}

output "security_group_vpc_id" {
  description = "The VPC ID"
  value       = try(module.vpc_endpoints_sg.security_group_vpc_id, null)
}

output "security_group_owner_id" {
  description = "The owner ID"
  value       = try(module.vpc_endpoints_sg.security_group_owner_id, null)
}

output "security_group_name" {
  description = "The name of the security group"
  value       = try(module.vpc_endpoints_sg.security_group_name, null)
}

###############################################################################
# VPC endpoints
###############################################################################

output "endpoints" {
  description = "Array containing the full resource object and attributes for all endpoints created"
  value       = try(module.vpc_endpoints.endpoints, null)
}

###############################################################################
#  AWS Cloud Map
###############################################################################

###############################################################################
#  Namespace
###############################################################################

output "namespace_id" {
  description = "The ID of the cloud map namespace"
  value       = try(module.namespace.namespace_id, null)
}

output "namespace_arn" {
  description = "The ARN of the cloud map namespace"
  value       = try(module.namespace.namespace_arn, null)
}

output "namespace_hosted_zone" {
  description = "The ID for the hosted zone that AWS Route 53 creates when you create a namespace"
  value       = try(module.namespace.namespace_hosted_zone, null)
}

output "namespace_tags" {
  description = "The tags of the cloud map namespace resource tags"
  value       = try(module.namespace.namespace_tags, null)
}

output "aws_cloud_map_iam_role_arn" {
  description = "The ARN of the IAM role for vpc to use aws cloud map service"
  value       = try(module.namespace.aws_cloud_map_iam_role_arn, null)
}

###############################################################################
#  IAM role for AWS Cloud Map Namespace
###############################################################################

output "aws_cloud_map_namespace_iam_role_arn" {
  description = "ARN of AWS Cloud Map IAM role"
  value       = try(aws_iam_role.aws_cloud_map_iam_role.arn, "")
}

output "aws_cloud_map_namespace_iam_role_name" {
  description = "Name of AWS Cloud Map IAM role"
  value       = try(aws_iam_role.aws_cloud_map_iam_role.name, "")
}

###############################################################################
# ECS Cluster
###############################################################################

output "ecs_cluster_arn" {
  description = "ARN that identifies the cluster"
  value       = try(module.ecs-cluster.arn, null)
}

output "ecs_cluster_id" {
  description = "ID that identifies the cluster"
  value       = try(module.ecs-cluster.id, null)
}

output "cluster_name" {
  description = "Name that identifies the cluster"
  value       = try(module.ecs-cluster.name, null)
}

###############################################################################
# ECS Cluster CloudWatch Log Group
###############################################################################

output "cloudwatch_log_group_name" {
  description = "Name of cloudwatch log group created"
  value       = try(module.ecs-cluster.cloudwatch_log_group_name, null)
}

output "cloudwatch_log_group_arn" {
  description = "Arn of cloudwatch log group created"
  value       = try(module.ecs-cluster.cloudwatch_log_group_arn, null)
}

###############################################################################
# ECS Cluster Capacity Providers
###############################################################################

output "cluster_capacity_providers" {
  description = "Map of cluster capacity providers attributes"
  value       = try(module.ecs-cluster.cluster_capacity_providers, null)
}

###############################################################################
# ECS Cluster logs KMS key
###############################################################################

output "ecs_cluster_logs_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.ecs_cluster_logs_kms_key.key_arn, null)
}

output "ecs_cluster_logs_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.ecs_cluster_logs_kms_key.key_id, null)
}

output "ecs_cluster_logs_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.ecs_cluster_logs_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for ECS Cluster logs
###############################################################################

output "ecs_cluster_logs_kms_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.ecs_cluster_logs_kms_key.aliases
}

###############################################################################
#  IAM role for ECS Cluster
###############################################################################

output "ecs_cluster_iam_role_arn" {
  description = "ARN of AWS ECS cluster IAM role"
  value       = try(aws_iam_role.aws_ecs_cluster_iam_role.arn, "")
}

output "ecs_cluster_iam_role_name" {
  description = "Name of AWS ECS cluster IAM role"
  value       = try(aws_iam_role.aws_ecs_cluster_iam_role.name, "")
}

###############################################################################
# ECS service
###############################################################################

output "service_id" {
  description = "ARN that identifies the service"
  value       = try(module.ecs-service.id, null)
}

output "service_name" {
  description = "Name of the service"
  value       = try(module.ecs-service.name, null)
}

###############################################################################
# Container Definition
###############################################################################

output "container_definitions" {
  description = "Container definitions"
  value       = try(module.ecs-service.container_definitions, null)
}

###############################################################################
# Task Definition
###############################################################################

output "task_definition_arn" {
  description = "Full ARN of the Task Definition (including both `family` and `revision`)"
  value       = try(module.ecs-service.task_definition_arn, null)
}

output "task_definition_revision" {
  description = "Revision of the task in a particular family"
  value       = try(module.ecs-service.task_definition_revision, null)
}

output "task_definition_family" {
  description = "The unique name of the task definition"
  value       = try(module.ecs-service.task_definition_family, null)
}

###############################################################################
# Task Execution - IAM Role
###############################################################################

output "task_exec_iam_role_name" {
  description = "Task execution IAM role name"
  value       = try(module.ecs-service.task_exec_iam_role_name, null)
}

output "task_exec_iam_role_arn" {
  description = "Task execution IAM role ARN"
  value       = try(module.ecs-service.task_exec_iam_role_arn, null)
}

output "task_exec_iam_role_unique_id" {
  description = "Stable and unique string identifying the task execution IAM role"
  value       = try(module.ecs-service.task_exec_iam_role_unique_id, null)
}

###############################################################################
# Tasks - IAM role
###############################################################################

output "tasks_iam_role_name" {
  description = "Tasks IAM role name"
  value       = try(module.ecs-service.tasks_iam_role_name, null)
}

output "tasks_iam_role_arn" {
  description = "Tasks IAM role ARN"
  value       = try(module.ecs-service.tasks_iam_role_arn, null)
}

output "tasks_iam_role_unique_id" {
  description = "Stable and unique string identifying the tasks IAM role"
  value       = try(module.ecs-service.tasks_iam_role_unique_id, null)
}

###############################################################################
# ECS Service SG
###############################################################################

output "service_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the security group"
  value       = try(module.ecs-service.security_group_arn, null)
}

output "service_security_group_id" {
  description = "ID of the security group"
  value       = try(module.ecs-service.security_group_id, null)
}

###############################################################################
# ECS service logs KMS key
###############################################################################

output "ecs_service_logs_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.ecs_service_logs_kms_key.key_arn, null)
}

output "ecs_service_logs_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.ecs_service_logs_kms_key.key_id, null)
}

output "ecs_service_logs_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.ecs_service_logs_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for ECS service logs
###############################################################################

output "ecs_service_logs_kms_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.ecs_service_logs_kms_key.aliases
}

###############################################################################
# ALB
###############################################################################

output "lb_id" {
  description = "The ID and ARN of the load balancer we created"
  value       = try(module.alb.lb_id, "")
}

output "lb_arn" {
  description = "The ID and ARN of the load balancer we created"
  value       = try(module.alb.arn, "")
}

output "lb_dns_name" {
  description = "The DNS name of the load balancer"
  value       = try(module.alb.dns_name, "")
}

output "http_tcp_listener_arns" {
  description = "The ARN of the TCP and HTTP load balancer listeners created"
  value       = try(module.alb.http_tcp_listener_arns, null)
}

output "http_tcp_listener_ids" {
  description = "The IDs of the TCP and HTTP load balancer listeners created"
  value       = try(module.alb.http_tcp_listener_ids, null)
}

output "https_listener_arns" {
  description = "The ARNs of the HTTPS load balancer listeners created"
  value       = try(module.alb.http_tcp_listener_arns, null)
}

output "https_listener_ids" {
  description = "The IDs of the load balancer listeners created"
  value       = try(module.alb.https_listener_ids, null)
}

output "target_group_arns" {
  description = "ARNs of the target groups. Useful for passing to your Auto Scaling group"
  value       = try(module.alb.target_group_arns, null)
}

output "target_group_names" {
  description = "Name of the target group. Useful for passing to your CodeDeploy Deployment Group"
  value       = try(module.alb.target_group_names, null)
}

output "target_group_attachments" {
  description = "ARNs of the target group attachment IDs"
  value       = try(module.alb.target_group_attachments, null)
}

###############################################################################
# ALB SG
###############################################################################

output "alb_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the security group"
  value       = try(module.alb.security_group_arn, null)
}

output "alb_security_group_id" {
  description = "ID of the security group"
  value       = try(module.alb.security_group_id, null)
}

###############################################################################
#  IAM role for ALB
###############################################################################

output "aws_alb_iam_role_arn" {
  description = "ARN of AWS ALB IAM role"
  value       = try(aws_iam_role.aws_alb_iam_role.arn, "")
}

output "aws_alb_iam_role_name" {
  description = "Name of AWS ALB IAM role"
  value       = try(aws_iam_role.aws_alb_iam_role.name, "")
}

###############################################################################
# ALB S3 logging Bucket
###############################################################################

output "alb_s3_bucket_id" {
  description = "The name of the bucket."
  value       = try(module.s3_bucket_alb_logs.s3_bucket_id, "")
}

output "alb_s3_bucket_arn" {
  description = "The ARN of the bucket. Will be of format arn:aws:s3:::bucketname."
  value       = try(module.s3_bucket_alb_logs.s3_bucket_arn, "")
}

output "alb_s3_bucket_lifecycle_configuration_rules" {
  description = "The lifecycle rules of the bucket, if the bucket is configured with lifecycle rules. If not, this will be an empty string."
  value       = try(module.s3_bucket_alb_logs.s3_bucket_lifecycle_configuration_rules, "")
}

output "alb_s3_bucket_policy" {
  description = "The policy of the bucket, if the bucket is configured with a policy. If not, this will be an empty string."
  value       = try(module.s3_bucket_alb_logs.s3_bucket_policy, "")
}

###############################################################################
# ALB S3 logs KMS key
###############################################################################

output "alb_logs_s3_bucket_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.alb_logs_s3_bucket_kms_key.key_arn, null)
}

output "alb_logs_s3_bucket_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.alb_logs_s3_bucket_kms_key.key_id, null)
}

output "alb_logs_s3_bucket_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.alb_logs_s3_bucket_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for ALB S3 logs
###############################################################################

output "alb_logs_s3_bucket_kms_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.alb_logs_s3_bucket_kms_key.aliases
}

###############################################################################
# CloudTrail
###############################################################################

output "cloudtrail_id" {
  description = "The name of the trail"
  value       = try(module.cloudtrail.cloudtrail_id, null)
}

output "cloudtrail_home_region" {
  description = "The region in which the trail was created"
  value       = try(module.cloudtrail.cloudtrail_home_region, null)
}

output "cloudtrail_arn" {
  description = "The Amazon Resource Name of the trail"
  value       = try(module.cloudtrail.cloudtrail_arn, null)
}

output "cloudtrail_bucket_domain_name" {
  description = "FQDN of the CloudTral S3 bucket"
  value       = try(module.cloudtrail.bucket_domain_name, null)
}

###############################################################################
#  IAM role for CT
###############################################################################

output "aws_ct_iam_role_iam_role_arn" {
  description = "ARN of AWS CloudTrail IAM role"
  value       = try(aws_iam_role.aws_ct_iam_role.arn, "")
}

output "aws_ct_iam_role_iam_role_name" {
  description = "Name of AWS CloudTrail IAM role"
  value       = try(aws_iam_role.aws_ct_iam_role.name, "")
}

###############################################################################
# CT S3 logging Bucket
###############################################################################

output "ct_s3_bucket_id" {
  description = "The name of the bucket."
  value       = try(module.s3_bucket_ct_logs.s3_bucket_id, "")
}

output "ct_s3_bucket_arn" {
  description = "The ARN of the bucket. Will be of format arn:aws:s3:::bucketname."
  value       = try(module.s3_bucket_ct_logs.s3_bucket_arn, "")
}

output "ct_s3_bucket_lifecycle_configuration_rules" {
  description = "The lifecycle rules of the bucket, if the bucket is configured with lifecycle rules. If not, this will be an empty string."
  value       = try(module.s3_bucket_ct_logs.s3_bucket_lifecycle_configuration_rules, "")
}

output "ct_s3_bucket_policy" {
  description = "The policy of the bucket, if the bucket is configured with a policy. If not, this will be an empty string."
  value       = try(module.s3_bucket_ct_logs.s3_bucket_policy, "")
}

###############################################################################
# CT S3 logs KMS key
###############################################################################

output "ct_logs_s3_bucket_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.ct_logs_s3_bucket_kms_key.key_arn, null)
}

output "ct_logs_s3_bucket_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.ct_logs_s3_bucket_kms_key.key_id, null)
}

output "ct_logs_s3_bucket_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.ct_logs_s3_bucket_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for CT S3 logs
###############################################################################

output "ct_logs_s3_bucket_kms_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.ct_logs_s3_bucket_kms_key.aliases
}

###############################################################################
# CT CW logs KMS key
###############################################################################

output "ct_logs_cw_logs_kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = try(module.ct_logs_cw_logs_kms_key.key_arn, null)
}

output "ct_logs_cw_logs_bucket_kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = try(module.ct_logs_cw_logs_kms_key.key_id, null)
}

output "ct_logs_cw_logs_bucket_kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = try(module.ct_logs_cw_logs_kms_key.key_policy, null)
}

###############################################################################
# Alias for KMS key for CloudWatch log groups for CT CW logs
###############################################################################

output "ct_logs_cw_logs_kms_aliases" {
  description = "A map of aliases created and their attributes"
  value       = module.ct_logs_cw_logs_kms_key.aliases
}

###############################################################################
#  IAM role for admin
###############################################################################

output "admin_iam_role_arn" {
  description = "ARN of admin IAM role"
  value       = try(aws_iam_role.admin_iam_role.arn, "")
}

output "admin_iam_role_name" {
  description = "Name of admin IAM role"
  value       = try(aws_iam_role.admin_iam_role.name, "")
}