###############################################################################
# ECS module: https://github.com/terraform-aws-modules/terraform-aws-ecs.git
###############################################################################

module "ecs-cluster" {
  #############################################################################
  # ECS cluster settings
  #############################################################################

  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "5.2.2"

  #############################################################################
  # ECS cluster
  #############################################################################

  cluster_name = format("${local.name}-cluster")

  tags = merge(
    { "Name" = format("${local.name}-cluster") },
    local.resource_tags
  )

  cluster_configuration = var.cluster_configuration

  #############################################################################
  # CloudWatch Log Group
  #############################################################################

  cloudwatch_log_group_kms_key_id = module.ecs_cluster_logs_kms_key.key_arn

  cloudwatch_log_group_tags = merge(
    { "Name" = format("${local.name}-ecs-cluster-cw-log-group") },
    local.resource_tags
  )

  #############################################################################
  # Capacity Providers
  #############################################################################

  fargate_capacity_providers = var.fargate_capacity_providers

}