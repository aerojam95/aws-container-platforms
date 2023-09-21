###############################################################################
# ECS module: https://github.com/terraform-aws-modules/terraform-aws-ecs.git
###############################################################################

module "ecs-service" {
  #############################################################################
  #  ECS service settings
  #############################################################################

  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "5.2.2"

  #############################################################################
  #  ECS service
  #############################################################################

  name        = format("${local.name}-service")
  tags        = local.resource_tags
  cluster_arn = module.ecs-cluster.arn

  load_balancer = {
    service = {
      target_group_arn = element(module.alb.target_group_arns, 0)
      container_name   = format("${local.name}-container")
      container_port   = 3000
    }
  }

  subnet_ids = module.vpc.private_subnets

  #############################################################################
  # Task defintion
  #############################################################################

  container_definitions = {
    "ecs-container-definition" = {
      cpu = 1024

      docker_labels = {
        "container-name" = format("${local.name}-container")
      }

      image              = ""
      interactive        = false
      memory             = 2048
      memory_reservation = 512
      name               = format("${local.name}-container")
      port_mappings = [
        {
          name          = format("${local.name}-container-port")
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ]
      privileged                      = false # Can only be false for fargate
      service                         = format("${local.name}-service")
      enable_cloudwatch_logging       = true
      create_cloudwatch_log_group     = true
      cloudwatch_log_group_kms_key_id = module.ecs_service_logs_kms_key.key_arn

      tags = merge(
        { "Name" = format("${local.name}-container-defintion") },
        local.resource_tags
      )

    }
  }

  network_mode = var.network_mode
  cpu          = var.cpu
  memory       = var.memory

  #############################################################################
  # Task Execution - IAM Role
  # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html
  #############################################################################

  task_exec_iam_role_name            = format("${local.name}-task-exec-iam-role")
  task_exec_iam_role_use_name_prefix = var.task_exec_iam_role_use_name_prefix

  task_exec_iam_role_tags = merge(
    { "Name" = format("${local.name}-task-exec-iam-role") },
    local.resource_tags
  )

  task_exec_ssm_param_arns = var.task_exec_ssm_param_arns
  task_exec_secret_arns    = var.task_exec_secret_arns

  #############################################################################
  # Tasks - IAM role
  # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
  #############################################################################

  tasks_iam_role_name            = format("${local.name}-task-iam-role")
  tasks_iam_role_use_name_prefix = var.tasks_iam_role_use_name_prefix

  tasks_iam_role_tags = merge(
    { "Name" = format("${local.name}-task-iam-role") },
    local.resource_tags
  )

  #############################################################################
  # Security Group
  #############################################################################
  security_group_name            = "${local.name}-ecs-service-sg"
  security_group_use_name_prefix = var.security_group_use_name_prefix
  security_group_description     = "Security group for ECS service"
  security_group_rules           = var.service_security_group_rules

  security_group_tags = merge(
    { "Name" = format("${local.name}-ecs-service-sg") },
    local.resource_tags
  )

}