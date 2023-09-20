###############################################################################
# ALB module: https://github.com/terraform-aws-modules/terraform-aws-alb.git
###############################################################################

module "alb" {
  #############################################################################
  # ALB settings
  #############################################################################

  source  = "terraform-aws-modules/alb/aws"
  version = "~> 8.0"

  #############################################################################
  # ALB
  #############################################################################

  https_listeners         = var.https_listeners
  http_tcp_listeners      = var.http_tcp_listeners
  https_listener_rules    = var.https_listener_rules
  http_tcp_listener_rules = var.http_tcp_listener_rules
  name                    = format("${local.name}-alb")

  access_logs = {
    bucket  = module.s3_bucket_alb_logs.s3_bucket_id
    prefix  = "ecs-cluster-alb-logs"
    enabled = true
  }

  subnets                      = module.vpc.public_subnets
  tags                         = local.resource_tags
  lb_tags                      = { "Name" = format("${local.name}-alb") }
  target_group_tags            = { "Name" = format("${local.name}-tg") }
  https_listener_rules_tags    = { "Name" = format("${local.name}-alb-https-listener-rule") }
  http_tcp_listener_rules_tags = { "Name" = format("${local.name}-alb-http-tcp-listener-rule") }

  target_groups = [
    {
      name             = format("${local.name}-tg")
      backend_protocol = "HTTP"
      backend_port     = 3000
      target_type      = "ip"
    }
  ]

  vpc_id = module.vpc.vpc_id

  #############################################################################
  # Security group
  #############################################################################

  security_group_name            = format("${local.name}-alb-sg")
  security_group_use_name_prefix = false
  security_group_rules           = var.alb_security_group_rules
  security_group_tags            = { "Name" = format("${local.name}-alb-sg") }
}