###############################################################################
# AWS Cloud Map namespace IAM role
###############################################################################

resource "aws_iam_role" "aws_cloud_map_iam_role" {
  name_prefix        = "aws-cloud-map-iam-role-"
  assume_role_policy = data.aws_iam_policy_document.aws_cloud_map_assume_role.json

  tags = merge(
    { "Name" = format("${local.name}-aws-cloud-map-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_cloud_map_assume_role" {

  statement {
    sid = "AWSCloudMapAssumeRole"
    principals {
      type        = "Service"
      identifiers = ["servicediscovery.amazonaws.com"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }

}

resource "aws_iam_role_policy_attachment" "aws_cloud_map_attachment" {
  role       = aws_iam_role.aws_cloud_map_iam_role.name
  policy_arn = aws_iam_policy.aws_cloud_map_iam_policy.arn
}

resource "aws_iam_policy" "aws_cloud_map_iam_policy" {
  name_prefix = "aws-cloud-map-iam-role-"
  policy      = data.aws_iam_policy_document.aws_cloud_map_iam_policy_document.json

  tags = merge(
    { "Name" = format("${local.name}-aws-cloud-map-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_cloud_map_iam_policy_document" {

  statement {
    sid    = "AWSCloudMapECSClusterAccess"
    effect = "Allow"
    actions = [
      "ecs:CreateCluster",
      "ecs:DeleteCluster",
      "ecs:DescribeClusters",
      "ecs:ListClusters",
    ]
    resources = [module.ecs-cluster.arn]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [module.namespace.namespace_arn]
    }
  }

}

###############################################################################
# ECS cluster IAM role
###############################################################################

resource "aws_iam_role" "aws_ecs_cluster_iam_role" {
  name_prefix        = "aws-ecs-cluster-iam-role-"
  assume_role_policy = data.aws_iam_policy_document.aws_ecs_cluster_assume_role.json

  tags = merge(
    { "Name" = format("${local.name}-aws-ecs-cluster-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_ecs_cluster_assume_role" {

  statement {
    sid = "AWSECSClusterAssumeRole"
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }

}

resource "aws_iam_role_policy_attachment" "aws_ecs_cluster_attachment" {
  role       = aws_iam_role.aws_ecs_cluster_iam_role.name
  policy_arn = aws_iam_policy.aws_ecs_cluster_iam_policy.arn
}

resource "aws_iam_policy" "aws_ecs_cluster_iam_policy" {
  name_prefix = "aws-ecs-cluster-iam-role-"
  policy      = data.aws_iam_policy_document.aws_ecs_cluster_iam_policy_document.json

  tags = merge(
    { "Name" = format("${local.name}-aws-ecs-cluster-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_ecs_cluster_iam_policy_document" {

  statement {
    sid    = "AWSECSClusterActions"
    effect = "Allow"
    actions = [
      "ecs:CreateCluster",
      "ecs:DeleteCluster",
      "ecs:DescribeClusters",
      "ecs:ListClusters",
      "ecs:RegisterContainerInstance",
      "ecs:CreateService",
      "ecs:DeleteService",
      "ecs:DeregisterContainerInstance",
      "ecs:DeregisterTaskDefinition",
      "ecs:DiscoverPollEndpoint",
      "ecs:Submit*",
      "ecs:Poll",
      "ecs:RegisterContainerInstance",
      "ecs:RegisterTaskDefinition",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:SubmitContainerStateChange",
      "ecs:SubmitTaskStateChange",
      "ecs:UpdateContainerAgent",
      "ecs:UpdateService",
      "ecs:UpdateContainerInstancesState"
    ]
    resources = [module.ecs-cluster.arn]
  }

  statement {
    sid    = "AWSECSClusterLogsPushToCloudWatch"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${module.ecs-cluster.cloudwatch_log_group_arn}:*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [module.ecs-cluster.arn]
    }
  }

}

###############################################################################
# ALB IAM role
###############################################################################

resource "aws_iam_role" "aws_alb_iam_role" {

  name_prefix        = "aws-alb-iam-role-"
  assume_role_policy = data.aws_iam_policy_document.aws_alb_assume_role.json

  tags = merge(
    { "Name" = format("${local.name}-aws-alb-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_alb_assume_role" {

  statement {
    sid = "AWSALBAssumeRole"
    principals {
      type        = "Service"
      identifiers = ["elasticloadbalancing.amazonaws.com"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }

}

resource "aws_iam_role_policy_attachment" "aws_alb_attachment" {

  role       = aws_iam_role.aws_alb_iam_role.name
  policy_arn = aws_iam_policy.aws_alb_iam_policy.arn

}

resource "aws_iam_policy" "aws_alb_iam_policy" {

  name_prefix = "aws-alb-iam-role-"
  policy      = data.aws_iam_policy_document.aws_alb_iam_policy_document.json

  tags = merge(
    { "Name" = format("${local.name}-aws-alb-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_alb_iam_policy_document" {

  statement {
    sid    = "AWSALBS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
    ]
    resources = [
      "${module.s3_bucket_alb_logs.s3_bucket_arn}/*",
      module.s3_bucket_alb_logs.s3_bucket_arn
    ]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [module.alb.lb_arn]
    }
  }

  statement {
    sid    = "AWSALBECSClusterAccess"
    effect = "Allow"
    actions = [
      "ecs:RegisterTaskDefinition",
      "ecs:ListClusters",
      "ecs:DescribeClusters",
      "ecs:ListServices",
      "ecs:DescribeTasks",
      "ecs:DescribeServices",
      "ecs:UpdateService",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
    ]
    resources = [module.ecs-cluster.arn]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [module.alb.lb_arn]
    }
  }
}

###############################################################################
# CT IAM role
###############################################################################

resource "aws_iam_role" "aws_ct_iam_role" {

  name_prefix        = "aws-ct-iam-role-"
  assume_role_policy = data.aws_iam_policy_document.aws_ct_assume_role.json

  tags = merge(
    { "Name" = format("${local.name}-aws-ct-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_ct_assume_role" {

  statement {
    sid = "AWSCTAssumeRole"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }

}

resource "aws_iam_role_policy_attachment" "aws_ct_attachment" {

  role       = aws_iam_role.aws_ct_iam_role.name
  policy_arn = aws_iam_policy.aws_ct_iam_policy.arn

}

resource "aws_iam_policy" "aws_ct_iam_policy" {

  name_prefix = "aws-ct-iam-role-"
  policy      = data.aws_iam_policy_document.aws_ct_iam_policy_document.json

  tags = merge(
    { "Name" = format("${local.name}-aws-ct-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "aws_ct_iam_policy_document" {

  statement {
    sid    = "AWSCTS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
    ]
    resources = [
      "${module.s3_bucket_ct_logs.s3_bucket_arn}/*",
      module.s3_bucket_ct_logs.s3_bucket_arn
    ]
  }

  statement {
    sid    = "AWSCTLogsPushToCloudWatch"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.aws_ct_cw_log_group.arn}:*"]
  }

}

###############################################################################
# ECS container platform user Admin IAM role
###############################################################################

resource "aws_iam_role" "admin_iam_role" {

  name_prefix        = "admin-"
  assume_role_policy = data.aws_iam_policy_document.admin_assume_role.json

  tags = merge(
    { "Name" = format("${local.name}-admin-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "admin_assume_role" {
  statement {
    sid = "AWSECSContainerPlatformAdminAssumeRole"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "admin_attachment" {

  role       = aws_iam_role.admin_iam_role.name
  policy_arn = aws_iam_policy.admin_iam_policy.arn

}

resource "aws_iam_policy" "admin_iam_policy" {

  name_prefix = "admin-iam-role-"
  policy      = data.aws_iam_policy_document.admin_iam_policy_document.json

  tags = merge(
    { "Name" = format("${local.name}-admin-iam-role") },
    local.resource_tags
  )

}

data "aws_iam_policy_document" "admin_iam_policy_document" {

  statement {
    sid     = "AWSECSContainerPlatformAdminIAM"
    effect  = "Allow"
    actions = ["iam:*"]
    resources = [
      module.vpc.vpc_flow_log_cloudwatch_iam_role_arn,
      module.namespace.aws_cloud_map_iam_role_arn,
      aws_iam_role.aws_cloud_map_iam_role.arn,
      aws_iam_role.aws_ecs_cluster_iam_role.arn,
      module.ecs-service.task_exec_iam_role_arn,
      module.ecs-service.tasks_iam_role_arn,
      aws_iam_role.aws_alb_iam_role.arn,
      aws_iam_role.aws_ct_iam_role.arn
    ]
  }

  statement {
    sid    = "AWSECSContainerPlatformAdminCW"
    effect = "Allow"
    actions = [
      "cloudwatch:*",
      "logs:*"
    ]
    resources = [
      module.vpc.vpc_flow_log_destination_arn,
      module.ecs-cluster.cloudwatch_log_group_arn,
      aws_cloudwatch_log_group.aws_ct_cw_log_group.arn
    ]
  }

  statement {
    sid     = "AWSECSContainerPlatformAdminCT"
    effect  = "Allow"
    actions = ["cloudtrail:*"]
    resources = [
      module.cloudtrail.cloudtrail_arn
    ]
  }

  statement {
    sid     = "AWSECSContainerPlatformAdminKMS"
    effect  = "Allow"
    actions = ["kms:*"]
    resources = [
      module.vpc_flow_log_kms_key.key_arn,
      module.ecs_cluster_logs_kms_key.key_arn,
      module.ecs_service_logs_kms_key.key_arn,
      module.alb_logs_s3_bucket_kms_key.key_arn,
      module.ct_logs_s3_bucket_kms_key.key_arn,
      module.ct_logs_cw_logs_kms_key.key_arn
    ]
  }

  statement {
    sid    = "AWSECSContainerPlatformAdminNetworking"
    effect = "Allow"
    actions = [
      "ec2:*"
      # "ec2:AcceptVpcPeeringConnection",
      # "ec2:AcceptVpcEndpointConnections",
      # "ec2:AllocateAddress",
      # "ec2:AssignIpv6Addresses",
      # "ec2:AssignPrivateIpAddresses",
      # "ec2:AssociateAddress",
      # "ec2:AssociateDhcpOptions",
      # "ec2:AssociateRouteTable",
      # "ec2:AssociateSubnetCidrBlock",
      # "ec2:AssociateVpcCidrBlock",
      # "ec2:AttachClassicLinkVpc",
      # "ec2:AttachInternetGateway",
      # "ec2:AttachNetworkInterface",
      # "ec2:AttachVpnGateway",
      # "ec2:AuthorizeSecurityGroupEgress",
      # "ec2:AuthorizeSecurityGroupIngress",
      # "ec2:CreateCarrierGateway",
      # "ec2:CreateCustomerGateway",
      # "ec2:CreateDefaultSubnet",
      # "ec2:CreateDefaultVpc",
      # "ec2:CreateDhcpOptions",
      # "ec2:CreateEgressOnlyInternetGateway",
      # "ec2:CreateFlowLogs",
      # "ec2:CreateInternetGateway",
      # "ec2:CreateLocalGatewayRouteTableVpcAssociation",
      # "ec2:CreateNatGateway",
      # "ec2:CreateNetworkAcl",
      # "ec2:CreateNetworkAclEntry",
      # "ec2:CreateNetworkInterface",
      # "ec2:CreateNetworkInterfacePermission",
      # "ec2:CreateRoute",
      # "ec2:CreateRouteTable",
      # "ec2:CreateSecurityGroup",
      # "ec2:CreateSubnet",
      # "ec2:CreateTags",
      # "ec2:CreateVpc",
      # "ec2:CreateVpcEndpoint",
      # "ec2:CreateVpcEndpointConnectionNotification",
      # "ec2:CreateVpcEndpointServiceConfiguration",
      # "ec2:CreateVpcPeeringConnection",
      # "ec2:CreateVpnConnection",
      # "ec2:CreateVpnConnectionRoute",
      # "ec2:CreateVpnGateway",
      # "ec2:DeleteCarrierGateway",
      # "ec2:DeleteCustomerGateway",
      # "ec2:DeleteDhcpOptions",
      # "ec2:DeleteEgressOnlyInternetGateway",
      # "ec2:DeleteFlowLogs",
      # "ec2:DeleteInternetGateway",
      # "ec2:DeleteLocalGatewayRouteTableVpcAssociation",
      # "ec2:DeleteNatGateway",
      # "ec2:DeleteNetworkAcl",
      # "ec2:DeleteNetworkAclEntry",
      # "ec2:DeleteNetworkInterface",
      # "ec2:DeleteNetworkInterfacePermission",
      # "ec2:DeleteRoute",
      # "ec2:DeleteRouteTable",
      # "ec2:DeleteSecurityGroup",
      # "ec2:DeleteSubnet",
      # "ec2:DeleteTags",
      # "ec2:DeleteVpc",
      # "ec2:DeleteVpcEndpoints",
      # "ec2:DeleteVpcEndpointConnectionNotifications",
      # "ec2:DeleteVpcEndpointServiceConfigurations",
      # "ec2:DeleteVpcPeeringConnection",
      # "ec2:DeleteVpnConnection",
      # "ec2:DeleteVpnConnectionRoute",
      # "ec2:DeleteVpnGateway",
      # "ec2:DescribeAccountAttributes",
      # "ec2:DescribeAddresses",
      # "ec2:DescribeAvailabilityZones",
      # "ec2:DescribeCarrierGateways",
      # "ec2:DescribeClassicLinkInstances",
      # "ec2:DescribeCustomerGateways",
      # "ec2:DescribeDhcpOptions",
      # "ec2:DescribeEgressOnlyInternetGateways",
      # "ec2:DescribeFlowLogs",
      # "ec2:DescribeInstances",
      # "ec2:DescribeInternetGateways",
      # "ec2:DescribeIpv6Pools",
      # "ec2:DescribeLocalGatewayRouteTables",
      # "ec2:DescribeLocalGatewayRouteTableVpcAssociations",
      # "ec2:DescribeKeyPairs",
      # "ec2:DescribeMovingAddresses",
      # "ec2:DescribeNatGateways",
      # "ec2:DescribeNetworkAcls",
      # "ec2:DescribeNetworkInterfaceAttribute",
      # "ec2:DescribeNetworkInterfacePermissions",
      # "ec2:DescribeNetworkInterfaces",
      # "ec2:DescribePrefixLists",
      # "ec2:DescribeRouteTables",
      # "ec2:DescribeSecurityGroupReferences",
      # "ec2:DescribeSecurityGroupRules",
      # "ec2:DescribeSecurityGroups",
      # "ec2:DescribeStaleSecurityGroups",
      # "ec2:DescribeSubnets",
      # "ec2:DescribeTags",
      # "ec2:DescribeVpcAttribute",
      # "ec2:DescribeVpcClassicLink",
      # "ec2:DescribeVpcClassicLinkDnsSupport",
      # "ec2:DescribeVpcEndpointConnectionNotifications",
      # "ec2:DescribeVpcEndpointConnections",
      # "ec2:DescribeVpcEndpoints",
      # "ec2:DescribeVpcEndpointServiceConfigurations",
      # "ec2:DescribeVpcEndpointServicePermissions",
      # "ec2:DescribeVpcEndpointServices",
      # "ec2:DescribeVpcPeeringConnections",
      # "ec2:DescribeVpcs",
      # "ec2:DescribeVpnConnections",
      # "ec2:DescribeVpnGateways",
      # "ec2:DetachClassicLinkVpc",
      # "ec2:DetachInternetGateway",
      # "ec2:DetachNetworkInterface",
      # "ec2:DetachVpnGateway",
      # "ec2:DisableVgwRoutePropagation",
      # "ec2:DisableVpcClassicLink",
      # "ec2:DisableVpcClassicLinkDnsSupport",
      # "ec2:DisassociateAddress",
      # "ec2:DisassociateRouteTable",
      # "ec2:DisassociateSubnetCidrBlock",
      # "ec2:DisassociateVpcCidrBlock",
      # "ec2:EnableVgwRoutePropagation",
      # "ec2:EnableVpcClassicLink",
      # "ec2:EnableVpcClassicLinkDnsSupport",
      # "ec2:ModifyNetworkInterfaceAttribute",
      # "ec2:ModifySecurityGroupRules",
      # "ec2:ModifySubnetAttribute",
      # "ec2:ModifyVpcAttribute",
      # "ec2:ModifyVpcEndpoint",
      # "ec2:ModifyVpcEndpointConnectionNotification",
      # "ec2:ModifyVpcEndpointServiceConfiguration",
      # "ec2:ModifyVpcEndpointServicePermissions",
      # "ec2:ModifyVpcPeeringConnectionOptions",
      # "ec2:ModifyVpcTenancy",
      # "ec2:MoveAddressToVpc",
      # "ec2:RejectVpcEndpointConnections",
      # "ec2:RejectVpcPeeringConnection",
      # "ec2:ReleaseAddress",
      # "ec2:ReplaceNetworkAclAssociation",
      # "ec2:ReplaceNetworkAclEntry",
      # "ec2:ReplaceRoute",
      # "ec2:ReplaceRouteTableAssociation",
      # "ec2:ResetNetworkInterfaceAttribute",
      # "ec2:RestoreAddressToClassic",
      # "ec2:RevokeSecurityGroupEgress",
      # "ec2:RevokeSecurityGroupIngress",
      # "ec2:UnassignIpv6Addresses",
      # "ec2:UnassignPrivateIpAddresses",
      # "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      # "ec2:UpdateSecurityGroupRuleDescriptionsIngress"
    ]
    resources = [
      module.vpc.vpc_arn,
      module.vpc_endpoints_sg.security_group_arn,
      module.ecs-service.security_group_arn,
      module.alb.security_group_arn
    ]
  }

  statement {
    sid       = "AWSECSContainerPlatformAdminAWSCloudMap"
    effect    = "Allow"
    actions   = ["servicediscovery:*"]
    resources = [module.namespace.namespace_arn]
  }

  statement {
    sid     = "AWSECSContainerPlatformAdminECS"
    effect  = "Allow"
    actions = ["ecs:*"]
    resources = [
      module.ecs-cluster.arn,
      module.ecs-service.id
    ]
  }

  statement {
    sid       = "AWSECSContainerPlatformAdminALB"
    effect    = "Allow"
    actions   = ["elasticloadbalancing:*"]
    resources = [module.alb.lb_arn]
  }

  statement {
    sid     = "AWSECSContainerPlatformAdminS3"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "${module.s3_bucket_alb_logs.s3_bucket_arn}/*",
      module.s3_bucket_alb_logs.s3_bucket_arn,
      "${module.s3_bucket_ct_logs.s3_bucket_arn}/*",
      module.s3_bucket_ct_logs.s3_bucket_arn
    ]
  }

}