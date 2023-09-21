# aws-ecs-fargate-container-platforms

## Description
Terraform for creating an AWS ECS fargate container platform

![Container Platform](docs/ecs-container-platform.png)

## Key infrastructure

| Name | Description |
|------|------|
| [vpc]( https://github.com/terraform-aws-modules/terraform-aws-vpc.git) | VPC such that infrastructure is secured on a networking level |
| [vpc-endpoints](https://github.com/terraform-aws-modules/terraform-aws-vpc.git) | Give the VPC access to AWS the required services  |
| [S3-bucket](https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git) | Logging the CloudTrail trail and ALB |
| [kms-keys](https://github.com/terraform-aws-modules/terraform-aws-kms.git) | Encryption for S3 buckets for logging of CloudTaril and ALB, encryption to the CloudWatch log groups for CloudTrail trail, VPC flow logs, ECS cluster and service and its tasks |
| [cloudtrail-trail](https://github.com/cloudposse/terraform-aws-cloudtrail.git) | Audit loggging for infrastructure |
| [iam-roles](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | Gives services, relevant permissions, and creates an admin role for administration |
| [alb](https://github.com/terraform-aws-modules/terraform-aws-alb.git) | Handles the traffic needs of the ECS fargate cluster and distributes traffic across tasks in different AZs where the ECS service can run |
| [aws-cloud-map-namespace](https://github.com/aerojam95/aws-cloud-map.git) | Give the ECS service, that runs on the ECS fragate cluster, a namespace in order to run on |
| [ecs-cluster-fargate](https://github.com/terraform-aws-modules/terraform-aws-ecs.git) | ECS fargate cluster where workloads will be computed |
| [ecs-service-fargate](https://github.com/terraform-aws-modules/terraform-aws-ecs.git) | ECS fargate service where workloads are orchestrated and defined |


## Pre-requisites
1. Get relevant AWS credentials (Access Key and Access Secret) to apply terraform locally or input credentials into the relevant Pipeline variables
2. Create S3 bucket and configure as Terraform remote backend to store the relevant Terraform statefile
3. Add the state file related values to to the backend block in the version.tf file once created
4. Create an image to be pulled from AWS ECR to use to spin containers in the task deifnitions of the ECS service
5. In the Task defintion block of the ecs-fargate-service.tf file add the image id of the image that wants to be pulled for the container defintion to be deployed by the ECS service

## Usage
```sh
terraform init
terraform fmt
terraform valiate
terraform plan -out=$PLAN
terraform apply -input=false --auto-approve $PLAN
terraform plan -destroy -out=$DESTROY
terraform apply -input=false --auto-approve $DESTROY
```