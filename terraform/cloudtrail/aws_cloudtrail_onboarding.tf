











































resource "aws_iam_role" "sentinelone_marketplace_access_role" {
 count = local.is_bucket_owner_account ? 1 : 0
 name = "singularity-aws-app-${var.identifier}"
 path = var.iam_path

 assume_role_policy = jsonencode({
 Version = "2012-10-17"
 Statement = [
 {
 Effect = "Allow"
 Action = "sts:AssumeRole"
 Principal = {
 AWS = local.marketplace_access_role_principals
 }
 Condition = {
 StringEquals = {
 "sts:ExternalId" = var.marketplace_external_id
 }
 }
 }
 ]
 })

 permissions_boundary = local.has_permission_boundary ? var.permission_boundary_arn : null
}

resource "aws_iam_policy" "sentinelone_cns_allow_cloudtrail_bucket_access_policy" {
 count = local.is_bucket_owner_account ? 1 : 0
 description = "Allow SentinelOne CNS access to CloudTrail bucket"
 path = var.iam_path

 policy = jsonencode({
 Version = "2012-10-17"
 Statement = [
 {
 Sid = "AllowSentinelOneCNSAccessCloudTrailS3ListGetLocation"
 Effect = "Allow"
 Action = [
 "s3:GetBucketLocation",
 "s3:ListBucket"
 ]
 Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}"
 Condition = {
 Bool = {
 "aws:SecureTransport" = "true"
 }
 }
 },
 {
 Sid = "AllowSentinelOneCNSAccessCloudTrailS3GetObject"
 Effect = "Allow"
 Action = [
 "s3:GetObject"
 ]
 Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}/*"
 Condition = {
 Bool = {
 "aws:SecureTransport" = "true"
 }
 }
 }
 ]
 })
}

resource "aws_iam_policy_attachment" "sentinelone_cns_allow_cloudtrail_bucket_access_policy_attachment" {
 count = local.is_bucket_owner_account ? 1 : 0
 name = "SentinelOneCNSAllowCloudTrailBucketAccessPolicyAttachment"
 roles = [
 var.audit_role_name,
 "singularity-aws-app-2056384125320855810"
 ]
 policy_arn = aws_iam_policy.sentinelone_cns_allow_cloudtrail_bucket_access_policy[0].arn
}


resource "aws_iam_policy" "sentinelone_cns_allow_cloudtrail_queue_access_policy" {
count = local.is_bucket_owner_account ? 1 : 0
description = "Allow SentinelOne CNS access to CloudTrail bucket"
path = var.iam_path
policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid = "AllowSentinelOneCNSAccessCloudTrailS3ListGetLocation"
Effect = "Allow"
Action = [
"sqs:DeleteMessage",
"sqs:ReceiveMessage",
"sqs:ChangeMessageVisibility"
]
Resource = "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${var.existing_sns_topic_account_id}:s1-marketplace-cloudtrail-logs-queue-${var.identifier}"
Condition = {
Bool = {
"aws:SecureTransport" = "true"
}
}
}
]
})
}

resource "aws_iam_policy_attachment" "sentinelone_cns_allow_cloudtrail_queue_access_policy_attachment" {
count = local.is_bucket_owner_account ? 1 : 0
name = "SentinelOneCNSAllowCloudTrailQueueAccessPolicyAttachment"
roles = [
"singularity-aws-app-2056384125320855810"
]
policy_arn = aws_iam_policy.sentinelone_cns_allow_cloudtrail_queue_access_policy[0].arn
}

resource "aws_iam_policy" "sentinelone_cns_allow_kms_decrypt_policy" {
 count = local.create_kms_policy ? 1 : 0
 description = "Allow SentinelOne CNS to decrypt CloudTrail KMS encryption"

 policy = jsonencode({
 Version = "2012-10-17"
 Statement = [
 {
 Sid = "AllowCNSToDecryptCloudtrailKMS"
 Effect = "Allow"
 Action = [
 "kms:Decrypt"
 ]
 Resource = var.cloudtrail_kms_arn
 }
 ]
 })
}

resource "aws_iam_policy_attachment" "sentinelone_cns_allow_kms_decrypt_policy_attachment" {
 count = local.create_kms_policy ? 1 : 0
 name = "SentinelOneCNSAllowKMSDecryptPolicyAttachment"
 roles = [
 var.audit_role_name,
 "singularity-aws-app-2056384125320855810"
 ]
 policy_arn = aws_iam_policy.sentinelone_cns_allow_kms_decrypt_policy[0].arn
}

resource "aws_sqs_queue" "marketplace_cloudtrail_logs_queue" {
 count = local.create_sqs ? 1 : 0

 name = "s1-marketplace-cloudtrail-logs-queue-${var.identifier}"
}

resource "aws_sqs_queue_policy" "marketplace_cloudtrail_logs_queue_policy" {
 count = local.create_sqs ? 1 : 0
 queue_url = aws_sqs_queue.marketplace_cloudtrail_logs_queue[0].id

 policy = jsonencode({
 Version = "2012-10-17"
 Statement = [
 {
 Sid = "Allow-SNS-SendMessage"
 Effect = "Allow"
 Principal = {
 Service = "sns.amazonaws.com"
 }
 Action = "sqs:SendMessage"
 Resource = aws_sqs_queue.marketplace_cloudtrail_logs_queue[0].arn
 Condition = {
 ArnEquals = {
 "aws:SourceArn" = var.existing_sns_topic_arn
 }
 }
 },
 {
 Sid = "Allow-SentinelOneMarketplaceAccess-RecvDeleteMsg"
 Effect = "Allow"
 Principal = {
 AWS = "arn:${data.aws_partition.current.partition}:iam::${var.bucket_owner_account_id}:role${var.iam_path}singularity-aws-app-${var.identifier}"
 }
 Action = [
 "sqs:DeleteMessage",
 "sqs:ReceiveMessage",
 "sqs:ChangeMessageVisibility"
 ]
 Resource = aws_sqs_queue.marketplace_cloudtrail_logs_queue[0].arn
 }
 ]
 })
}

resource "aws_sns_topic_subscription" "marketplace_cloudtrail_logs_notification_queue_subscription" {
 count = local.create_sqs ? 1 : 0
 topic_arn = var.existing_sns_topic_arn
 protocol = "sqs"
 endpoint = aws_sqs_queue.marketplace_cloudtrail_logs_queue[0].arn

 raw_message_delivery = false
}

resource "aws_cloudformation_stack_set" "sentinel_one_stack_set" {
count = local.is_organization_onboarding ? 1 : 0
name = "s1-cnapp-cloudtrail-stackset-${var.identifier}"
capabilities = [
"CAPABILITY_NAMED_IAM",
"CAPABILITY_IAM"
]
managed_execution {
active = true
}

permission_model = "SERVICE_MANAGED"

auto_deployment {
enabled = true
retain_stacks_on_account_removal = false
}

operation_preferences {
failure_tolerance_count = 24
max_concurrent_count = 25
region_concurrency_type = "PARALLEL"
}

parameters = {
identifier = var.identifier
auditRoleName = var.audit_role_name
rootOUId = var.root_ou_id
marketplaceExternalId = var.marketplace_external_id
iamPath = var.iam_path
permissionsBoundaryArn = var.permission_boundary_arn
existingSNSTopicARN = var.existing_sns_topic_arn
}

template_body = jsonencode({
Conditions = {
CreateKMSPolicy = {
"Fn::Not" = [
{
"Fn::Equals" = [
"", ""
]
}
]
}
CreateSQS = {
Condition = "SNSAccount"
}
HasPermissionsBoundary = {
"Fn::Not" = [
{
"Fn::Equals" = [
{ "Ref" = "permissionsBoundaryArn" }, ""
]
}
]
}
IsBucketOwnerAccount = {
"Fn::Equals" = [
"688567271939", { "Ref" = "AWS::AccountId" }
]
}
IsNotBucketOwnerAccount = {
"Fn::Not" = [
{ "Condition" = "IsBucketOwnerAccount" }
]
}
SNSAccount = {
"Fn::Equals" = [
"207567775001", { "Ref" = "AWS::AccountId" }
]
}
CreateKMSPolicy = {
"Fn::Not" = [
{
"Fn::Equals" = [
"", ""
]
}
]
}
},
Parameters = {
auditRoleName = { Type = "String" }
iamPath = { Type = "String" }
identifier = { Type = "String" }
marketplaceExternalId = { Type = "String" }
permissionsBoundaryArn = { Type = "String" }
rootOUId = { Type = "String" }
existingSNSTopicARN = { Type = "String" }
},
Resources = {
MarketplaceCloudTrailLogsNotificationQueueSubscription = {
Condition = "CreateSQS",
Properties = {
Endpoint = { "Fn::GetAtt" = ["MarketplaceCloudTrailLogsQueue", "Arn"] }
Protocol = "sqs"
RawMessageDelivery = false
TopicArn = "arn:aws:sns:us-east-1:207567775001:aws-controltower-AllConfigNotifications"
},
Type = "AWS::SNS::Subscription"
},
MarketplaceCloudTrailLogsQueue = {
Condition = "CreateSQS",
Properties = {
QueueName = {
"Fn::Join" = [
"",
["s1-marketplace-cloudtrail-logs-queue-", { "Ref" = "identifier" }]
]
}
},
Type = "AWS::SQS::Queue"
},
MarketplaceCloudTrailLogsQueuePolicyAllow = {
Condition = "CreateSQS",
Properties = {
PolicyDocument = {
Statement = [
{
Action = "sqs:SendMessage"
Condition = {
ArnEquals = {
"aws:SourceArn" = "arn:aws:sns:us-east-1:207567775001:aws-controltower-AllConfigNotifications"
}
}
Effect = "Allow"
Principal = {
Service = "sns.amazonaws.com"
}
Resource = { "Fn::GetAtt" = ["MarketplaceCloudTrailLogsQueue", "Arn"] }
Sid = "Allow-SNS-SendMessage"
},
{
Action = [
"sqs:DeleteMessage",
"sqs:ReceiveMessage",
"sqs:ChangeMessageVisibility"
]
Effect = "Allow"
Principal = {
AWS = {"Fn::Sub" = "arn:${data.aws_partition.current.partition}:iam::688567271939:role${var.iam_path}singularity-aws-app-${var.identifier}"}
}
Resource = { "Fn::GetAtt" = ["MarketplaceCloudTrailLogsQueue", "Arn"] }
Sid = "Allow-SentinelOneMarketplaceAccess-RecvDeleteMsg"
}
]
},
Queues = [
{ "Ref" = "MarketplaceCloudTrailLogsQueue" }
]
},
Type = "AWS::SQS::QueuePolicy"
}

SentinelOneCNSAllowKMSDecryptPolicy = {
Condition = "CreateKMSPolicy",
DependsOn = "SentinelOneMarketplaceAccessRole",
Properties = {
Description = "Allow SentinelOne CNS to decrypt CloudTrail KMS encryption",
Path = { "Ref" = "iamPath" },
PolicyDocument = {
Statement = [
{
Action = ["kms:Decrypt"]
Effect = "Allow"
Resource = ""
Sid = "AllowCNSToDecryptCloudtrailKMS"
}
],
Version = "2012-10-17"
},
Roles = [
{ "Ref" = "auditRoleName" },
{ "Fn::Sub" = "singularity-aws-app-${var.identifier}" }
]
},
Type = "AWS::IAM::ManagedPolicy"
}

SentinelOneCNSLogsNotificationQueueSubscription = {
Condition = "CreateSQS",
Properties = {
Endpoint = { "Fn::GetAtt" = ["SentinelOneCNSLogsQueue", "Arn"] },
Protocol = "sqs",
RawMessageDelivery = false,
TopicArn = "arn:aws:sns:us-east-1:207567775001:aws-controltower-AllConfigNotifications"
},
Type = "AWS::SNS::Subscription"
}

SentinelOneCNSLogsQueue = {
Condition = "CreateSQS",
Properties = {
QueueName = {
"Fn::Join" = [
"",
[
"s1-cns-cloudtrail-logs-queue-",
{ "Ref" = "identifier" }
]
]
}
},
Type = "AWS::SQS::Queue"
},
SentinelOneMarketplaceAccessRole = {
Properties = {
AssumeRolePolicyDocument = {
Statement = [
{
Action = "sts:AssumeRole"
Condition = {
StringEquals = {
"sts:ExternalId" = { "Ref" = "marketplaceExternalId" }
}
}
Effect = "Allow"
Principal = {
AWS = "arn:aws:iam::913057016266:user/Scalyr"
}
}
]
},
Path = { "Ref" = "iamPath" },
PermissionsBoundary = {
"Fn::If" = [
"HasPermissionsBoundary",
{ "Ref" = "permissionsBoundaryArn" },
{ "Ref" = "AWS::NoValue" }
]
},
RoleName = { "Fn::Sub" = "singularity-aws-app-${var.identifier}" }
},
Type = "AWS::IAM::Role"
}

SentinelOneCNSAllowCloudTrailBucketAccessPolicy = {
Condition = "IsBucketOwnerAccount",
DependsOn = "SentinelOneMarketplaceAccessRole",
Properties = {
Description = "Allow SentinelOne CNS access to cloudtrail bucket",
Path = { "Ref" = "iamPath" },
PolicyDocument = {
Version = "2012-10-17",
Statement = [
{
Action = ["s3:GetBucketLocation", "s3:ListBucket"],
Condition = {
Bool = { "aws:SecureTransport" = "true" }
},
Effect = "Allow",
Resource = {
"Fn::Join" = [
"",
["arn:${data.aws_partition.current.partition}:s3:::", "aws-controltower-logs-688567271939-us-east-1"]
]
},
Sid = "AllowSentinelOneCNSAccessCloudTrailS3ListGetLocation"
},
{
Action = ["s3:GetObject"],
Condition = {
Bool = { "aws:SecureTransport" = "true" }
},
Effect = "Allow",
Resource = {
"Fn::Join" = [
"",
["arn:${data.aws_partition.current.partition}:s3:::", "aws-controltower-logs-688567271939-us-east-1", "/*"]
]
},
Sid = "AllowSentinelOneCNSAccessCloudTrailS3GetObject"
}
]
},
Roles = [
"singularity-aws-app-2056384125320855810"
]
},
Type = "AWS::IAM::ManagedPolicy"
}

SentinelOneCNSAllowCloudTrailQueueAccessPolicyWithMarketPlace = {
Condition = "IsBucketOwnerAccount",
DependsOn = "SentinelOneMarketplaceAccessRole",
Properties = {
Description = "Allow SentinelOne CNS access to cloudtrail bucket",
Path = { "Ref" = "iamPath" },
PolicyDocument = {
Version = "2012-10-17",
Statement = [
{
Action = [ "sqs:DeleteMessage","sqs:ReceiveMessage","sqs:GetQueueAttributes"],
Condition = {
Bool = { "aws:SecureTransport" = "true" }
},
Effect = "Allow",
Resource = {"Fn::Sub" = "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${var.existing_sns_topic_account_id}:s1-marketplace-cloudtrail-logs-queue-${var.identifier}"},
Sid = "AllowSentinelOneCNSAccessCloudTrailS3ListGetLocation"
}
]
},
Roles = [
"singularity-aws-app-2056384125320855810"
]
},
Type = "AWS::IAM::ManagedPolicy"
}

}
})
}

resource "aws_cloudformation_stack_set_instance" "stack_instances_group" {
count = local.is_organization_onboarding ? 1 : 0
deployment_targets {
organizational_unit_ids = [data.aws_organizations_organization.roots.roots[0].id]
}
operation_preferences {
failure_tolerance_count = 24
max_concurrent_count = 25
region_concurrency_type = "PARALLEL"
}
region = "${data.aws_region.current.name}"
stack_set_name = aws_cloudformation_stack_set.sentinel_one_stack_set[0].name
}

# Output

output "sns_topic_arn" {
 description = "The ARN of the SNS topic."
 value = var.existing_sns_topic_arn
}

output "sqs_queue_arn" {
 description = "The ARN of the SQS queue."
 value = "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${var.existing_sns_topic_account_id}:s1-cns-cloudtrail-logs-queue-${var.identifier}"
}

output "marketplace_cloudtrail_logs_queue" {
 description = "The URL of the MarketPlace SQS queue."
 value = "https://sqs.${data.aws_region.current.name}.amazonaws.com/${var.existing_sns_topic_account_id}/s1-marketplace-cloudtrail-logs-queue-${var.identifier}"
}

output "sentinelone_marketplace_access_role_arn" {
 description = "The ARN of the Marketplace role."
 value = "arn:${data.aws_partition.current.partition}:iam::688567271939:role${var.iam_path}singularity-aws-app-${var.identifier}"
}
