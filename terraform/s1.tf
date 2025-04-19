terraform {
required_providers {
aws = {
version = "~>5.87"
}
}
}

provider "aws" {
alias = "alias_cns_onboarding"
use_fips_endpoint= false  
}

variable "identifier" {
description = "A unique string to resolve conflicts with existing resources. Do not change this value."
type        = string
default     = "2194990624246074959"
validation {
condition     = can(regex("^[0-9]*$", var.identifier))
error_message = "Must be string with no spaces."
}
}

variable "role_name" {
description = "The name of IAM role to be created in AWS account. Do not change this value."
type        = string
default     = "s1-cns-audit-2194990624246074959"
validation {
condition     = can(regex("^[a-z0-9-]*$", var.role_name))
error_message = "Must be lowercase or numbers, no spaces."
}
}

variable "iam_path" {
description = "The path for the IAM role to be created in AWS account."
type        = string
default     = "/"
validation {
condition     = can(regex("^/[a-z0-9-]*$", var.iam_path))
error_message = "Must be lowercase starts with /, no spaces."
}
}

variable "permissions_boundary_arn" {
description = "The ARN of the policy that is used to set the permissions boundary for the IAM role."
type        = string
default     = ""
}

variable "external_id" {
description = "The External ID is auto-generated. Do not change this value."
type        = string
default     = "f1f9919835fa4d7beac67464151e600d8ecb0bd56513f9cd030f64e5abb70dc0"
validation {
condition     = can(regex("^[a-z0-9]*$", var.external_id))
error_message = "Must be lowercase or numbers, no spaces."
}
}

variable "assume_role_service_account" {
description = "SentinelOne CNS Service Account which will perform sts:assumeRole. Do not change this value."
type        = string
default     = "arn:aws:iam::613274416560:user/sentinelone-cns-service-account-dev"
}

variable "is_organization_onboarding" {
description = "Create the stackset in case of Organization Onboarding"
type        = string
default     = "No"
validation {
condition     = can(regex("^(Yes|No)$", var.is_organization_onboarding))
error_message = "The input must be either 'Yes' or 'No'."
}
}

variable "excluded_accounts" {
description = "Excluded accounts from stack set operation"
type        = string
default     = ""
}

variable "enable_snapshot_scanning" {
description = "Whether to enable snapshot scanning."
type        = string
default     = "Yes"
validation {
condition = can(regex("^(Yes|No)$", var.enable_snapshot_scanning))
error_message = "The input must be either 'Yes' or 'No'."
}
}

variable "integration_mode" {
description = "Select mode \n 1. DETECT (In Detect mode, SentinelOne CNS has read-only access to your AWS Cloud resources.)  \n 2. DETECT_AND_REMEDIATE (In Detect & Remediate mode, SentinelOne CNS can access and remediate resource configuration issues for continuous compliance in your AWS account.) (Allowed values - DETECT, DETECT_AND_REMEDIATE) "
type        = string
default     = "DETECT_AND_REMEDIATE"
validation {
condition = can(regex("^(DETECT|DETECT_AND_REMEDIATE)$", var.integration_mode))
error_message = "The input must be either 'DETECT' or 'DETECT_AND_REMEDIATE'."
}
}

variable "enable_cds_integration" {
description = "Whether to enable CDS integration."
type        = string
default     = "Yes"
validation {
condition = can(regex("^(Yes|No)$", var.enable_cds_integration))
error_message = "The input must be either 'Yes' or 'No'."
}
}


locals {
has_permissions_boundary = var.permissions_boundary_arn != ""
snapshot_scanning_enabled = var.enable_snapshot_scanning == "Yes"
auto_remediation_enabled = var.integration_mode == "DETECT_AND_REMEDIATE"
is_cds_integration_enabled = var.enable_cds_integration == "Yes"
is_organization_onboarding_selected = var.is_organization_onboarding == "Yes"
has_excluded_accounts = var.is_organization_onboarding == "Yes" && var.excluded_accounts != ""
has_no_excluded_accounts = var.is_organization_onboarding == "Yes" && var.excluded_accounts == ""
}

data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "roots" {}

resource "aws_iam_role" "sentinelone_cns_access_role_cns_onboarding" {
name = var.role_name
path = var.iam_path
provider = aws.alias_cns_onboarding
assume_role_policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Action = "sts:AssumeRole"
Condition = {
StringEquals = {
"sts:ExternalId" = var.external_id
}
}
Effect = "Allow"
Principal = {
AWS = var.assume_role_service_account
}
}
]
})

managed_policy_arns = [
"arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit",
"arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
"arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
]

permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : ""
}

resource "aws_iam_role" "cross_account_scan_role_cns_onboarding" {
count = local.is_cds_integration_enabled ? 1 : 0

name = "s1-cds-cross-account-scan-${var.identifier}"
path = var.iam_path
provider = aws.alias_cns_onboarding
assume_role_policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Effect = "Allow"
Principal = {
AWS = "*"
}
Condition = {
StringEquals = {
"aws:ResourceOrgID" = "$${aws:PrincipalOrgID}"
}
}
Action = "sts:AssumeRole"
}
]
})

max_session_duration = 43200

tags = {
s1service = "cds"
}

permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : ""
}

resource "aws_iam_policy" "cross_account_scan_policy_cns_onboarding" {
count = local.is_cds_integration_enabled ? 1 : 0
provider = aws.alias_cns_onboarding
policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid = "CDSObjectsAccess"
Effect = "Allow"
Action = [
"s3:DeleteObjectTagging",
"s3:ReplicateObject",
"s3:PutObject",
"s3:GetObject",
"s3:GetObjectAttributes",
"s3:GetObjectTagging",
"s3:PutObjectTagging",
"s3:DeleteObject"
]
Resource = "arn:${data.aws_partition.current.partition}:s3:::*/*"
},
{
Sid = "CDSBucketAccess"
Effect = "Allow"
Action = [
"s3:PutBucketNotification",
"s3:ListBucket",
"s3:GetBucketNotification"
]
Resource = "arn:${data.aws_partition.current.partition}:s3:::*"
}
]
})
}

resource "aws_iam_role_policy_attachment" "cross_account_scan_role_policy_attachment_cns_onboarding" {
count = local.is_cds_integration_enabled ? 1 : 0
role       = aws_iam_role.cross_account_scan_role_cns_onboarding[0].name
policy_arn = aws_iam_policy.cross_account_scan_policy_cns_onboarding[0].arn
provider = aws.alias_cns_onboarding
}
resource "aws_cloudformation_stack_set" "sentinelone_stack_set_cns_onboarding" {
count = local.is_organization_onboarding_selected ? 1 : 0
name = "s1-cnapp-initial-stackset-${var.identifier}"
provider = aws.alias_cns_onboarding
managed_execution {
active = true
}
template_body = jsonencode({
Conditions = {
IsCDSIntegrationEnabled = {
"Fn::Equals" = [
"${var.enable_cds_integration}",
"Yes"
]
}
IsSnapshotScanningEnabled = {
"Fn::Equals" = [
"${var.enable_snapshot_scanning}",
"Yes"
]
}
IsAutoRemediationEnabled = {
"Fn::Equals" = [
"${var.integration_mode}",
"DETECT_AND_REMEDIATE"
]
}
HasPermissionsBoundary = {
"Fn::Not" = [
{
"Fn::Equals" = [
"${var.permissions_boundary_arn}",
""
]
}
]
}
}

Parameters = {
identifier = {
Type        = "String"
Description = "A unique string to resolve conflicts with existing resources. Do not change this value."
}
roleName = {
Type        = "String"
Description = "The name of IAM role to be created in AWS account. Do not change this value."

}

iamPath = {
Type        = "String"
Description = "The path for the IAM role to be created in AWS account."

}

permissionsBoundaryArn = {
Type        = "String"
Description = "The ARN of the policy that is used to set the permissions boundary for the IAM role."
}

externalId = {
Type        = "String"
Description = "The External ID is auto-generated. Do not change this value."
}

assumeRoleServiceAccount = {
Type        = "String"
Description = "SentinelOne CNS Service Account which will perform sts:assumeRole. Do not change this value."
}

enableSnapshotScanning = {
Description = "Whether to enable snapshot scanning."
Type        = "String"

}


enableCdsIntegration = {
Description = "Whether to enable CDS integration."
Type        = "String"
}
}

Resources = {
sentineloneCnsAccessRole = {
Type= "AWS::IAM::Role",
Properties = {
"PermissionsBoundary" = {
"Fn::If" = [
"HasPermissionsBoundary",
{
"Ref": "permissionsBoundaryArn"
},
{
"Ref": "AWS::NoValue"
}
]
}
AssumeRolePolicyDocument = {
Version = "2012-10-17"
Statement = [
{
Action = "sts:AssumeRole"
Condition = {
StringEquals = {
"sts:ExternalId" = {
"Ref" = "externalId"
}
}
}

Effect = "Allow"
Principal = {
AWS = {
"Ref" = "assumeRoleServiceAccount"
}
}
}
]
}

RoleName = {
"Ref" = "roleName"
}
Path = {
"Ref" = "iamPath"
}

ManagedPolicyArns = [
"arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit",
"arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
"arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
]
}
}

crossAccountScanRole = {
Condition = "IsCDSIntegrationEnabled"
Type = "AWS::IAM::Role"
Properties = {
RoleName = "s1-cds-cross-account-scan-${var.identifier}"
Path = {
"Ref" = "iamPath"
}
"PermissionsBoundary" = {
"Fn::If" = [
"HasPermissionsBoundary",
{
"Ref": "permissionsBoundaryArn"
},
{
"Ref": "AWS::NoValue"
}
]
}
AssumeRolePolicyDocument = jsonencode({
Version = "2012-10-17"
Statement = [
{
Effect = "Allow"
Principal = {
AWS = "*"
}
Condition = {
StringEquals = {
"aws:ResourceOrgID" = "$${aws:PrincipalOrgID}"
}
StringLike = {
"aws:PrincipalArn": "arn:aws:iam::*:role/s1-78909-*-service-*-role"
}
}
Action = "sts:AssumeRole"
}
]
})
MaxSessionDuration = 43200
Tags = [
{
Key= "s1service",
Value=  "cds"
}
]
Policies =[{
PolicyDocument = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid = "CDSObjectsAccess"
Effect = "Allow"
Action = [
"s3:DeleteObjectTagging",
"s3:ReplicateObject",
"s3:PutObject",
"s3:GetObject",
"s3:GetObjectAttributes",
"s3:GetObjectTagging",
"s3:PutObjectTagging",
"s3:DeleteObject"
]
Resource = "arn:${data.aws_partition.current.partition}:s3:::*"
},
{
Sid = "CDSBucketAccess"
Effect = "Allow"
Action = [
"s3:PutBucketNotification",
"s3:ListBucket",
"s3:GetBucketNotification"
]
Resource = "arn:${data.aws_partition.current.partition}:s3:::*"
}
]
})
}]
}
}

sentineloneCnsScannerSupplementReadPolicy= {
Type        = "AWS::IAM::ManagedPolicy"
Properties = {
Description = "Permissions for SentinelOne CNS scanner"
Roles = [
{
"Ref" = "sentineloneCnsAccessRole"
}
]
Path  = {
"Ref" = "iamPath"
}
PolicyDocument = jsonencode({
Version = "2012-10-17"
Statement = [
{
Effect = "Allow"
Action = [
"sqs:GetQueueUrl",
"ses:DescribeActiveReceiptRuleSet",
"elastictranscoder:ListPipelines",
"airflow:ListEnvironments",
"glue:GetSecurityConfigurations",
"devops-guru:ListNotificationChannels",
"ec2:GetEbsEncryptionByDefault",
"ec2:GetEbsDefaultKmsKeyId",
"organizations:ListAccounts",
"kendra:ListIndices",
"proton:ListEnvironmentTemplates",
"qldb:ListLedgers",
"profile:ListDomains",
"timestream:DescribeEndpoints",
"memorydb:DescribeClusters",
"kafka:ListClusters",
"apprunner:ListServices",
"finspace:ListEnvironments",
"healthlake:ListFHIRDatastores",
"codeartifact:ListDomains",
"auditmanager:GetSettings",
"appflow:ListFlows",
"databrew:ListJobs",
"managedblockchain:ListNetworks",
"connect:ListInstances",
"backup:ListBackupVaults",
"dlm:GetLifecyclePolicies",
"dlm:GetLifecyclePolicy",
"ssm:GetServiceSetting",
"ecr:DescribeRegistry",
"kinesisvideo:ListStreams",
"wisdom:ListAssistants",
"voiceid:ListDomains",
"lookoutequipment:ListDatasets",
"iotsitewise:DescribeDefaultEncryptionConfiguration",
"geo:ListTrackers",
"geo:ListGeofenceCollections",
"lookoutvision:ListProjects",
"lookoutmetrics:ListAnomalyDetectors",
"lex:ListBots",
"forecast:ListDatasets",
"forecast:ListForecastExportJobs",
"backup:ListTags",
"backup:GetBackupVaultAccessPolicy",
"cloudwatch:ListTagsForResource",
"cognito-identity:ListTagsForResource",
"cognito-identity:DescribeIdentityPool",
"cognito-idp:ListTagsForResource",
"codeartifact:DescribeDomain",
"codeartifact:GetDomainPermissionsPolicy",
"codeartifact:ListTagsForResource",
"codeartifact:ListRepositories",
"codeartifact:DescribeRepository",
"codeartifact:GetRepositoryPermissionsPolicy",
"ds:ListTagsForResource",
"dynamodb:ListTagsOfResource",
"ec2:SearchTransitGatewayRoutes",
"ecr:DescribeImages",
"ecr:GetLifecyclePolicy",
"ecr:ListTagsForResource",
"ecr-public:ListTagsForResource",
"eks:ListTagsForResource",
"eks:ListFargateProfiles",
"eks:DescribeFargateProfile",
"elasticbeanstalk:ListTagsForResource",
"elasticfilesystem:DescribeTags",
"elasticfilesystem:DescribeFileSystemPolicy",
"elasticache:ListTagsForResource",
"es:ListTags",
"glacier:GetVaultLock",
"glacier:ListTagsForVault",
"glue:GetConnections",
"lex:GetBot",
"lex:GetBots",
"lex:GetBotVersions",
"lex:ListTagsForResource",
"lex:ListBotVersions",
"lex:DescribeBotVersion",
"lex:DescribeBot",
"logs:GetLogEvents",
"mq:listBrokers",
"mq:describeBroker",
"mediastore:ListTagsForResource",
"mediastore:GetCorsPolicy",
"ram:GetResourceShares",
"ssm:GetDocument",
"ssm:GetParameters",
"ssm:ListTagsForResource",
"elasticmapreduce:ListSecurityConfigurations",
"elasticmapreduce:GetBlockPublicAccessConfiguration",
"sns:listSubscriptions",
"sns:ListTagsForResource",
"sns:ListPlatformApplications",
"wafv2:ListResourcesForWebACL",
"wafv2:ListWebACLs",
"wafv2:ListTagsForResource",
"wafv2:GetWebACL",
"wafv2:GetLoggingConfiguration",
"waf:GetWebACL",
"waf:ListTagsForResource",
"waf:GetLoggingConfiguration",
"waf-regional:GetLoggingConfiguration",
"waf-regional:ListResourcesForWebACL",
"waf-regional:ListTagsForResource",
"codebuild:BatchGetProjects",
"s3:DescribeJob",
"s3:ListJobs",
"s3:GetJobTagging",
"ssm:GetInventory",
"shield:GetSubscriptionState",
"storagegateway:DescribeSMBFileShares",
"storagegateway:DescribeSMBSettings",
"ecr:BatchCheckLayerAvailability",
"ecr:BatchGetImage",
"ecr:GetAuthorizationToken",
"ecr:GetDownloadUrlForLayer",
"ecr:GetLifecyclePolicyPreview",
"lambda:GetLayerVersion",
"ssm:GetParameter",
"securityhub:BatchImportFindings",
"lambda:GetFunction",
"logs:StartQuery",
"logs:GetQueryResults",
"s3:ListBucket",
"lambda:GetEventSourceMapping",
"lambda:GetFunctionUrlConfig",
"sns:GetSubscriptionAttributes",
"apigateway:GET",
"lightsail:Get*",
"bedrock:list*",
"bedrock:get*",
"sso:GetInlinePolicyForPermissionSet"
]
Resource = "*"
}
]
})
}
}

sentineloneCnsAutoRemediationPolicy = {
Condition = "IsAutoRemediationEnabled"
Type        =  "AWS::IAM::ManagedPolicy"
Properties = {
Roles = [
{
"Ref" = "sentineloneCnsAccessRole"
}
]
Description = "Allow SentinelOne CNS access to auto-remediate issues from SentinelOne CNS dashboard"
Path        = {
"Ref" = "iamPath"
}
PolicyDocument = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid    = "AllowSentinelOneCNSRemediateGeneric"
Effect = "Allow"
Action = [
"iam:UpdateAccountPasswordPolicy",
"ec2:ModifyImageAttribute",
"rds:ModifyDBSnapshotAttribute",
"s3:PutBucketAcl",
"ec2:RevokeSecurityGroupEgress",
"ec2:RevokeSecurityGroupIngress",
"ec2:ModifySnapshotAttribute",
"cloudtrail:UpdateTrail",
"rds:ModifyDBInstance",
"redshift:ModifyCluster",
"kms:EnableKeyRotation",
"rds:ModifyEventSubscription",
"eks:UpdateClusterConfig",
"ec2:ModifySubnetAttribute",
"elasticloadbalancing:ModifyLoadBalancerAttributes",
"cloudtrail:StartLogging",
"elasticache:ModifyReplicationGroup",
"s3:PutBucketVersioning",
"s3:PutBucketPublicAccessBlock",
"lambda:UpdateFunctionConfiguration",
"ecs:UpdateClusterSettings",
"rds:ModifyDBCluster",
"rds:ModifyDBClusterSnapshotAttribute",
"acm:UpdateCertificateOptions",
"apigateway:PATCH",
"athena:UpdateWorkGroup",
"cloudformation:UpdateTerminationProtection",
"ecr:PutImageTagMutability",
"elasticache:ModifyCacheCluster",
"es:UpdateDomainConfig",
"iam:DeleteSSHPublicKey",
"lightsail:EnableAddOn",
"lightsail:UpdateRelationalDatabase",
"route53domains:EnableDomainAutoRenew",
"route53domains:EnableDomainTransferLock",
"sns:SetTopicAttributes",
"sqs:SetQueueAttributes",
"es:UpdateElasticsearchDomainConfig",
"route53domains:EnableDomainTransferLock",
"route53domains:DisableDomainTransferLock"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateEC2"
Effect = "Allow"
Action = [
"ec2:AuthorizeSecurityGroupEgress",
"ec2:AuthorizeSecurityGroupIngress",
"ec2:CreateSecurityGroup",
"ec2:CreateTags",
"ec2:RevokeSecurityGroupEgress",
"ec2:DeleteSecurityGroup",
"ec2:RunInstances",
"ec2:TerminateInstances",
"ec2:EnableEbsEncryptionByDefault",
"ec2:ReplaceNetworkAclEntry"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateLambda"
Effect = "Allow"
Action = [
"lambda:PublishLayerVersion",
"lambda:UpdateFunctionConfiguration",
"lambda:DeleteLayerVersion"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateSSM"
Effect = "Allow"
Action = [
"ssm:SendCommand",
"ssm:ListCommandInvocations",
"ssm:CancelCommand",
"ssm:CreateAssociation"
]
Resource = "*"
}
]
})
}
}

sentineloneCnsSnapshotScanningPolicy = {
Condition = "IsSnapshotScanningEnabled"
Type        = "AWS::IAM::ManagedPolicy"

Properties = {
Description = "Allow SentinelOne CNS access to create and share VM snapshots"
Path        = {
"Ref" = "iamPath"
}
Roles = [
{
"Ref" = "sentineloneCnsAccessRole"
}
]
PolicyDocument = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid      = "AllowSentinelOneCNSToCreateKMS"
Effect   = "Allow"
Action   = ["kms:TagResource"]
Resource = "*"
Condition = {
StringEquals = {
"aws:RequestTag/owner" = "sentinelone-cns"
}
}
},
{
Sid      = "AllowSentinelOneCNSToTagEC2Resources"
Effect   = "Allow"
Action   = ["ec2:CreateTags"]
Resource = "*"
Condition = {
StringLike = {
"ec2:CreateAction" = "*"
}
StringEquals = {
"aws:RequestTag/owner" = "sentinelone-cns"
}
}
},
{
Sid      = "AllowSentinelOneCNSCreatedKMS"
Effect   = "Allow"
Action   = [
"kms:Encrypt",
"kms:ReEncrypt*",
"kms:ListGrants",
"kms:RevokeGrant",
"kms:GetKeyPolicy",
"kms:DescribeKey",
"kms:PutKeyPolicy",
"kms:CreateGrant",
"kms:GenerateDataKey*"
]
Resource = "*"
Condition = {
StringEquals = {
"kms:ResourceAliases" = "alias/sentinelOneCNSKey"
}
}
},
{
Sid      = "AllowSentinelOneCNSCreateSnapshot"
Effect   = "Allow"
Action   = [
"ec2:CreateSnapshot",
"ec2:CopySnapshot",
"kms:CreateKey"
]
Resource = "*"
},
{
Sid      = "AllowSentinelOneCNSTaggedResources"
Effect   = "Allow"
Action   = [
"ec2:ModifySnapshotAttribute",
"ec2:DeleteSnapshot"
]
Resource = "*"
Condition = {
StringEquals = {
"aws:ResourceTag/owner" = "sentinelone-cns"
}
}
},
{
Effect   = "Allow"
Action   = "kms:CreateAlias"
Resource = "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
Condition = {
StringEquals = {
"aws:ResourceTag/owner" = "sentinelone-cns"
}
}
},
{
Effect   = "Allow"
Action   = "kms:CreateAlias"
Resource = "arn:${data.aws_partition.current.partition}:kms:*:*:alias/sentinelOneCNS*"
},
{
"Action": [
"ce:UpdateCostAllocationTagsStatus",
"ce:ListCostAllocationTags",
"ce:GetCostAndUsage"
],
"Resource": "*",
"Effect": "Allow",
"Sid": "AllowSentinelOneCNSToMonitorCosts"
}
]
})
}
}
listRegionsPolicy =  {
Type        = "AWS::IAM::Policy"
Properties = {
Roles = [
{
"Ref" = "sentineloneCnsAccessRole"
}
]
PolicyName = "s1-cns-list-regions"
PolicyDocument = jsonencode(
{
Version = "2012-10-17"
Statement = [
{
Sid      = "AllowGetObject"
Effect   = "Allow"
Action   = ["account:ListRegions"]
Resource = [
"arn:${data.aws_partition.current.partition}:account::*:account/o-*/*",
"arn:${data.aws_partition.current.partition}:account::*:account"
]
}
]
})
}
}
}
})
parameters = {
identifier               = var.identifier
permissionsBoundaryArn = var.permissions_boundary_arn
externalId             = var.external_id
roleName               = var.role_name
iamPath                = var.iam_path
assumeRoleServiceAccount = var.assume_role_service_account
enableCdsIntegration = var.enable_cds_integration
enableSnapshotScanning = var.enable_snapshot_scanning
}

capabilities = ["CAPABILITY_NAMED_IAM", "CAPABILITY_IAM"]
permission_model = "SERVICE_MANAGED"
auto_deployment  {
enabled = true
retain_stacks_on_account_removal = false
}
operation_preferences {
failure_tolerance_count = 24
max_concurrent_count = 25
region_concurrency_type = "PARALLEL"
}
}

resource "aws_cloudformation_stack_set_instance" "stack_instances_group_has_excluded_accounts_cns_onboarding" {
count = local.has_excluded_accounts ? 1 : 0
provider = aws.alias_cns_onboarding
deployment_targets {
account_filter_type =  "DIFFERENCE"
accounts = split(",", var.excluded_accounts)
organizational_unit_ids = [data.aws_organizations_organization.roots.roots[0].id]
}
operation_preferences {
failure_tolerance_count = 24
max_concurrent_count = 25
region_concurrency_type = "PARALLEL"
}
region = "${data.aws_region.current.name}"
stack_set_name = aws_cloudformation_stack_set.sentinelone_stack_set_cns_onboarding[0].name
}


resource "aws_cloudformation_stack_set_instance" "stack_instances_group_has_no_excluded_accounts_cns_onboarding" {
count = local.has_no_excluded_accounts ? 1 : 0
provider = aws.alias_cns_onboarding
deployment_targets {
organizational_unit_ids = [data.aws_organizations_organization.roots.roots[0].id]
}
operation_preferences {
failure_tolerance_count = 24
max_concurrent_count = 25
region_concurrency_type = "PARALLEL"
}
region = "${data.aws_region.current.name}"
stack_set_name = aws_cloudformation_stack_set.sentinelone_stack_set_cns_onboarding[0].name
}

resource "aws_iam_policy" "sentinelone_cns_scanner_supplement_read_policy_cns_onboarding" {
description = "Permissions for SentinelOne CNS scanner"
path        = var.iam_path
provider = aws.alias_cns_onboarding
policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Effect = "Allow"
Action = [
"sqs:GetQueueUrl",
"ses:DescribeActiveReceiptRuleSet",
"elastictranscoder:ListPipelines",
"airflow:ListEnvironments",
"glue:GetSecurityConfigurations",
"devops-guru:ListNotificationChannels",
"ec2:GetEbsEncryptionByDefault",
"ec2:GetEbsDefaultKmsKeyId",
"organizations:ListAccounts",
"kendra:ListIndices",
"proton:ListEnvironmentTemplates",
"qldb:ListLedgers",
"profile:ListDomains",
"timestream:DescribeEndpoints",
"memorydb:DescribeClusters",
"kafka:ListClusters",
"apprunner:ListServices",
"finspace:ListEnvironments",
"healthlake:ListFHIRDatastores",
"codeartifact:ListDomains",
"auditmanager:GetSettings",
"appflow:ListFlows",
"databrew:ListJobs",
"managedblockchain:ListNetworks",
"connect:ListInstances",
"backup:ListBackupVaults",
"dlm:GetLifecyclePolicies",
"dlm:GetLifecyclePolicy",
"ssm:GetServiceSetting",
"ecr:DescribeRegistry",
"kinesisvideo:ListStreams",
"wisdom:ListAssistants",
"voiceid:ListDomains",
"lookoutequipment:ListDatasets",
"iotsitewise:DescribeDefaultEncryptionConfiguration",
"geo:ListTrackers",
"geo:ListGeofenceCollections",
"lookoutvision:ListProjects",
"lookoutmetrics:ListAnomalyDetectors",
"lex:ListBots",
"forecast:ListDatasets",
"forecast:ListForecastExportJobs",
"backup:ListTags",
"backup:GetBackupVaultAccessPolicy",
"cloudwatch:ListTagsForResource",
"cognito-identity:ListTagsForResource",
"cognito-identity:DescribeIdentityPool",
"cognito-idp:ListTagsForResource",
"codeartifact:DescribeDomain",
"codeartifact:GetDomainPermissionsPolicy",
"codeartifact:ListTagsForResource",
"codeartifact:ListRepositories",
"codeartifact:DescribeRepository",
"codeartifact:GetRepositoryPermissionsPolicy",
"ds:ListTagsForResource",
"dynamodb:ListTagsOfResource",
"ec2:SearchTransitGatewayRoutes",
"ecr:DescribeImages",
"ecr:GetLifecyclePolicy",
"ecr:ListTagsForResource",
"ecr-public:ListTagsForResource",
"eks:ListTagsForResource",
"eks:ListFargateProfiles",
"eks:DescribeFargateProfile",
"elasticbeanstalk:ListTagsForResource",
"elasticfilesystem:DescribeTags",
"elasticfilesystem:DescribeFileSystemPolicy",
"elasticache:ListTagsForResource",
"es:ListTags",
"glacier:GetVaultLock",
"glacier:ListTagsForVault",
"glue:GetConnections",
"lex:GetBot",
"lex:GetBots",
"lex:GetBotVersions",
"lex:ListTagsForResource",
"lex:ListBotVersions",
"lex:DescribeBotVersion",
"lex:DescribeBot",
"logs:GetLogEvents",
"mq:listBrokers",
"mq:describeBroker",
"mediastore:ListTagsForResource",
"mediastore:GetCorsPolicy",
"ram:GetResourceShares",
"ssm:GetDocument",
"ssm:GetParameters",
"ssm:ListTagsForResource",
"elasticmapreduce:ListSecurityConfigurations",
"elasticmapreduce:GetBlockPublicAccessConfiguration",
"sns:listSubscriptions",
"sns:ListTagsForResource",
"sns:ListPlatformApplications",
"wafv2:ListResourcesForWebACL",
"wafv2:ListWebACLs",
"wafv2:ListTagsForResource",
"wafv2:GetWebACL",
"wafv2:GetLoggingConfiguration",
"waf:GetWebACL",
"waf:ListTagsForResource",
"waf:GetLoggingConfiguration",
"waf-regional:GetLoggingConfiguration",
"waf-regional:ListResourcesForWebACL",
"waf-regional:ListTagsForResource",
"codebuild:BatchGetProjects",
"s3:DescribeJob",
"s3:ListJobs",
"s3:GetJobTagging",
"ssm:GetInventory",
"shield:GetSubscriptionState",
"storagegateway:DescribeSMBFileShares",
"storagegateway:DescribeSMBSettings",
"ecr:BatchCheckLayerAvailability",
"ecr:BatchGetImage",
"ecr:GetAuthorizationToken",
"ecr:GetDownloadUrlForLayer",
"ecr:GetLifecyclePolicyPreview",
"lambda:GetLayerVersion",
"ssm:GetParameter",
"securityhub:BatchImportFindings",
"lambda:GetFunction",
"logs:StartQuery",
"logs:GetQueryResults",
"s3:ListBucket",
"lambda:GetEventSourceMapping",
"lambda:GetFunctionUrlConfig",
"sns:GetSubscriptionAttributes",
"apigateway:GET",
"lightsail:Get*",
"bedrock:list*",
"bedrock:get*",
"sso:GetInlinePolicyForPermissionSet"
]
Resource = "*"
}
]
})
}

resource "aws_iam_role_policy_attachment" "sentinelone_cns_scanner_supplement_read_policy_attachment_cns_onboarding" {
role       = aws_iam_role.sentinelone_cns_access_role_cns_onboarding.name
policy_arn = aws_iam_policy.sentinelone_cns_scanner_supplement_read_policy_cns_onboarding.arn
provider = aws.alias_cns_onboarding
}

resource "aws_iam_policy" "sentinelone_cns_auto_remediation_policy_cns_onboarding" {
count       = local.auto_remediation_enabled ? 1 : 0
description = "Allow SentinelOne CNS access to auto-remediate issues from SentinelOne CNS dashboard"
path        = var.iam_path
provider = aws.alias_cns_onboarding
policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid    = "AllowSentinelOneCNSRemediateGeneric"
Effect = "Allow"
Action = [
"iam:UpdateAccountPasswordPolicy",
"ec2:ModifyImageAttribute",
"rds:ModifyDBSnapshotAttribute",
"s3:PutBucketAcl",
"ec2:RevokeSecurityGroupEgress",
"ec2:RevokeSecurityGroupIngress",
"ec2:ModifySnapshotAttribute",
"cloudtrail:UpdateTrail",
"rds:ModifyDBInstance",
"redshift:ModifyCluster",
"kms:EnableKeyRotation",
"rds:ModifyEventSubscription",
"eks:UpdateClusterConfig",
"ec2:ModifySubnetAttribute",
"elasticloadbalancing:ModifyLoadBalancerAttributes",
"cloudtrail:StartLogging",
"elasticache:ModifyReplicationGroup",
"s3:PutBucketVersioning",
"s3:PutBucketPublicAccessBlock",
"lambda:UpdateFunctionConfiguration",
"ecs:UpdateClusterSettings",
"rds:ModifyDBCluster",
"rds:ModifyDBClusterSnapshotAttribute",
"acm:UpdateCertificateOptions",
"apigateway:PATCH",
"athena:UpdateWorkGroup",
"cloudformation:UpdateTerminationProtection",
"ecr:PutImageTagMutability",
"elasticache:ModifyCacheCluster",
"es:UpdateDomainConfig",
"iam:DeleteSSHPublicKey",
"lightsail:EnableAddOn",
"lightsail:UpdateRelationalDatabase",
"route53domains:EnableDomainAutoRenew",
"route53domains:EnableDomainTransferLock",
"sns:SetTopicAttributes",
"sqs:SetQueueAttributes",
"es:UpdateElasticsearchDomainConfig",
"route53domains:EnableDomainTransferLock",
"route53domains:DisableDomainTransferLock"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateEC2"
Effect = "Allow"
Action = [
"ec2:AuthorizeSecurityGroupEgress",
"ec2:AuthorizeSecurityGroupIngress",
"ec2:CreateSecurityGroup",
"ec2:CreateTags",
"ec2:RevokeSecurityGroupEgress",
"ec2:DeleteSecurityGroup",
"ec2:RunInstances",
"ec2:TerminateInstances",
"ec2:EnableEbsEncryptionByDefault",
"ec2:ReplaceNetworkAclEntry"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateLambda"
Effect = "Allow"
Action = [
"lambda:PublishLayerVersion",
"lambda:UpdateFunctionConfiguration",
"lambda:DeleteLayerVersion"
]
Resource = "*"
},
{
Sid    = "AllowSentinelOneCNSRemediateSSM"
Effect = "Allow"
Action = [
"ssm:SendCommand",
"ssm:ListCommandInvocations",
"ssm:CancelCommand",
"ssm:CreateAssociation"
]
Resource = "*"
}
]
})
}

resource "aws_iam_role_policy_attachment" "sentinelone_cns_auto_remediation_policy_attachment_cns_onboarding" {
count     = local.auto_remediation_enabled ? 1 : 0
role      = aws_iam_role.sentinelone_cns_access_role_cns_onboarding.name
policy_arn = aws_iam_policy.sentinelone_cns_auto_remediation_policy_cns_onboarding[0].arn
provider = aws.alias_cns_onboarding
}

resource "aws_iam_policy" "sentinelone_cns_snapshot_scanning_policy_cns_onboarding" {
count       = local.snapshot_scanning_enabled ? 1 : 0
description = "Allow SentinelOne CNS access to create and share VM snapshots"
path        = var.iam_path
provider = aws.alias_cns_onboarding
policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid      = "AllowSentinelOneCNSToCreateKMS"
Effect   = "Allow"
Action   = ["kms:TagResource"]
Resource = "*"
Condition = {
StringEquals = {
"aws:RequestTag/owner" = "sentinelone-cns"
}
}
},
{
Sid      = "AllowSentinelOneCNSToTagEC2Resources"
Effect   = "Allow"
Action   = ["ec2:CreateTags"]
Resource = "*"
Condition = {
StringLike = {
"ec2:CreateAction" = "*"
}
StringEquals = {
"aws:RequestTag/owner" = "sentinelone-cns"
}
}
},
{
Sid      = "AllowSentinelOneCNSCreatedKMS"
Effect   = "Allow"
Action   = [
"kms:Encrypt",
"kms:ReEncrypt*",
"kms:ListGrants",
"kms:RevokeGrant",
"kms:GetKeyPolicy",
"kms:DescribeKey",
"kms:PutKeyPolicy",
"kms:CreateGrant",
"kms:GenerateDataKey*"
]
Resource = "*"
Condition = {
StringEquals = {
"kms:ResourceAliases" = "alias/sentinelOneCNSKey"
}
}
},
{
Sid      = "AllowSentinelOneCNSCreateSnapshot"
Effect   = "Allow"
Action   = [
"ec2:CreateSnapshot",
"ec2:CopySnapshot",
"kms:CreateKey"
]
Resource = "*"
},
{
Sid      = "AllowSentinelOneCNSTaggedResources"
Effect   = "Allow"
Action   = [
"ec2:ModifySnapshotAttribute",
"ec2:DeleteSnapshot"
]
Resource = "*"
Condition = {
StringEquals = {
"aws:ResourceTag/owner" = "sentinelone-cns"
}
}
},
{
Effect   = "Allow"
Action   = "kms:CreateAlias"
Resource = "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
Condition = {
StringEquals = {
"aws:ResourceTag/owner" = "sentinelone-cns"
}
}
},
{
Effect   = "Allow"
Action   = "kms:CreateAlias"
Resource = "arn:${data.aws_partition.current.partition}:kms:*:*:alias/sentinelOneCNS*"
},
{
"Action" : [
"ce:UpdateCostAllocationTagsStatus",
"ce:ListCostAllocationTags",
"ce:GetCostAndUsage"
],
"Resource" : "*",
"Effect" : "Allow",
"Sid" : "AllowSentinelOneCNSToMonitorCosts"
}
]
})
}

resource "aws_iam_role_policy_attachment" "sentinelone_cns_snapshot_scanning_policy_attachment_cns_onboarding" {
provider = aws.alias_cns_onboarding
count     = local.snapshot_scanning_enabled ? 1 : 0
role      = aws_iam_role.sentinelone_cns_access_role_cns_onboarding.name
policy_arn = aws_iam_policy.sentinelone_cns_snapshot_scanning_policy_cns_onboarding[0].arn
}

resource "aws_iam_policy" "list_regions_policy_cns_onboarding" {
provider = aws.alias_cns_onboarding
description = "Policy to allow listing AWS regions"
path        = var.iam_path

policy = jsonencode({
Version = "2012-10-17"
Statement = [
{
Sid      = "AllowGetObject"
Effect   = "Allow"
Action   = ["account:ListRegions"]
Resource = [
"arn:${data.aws_partition.current.partition}:account::*:account/o-*/*",
"arn:${data.aws_partition.current.partition}:account::*:account"
]
}
]
})
}

resource "aws_iam_role_policy_attachment" "list_regions_policy_attachment_cns_onboarding" {
provider = aws.alias_cns_onboarding
role       = aws_iam_role.sentinelone_cns_access_role_cns_onboarding.name
policy_arn = aws_iam_policy.list_regions_policy_cns_onboarding.arn
}

output "iam_role_arn_cns_onboarding" {
description = "The ARN of the IAM role."
value       = aws_iam_role.sentinelone_cns_access_role_cns_onboarding.arn
}