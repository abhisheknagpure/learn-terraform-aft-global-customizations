locals {
 create_sqs = (
 var.existing_sns_topic_account_id == data.aws_caller_identity.current.account_id
 )
 create_kms_policy = (
 var.cloudtrail_kms_arn != ""
 )
 is_bucket_owner_account = (
 var.bucket_owner_account_id == data.aws_caller_identity.current.account_id
 )
 has_permission_boundary = (
 var.permission_boundary_arn != ""
 )
 is_organization_onboarding = ( var.is_organization_onboarding == "Yes" )
 is_govcloud = (data.aws_partition.current.partition == "aws-us-gov")
 marketplace_access_role_principals = (local.is_govcloud ? [
 "arn:aws-us-gov:iam::159119422408:user/scalyr-hvla-dev",
 "arn:aws-us-gov:iam::773463581296:user/scalyr-hvla-prod"
 ] : [
 "arn:aws:iam::913057016266:user/Scalyr"
 ])
}
locals {
 cloud_trail_enabled = (
 var.enable_cloudtrail == "Yes"
 )
}