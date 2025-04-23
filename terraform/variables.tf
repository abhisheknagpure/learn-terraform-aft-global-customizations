variable "identifier" {
description = "A unique string to resolve conflicts with existing resources. Do not change this value."
type = string
default = "2199176901866569658"
validation {
condition = can(regex("^[0-9]*$", var.identifier))
error_message = "Must be string with no spaces."
}
}
variable "role_name" {
description = "The name of IAM role to be created in AWS account. Do not change this value."
type = string
default = "s1-cns-audit-2199176901866569658"
validation {
condition = can(regex("^[a-z0-9-]*$", var.role_name))
error_message = "Must be lowercase or numbers, no spaces."
}
}
variable "iam_path" {
description = "The path for the IAM role to be created in AWS account."
type = string
default = "/"
validation {
condition = can(regex("^/[a-z0-9-]*$", var.iam_path))
error_message = "Must be lowercase starts with /, no spaces."
}
}
variable "permissions_boundary_arn" {
description = "The ARN of the policy that is used to set the permissions boundary for the IAM role."
type = string
default = ""
}
variable "external_id" {
description = "The External ID is auto-generated. Do not change this value."
type = string
default = "02c715d72e193139ed5fb1fcae8a243571269a077e95ce2eaab61ad495830154"
validation {
condition = can(regex("^[a-z0-9]*$", var.external_id))
error_message = "Must be lowercase or numbers, no spaces."
}
}
variable "assume_role_service_account" {
description = "SentinelOne CNS Service Account which will perform sts:assumeRole. Do not change this value."
type = string
default = "arn:aws:iam::613274416560:user/sentinelone-cns-service-account-dev"
}
variable "is_organization_onboarding" {
description = "Create the stackset in case of Organization Onboarding"
type = string
default = "No"
validation {
condition = can(regex("^(Yes|No)$", var.is_organization_onboarding))
error_message = "The input must be either 'Yes' or 'No'."
}
}
variable "excluded_accounts" {
description = "Excluded accounts from stack set operation"
type = string
default = ""
}
variable "enable_snapshot_scanning" {
description = "Whether to enable snapshot scanning."
type = string
default = "Yes"
validation {
condition = can(regex("^(Yes|No)$", var.enable_snapshot_scanning))
error_message = "The input must be either 'Yes' or 'No'."
}
}
variable "integration_mode" {
description = "Select mode \n 1. DETECT (In Detect mode, SentinelOne CNS has read-only access to your AWS Cloud resources.) \n 2. DETECT_AND_REMEDIATE (In Detect & Remediate mode, SentinelOne CNS can access and remediate resource configuration issues for continuous compliance in your AWS account.) (Allowed values - DETECT, DETECT_AND_REMEDIATE) "
type = string
default = "DETECT_AND_REMEDIATE"
validation {
condition = can(regex("^(DETECT|DETECT_AND_REMEDIATE)$", var.integration_mode))
error_message = "The input must be either 'DETECT' or 'DETECT_AND_REMEDIATE'."
}
}
variable "enable_cds_integration" {
description = "Whether to enable CDS integration."
type = string
default = "Yes"
validation {
condition = can(regex("^(Yes|No)$", var.enable_cds_integration))
error_message = "The input must be either 'Yes' or 'No'."
}
}