locals {
has_permissions_boundary = var.permissions_boundary_arn != ""
snapshot_scanning_enabled = var.enable_snapshot_scanning == "Yes"
auto_remediation_enabled = var.integration_mode == "DETECT_AND_REMEDIATE"
is_cds_integration_enabled = var.enable_cds_integration == "Yes"
is_organization_onboarding_selected = var.is_organization_onboarding == "Yes"
has_excluded_accounts = var.is_organization_onboarding == "Yes" && var.excluded_accounts != ""
has_no_excluded_accounts = var.is_organization_onboarding == "Yes" && var.excluded_accounts == ""
}