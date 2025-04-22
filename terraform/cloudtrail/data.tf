data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "roots" {}
data "aws_region" "current" {}