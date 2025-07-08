##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  snapshot_preservation      = try(var.settings.malware_protection.ebs_snapshot_preservation, false) ? "RETENTION_WITH_FINDING" : "NO_RETENTION"
  scan_resource_criteria_obj = try(var.settings.malware_protection.scan_criteria, {})
  scan_resource_criteria     = length(local.scan_resource_criteria_obj) > 0 ? "--scan-resource-criteria ${jsonencode(local.scan_resource_criteria_obj)}" : ""
}

data "aws_guardduty_detector" "existing" {
  count = try(var.settings.detector.enabled, true) ? 0 : 1
}

resource "aws_guardduty_detector" "this" {
  count = (
    ((try(var.settings.organization.enabled, false) && var.is_hub) ||
    (!try(var.settings.organization.delegated, false) && !var.is_hub)) &&
    length(data.aws_guardduty_detector.existing) == 0
  ) ? 1 : 0
  enable                       = try(var.settings.enabled, true)
  finding_publishing_frequency = try(var.settings.finding_publishing_frequency, null)
  tags                         = local.all_tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = {
    for feature in try(var.settings.features, []) : feature.name => feature
  }
  detector_id = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
  name        = each.value.name
  status      = try(each.value.enabled, true) ? "ENABLED" : "DISABLED"
  dynamic "additional_configuration" {
    for_each = try(each.value.additional_configurations, [])
    content {
      name   = additional_configuration.value.name
      status = try(additional_configuration.value.enabled, true) ? "ENABLED" : "DISABLED"
    }
  }
}

resource "aws_guardduty_organization_admin_account" "this" {
  count            = try(var.settings.organization.delegated, false) && try(var.settings.organization.administrator_account_id, "") != "" ? 1 : 0
  admin_account_id = var.settings.organization.administrator_account_id
}

resource "aws_guardduty_organization_configuration" "this" {
  count                            = try(var.settings.organization.enabled, false) ? 1 : 0
  auto_enable_organization_members = try(var.settings.organization.auto_enable, "ALL")
  detector_id                      = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = {
    for feature in try(var.settings.organization.features, []) : feature.name => feature
  }
  detector_id = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
  name        = each.value.name
  auto_enable = try(each.value.auto_enable, "ALL")
  dynamic "additional_configuration" {
    for_each = try(each.value.additional_configurations, [])
    content {
      name        = additional_configuration.value.name
      auto_enable = try(additional_configuration.value.auto_enable, "ALL")
    }
  }

  provisioner "local-exec" {
    command = "aws guardduty update-malware-scan-settings --detector-id ${self.detector_id} --ebs-snapshot-preservation '${local.snapshot_preservation}' ${local.scan_resource_criteria}"
  }
}

resource "aws_guardduty_filter" "this" {
  for_each    = try(var.settings.filters, {})
  name        = format("%s-%s", each.key, local.system_name_short)
  description = try(each.value.description, "Filter for Guard Duty findings - ${each.key}")
  detector_id = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
  action      = try(each.value.action, "ARCHIVE")
  rank        = try(each.value.rank, 0)
  finding_criteria {
    dynamic "criterion" {
      for_each = try(each.value.criteria_list, [])
      content {
        field                 = criterion.value.field
        equals                = try(criterion.value.equals, null)
        not_equals            = try(criterion.value.not_equals, null)
        greater_than          = try(criterion.value.greater_than, null)
        less_than             = try(criterion.value.less_than, null)
        greater_than_or_equal = try(criterion.value.greater_than_or_equal, null)
        less_than_or_equal    = try(criterion.value.less_than_or_equal, null)
      }
    }
  }
  tags = local.all_tags
}