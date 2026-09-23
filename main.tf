##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  snapshot_preservation  = try(var.settings.malware_protection.ebs_snapshot_preservation, false) ? "RETENTION_WITH_FINDING" : "NO_RETENTION"
  scan_resource_criteria = try(var.settings.malware_protection.scan_criteria, {})
  # The AWS provider has no resource for UpdateMalwareScanSettings (hashicorp/terraform-provider-aws#33979),
  # so the settings are applied through the AWS CLI, and only when the operator configures them.
  malware_scan_settings_enabled = (
    try(var.settings.malware_protection.ebs_snapshot_preservation, null) != null ||
    length(local.scan_resource_criteria) > 0
  )
  detectors = {
    for detector in data.aws_guardduty_detector.existing : detector.id => detector
  }
  # Organization auto-enable only reaches member accounts, never the delegated administrator itself.
  # When settings.features is not set, the administrator detector inherits settings.organization.features.
  organization_self_features = [
    for feature in try(var.settings.organization.features, []) : {
      name    = feature.name
      enabled = try(feature.auto_enable, "ALL") != "NONE"
      additional_configurations = [
        for config in try(feature.additional_configurations, []) : {
          name    = config.name
          enabled = try(config.auto_enable, "ALL") != "NONE"
        }
      ]
    } if try(var.settings.organization.enabled, false)
  ]
  detector_features = try(var.settings.features, local.organization_self_features)
}

data "aws_guardduty_detector" "existing" {
  count = try(var.settings.detector.enabled, true) ? 0 : 1
}

import {
  for_each = local.detectors
  id       = each.key
  to       = aws_guardduty_detector.this[0]
}

resource "aws_guardduty_detector" "this" {
  count = (
    ((try(var.settings.organization.enabled, false) && var.is_hub) ||
    (!try(var.settings.organization.delegated, false) && !var.is_hub))
  ) ? 1 : 0
  enable                       = try(var.settings.enabled, true)
  finding_publishing_frequency = try(var.settings.finding_publishing_frequency, null)
  tags                         = local.all_tags
}

# Runs against the effective detector (created or adopted) and re-runs whenever the settings change.
resource "terraform_data" "malware_scan_settings" {
  count = local.malware_scan_settings_enabled ? 1 : 0
  triggers_replace = {
    detector_id            = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
    region                 = data.aws_region.current.region
    snapshot_preservation  = local.snapshot_preservation
    scan_resource_criteria = length(local.scan_resource_criteria) > 0 ? jsonencode(local.scan_resource_criteria) : ""
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -e
      if [ -n "$SCAN_RESOURCE_CRITERIA" ]; then
        aws guardduty update-malware-scan-settings --region "$REGION" --detector-id "$DETECTOR_ID" \
          --ebs-snapshot-preservation "$SNAPSHOT_PRESERVATION" --scan-resource-criteria "$SCAN_RESOURCE_CRITERIA"
      else
        aws guardduty update-malware-scan-settings --region "$REGION" --detector-id "$DETECTOR_ID" \
          --ebs-snapshot-preservation "$SNAPSHOT_PRESERVATION"
      fi
    EOT
    environment = {
      REGION                 = self.triggers_replace.region
      DETECTOR_ID            = self.triggers_replace.detector_id
      SNAPSHOT_PRESERVATION  = self.triggers_replace.snapshot_preservation
      SCAN_RESOURCE_CRITERIA = self.triggers_replace.scan_resource_criteria
    }
  }
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = {
    for feature in local.detector_features : feature.name => feature
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