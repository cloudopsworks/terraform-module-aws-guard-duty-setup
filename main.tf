##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

resource "aws_organizations_delegated_administrator" "this" {
  count             = try(var.settings.organization.delegated, false) && !var.is_hub ? 1 : 0
  account_id        = var.settings.organization.account_id
  service_principal = "guardduty.amazonaws.com"
}

resource "aws_guardduty_detector" "this" {
  count = (
    (try(var.settings.organization.delegated, false) && var.is_hub) ||
    (!try(var.settings.organization.delegated, false) && !var.is_hub)
  ) ? 1 : 0
  enable                       = try(var.settings.enabled, true)
  finding_publishing_frequency = try(var.settings.finding_publishing_frequency, null)
  tags                         = local.all_tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = {
    for feature in try(var.settings.features, []) : feature.name => feature
  }
  detector_id = aws_guardduty_detector.this[0].id
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
  count            = try(var.settings.organization.delegated, false) && !var.is_hub ? 1 : 0
  admin_account_id = var.settings.organization.account_id
}

resource "aws_guardduty_organization_configuration" "this" {
  depends_on                       = [aws_guardduty_organization_admin_account.this]
  count                            = try(var.settings.organization.enabled, false) ? 1 : 0
  auto_enable_organization_members = try(var.settings.organization.auto_enable, "ALL")
  detector_id                      = aws_guardduty_detector.this[0].id
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = {
    for feature in try(var.settings.organization.features, []) : feature.name => feature
  }
  detector_id = aws_guardduty_detector.this[0].id
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