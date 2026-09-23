##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

## settings as yaml Entries:
#settings:
#  enabled: true                                 # (Optional) Enable the GuardDuty detector. Default: true.
#  finding_publishing_frequency: "SIX_HOURS"     # (Optional) Valid values: "FIFTEEN_MINUTES" | "ONE_HOUR" | "SIX_HOURS". Default: AWS default ("SIX_HOURS").
#  detector:                                     # (Optional) Detector ownership. Default: {}.
#    enabled: true                               # (Optional) true: the module creates the detector. false: the detector already in this account/region is looked up and imported,
#                                                #   e.g. the one AWS auto-creates when the account is designated delegated administrator. Default: true.
#  features:                                     # (Optional) Detector features of THIS account. When omitted and organization.enabled is true, they are inherited from
#                                                #   organization.features (auto_enable ALL/NEW -> ENABLED, NONE -> DISABLED), because organization auto-enable never
#                                                #   reaches the delegated administrator itself. Set "features: []" to opt out of the inheritance. Default: inherited or [].
#    - name: "RUNTIME_MONITORING"                # (Required) Valid values (AWS API): "S3_DATA_EVENTS" | "EKS_AUDIT_LOGS" | "EBS_MALWARE_PROTECTION" | "RDS_LOGIN_EVENTS" |
#                                                #   "EKS_RUNTIME_MONITORING" | "LAMBDA_NETWORK_LOGS" | "RUNTIME_MONITORING" | "AI_PROTECTION".
#      enabled: true                             # (Optional) true -> ENABLED, false -> DISABLED. Default: true.
#      additional_configurations:                # (Optional) Only for EKS_RUNTIME_MONITORING / RUNTIME_MONITORING. Default: [].
#        - name: "EKS_ADDON_MANAGEMENT"          # (Required) Valid values: "EKS_ADDON_MANAGEMENT" | "ECS_FARGATE_AGENT_MANAGEMENT" | "EC2_AGENT_MANAGEMENT".
#          enabled: true                         # (Optional) true -> ENABLED, false -> DISABLED. Default: true.
#  organization:                                 # (Optional) AWS Organizations integration. Default: {} (disabled).
#    delegated: false                            # (Optional) Organizations management account only: designate administrator_account_id as the GuardDuty
#                                                #   delegated administrator. The module manages no detector in that account. Default: false.
#    administrator_account_id: "123456789012"    # (Optional) 12-digit account ID of the delegated administrator, required when delegated is true. Default: "".
#    enabled: false                              # (Optional) Delegated administrator account only (is_hub: true): manage the organization configuration. Default: false.
#    auto_enable: "ALL"                          # (Optional) Enrolment of member accounts. Valid values: "ALL" | "NEW" | "NONE". Default: "ALL".
#    features:                                   # (Optional) Protection plans auto-enabled for MEMBER accounts, also inherited by the administrator detector when
#                                                #   settings.features is omitted. Default: [].
#      - name: "RUNTIME_MONITORING"              # (Required) Same valid values as settings.features[].name.
#        auto_enable: "ALL"                      # (Optional) Valid values: "ALL" | "NEW" | "NONE". Default: "ALL".
#        additional_configurations:              # (Optional) Default: [].
#          - name: "EKS_ADDON_MANAGEMENT"        # (Required) Valid values: "EKS_ADDON_MANAGEMENT" | "ECS_FARGATE_AGENT_MANAGEMENT" | "EC2_AGENT_MANAGEMENT".
#            auto_enable: "ALL"                  # (Optional) Valid values: "ALL" | "NEW" | "NONE". Default: "ALL".
#  malware_protection:                           # (Optional) Malware Protection settings. Default: {}.
#    ebs_snapshot_preservation: false            # (Optional) EBS malware scan setting of the detector, true -> RETENTION_WITH_FINDING, false -> NO_RETENTION.
#                                                #   Applied through the AWS CLI (see "EBS malware scan settings"). Default: unset, left untouched in AWS.
#    scan_criteria:                              # (Optional) EC2 instances selected for EBS malware scans, applied through the AWS CLI. Default: {}, left untouched in AWS.
#                                                #   Removing it later does not clear criteria already applied.
#      Include:                                  # (Optional) Scan only instances matching these tags.
#        EC2_INSTANCE_TAG:                       # (Required) Only valid key: "EC2_INSTANCE_TAG".
#          MapEquals:                            # (Required) Tag conditions.
#            - Key: "Scan"                       # (Required) Tag key, 1-128 chars, must not start with "aws:".
#              Value: "true"                     # (Optional) Tag value, when omitted only the key is matched.
#      Exclude:                                  # (Optional) Skip instances matching these tags.
#        EC2_INSTANCE_TAG:                       # (Required) Only valid key: "EC2_INSTANCE_TAG".
#          MapEquals:                            # (Required) Tag conditions.
#            - Key: "SkipMalwareScan"            # (Required) Tag key.
#              Value: "true"                     # (Optional) Tag value.
#    plans:                                      # (Optional) Malware Protection for S3 plans, one per bucket. Creates the "malware-prot-<system_name>-role" IAM role. Default: [].
#      - bucket_name: "my-uploads-bucket"        # (Required) Existing S3 bucket to protect, also the key of the plan.
#        object_prefixes:                        # (Optional) Scan only objects under these prefixes. Default: [] (whole bucket).
#          - "incoming/"
#        tagging_enabled: true                   # (Optional) Tag scanned objects with the scan result. Default: true.
#        bucket_kms_key_id: "1234abcd-12ab-34cd-56ef-1234567890ab" # (Optional) KMS key ID when the bucket uses SSE-KMS, grants the role kms:Decrypt. Default: unset.
#        bucket_kms_key_region: "us-east-1"      # (Optional) Region of bucket_kms_key_id. Default: current region.
#        bucket_kms_key_account_id: "123456789012" # (Optional) Account of bucket_kms_key_id. Default: current account.
#  publishing_destination:                       # (Optional) Export of findings to S3. Default: {} (no export).
#    enabled: false                              # (Optional) Create the findings S3 bucket and register it as the publishing destination. Default: false.
#    bucket_name: "existing-findings-bucket"     # (Optional) Publish to this existing bucket instead, used when enabled is false. Default: "".
#    expiration_days: 90                         # (Optional) Days before exported findings expire in the managed bucket. Default: 90.
#    retain_bucket: false                        # (Optional) Keep the bucket and its managed KMS key when enabled is switched to false. Default: false.
#    force_destroy: false                        # (Optional) Allow Terraform to delete the bucket while it still holds objects. Default: false.
#    encryption:                                 # (Optional) KMS settings. GuardDuty requires a KMS key to export findings to S3. Default: {}.
#      enabled: true                             # (Optional) Create a module-managed KMS key. When false and a destination is configured, kms_key_arn or
#                                                #   kms_key_alias is required (enforced by validation). Default: true.
#      kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab" # (Optional) Existing key, used when enabled is false or
#                                                #   when publishing to bucket_name. Takes precedence over kms_key_alias. Default: "".
#      kms_key_alias: "my-findings-key"          # (Optional) Existing key alias resolved to its ARN, with or without the "alias/" prefix. Default: "".
#      deletion_window_days: 30                  # (Optional) Managed key deletion window, valid values 7-30. Default: 30.
#      rotation_enabled: true                    # (Optional) Automatic rotation of the managed key. Default: true.
#      rotation_period_days: 90                  # (Optional) Rotation period, valid values 90-2560, used when rotation_enabled is true. Default: 90.
#      multi_region: false                       # (Optional) Create the managed key as a multi-region primary key. Default: false.
#      admin_role: "terraform-access-role"       # (Optional) IAM role name granted full administration of the managed key. Default: "terraform-access-role".
#      alias: "alias/guardduty-pd-custom"        # (Optional) Alias of the managed key. Default: "alias/guardduty-pd-<system_name_short>".
#      description: "KMS key for GuardDuty publishing destination" # (Optional) Description of the managed key. Default: as shown.
#    kms_key_admin_role: "terraform-access-role" # (Deprecated) Use encryption.admin_role. Still honoured as a fallback.
#    kms_key_deletion_window: 30                 # (Deprecated) Use encryption.deletion_window_days. Still honoured as a fallback.
#    kms_key_arn: "arn:aws:kms:..."              # (Deprecated) Use encryption.kms_key_arn. Still honoured as a fallback.
#  filters:                                      # (Optional) Findings filters, keyed by name. The filter name is "<key>-<system_name_short>". Default: {}.
#    low-severity:
#      action: "ARCHIVE"                         # (Optional) Valid values: "ARCHIVE" | "NOOP". Default: "ARCHIVE".
#      description: "Archive low severity findings" # (Optional) Default: "Filter for Guard Duty findings - <key>".
#      rank: 1                                   # (Optional) Order in which filters are applied, valid values 1-100. Default: 0, which AWS rejects, so set it.
#      criteria_list:                            # (Required) Finding criteria, combined with AND.
#        - field: "severity"                     # (Required) Finding attribute, e.g. "severity", "type", "resource.resourceType", "updatedAt".
#          less_than: 4                          # (Optional) One or more of: equals | not_equals (lists of strings), greater_than | greater_than_or_equal |
#                                                #   less_than | less_than_or_equal (number, or RFC 3339 date for date fields).
variable "settings" {
  description = "Settings for the Guard Duty configuration"
  type        = any
  default     = {}

  validation {
    condition = (
      !try(var.settings.publishing_destination.enabled, false) ||
      try(var.settings.publishing_destination.encryption.enabled, true) ||
      try(var.settings.publishing_destination.encryption.kms_key_arn, var.settings.publishing_destination.kms_key_arn, "") != "" ||
      try(var.settings.publishing_destination.encryption.kms_key_alias, "") != ""
    )
    error_message = "settings.publishing_destination.encryption.kms_key_arn or kms_key_alias is required when settings.publishing_destination.enabled is true and settings.publishing_destination.encryption.enabled is false, GuardDuty requires a KMS key to export findings to S3."
  }

  validation {
    condition = (
      !try(var.settings.publishing_destination.encryption.rotation_enabled, true) ||
      (
        try(var.settings.publishing_destination.encryption.rotation_period_days, 90) >= 90 &&
        try(var.settings.publishing_destination.encryption.rotation_period_days, 90) <= 2560
      )
    )
    error_message = "settings.publishing_destination.encryption.rotation_period_days must be between 90 and 2560 days."
  }

  validation {
    condition = (
      try(var.settings.publishing_destination.encryption.deletion_window_days, var.settings.publishing_destination.kms_key_deletion_window, 30) >= 7 &&
      try(var.settings.publishing_destination.encryption.deletion_window_days, var.settings.publishing_destination.kms_key_deletion_window, 30) <= 30
    )
    error_message = "settings.publishing_destination.encryption.deletion_window_days (or the deprecated kms_key_deletion_window) must be between 7 and 30 days."
  }
}
