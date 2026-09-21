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
#  enabled: true | false  # Whether to enable Guard Duty
#  finding_publishing_frequency: "FIFTEEN_MINUTES" | "ONE_HOUR" | "SIX_HOURS" # Frequency of finding publishing
#  malware_protection: # (optional) Malware protection settings
#    ebs_snapshot_preservation: true | false  # Whether to preserve EBS snapshots for malware protection
#    scan_criteria:
#      Include:
#        EC2_INSTANCE_TAG:
#          MapEquals: # (optional) List of tags to include in the scan criteria
#            - Key: "tag_key"  # Tag key to include in the scan criteria
#              Value: "tag_value"  # Tag value to include in the scan criteria
#      Exclude:
#        EC2_INSTANCE_TAG:
#          MapEquals: # (optional) List of tags to include in the scan criteria
#            - Key: "tag_key"  # Tag key to include in the scan criteria
#              Value: "tag_value"  # Tag value to include in the scan criteria
#  features:
#    - name: "feature_name"  # Name of the feature
#      enabled: true | false  # Whether the feature is enabled
#      additional_configurations:
#        - name: "config_name"  # Name of the additional configuration
#          enabled: true | false # Auto-enable setting for the additional configuration
#  organization:
#    delegated: true | false  # Whether to delegate Guard Duty management to the organization administrator account
#    administrator_account_id: "123456789012"  # The AWS account ID of the Guard Duty administrator account, can be used only on the Organization Account
#    account_id: "123456789012"  # The AWS account ID of the Guard Duty administrator account
#    enabled: true | false  # Whether to enable Guard Duty for the organization.
#    auto_enable: ALL | NONE | NEW # Auto-enable Guard Duty for new accounts in the organization
#    features:
#      - name: "org_feature_name"  # Name of the organization feature
#        auto_enable: ALL | NONE | NEW # Auto-enable setting for the organization feature
#        additional_configurations:
#          - name: "org_config_name"  # Name of the additional configuration for the organization feature
#            auto_enable: ALL | NONE | NEW # Auto-enable setting for the organization feature
#  malware_protection:
#    plans: # (optional) List of malware protection plans
#      - bucket_name: "my-malware-protection-bucket"  # S3 bucket name for malware protection
#        object_prefixes: # (optional) List of object prefixes for the malware protection bucket
#          - "prefix1"
#          - "prefix2"
#        tagging_enabled: true | false # (optional) Whether to enable tagging for the malware protection bucket, default is true
#        bucket_kms_key_id: "ae853tgjvgyuu43" # (optional) KMS key ID for the malware protection bucket, default is null
#        bucket_kms_key_region: "us-west-2" # (optional) KMS key region for the malware protection bucket, default is current region
#        bucket_kms_key_account_id: "123456789012" # (optional) KMS key account ID for the malware protection bucket, default is is current account
#  publishing_destination:
#    enabled: true | false  # (optional) Create the findings S3 bucket and register it as the publishing destination, default is false
#    bucket_name: "existing-findings-bucket" # (optional) Existing bucket to publish findings to when enabled is false, default is ""
#    expiration_days: 90 # (optional) Number of days after which findings in the publishing destination bucket will expire, default is 90
#    encryption: # (optional) KMS settings for the publishing destination. GuardDuty always requires a KMS key for S3 export.
#      enabled: true | false  # (optional) Create a module-managed KMS key, default is true. When false, kms_key_arn is required.
#      kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/..." # (optional) Existing KMS key ARN used when enabled is false or when publishing to an existing bucket, default is ""
#      deletion_window_days: 30 # (optional) KMS key deletion window in days, valid values 7-30, default is 30
#      rotation_enabled: true | false # (optional) Enable automatic KMS key rotation, default is true
#      rotation_period_days: 365 # (optional) Rotation period in days, only used when rotation_enabled is true, valid values 90-2560, default is 365
#      multi_region: true | false # (optional) Create the KMS key as a multi-region primary key, default is false
#      admin_role: "terraform-access-role" # (optional) IAM role name granted full administration over the KMS key, default is "terraform-access-role"
#      alias: "alias/guardduty-pd-custom" # (optional) KMS alias name, default is "alias/guardduty-pd-<system_name_short>"
#      description: "KMS key for GuardDuty publishing destination" # (optional) KMS key description
#    kms_key_admin_role: "terraform-access-role" # (deprecated) Use encryption.admin_role instead, default is "terraform-access-role"
#    kms_key_deletion_window: 30 # (deprecated) Use encryption.deletion_window_days instead, default is 30
#    kms_key_arn: "arn:aws:kms:..." # (deprecated) Use encryption.kms_key_arn instead, default is ""
#  filters: # (optional) List of filters for Guard Duty findings
#    <filter_name>:
#      action: "NOOP" | "ARCHIVE"  # Action to take on the filter, defaults to "ARCHIVE"
#      description: "Filter description"  # Description of the filter
#      rank: 0  # Rank of the filter, lower numbers are higher priority
#      criteria_list: # List of criteria for the filter
#        - field: "field_name"  # Field to filter on
#          equals: ["value1", "value2"]  # Values to match for the field
#          not_equals: ["value3", "value4"]  # Values to exclude for the field
#          greater_than: 10 | <date> # (optional) Greater than value for numeric fields
#          less_than: 100 | <date> # (optional) Less than value for numeric fields
#          greater_than_or_equal: 10 | <date> # (optional) Greater than or equal value for numeric fields
#          less_than_or_equal: 100 | <date> # (optional) Less than or equal value for numeric fields
variable "settings" {
  description = "Settings for the Guard Duty configuration"
  type        = any
  default     = {}

  validation {
    condition = (
      !try(var.settings.publishing_destination.enabled, false) ||
      try(var.settings.publishing_destination.encryption.enabled, true) ||
      try(var.settings.publishing_destination.encryption.kms_key_arn, var.settings.publishing_destination.kms_key_arn, "") != ""
    )
    error_message = "settings.publishing_destination.encryption.kms_key_arn is required when settings.publishing_destination.enabled is true and settings.publishing_destination.encryption.enabled is false, GuardDuty requires a KMS key to export findings to S3."
  }

  validation {
    condition = (
      !try(var.settings.publishing_destination.encryption.rotation_enabled, true) ||
      (
        try(var.settings.publishing_destination.encryption.rotation_period_days, 365) >= 90 &&
        try(var.settings.publishing_destination.encryption.rotation_period_days, 365) <= 2560
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
