##
# (c) 2021-2025
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
#    enabled: true | false  # Whether to enable publishing destination for Guard Duty findings
#    kms_key_admin_role: "terraform-access-role" # IAM role for KMS key administration, default is "terraform-access-role"
#    kms_key_deletion_window: 30 # KMS key deletion window in days, default is 30
#    expiration_days: 90 # (optional) Number of days after which findings in the publishing destination bucket will expire, default is 90
variable "settings" {
  description = "Settings for the Guard Duty configuration"
  type        = any
  default     = {}
}
