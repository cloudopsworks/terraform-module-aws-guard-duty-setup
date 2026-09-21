##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

output "publishing_destination_bucket_name" {
  description = "Name of the module-managed S3 bucket that receives GuardDuty findings, null when neither publishing_destination.enabled nor retain_bucket is true"
  value       = local.publishing_destination_bucket_create ? module.publishing_destination.s3_bucket_id : null
}

output "publishing_destination_bucket_arn" {
  description = "ARN of the module-managed S3 bucket that receives GuardDuty findings, null when neither publishing_destination.enabled nor retain_bucket is true"
  value       = local.publishing_destination_bucket_create ? module.publishing_destination.s3_bucket_arn : null
}

output "publishing_destination_kms_key_id" {
  description = "ID of the module-managed KMS key for the publishing destination, null when the key is not managed by this module"
  value       = local.publishing_destination_kms_managed ? aws_kms_key.publishing_destination[0].id : null
}

output "publishing_destination_kms_key_arn" {
  description = "ARN of the KMS key used by the publishing destination, module-managed or externally supplied via encryption.kms_key_arn or kms_key_alias, null when no publishing destination is configured"
  value       = local.publishing_destination_kms_key_arn != "" ? local.publishing_destination_kms_key_arn : null
}

output "publishing_destination_kms_key_managed" {
  description = "Whether the publishing destination KMS key is created and managed by this module"
  value       = local.publishing_destination_kms_managed
}
