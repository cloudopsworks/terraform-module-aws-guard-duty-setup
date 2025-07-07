##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

output "publishing_destination_bucket_name" {
  value = try(var.settings.publishing_destination.enabled, false) ? module.publishing_destination.s3_bucket_id : null
}

output "publishing_destination_bucket_arn" {
  value = try(var.settings.publishing_destination.enabled, false) ? module.publishing_destination.s3_bucket_arn : null
}

output "publishing_destination_kms_key_id" {
  value = try(var.settings.publishing_destination.enabled, false) ? aws_kms_key.publishing_destination[0].id : null
}

output "publishing_destination_kms_key_arn" {
  value = try(var.settings.publishing_destination.enabled, false) ? aws_kms_key.publishing_destination[0].arn : null
}