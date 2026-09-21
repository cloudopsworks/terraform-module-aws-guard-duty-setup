##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  destination_bucket_name        = format("guard-duty-findings-%s", local.system_name)
  publishing_destination_enabled = try(var.settings.publishing_destination.enabled, false)
  # Normalized KMS settings live under settings.publishing_destination.encryption.
  # The legacy flat keys (kms_key_admin_role, kms_key_deletion_window, kms_key_arn) are
  # deprecated but still honored as fallbacks so existing deployments keep working.
  publishing_destination_encryption          = try(var.settings.publishing_destination.encryption, {})
  publishing_destination_kms_managed         = local.publishing_destination_enabled && try(local.publishing_destination_encryption.enabled, true)
  publishing_destination_kms_external_arn    = try(local.publishing_destination_encryption.kms_key_arn, var.settings.publishing_destination.kms_key_arn, "")
  publishing_destination_kms_deletion_window = try(local.publishing_destination_encryption.deletion_window_days, var.settings.publishing_destination.kms_key_deletion_window, 30)
  publishing_destination_kms_admin_role      = try(local.publishing_destination_encryption.admin_role, var.settings.publishing_destination.kms_key_admin_role, "terraform-access-role")
  publishing_destination_kms_rotation        = try(local.publishing_destination_encryption.rotation_enabled, true)
  publishing_destination_kms_rotation_period = local.publishing_destination_kms_rotation ? try(local.publishing_destination_encryption.rotation_period_days, 90) : null
  publishing_destination_kms_alias           = try(local.publishing_destination_encryption.alias, format("alias/guardduty-pd-%s", local.system_name_short))
  publishing_destination_kms_key_arn         = local.publishing_destination_kms_managed ? aws_kms_key.publishing_destination[0].arn : local.publishing_destination_kms_external_arn
}

module "publishing_destination" {
  source                                    = "terraform-aws-modules/s3-bucket/aws"
  version                                   = "~> 5.00"
  create_bucket                             = local.publishing_destination_enabled
  bucket                                    = local.destination_bucket_name
  acl                                       = "private"
  force_destroy                             = false
  control_object_ownership                  = true
  object_ownership                          = "ObjectWriter"
  attach_deny_incorrect_encryption_headers  = true
  attach_deny_insecure_transport_policy     = true
  attach_deny_unencrypted_object_uploads    = true
  attach_deny_ssec_encrypted_object_uploads = true
  attach_require_latest_tls_policy          = true
  attach_public_policy                      = true
  attach_policy                             = true
  policy                                    = local.publishing_destination_enabled ? data.aws_iam_policy_document.publishing_destination_bucket_policy[0].json : ""
  block_public_acls                         = true
  block_public_policy                       = true
  ignore_public_acls                        = true
  restrict_public_buckets                   = true
  versioning = {
    enabled = false
  }
  allowed_kms_key_arn = local.publishing_destination_enabled ? local.publishing_destination_kms_key_arn : null
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = local.publishing_destination_enabled ? local.publishing_destination_kms_key_arn : null
      }
    }
  }
  lifecycle_rule = [
    {
      id      = "expire_findings"
      enabled = true
      expiration = {
        days = try(var.settings.publishing_destination.expiration_days, 90)
      }
    }
  ]
  tags = local.all_tags
}

data "aws_iam_policy_document" "publishing_destination_bucket_policy" {
  count = local.publishing_destination_enabled ? 1 : 0
  statement {
    sid = "AllowPutObject"
    actions = [
      "s3:PutObject"
    ]

    resources = [
      "arn:aws:s3:::${local.destination_bucket_name}/*"
    ]

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com"
      ]
    }
  }

  statement {
    sid = "AllowGetBucketLocation"
    actions = [
      "s3:GetBucketLocation"
    ]

    resources = [
      "arn:aws:s3:::${local.destination_bucket_name}"
    ]

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com"
      ]
    }
  }
}

data "aws_iam_policy_document" "publishing_destination_kms_key_policy" {
  count = local.publishing_destination_kms_managed ? 1 : 0
  statement {
    sid    = "AllowGuardDutyUseOfKMSKey"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
    ]
    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com"
      ]
    }
    resources = [
      aws_kms_key.publishing_destination[0].arn
    ]
  }
  statement {
    sid    = "AllowAdminUserFullAccess"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.publishing_destination_kms_admin_role}",
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    actions = [
      "kms:*"
    ]
    resources = [
      aws_kms_key.publishing_destination[0].arn
    ]
  }
}

resource "aws_kms_key" "publishing_destination" {
  count                   = local.publishing_destination_kms_managed ? 1 : 0
  description             = try(local.publishing_destination_encryption.description, "KMS key for GuardDuty publishing destination")
  deletion_window_in_days = local.publishing_destination_kms_deletion_window
  enable_key_rotation     = local.publishing_destination_kms_rotation
  rotation_period_in_days = local.publishing_destination_kms_rotation_period
  multi_region            = try(local.publishing_destination_encryption.multi_region, false)
  is_enabled              = true
  tags                    = local.all_tags
}

resource "aws_kms_key_policy" "publishing_destination" {
  count  = local.publishing_destination_kms_managed ? 1 : 0
  key_id = aws_kms_key.publishing_destination[0].id
  policy = data.aws_iam_policy_document.publishing_destination_kms_key_policy[0].json
}

resource "aws_kms_alias" "publishing_destination" {
  count         = local.publishing_destination_kms_managed ? 1 : 0
  target_key_id = aws_kms_key.publishing_destination[0].id
  name          = local.publishing_destination_kms_alias
}

resource "aws_guardduty_publishing_destination" "publishing_destination" {
  count           = local.publishing_destination_enabled || try(var.settings.publishing_destination.bucket_name, "") != "" ? 1 : 0
  destination_arn = local.publishing_destination_enabled ? module.publishing_destination.s3_bucket_arn : format("arn:aws:s3:::%s", var.settings.publishing_destination.bucket_name)
  detector_id     = try(var.settings.detector.enabled, true) ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
  kms_key_arn     = local.publishing_destination_kms_key_arn
  depends_on = [
    module.publishing_destination,
    aws_kms_key_policy.publishing_destination,
  ]
}
