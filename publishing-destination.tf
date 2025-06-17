##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  destination_bucket_name = format("guard-duty-findings-%s", local.system_name)
}

module "publishing_destination" {
  source                                    = "terraform-aws-modules/s3-bucket/aws"
  version                                   = "~> 4.10"
  create_bucket                             = try(var.settings.publishing_destination.enabled, false)
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
  policy                                    = data.aws_iam_policy_document.publishing_destination_bucket_policy[0].json
  block_public_acls                         = true
  block_public_policy                       = true
  ignore_public_acls                        = true
  restrict_public_buckets                   = true
  versioning = {
    enabled = false
  }
  allowed_kms_key_arn = aws_kms_key.publishing_destination[0].arn
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.publishing_destination[0].arn
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
  count = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
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
  count = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
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
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${try(var.settings.publishing_destination.kms_key_admin_role, "terraform-access-role")}",
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
  count                   = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
  description             = "KMS key for GuardDuty publishing destination"
  deletion_window_in_days = try(var.settings.publishing_destination.kms_key_deletion_window, 30)
  enable_key_rotation     = true
  is_enabled              = true
  tags                    = local.all_tags
}

resource "aws_kms_key_policy" "publishing_destination" {
  count  = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
  key_id = aws_kms_key.publishing_destination[0].id
  policy = data.aws_iam_policy_document.publishing_destination_kms_key_policy[0].json
}

resource "aws_kms_alias" "publishing_destination" {
  count         = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
  target_key_id = aws_kms_key.publishing_destination[0].id
  name          = format("alias/guardduty-pd-%s", local.system_name_short)
}

resource "aws_guardduty_publishing_destination" "publishing_destination" {
  count           = try(var.settings.publishing_destination.enabled, false) ? 1 : 0
  destination_arn = module.publishing_destination.s3_bucket_arn
  detector_id     = aws_guardduty_detector.this[0].id
  kms_key_arn     = aws_kms_key.publishing_destination[0].arn
  depends_on = [
    module.publishing_destination,
    aws_kms_key_policy.publishing_destination,
  ]
}