locals {
  alice_policy = <<-EOT
    path "${var.db_mount_path}/creds/readOnly" {
      capabilities = ["read"]
    }

    path "${local.transit_mount_path}/decrypt/${var.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.kv_secret_mount}/data/${local.kv_secret_path}" {
      capabilities = ["create", "read", "update", "delete"]
    }

    path "${local.kv_secret_mount}/metadata/${local.kv_secret_path}" {
      capabilities = ["read", "delete"]
    }

    path "${local.kv_secret_mount}/undelete/${local.kv_secret_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_secret_mount}/destroy/${local.kv_secret_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_demo_mount}/data/${local.kv_demo_path}" {
      capabilities = ["create", "read", "update", "delete"]
    }

    path "${local.kv_demo_mount}/metadata/${local.kv_demo_path}" {
      capabilities = ["read", "delete"]
    }

    path "${local.kv_demo_mount}/undelete/${local.kv_demo_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_demo_mount}/destroy/${local.kv_demo_path}" {
      capabilities = ["update"]
    }

    path "${var.aws_mount_path}/creds/${var.aws_role_name}" {
      capabilities = ["read"]
    }

    path "sys/leases/renew" {
      capabilities = ["update"]
    }

    path "sys/leases/revoke" {
      capabilities = ["update"]
    }

    path "auth/token/renew-self" {
      capabilities = ["update"]
    }
  EOT

  bob_policy = <<-EOT
    path "${var.db_mount_path}/creds/readOnly" {
      capabilities = ["read"]
    }

    path "${var.db_mount_path}/creds/readWrite" {
      capabilities = ["read"]
    }

    path "${local.transit_mount_path}/encrypt/${var.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/decrypt/${var.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/rewrap/${var.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/keys/${var.transit_key_name}/rotate" {
      capabilities = ["update"]
    }

    path "${local.kv_secret_mount}/data/${local.kv_secret_path}" {
      capabilities = ["create", "read", "update", "delete"]
    }

    path "${local.kv_secret_mount}/metadata/${local.kv_secret_path}" {
      capabilities = ["read", "delete"]
    }

    path "${local.kv_secret_mount}/undelete/${local.kv_secret_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_secret_mount}/destroy/${local.kv_secret_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_demo_mount}/data/${local.kv_demo_path}" {
      capabilities = ["create", "read", "update", "delete"]
    }

    path "${local.kv_demo_mount}/metadata/${local.kv_demo_path}" {
      capabilities = ["read", "delete"]
    }

    path "${local.kv_demo_mount}/undelete/${local.kv_demo_path}" {
      capabilities = ["update"]
    }

    path "${local.kv_demo_mount}/destroy/${local.kv_demo_path}" {
      capabilities = ["update"]
    }

    path "${var.aws_mount_path}/creds/${var.aws_role_name}" {
      capabilities = ["read"]
    }

    path "sys/leases/renew" {
      capabilities = ["update"]
    }

    path "sys/leases/revoke" {
      capabilities = ["update"]
    }

    path "auth/token/renew-self" {
      capabilities = ["update"]
    }
  EOT
}
