# Terraform >= 1.7 is required for these mocked, offline plan tests.
mock_provider "aws" {}
mock_provider "vault" {}

override_data {
  target = data.aws_availability_zones.available
  values = { names = ["us-east-1a", "us-east-1b"] }
}

variables {
  region           = "us-east-1"
  vault_address    = "https://vault.example.invalid:8200"
  login_username   = "test-admin"
  login_password   = "test-only-placeholder"
  alice_password   = "test-only-placeholder"
  bob_password     = "test-only-placeholder"
  db_password      = "test-only-placeholder"
  db_allowed_cidrs = ["10.1.2.3/32"]
  db_name          = "sampledb"
  db_schema        = "sample_schema"
  db_table         = "sample_customers"
  db_mount_path    = "sample-db"
  transit_key_name = "sample-key"
}

run "private_defaults_and_shared_settings" {
  command = plan

  assert {
    condition     = !aws_db_instance.demo.publicly_accessible && aws_db_instance.demo.storage_encrypted
    error_message = "RDS must default to private access and encrypted storage."
  }
  assert {
    condition     = alltrue([for rule in aws_security_group.rds.ingress : rule.from_port == 5432 && rule.to_port == 5432 && rule.cidr_blocks == tolist(["10.1.2.3/32"])])
    error_message = "Postgres ingress must use only the configured client CIDRs."
  }
  assert {
    condition     = anytrue([for parameter in aws_db_parameter_group.demo.parameter : parameter.name == "rds.force_ssl" && parameter.value == "1"])
    error_message = "Postgres must enforce TLS."
  }
  assert {
    condition     = aws_db_instance.demo.db_name == "sampledb" && output.demo_app_environment.PGDATABASE == "sampledb" && output.demo_app_environment.PGSCHEMA == "sample_schema" && output.demo_app_environment.PGTABLE == "sample_customers"
    error_message = "Custom database settings must propagate to RDS and the app environment."
  }
  assert {
    condition     = contains(vault_database_secret_backend_role.read_only.creation_statements, "GRANT CONNECT ON DATABASE \"sampledb\" TO \"{{name}}\";") && strcontains(vault_policy.bob.policy, "sample-db/creds/readWrite") && output.demo_app_environment.VAULT_DB_MOUNT == "sample-db" && vault_transit_secret_backend_key.customer_data.name == output.demo_app_environment.VAULT_TRANSIT_KEY
    error_message = "Vault grants, policies, and app paths must follow customized settings."
  }
}

run "public_access_requires_opt_in" {
  command = plan
  variables {
    db_publicly_accessible = true
    db_allowed_cidrs       = ["192.0.2.10/32"]
  }
  assert {
    condition     = aws_db_instance.demo.publicly_accessible && alltrue([for rule in aws_security_group.rds.ingress : rule.cidr_blocks == tolist(["192.0.2.10/32"])])
    error_message = "Public opt-in must retain the explicit ingress allowlist."
  }
}

run "reject_unrestricted_ingress" {
  command = plan
  variables { db_allowed_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.db_allowed_cidrs]
}

run "reject_empty_ingress" {
  command = plan
  variables { db_allowed_cidrs = [] }
  expect_failures = [var.db_allowed_cidrs]
}
