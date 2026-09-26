terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "~> 1.22"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

locals {
  name_prefix        = "dap-education"
  db_name            = "postgres"
  db_schema          = "public"
  db_table           = "customers"
  db_mount_path      = "db"
  transit_mount_path = "transit"
  transit_key_name   = "customer-data"
  kv_secret_mount    = "secret"
  kv_secret_path     = "circleci-demo/demo-secrets"
  kv_demo_mount      = "kv-v2"
  kv_demo_path       = "database/dev"
  userpass_mount     = "userpass"
  aws_mount_path     = "aws"
  aws_role_name      = "ec2-iam-user-role"

  common_tags = {
    name       = local.name_prefix
    owner      = var.prefix
    region     = var.hashi_region
    purpose    = var.purpose
    ttl        = var.ttl
    Department = var.department
    Billable   = var.billable
  }

  alice_policy = <<-EOT
    path "${local.db_mount_path}/creds/readOnly" {
      capabilities = ["read"]
    }

    path "${local.transit_mount_path}/decrypt/${local.transit_key_name}" {
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

    path "${local.aws_mount_path}/creds/${local.aws_role_name}" {
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
    path "${local.db_mount_path}/creds/readOnly" {
      capabilities = ["read"]
    }

    path "${local.db_mount_path}/creds/readWrite" {
      capabilities = ["read"]
    }

    path "${local.transit_mount_path}/encrypt/${local.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/decrypt/${local.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/rewrap/${local.transit_key_name}" {
      capabilities = ["update"]
    }

    path "${local.transit_mount_path}/keys/${local.transit_key_name}/rotate" {
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

    path "${local.aws_mount_path}/creds/${local.aws_role_name}" {
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

variable "vault_address" {
  description = "HCP Vault or Vault Enterprise address."
  type        = string
}

variable "vault_namespace" {
  description = "Vault namespace used by the demo app."
  type        = string
  default     = "admin"
}

variable "login_username" {
  description = "Vault username Terraform uses to authenticate."
  type        = string
}

variable "login_password" {
  description = "Vault password Terraform uses to authenticate."
  type        = string
  sensitive   = true
}

variable "alice_password" {
  description = "Vault userpass password for demo user alice."
  type        = string
  sensitive   = true
}

variable "bob_password" {
  description = "Vault userpass password for demo user bob."
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Master password for the RDS Postgres instance."
  type        = string
  sensitive   = true
}

variable "region" {
  description = "AWS region for the demo infrastructure."
  type        = string
}

variable "prefix" {
  description = "Owner or workspace prefix tag value."
  type        = string
  default     = "demo"
}

variable "hashi_region" {
  description = "Tag value used by the existing demo naming scheme."
  type        = string
  default     = "global"
}

variable "purpose" {
  description = "Purpose tag for created resources."
  type        = string
  default     = "vault-demo"
}

variable "ttl" {
  description = "TTL tag for created resources."
  type        = string
  default     = "24h"
}

variable "department" {
  description = "Department tag value."
  type        = string
  default     = "education"
}

variable "billable" {
  description = "Billable tag value."
  type        = string
  default     = "true"
}

provider "aws" {
  region = var.region
}

provider "vault" {
  address   = var.vault_address
  namespace = var.vault_namespace

  auth_login {
    path      = "auth/userpass/login/${var.login_username}"
    namespace = var.vault_namespace

    parameters = {
      password = var.login_password
    }
  }
}

provider "postgresql" {
  alias     = "bootstrap"
  host      = aws_db_instance.dap_education.address
  port      = aws_db_instance.dap_education.port
  database  = local.db_name
  username  = aws_db_instance.dap_education.username
  password  = var.db_password
  sslmode   = "require"
  superuser = false
}

data "aws_availability_zones" "available" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.77.0"

  name                 = "dap-vpc"
  cidr                 = "10.0.0.0/16"
  azs                  = data.aws_availability_zones.available.names
  public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = local.common_tags
}

resource "aws_db_subnet_group" "dap_edu" {
  name       = "dap-db-subnet-group"
  subnet_ids = module.vpc.public_subnets
  tags       = merge(local.common_tags, { name = "dap-dbsubnetgroup" })
}

resource "aws_security_group" "rds" {
  name   = "dap-rds"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { name = "dap-dbsecgroup" })
}

resource "aws_db_parameter_group" "dap_education" {
  name   = "dap-education"
  family = "postgres16"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }

  tags = merge(local.common_tags, { name = "dap-rdsdbparameters" })
}

resource "aws_db_instance" "dap_education" {
  identifier             = "dap-education"
  instance_class         = "db.t3.micro"
  allocated_storage      = 5
  engine                 = "postgres"
  engine_version         = "16.13"
  username               = "rootedu"
  password               = var.db_password
  db_name                = local.db_name
  db_subnet_group_name   = aws_db_subnet_group.dap_edu.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.dap_education.name
  publicly_accessible    = true
  skip_final_snapshot    = true
  apply_immediately      = true
  tags                   = local.common_tags
}

resource "postgresql_query" "demo_schema" {
  provider = postgresql.bootstrap
  database = local.db_name
  query    = <<-SQL
    CREATE TABLE IF NOT EXISTS public.customers (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      age INTEGER,
      address_cipher TEXT NOT NULL,
      ssn_cipher TEXT NOT NULL
    );
  SQL

  depends_on = [aws_db_instance.dap_education]
}

resource "vault_mount" "transit" {
  path = local.transit_mount_path
  type = "transit"
}

resource "vault_transit_secret_backend_key" "customer_data" {
  backend = vault_mount.transit.path
  name    = local.transit_key_name
}

resource "vault_mount" "secret" {
  path = local.kv_secret_mount
  type = "kv"

  options = {
    version = "2"
  }
}

resource "vault_mount" "kv_demo" {
  path = local.kv_demo_mount
  type = "kv"

  options = {
    version = "2"
  }
}

resource "vault_kv_secret_v2" "circleci_demo" {
  mount               = vault_mount.secret.path
  name                = local.kv_secret_path
  delete_all_versions = false
  data_json = jsonencode({
    username = "demo-user"
    password = "demo-password"
  })
}

resource "vault_kv_secret_v2" "database_dev" {
  mount               = vault_mount.kv_demo.path
  name                = local.kv_demo_path
  delete_all_versions = false
  data_json = jsonencode({
    host     = aws_db_instance.dap_education.address
    port     = tostring(aws_db_instance.dap_education.port)
    database = local.db_name
    schema   = local.db_schema
    table    = local.db_table
  })
}

resource "vault_database_secrets_mount" "db" {
  path = local.db_mount_path

  postgresql {
    name              = "postgres"
    username          = aws_db_instance.dap_education.username
    password          = var.db_password
    connection_url    = "postgresql://{{username}}:{{password}}@${aws_db_instance.dap_education.address}:${aws_db_instance.dap_education.port}/${local.db_name}?sslmode=require"
    verify_connection = true
    allowed_roles     = ["readOnly", "readWrite"]
  }

  depends_on = [aws_db_instance.dap_education]
}

resource "vault_database_secret_backend_role" "read_only" {
  name        = "readOnly"
  backend     = vault_database_secrets_mount.db.path
  db_name     = vault_database_secrets_mount.db.postgresql[0].name
  default_ttl = 950
  max_ttl     = 2700
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT CONNECT ON DATABASE ${local.db_name} TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA ${local.db_schema} TO \"{{name}}\";",
    "GRANT SELECT ON ALL TABLES IN SCHEMA ${local.db_schema} TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA ${local.db_schema} GRANT SELECT ON TABLES TO \"{{name}}\";"
  ]

  depends_on = [postgresql_query.demo_schema]
}

resource "vault_database_secret_backend_role" "read_write" {
  name        = "readWrite"
  backend     = vault_database_secrets_mount.db.path
  db_name     = vault_database_secrets_mount.db.postgresql[0].name
  default_ttl = 600
  max_ttl     = 1200
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT CONNECT ON DATABASE ${local.db_name} TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA ${local.db_schema} TO \"{{name}}\";",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${local.db_schema} TO \"{{name}}\";",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${local.db_schema} TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA ${local.db_schema} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA ${local.db_schema} GRANT USAGE, SELECT ON SEQUENCES TO \"{{name}}\";"
  ]

  depends_on = [postgresql_query.demo_schema]
}

resource "vault_policy" "alice" {
  name   = "demo-alice"
  policy = local.alice_policy
}

resource "vault_policy" "bob" {
  name   = "demo-bob"
  policy = local.bob_policy
}

resource "vault_generic_endpoint" "alice_user" {
  path                 = "auth/${local.userpass_mount}/users/alice"
  disable_read         = true
  ignore_absent_fields = true
  data_json = jsonencode({
    password      = var.alice_password
    policies      = vault_policy.alice.name
    token_ttl     = 1800
    token_max_ttl = 7200
  })
}

resource "vault_generic_endpoint" "bob_user" {
  path                 = "auth/${local.userpass_mount}/users/bob"
  disable_read         = true
  ignore_absent_fields = true
  data_json = jsonencode({
    password      = var.bob_password
    policies      = vault_policy.bob.name
    token_ttl     = 1800
    token_max_ttl = 7200
  })
}

output "demo_app_environment" {
  description = "Environment variables the Python demo app expects."
  value = {
    VAULT_ADDR              = var.vault_address
    VAULT_NAMESPACE         = var.vault_namespace
    VAULT_TRANSIT_KEY       = local.transit_key_name
    VAULT_DB_MOUNT          = local.db_mount_path
    VAULT_DB_READONLY_ROLE  = "readOnly"
    VAULT_DB_READWRITE_ROLE = "readWrite"
    VAULT_AWS_MOUNT         = local.aws_mount_path
    VAULT_AWS_ROLE          = local.aws_role_name
    VAULT_USERPASS_MOUNT    = local.userpass_mount
    PGHOST                  = aws_db_instance.dap_education.address
    PGPORT                  = aws_db_instance.dap_education.port
    PGDATABASE              = local.db_name
    PGSCHEMA                = local.db_schema
    PGTABLE                 = local.db_table
    PGSSLMODE               = "require"
  }
}

output "rds_endpoint" {
  description = "Postgres endpoint for the demo database."
  value       = aws_db_instance.dap_education.address
}
