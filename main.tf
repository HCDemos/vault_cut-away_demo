locals {
  transit_mount_path = "transit"
  kv_secret_mount    = "secret"
  kv_secret_path     = "demo/app-secrets"
  kv_demo_mount      = "kv-v2"
  kv_demo_path       = "database/dev"

  common_tags = merge(var.tags, { Project = var.name_prefix })
}

provider "aws" {
  region = var.region
}

provider "vault" {
  address   = var.vault_address
  namespace = var.vault_namespace

  auth_login {
    path      = "auth/${var.userpass_mount}/login/${var.login_username}"
    namespace = var.vault_namespace

    parameters = {
      password = var.login_password
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.21.0"

  name                 = "${var.name_prefix}-vpc"
  cidr                 = var.vpc_cidr
  azs                  = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnets       = [for index in range(2) : cidrsubnet(var.vpc_cidr, 4, index + 4)]
  private_subnets      = [for index in range(2) : cidrsubnet(var.vpc_cidr, 4, index)]
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = local.common_tags
}

resource "aws_db_subnet_group" "demo" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.db_publicly_accessible ? module.vpc.public_subnets : module.vpc.private_subnets
  tags       = merge(local.common_tags, { name = "${var.name_prefix}-db" })
}

resource "aws_security_group" "rds" {
  name   = "${var.name_prefix}-db"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.db_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { name = "${var.name_prefix}-db" })
}

resource "aws_db_parameter_group" "demo" {
  name   = var.name_prefix
  family = "postgres${split(".", var.db_engine_version)[0]}"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = merge(local.common_tags, { name = "${var.name_prefix}-postgres" })
}

resource "aws_db_instance" "demo" {
  identifier             = var.name_prefix
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage
  storage_type           = "gp3"
  storage_encrypted      = true
  engine                 = "postgres"
  engine_version         = var.db_engine_version
  username               = var.db_username
  password               = var.db_password
  db_name                = var.db_name
  db_subnet_group_name   = aws_db_subnet_group.demo.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.demo.name
  publicly_accessible    = var.db_publicly_accessible
  skip_final_snapshot    = true
  apply_immediately      = true
  tags                   = local.common_tags
}

resource "vault_mount" "transit" {
  path = local.transit_mount_path
  type = "transit"
}

resource "vault_transit_secret_backend_key" "customer_data" {
  backend = vault_mount.transit.path
  name    = var.transit_key_name
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

resource "vault_kv_secret_v2" "app_demo" {
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
    host     = aws_db_instance.demo.address
    port     = tostring(aws_db_instance.demo.port)
    database = var.db_name
    schema   = var.db_schema
    table    = var.db_table
  })
}

resource "vault_database_secrets_mount" "db" {
  path = var.db_mount_path

  postgresql {
    name              = "postgres"
    username          = aws_db_instance.demo.username
    password          = var.db_password
    connection_url    = "postgresql://{{username}}:{{password}}@${aws_db_instance.demo.address}:${aws_db_instance.demo.port}/${var.db_name}?sslmode=require"
    verify_connection = true
    allowed_roles     = ["readOnly", "readWrite"]
  }

  depends_on = [aws_db_instance.demo]
}

resource "vault_database_secret_backend_role" "read_only" {
  name        = "readOnly"
  backend     = vault_database_secrets_mount.db.path
  db_name     = vault_database_secrets_mount.db.postgresql[0].name
  default_ttl = 950
  max_ttl     = 2700
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT CONNECT ON DATABASE \"${var.db_name}\" TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA \"${var.db_schema}\" TO \"{{name}}\";",
    "GRANT SELECT ON ALL TABLES IN SCHEMA \"${var.db_schema}\" TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA \"${var.db_schema}\" GRANT SELECT ON TABLES TO \"{{name}}\";"
  ]
}

resource "vault_database_secret_backend_role" "read_write" {
  name        = "readWrite"
  backend     = vault_database_secrets_mount.db.path
  db_name     = vault_database_secrets_mount.db.postgresql[0].name
  default_ttl = 600
  max_ttl     = 1200
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT CONNECT ON DATABASE \"${var.db_name}\" TO \"{{name}}\";",
    "GRANT USAGE ON SCHEMA \"${var.db_schema}\" TO \"{{name}}\";",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA \"${var.db_schema}\" TO \"{{name}}\";",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA \"${var.db_schema}\" TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA \"${var.db_schema}\" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA \"${var.db_schema}\" GRANT USAGE, SELECT ON SEQUENCES TO \"{{name}}\";"
  ]
}

resource "vault_policy" "alice" {
  name   = "${var.name_prefix}-alice"
  policy = local.alice_policy
}

resource "vault_policy" "bob" {
  name   = "${var.name_prefix}-bob"
  policy = local.bob_policy
}

resource "vault_generic_endpoint" "alice_user" {
  path                 = "auth/${var.userpass_mount}/users/alice"
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
  path                 = "auth/${var.userpass_mount}/users/bob"
  disable_read         = true
  ignore_absent_fields = true
  data_json = jsonencode({
    password      = var.bob_password
    policies      = vault_policy.bob.name
    token_ttl     = 1800
    token_max_ttl = 7200
  })
}
