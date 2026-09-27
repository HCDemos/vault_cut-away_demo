output "demo_app_environment" {
  description = "Environment variables the Python demo app expects."
  value = {
    VAULT_ADDR              = var.vault_address
    VAULT_NAMESPACE         = var.vault_namespace
    VAULT_TRANSIT_KEY       = var.transit_key_name
    VAULT_DB_MOUNT          = var.db_mount_path
    VAULT_DB_READONLY_ROLE  = "readOnly"
    VAULT_DB_READWRITE_ROLE = "readWrite"
    VAULT_AWS_MOUNT         = var.aws_mount_path
    VAULT_AWS_ROLE          = var.aws_role_name
    VAULT_USERPASS_MOUNT    = var.userpass_mount
    PGHOST                  = aws_db_instance.demo.address
    PGPORT                  = aws_db_instance.demo.port
    PGDATABASE              = var.db_name
    PGSCHEMA                = var.db_schema
    PGTABLE                 = var.db_table
    PGSSLMODE               = "require"
  }
}

output "rds_endpoint" {
  description = "Postgres endpoint for the demo database."
  value       = aws_db_instance.demo.address
}

output "db_admin_username" {
  description = "PGUSER for prepare_pg.sh; never use this admin login in the demo app."
  value       = var.db_username
}
