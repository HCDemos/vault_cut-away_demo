# Shared demo configuration. Copy terraform.tfvars.example to terraform.tfvars.
# Passwords should come from TF_VAR_* environment variables or your secret store.
# Terraform state contains secrets even when inputs are marked sensitive.
# Outputs in outputs.tf export matching app/seed/prepare_pg.sh environment values.

# Existing Vault: userpass must already be enabled. This stack creates the demo
# users and secrets engines, but does not provision Vault or AWS dynamic roles.
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

variable "db_allowed_cidrs" {
  description = "IPv4 CIDRs allowed to reach Postgres, including the app, database preparation client, and Vault. Use narrow ranges reachable through your network."
  type        = list(string)

  validation {
    condition = length(var.db_allowed_cidrs) > 0 && alltrue([
      for cidr in var.db_allowed_cidrs : can(cidrnetmask(cidr)) && !endswith(cidr, "/0")
    ])
    error_message = "Provide at least one valid IPv4 CIDR; unrestricted /0 access is not allowed."
  }
}

variable "db_publicly_accessible" {
  description = "Opt in to a public RDS endpoint for a demo without private connectivity. Access is still restricted by db_allowed_cidrs."
  type        = bool
  default     = false
}

# Changing names on existing resources may cause replacement.
variable "name_prefix" {
  description = "Prefix for AWS resource names and Vault policies. Use a unique prefix per deployment."
  type        = string
  default     = "vault-demo"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,30}[a-z0-9]$", var.name_prefix)) && !strcontains(var.name_prefix, "--")
    error_message = "Use 2-32 lowercase letters, digits, or hyphens, starting with a letter and ending with a letter or digit; no double hyphens."
  }
}

variable "tags" {
  description = "Optional AWS tags, such as Owner, Purpose, or CostCenter. Tags do not implement automatic cleanup."
  type        = map(string)
  default     = {}
}

# Shared database identifiers: lowercase names avoid SQL identifier case differences.
variable "db_name" {
  description = "Database created in RDS, used in Vault connection URLs and grants, and exported as PGDATABASE."
  type        = string
  default     = "postgres"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.db_name))
    error_message = "Use a lowercase SQL identifier starting with a letter, at most 63 characters."
  }
}

# Shared database identifiers: lowercase names avoid SQL identifier case differences.
variable "db_schema" {
  description = "Schema prepared by prepare_pg.sh, granted by Vault roles, and exported as PGSCHEMA."
  type        = string
  default     = "public"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.db_schema))
    error_message = "Use a lowercase SQL identifier starting with a letter, at most 63 characters."
  }
}

# Shared database identifiers: lowercase names avoid SQL identifier case differences.
variable "db_table" {
  description = "Table prepared by prepare_pg.sh and exported as PGTABLE. Vault role grants cover the entire demo schema."
  type        = string
  default     = "customers"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.db_table))
    error_message = "Use a lowercase SQL identifier starting with a letter, at most 63 characters."
  }
}

# Shared database identifiers: lowercase names avoid SQL identifier case differences.
variable "db_username" {
  description = "RDS administrator used by Vault and prepare_pg.sh; the app uses dynamic credentials instead."
  type        = string
  default     = "demo_admin"
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,62}$", var.db_username))
    error_message = "Use a lowercase SQL identifier starting with a letter, at most 63 characters."
  }
}

variable "db_instance_class" {
  description = "RDS instance size; availability and cost depend on the AWS region."
  type        = string
  default     = "db.t3.micro"
}

variable "db_engine_version" {
  description = "PostgreSQL version available in your region; parameter group family follows its major version."
  type        = string
  default     = "16.13"
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+$", var.db_engine_version))
    error_message = "Specify a PostgreSQL major.minor version, such as 16.13."
  }
}

variable "db_allocated_storage" {
  description = "Initial gp3 storage in GiB."
  type        = number
  default     = 20
  validation {
    condition     = var.db_allocated_storage >= 20 && floor(var.db_allocated_storage) == var.db_allocated_storage
    error_message = "Allocate at least 20 GiB, using a whole number."
  }
}

# Choose a range that does not overlap your Vault/VPN networks. This stack creates no VPN, peering, or NAT.
variable "vpc_cidr" {
  description = "VPC IPv4 CIDR. Two private and two public subnets are derived with four extra prefix bits."
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && can(cidrsubnet(var.vpc_cidr, 4, 5)) && try(tonumber(split("/", var.vpc_cidr)[1]) >= 16 && tonumber(split("/", var.vpc_cidr)[1]) <= 24, false)
    error_message = "Use a valid IPv4 VPC CIDR with a prefix between /16 and /24."
  }
}

variable "db_mount_path" {
  description = "Vault database secrets mount; exported as VAULT_DB_MOUNT."
  type        = string
  default     = "db"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.db_mount_path))
    error_message = "Use a single path segment containing letters, digits, underscores, or hyphens."
  }
}

variable "transit_key_name" {
  description = "Key at the fixed transit/ mount; exported as VAULT_TRANSIT_KEY."
  type        = string
  default     = "customer-data"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.transit_key_name))
    error_message = "Use a single path segment containing letters, digits, underscores, or hyphens."
  }
}

variable "userpass_mount" {
  description = "Existing userpass mount used by Terraform login and demo users; exported as VAULT_USERPASS_MOUNT."
  type        = string
  default     = "userpass"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.userpass_mount))
    error_message = "Use a single path segment containing letters, digits, underscores, or hyphens."
  }
}

variable "aws_mount_path" {
  description = "Existing AWS secrets mount; exported as VAULT_AWS_MOUNT. This stack only creates policy access to it."
  type        = string
  default     = "aws"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.aws_mount_path))
    error_message = "Use a single path segment containing letters, digits, underscores, or hyphens."
  }
}

variable "aws_role_name" {
  description = "Existing AWS dynamic credentials role; exported as VAULT_AWS_ROLE."
  type        = string
  default     = "ec2-iam-user-role"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.aws_role_name))
    error_message = "Use a single path segment containing letters, digits, underscores, or hyphens."
  }
}

# Intentionally fixed demo conventions: alice/bob users, readOnly/readWrite DB
# roles, transit/ mount, and the two KV targets shown in the UI. Changing these
# requires coordinated UI/policy changes, rather than just a Terraform override.
