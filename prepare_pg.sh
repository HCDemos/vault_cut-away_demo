#!/usr/bin/env bash
# Prepare an existing PostgreSQL/RDS database for the Vault demo.
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'HELP'
Usage: ./prepare_pg.sh

Required: PGHOST, PGUSER (database owner/admin).
Optional: PGPORT=5432 PGDATABASE=postgres PGSSLMODE=require
          PGSCHEMA=public PGTABLE=customers PGCONNECT_TIMEOUT=10
          VAULT_DB_USER=<existing database login used by Vault>

Use ~/.pgpass or PGPASSWORD for authentication; otherwise psql prompts.
Run as the database login configured in Vault, or set VAULT_DB_USER to
grant that existing login permission to grant demo access to dynamic users.
The Vault login must already be able to create roles (CREATEROLE).

Creates the schema/table if absent and adds created_at to older demo tables.
Existing customer rows are preserved. All changes run in one transaction.
Does not provision a server/database, configure Vault, or seed customer data.
HELP
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo 'Unexpected arguments. Use --help for usage.' >&2
  exit 1
fi
command -v psql >/dev/null 2>&1 || { echo 'Install the PostgreSQL psql client first.' >&2; exit 1; }
export PGHOST="${PGHOST:-${RDS_HOST:-}}"
export PGPORT="${PGPORT:-${RDS_PORT:-5432}}"
export PGDATABASE="${PGDATABASE:-${RDS_DATABASE:-postgres}}"
export PGSSLMODE="${PGSSLMODE:-${RDS_SSLMODE:-require}}"
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-10}"
: "${PGHOST:?Set PGHOST to your PostgreSQL/RDS endpoint}"
: "${PGUSER:?Set PGUSER to your database owner/admin login}"
schema="${PGSCHEMA:-${RDS_SCHEMA:-public}}"
table="${PGTABLE:-${RDS_TABLE:-customers}}"
# Match the identifiers supported by the app, also avoiding PG truncation.
for identifier in "$schema" "$table"; do
  if [[ ! "$identifier" =~ ^[A-Za-z_][A-Za-z0-9_]*$ || ${#identifier} -gt 63 ]]; then
    echo 'PGSCHEMA and PGTABLE must be SQL identifiers of at most 63 characters.' >&2
    exit 1
  fi
done

psql -X --set=ON_ERROR_STOP=1 --single-transaction \
  --set=demo_schema="$schema" --set=demo_table="$table" \
  --set=vault_db_user="${VAULT_DB_USER:-$PGUSER}" <<'SQL'
CREATE SCHEMA IF NOT EXISTS :"demo_schema";
CREATE TABLE IF NOT EXISTS :"demo_schema".:"demo_table" (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  age INTEGER,
  address_cipher TEXT NOT NULL,
  ssn_cipher TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE :"demo_schema".:"demo_table"
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Fail before committing if an older table lacks the app's required columns.
SELECT id, name, age, address_cipher, ssn_cipher, created_at
FROM :"demo_schema".:"demo_table" LIMIT 0;

-- Vault needs grant options when its connection login differs from the owner.
SELECT format('GRANT CONNECT ON DATABASE %I TO %I WITH GRANT OPTION',
              current_database(), :'vault_db_user') \gexec
GRANT USAGE ON SCHEMA :"demo_schema" TO :"vault_db_user" WITH GRANT OPTION;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE :"demo_schema".:"demo_table"
  TO :"vault_db_user" WITH GRANT OPTION;

-- Resolve the actual sequence name rather than assuming customers_id_seq.
SELECT pg_get_serial_sequence(format('%I.%I', :'demo_schema', :'demo_table'), 'id') IS NOT NULL AS has_sequence \gset
\if :has_sequence
SELECT format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I WITH GRANT OPTION',
              pg_get_serial_sequence(format('%I.%I', :'demo_schema', :'demo_table'), 'id'),
              :'vault_db_user') \gexec
\else
\echo 'ERROR: Existing table id has no serial/identity sequence. Review its schema.'
-- Force rollback of the entire setup.
SELECT 1 / 0;
\endif
SQL

printf 'Prepared %s.%s in database %s. Existing rows preserved.\n' "$schema" "$table" "$PGDATABASE"
printf '%s\n' 'Request fresh Vault database credentials before using the app.' \
  'To seed encrypted data: python3 seed_customers.py --count 100 (requires VAULT_ADDR and VAULT_TOKEN).'
