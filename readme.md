# Vault Cut-away Demo

<img src="docs/images/transit-batch-rewrap.png" alt="Transit batch rewrap demo showing Vault commands, key operations, and encrypted customer data in Postgres" width="700">

This Flask app demonstrates several common Vault developer workflows in one UI:

- Transit encryption for customer data
- KV v2 secret CRUD and version operations
- Dynamic Postgres/RDS credentials
- Dynamic AWS credentials and leases
- A sanitized command log showing the Vault CLI and HTTP API calls used by the app

The app logs into Vault with the `userpass` auth method for `alice` or `bob`, then stores the returned client token server-side. Tokens and generated secrets are not rendered into the UI.

For the beginning-to-end presenter workflow, see [demo_workflow_howto.md](demo_workflow_howto.md).

## Requirements

```bash
pip install -r requirements.txt
```

The Postgres/RDS instance and Vault secrets engines are expected to be provisioned before running the app.

## Vault Paths

Defaults are configurable with environment variables:

```bash
export VAULT_ADDR="https://your-vault.example:8200"
export VAULT_NAMESPACE="admin"
export VAULT_TRANSIT_KEY="customer-data"
export VAULT_DB_MOUNT="db"
export VAULT_DB_READONLY_ROLE="readOnly"
export VAULT_DB_READWRITE_ROLE="readWrite"
export VAULT_AWS_MOUNT="aws"
export VAULT_AWS_ROLE="ec2-iam-user-role"
export VAULT_USERPASS_MOUNT="userpass"
```

The KV tab updates these Secrets Sync KV v2 secrets:

- `secret/circleci-demo/demo-secrets`
- `kv-v2/database/dev`

## Demo Users

Create Vault userpass users named `alice` and `bob`, then attach the policies shown below to those users. The app login form sends the entered username/password to `auth/userpass/login/<username>` and stores the returned client token server-side.

If your userpass auth method is mounted somewhere else, set `VAULT_USERPASS_MOUNT`.

The app tracks the returned token TTL and automatically renews the token when remaining TTL reaches 50 percent of the original TTL. The page header shows remaining TTL, renewable status, and token policies.

## Postgres/RDS Configuration

Prepare an existing database with the PostgreSQL `psql` client installed:

```bash
export PGHOST="<rds-endpoint>"
export PGUSER="rootedu" # Database owner/admin; use your actual login.
export PGDATABASE="postgres"
export PGSSLMODE="require"
./prepare_pg.sh
```

The script prompts for the database password unless supplied through `.pgpass`
or `PGPASSWORD`. It creates the schema and table, adds `created_at` to older demo
tables, and preserves existing rows. Run it with the database login configured
in Vault. If Vault uses a different existing login, set `VAULT_DB_USER` to that
login so it receives grant options on the demo objects. That login must already
have permission to create database roles. Run `./prepare_pg.sh --help` for options.

This prepares the database objects only; the database/server and Vault database
connection, roles, and Transit key must already exist. The Vault role statements
below must grant table and sequence access. Request fresh dynamic credentials
after setup (log out and back into the app if credentials are cached), then use
the Seed Data instructions below to add encrypted customers.

```bash
export PGHOST="<rds-endpoint>"
export PGPORT="5432"
export PGDATABASE="postgres"
export PGSSLMODE="require"
export PGSCHEMA="public"
export PGTABLE="customers"
```

The app expects this table shape:

```sql
CREATE TABLE IF NOT EXISTS public.customers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  age INTEGER,
  address_cipher TEXT NOT NULL,
  ssn_cipher TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The Vault database `readWrite` role must grant privileges on both the table and the sequence behind `BIGSERIAL`. In the role creation statement, include grants like:

```sql
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE ON TABLE public.customers TO "{{name}}";
GRANT USAGE, SELECT ON SEQUENCE public.customers_id_seq TO "{{name}}";
```

Or, for a broader demo schema grant:

```sql
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
```

## Run

```bash
python3 vault_demo_transit_app_batch.py
```

Open http://localhost:5001.

## Seed Data

Run `./prepare_pg.sh` first, then confirm the deployed Vault database
`readWrite` role includes the sequence grant shown above. The preparation
script grants Vault's database connection login permission to grant access;
the role's `creation_statements` must pass that access to each generated user.

Use a Vault token that can read the read-write database role and encrypt with Transit:

```bash
export VAULT_TOKEN="<bob-or-admin-token-with-demo-permissions>"
python3 seed_customers.py --count 100
```

If the dynamic database role has DDL permission and you want the script to create the table:

```bash
python3 seed_customers.py --count 100 --create-schema
```

### Troubleshooting seeding and viewing rows

- **Vault `permission denied` on `transit/encrypt/customer-data`:** the seed
  script uses the exported `VAULT_TOKEN`, while the app obtains its own token
  through userpass login. Check the seed token in the same namespace as the
  demo engines:

  ```bash
  export VAULT_NAMESPACE="admin" # Change if your demo uses another namespace.
  vault token capabilities transit/encrypt/customer-data # Needs update
  vault token capabilities db/creds/readWrite             # Needs read
  vault token capabilities db/creds/readOnly              # Needs read for app browsing
  ```

  These paths assume the default mount, key, and role names. Adjust them if
  you override the corresponding environment variables. Ensure Bob's attached
  policy includes the Read-write persona rules below. The existing demo uses
  `bob-policy`; this repository's Terraform creates a policy named `demo-bob`.
  Update the policy actually attached to your deployed user, preserving its
  other rules.

- **`Postgres denied access to the table id sequence`:** using a Vault admin
  token, append the following to the existing `creation_statements` on
  `db/roles/readWrite`, preserving its other statements and settings:

  ```sql
  GRANT USAGE, SELECT ON SEQUENCE public.customers_id_seq TO "{{name}}";
  ```

  Adjust the sequence name for a custom table. This is a Vault **database role**
  change, not a change to `bob-policy`. Retry the seed script using Bob's token;
  each run requests fresh database credentials and receives the updated grants.

- **Confirm success:** start with `python3 seed_customers.py --count 1`, then
  run with `--count 100`. Each run adds rows; it does not replace existing data.
  For the default table, verify with
  `psql -c 'SELECT count(*) FROM public.customers;'` using your database admin
  connection. Start the app from a terminal with the same `PGHOST`,
  `PGDATABASE`, `PGSCHEMA`, and `PGTABLE` settings. The Transit page reads with
  the `readOnly` database role even when logged in as Bob. Log out and back in
  to obtain fresh credentials if the app cached credentials issued before the
  grants changed.

The Python 3.9 LibreSSL/urllib3 warning is separate from Vault authorization
and PostgreSQL permission errors; changing database grants does not address
that warning.

## Expected Vault Capabilities

Read-only persona:

```hcl
path "db/creds/readOnly" {
  capabilities = ["read"]
}

path "transit/decrypt/customer-data" {
  capabilities = ["update"]
}

path "secret/data/circleci-demo/demo-secrets" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/circleci-demo/demo-secrets" {
  capabilities = ["read", "delete"]
}

path "secret/undelete/circleci-demo/demo-secrets" {
  capabilities = ["update"]
}

path "secret/destroy/circleci-demo/demo-secrets" {
  capabilities = ["update"]
}

path "kv-v2/data/database/dev" {
  capabilities = ["create", "read", "update", "delete"]
}

path "kv-v2/metadata/database/dev" {
  capabilities = ["read", "delete"]
}

path "kv-v2/undelete/database/dev" {
  capabilities = ["update"]
}

path "kv-v2/destroy/database/dev" {
  capabilities = ["update"]
}

path "aws/creds/ec2-iam-user-role" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}
```

Read-write persona:

```hcl
path "db/creds/readOnly" {
  capabilities = ["read"]
}

path "db/creds/readWrite" {
  capabilities = ["read"]
}

path "transit/encrypt/customer-data" {
  capabilities = ["update"]
}

path "transit/decrypt/customer-data" {
  capabilities = ["update"]
}

path "transit/rewrap/customer-data" {
  capabilities = ["update"]
}

path "transit/keys/customer-data/rotate" {
  capabilities = ["update"]
}

path "secret/data/circleci-demo/demo-secrets" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/circleci-demo/demo-secrets" {
  capabilities = ["read", "delete"]
}

path "secret/undelete/circleci-demo/demo-secrets" {
  capabilities = ["update"]
}

path "secret/destroy/circleci-demo/demo-secrets" {
  capabilities = ["update"]
}

path "kv-v2/data/database/dev" {
  capabilities = ["create", "read", "update", "delete"]
}

path "kv-v2/metadata/database/dev" {
  capabilities = ["read", "delete"]
}

path "kv-v2/undelete/database/dev" {
  capabilities = ["update"]
}

path "kv-v2/destroy/database/dev" {
  capabilities = ["update"]
}

path "aws/creds/ec2-iam-user-role" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}
```

Adjust paths if your mounts, roles, or namespace differ.

## Verification

- Transit tab: insert a customer and confirm `address_cipher` and `ssn_cipher` start with `vault:`.
- Database tab: use the read-only role to query and the read-write role to insert a sample record.
- KV v2 tab: write a key, view version metadata, soft delete, undelete, and destroy a selected version.
- AWS tab: request credentials and confirm only masked access key and lease metadata are shown.
- Command Log tab: confirm commands show CLI/API equivalents without full tokens, passwords, KV values, AWS secret keys, or session tokens.

## Security Notes

Keep credentials in environment variables or local credential stores. The
project `.gitignore` excludes local databases, environment files, Terraform
state/variable files, keys, and caches. Without `FLASK_SECRET_KEY`, the app
generates a random session-signing key at startup; restarting requires logging
in again.

This is a demo application, not production scaffolding. Use proper authentication, CSRF protection, server-side sessions, TLS, least-privilege Vault policies, and a production WSGI server for real applications.
