# Vault Developer Demo Workflow How-To

This guide maps the current demo from setup through the live walkthrough. It assumes the Vault engines, RDS/Postgres instance, AWS role, and Secrets Sync destinations already exist.

## 1. Pre-Demo Setup

Install app dependencies:

```bash
pip install -r requirements.txt
```

Export Vault connection details:

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

Export Postgres/RDS connection details. The app gets the username/password dynamically from Vault, but still needs the target host/database:

```bash
export PGHOST="<rds-endpoint>"
export PGPORT="5432"
export PGDATABASE="postgres"
export PGSSLMODE="require"
export PGSCHEMA="public"
export PGTABLE="customers"
```

The demo table should exist before the walkthrough:

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

The dynamic `readWrite` database role must also grant sequence privileges. Without this, inserts fail with `permission denied for sequence customers_id_seq` because `BIGSERIAL` calls `nextval()` on a separate sequence.

Add equivalent grants to the Vault database role creation statement:

```sql
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE ON TABLE public.customers TO "{{name}}";
GRANT USAGE, SELECT ON SEQUENCE public.customers_id_seq TO "{{name}}";
```

For a broader demo schema grant:

```sql
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
```

Seed data is optional:

```bash
export VAULT_TOKEN="<bob-or-admin-token-with-demo-permissions>"
python3 seed_customers.py --count 25
```

## 2. Demo Users And Vault Userpass

The app login form uses Vault `userpass`. When someone logs in as `alice` or `bob`, the app calls `auth/userpass/login/<username>`, receives a Vault client token, and stores that token server-side. The browser only gets a session reference, and the Session tab shows a masked token.

Create Vault userpass users named `alice` and `bob`, and attach the policies below. Also set `FLASK_SECRET_KEY` before starting the app:

```bash
export FLASK_SECRET_KEY="<random-demo-secret>"
```

The app tracks the token TTL returned by userpass login. On every protected page request and Vault operation, it renews the token automatically when the remaining TTL is at or below 50 percent of the original TTL. The header shows remaining TTL, whether the token is renewable, and the token policies.

Confirm the userpass mount issues renewable tokens with a useful TTL:

```bash
vault auth tune -default-lease-ttl=30m -max-lease-ttl=2h userpass/
```

Alice is intended to show read-only database access plus KV, AWS, and decrypt-only Transit behavior.

Bob is intended to show the full workflow, including database writes, Transit encryption, rewrap, and key rotation.

## 3. Required Alice Policy

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

## 4. Required Bob Policy

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

## 5. Start The App

```bash
python3 vault_demo_transit_app_batch.py
```

Open:

```text
http://localhost:5001
```

If that port is busy:

```bash
PORT=5002 python3 vault_demo_transit_app_batch.py
```

## 6. Login Flow

1. Open the app URL.
2. Log in as `alice` or `bob` using that user's Vault userpass password.
3. Open the Session tab.
4. Confirm the Vault address, namespace, userpass mount, masked token, remaining token TTL, token policies, Postgres target, and `psycopg` status.

Expected talking point: the app login is Vault auth. The app exchanges userpass credentials for a scoped Vault token, then uses that token for all demo operations.

## 7. Transit Demo

Use Bob for the full Transit workflow.

1. Open the Transit tab.
2. Add a customer with name, age, address, and SSN.
3. Click **Encrypt and Save**.
4. Explain that the app calls `transit/encrypt/customer-data` before writing to Postgres.
5. Show the table: `address_cipher` and `ssn_cipher` should contain `vault:` ciphertext.
6. Click **Show cleartext via batch decrypt**.
7. Explain that plaintext is displayed only after a runtime call to `transit/decrypt/customer-data`.
8. Click **Rotate Key**.
9. Click **Rewrap Batch**.
10. Explain that rewrap updates ciphertext to the latest key version without exposing plaintext.

Optional permission contrast:

1. Log out.
2. Log in as Alice.
3. Open Transit.
4. Alice can read/decrypt existing records if her DB and Transit decrypt policies are present.
5. Alice should fail if she tries to add a customer or rotate/rewrap because she lacks DB read-write and Transit write/rotate permissions.

## 8. Dynamic Database Credentials Demo

Use Alice first, then Bob.

Alice:

1. Log in as Alice.
2. Open the Database tab.
3. Select the `readOnly` role.
4. Click **Get Credentials and Query**.
5. Explain that Vault generated temporary Postgres credentials from `db/creds/readOnly`.
6. Show the masked dynamic DB user and lease TTL.
7. Click **Insert Sample with Read-Write Role**.
8. The write should fail because Alice does not have access to `db/creds/readWrite`.

Bob:

1. Log out and log in as Bob.
2. Open the Database tab.
3. Select `readOnly` and query.
4. Select `readWrite` and query.
5. Click **Insert Sample with Read-Write Role**.
6. Explain that Bob can request `db/creds/readWrite`, connect to RDS/Postgres, and insert an encrypted sample row.

## 9. KV v2 And Secrets Sync Demo

Both Alice and Bob can update the two KV v2 secrets used by Secrets Sync:

- `secret/circleci-demo/demo-secrets`
- `kv-v2/database/dev`

Walkthrough:

1. Open the KV v2 tab.
2. Choose `secret/circleci-demo/demo-secrets`.
3. Click **Load Secret**.
4. Enter a key and value, for example `demo_updated_by=alice` or `demo_updated_by=bob`.
5. Click **Write Secret Version**.
6. Explain that values are redacted in the UI and command log.
7. Show the current secret keys and version metadata.
8. Repeat for `kv-v2/database/dev`.
9. In the Vault UI, open Secrets Sync and show that the destination status updates after the source KV secret changes.

Optional version operations:

1. Click **Soft Delete Latest** to demonstrate KV v2 soft delete.
2. Use **Undelete** on the listed version to restore it.
3. Use **Destroy** only when you intentionally want to permanently remove that version.

## 10. Dynamic AWS Credentials Demo

Either Alice or Bob can perform this demo if the AWS policy is attached.

1. Open the AWS tab.
2. Click **Read AWS Credentials**.
3. Show the masked access key, lease ID, TTL, and renewable status.
4. Explain that the app does not call AWS; it only demonstrates Vault-generated AWS credentials and lease handling.
5. Click **Renew** to renew the lease if it is renewable.
6. Click **Revoke** to revoke the lease.

Expected talking point: credentials are dynamic, leased, and revocable. The secret key and session token are never shown in the UI.

## 11. Command Log Demo

1. Open the Command Log tab.
2. Show the CLI equivalent, HTTP API equivalent, actor, status, lease data, and elapsed time.
3. Confirm that sensitive values are redacted:
   - Vault tokens
   - DB passwords
   - KV values
   - AWS secret keys
   - AWS session tokens
   - Transit plaintext
4. Click **Clear Command Log** to clear only the current app session’s in-memory log.

When token TTL drops to 50 percent or lower, the app also logs:

```text
vault token renew
POST /v1/auth/token/renew-self
```

## 12. Suggested End-To-End Demo Order

1. Start as Alice.
2. Show Session tab and explain persona-to-token mapping.
3. Show Database read-only success.
4. Show Database read-write failure.
5. Show KV update for both Secrets Sync paths.
6. Show AWS credentials and lease metadata.
7. Open Command Log and point out redaction.
8. Log out.
9. Log in as Bob.
10. Add encrypted customer on Transit tab.
11. Show ciphertext in Postgres.
12. Show batch decrypt cleartext.
13. Rotate and batch rewrap.
14. Insert sample row with dynamic read-write DB credentials.
15. Finish on Command Log with all Vault calls visible and sanitized.

## 13. Common Failure Checks

- Vault userpass login fails: confirm the user exists at `auth/userpass/users/<username>`, the password is correct, and `VAULT_USERPASS_MOUNT` matches the auth mount.
- `VAULT_ADDR is not configured`: export `VAULT_ADDR`.
- `psycopg package is not installed`: run `pip install -r requirements.txt`.
- Database query fails: confirm `PGHOST`, `PGDATABASE`, network access, and Vault database role SQL grants.
- `permission denied for sequence customers_id_seq`: add `GRANT USAGE, SELECT` on the sequence to the Vault database `readWrite` role.
- KV update fails: confirm the policy uses KV v2 API paths, such as `secret/data/...` and `secret/metadata/...`.
- AWS lease renew/revoke fails: confirm the token has `sys/leases/renew` and `sys/leases/revoke` update capability.
