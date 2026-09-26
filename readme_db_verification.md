# Verify Postgres/RDS Transit Encryption

This guide verifies that the demo app stores only Vault Transit ciphertext for sensitive customer fields.

## Table

The app reads and writes this configurable table, defaulting to `public.customers`:

```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'customers'
ORDER BY ordinal_position;
```

Expected sensitive columns:

- `address_cipher`
- `ssn_cipher`

## Verify Ciphertext

Run with a database account that can read the demo table:

```sql
SELECT
  id,
  name,
  age,
  left(address_cipher, 20) AS address_prefix,
  left(ssn_cipher, 20) AS ssn_prefix
FROM public.customers
ORDER BY id DESC
LIMIT 10;
```

Both prefixes should start with `vault:`.

## Count Valid Ciphertexts

```sql
SELECT
  count(*) AS total,
  count(*) FILTER (WHERE address_cipher LIKE 'vault:%') AS address_vault_like,
  count(*) FILTER (WHERE ssn_cipher LIKE 'vault:%') AS ssn_vault_like
FROM public.customers;
```

The two `*_vault_like` counts should equal `total`.

## App Verification

1. Log in as the read-write persona.
2. Add a customer on the Transit tab.
3. Confirm the table view shows ciphertext only.
4. Use the cleartext view link to decrypt at runtime through Vault Transit.
5. Open the Command Log tab and confirm the decrypt/encrypt commands are shown with sensitive values redacted.

The demo should never persist plaintext address or SSN values in Postgres.
