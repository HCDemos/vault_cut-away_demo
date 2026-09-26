"""
Seed the Vault developer demo Postgres table with fake encrypted customers.

The script gets dynamic read-write database credentials from Vault, encrypts
customer fields with Vault Transit, and inserts ciphertext into Postgres/RDS.
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import re
from typing import Optional, Tuple

import hvac
from faker import Faker

try:
    import psycopg
    from psycopg import sql
except ImportError as exc:  # pragma: no cover
    raise SystemExit("psycopg is required. Install with: pip install psycopg[binary]") from exc


VAULT_ADDR: Optional[str] = os.environ.get("VAULT_ADDR")
VAULT_NAMESPACE: str = os.environ.get("VAULT_NAMESPACE", "admin")
VAULT_TOKEN: Optional[str] = os.environ.get("VAULT_TOKEN")
TRANSIT_KEY: str = os.environ.get("VAULT_TRANSIT_KEY", "customer-data")
DB_MOUNT: str = os.environ.get("VAULT_DB_MOUNT", "db").strip("/")
DB_READWRITE_ROLE: str = os.environ.get("VAULT_DB_READWRITE_ROLE", "readWrite")

PG_HOST: str = os.environ.get("PGHOST") or os.environ.get("RDS_HOST", "")
PG_PORT: int = int(os.environ.get("PGPORT") or os.environ.get("RDS_PORT", "5432"))
PG_DATABASE: str = os.environ.get("PGDATABASE") or os.environ.get("RDS_DATABASE", "postgres")
PG_SSLMODE: str = os.environ.get("PGSSLMODE") or os.environ.get("RDS_SSLMODE", "require")
PG_SCHEMA: str = os.environ.get("PGSCHEMA") or os.environ.get("RDS_SCHEMA", "public")
PG_TABLE: str = os.environ.get("PGTABLE") or os.environ.get("RDS_TABLE", "customers")

if not VAULT_ADDR or not VAULT_TOKEN:
    raise SystemExit("VAULT_ADDR and VAULT_TOKEN must be set.")
if not PG_HOST:
    raise SystemExit("PGHOST or RDS_HOST must be set.")

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN, namespace=VAULT_NAMESPACE)


def require_identifier(value: str, fallback: str) -> str:
    candidate = (value or fallback).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
        raise SystemExit(f"Invalid SQL identifier: {candidate!r}")
    return candidate


def customer_table() -> Tuple[str, str]:
    return require_identifier(PG_SCHEMA, "public"), require_identifier(PG_TABLE, "customers")


def transit_encrypt(plaintext: str) -> str:
    b64_plain = base64.b64encode((plaintext or "").encode("utf-8")).decode("utf-8")
    response = client.secrets.transit.encrypt_data(name=TRANSIT_KEY, plaintext=b64_plain)
    return response["data"]["ciphertext"]


def dynamic_db_creds() -> Tuple[str, str]:
    response = client.secrets.database.generate_credentials(
        name=DB_READWRITE_ROLE,
        mount_point=DB_MOUNT,
    )
    data = response.get("data", {})
    return data["username"], data["password"]


def connect_dynamic():
    username, password = dynamic_db_creds()
    return psycopg.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=username,
        password=password,
        sslmode=PG_SSLMODE,
    )


def ensure_schema(conn) -> None:
    schema_name, table_name = customer_table()
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                """
                CREATE TABLE IF NOT EXISTS {}.{} (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    age INTEGER,
                    address_cipher TEXT NOT NULL,
                    ssn_cipher TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            ).format(sql.Identifier(schema_name), sql.Identifier(table_name))
        )
    conn.commit()


def insert_customer(conn, name: str, age: int, address: str, ssn: str) -> None:
    schema_name, table_name = customer_table()
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                """
                INSERT INTO {}.{} (name, age, address_cipher, ssn_cipher)
                VALUES (%s, %s, %s, %s)
                """
            ).format(sql.Identifier(schema_name), sql.Identifier(table_name)),
            (name, age, transit_encrypt(address), transit_encrypt(ssn)),
        )


def main(count: int, create_schema: bool) -> None:
    fake = Faker("en_US")
    try:
        with connect_dynamic() as conn:
            if create_schema:
                ensure_schema(conn)
            for index in range(1, count + 1):
                insert_customer(
                    conn,
                    fake.name(),
                    random.randint(18, 90),
                    fake.address().replace("\n", ", "),
                    fake.ssn(),
                )
                if index % 10 == 0:
                    conn.commit()
                    print(f"Inserted {index}/{count} customers...")
            conn.commit()
    except psycopg.errors.InsufficientPrivilege as exc:
        if "sequence" in str(exc).lower():
            schema_name, table_name = customer_table()
            raise SystemExit(
                "Postgres denied access to the table id sequence. Update the Vault "
                f"database read-write role so generated users get sequence privileges, "
                f"for example: GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "
                f"{schema_name} TO \"{{{{name}}}}\"; or grant USAGE, SELECT on "
                f"{schema_name}.{table_name}_id_seq."
            ) from exc
        raise
    print(f"Done. Inserted {count} encrypted customers into {PG_SCHEMA}.{PG_TABLE}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed encrypted demo customers into Postgres/RDS.")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument(
        "--create-schema",
        action="store_true",
        help="Create the demo table first. Requires the Vault DB role to have DDL permissions.",
    )
    args = parser.parse_args()
    main(args.count, args.create_schema)
