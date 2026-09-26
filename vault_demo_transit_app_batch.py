"""
General purpose HashiCorp Vault developer demo app.

Use cases:
- Transit encryption for customer fields stored in Postgres/RDS
- KV v2 secret CRUD and version operations
- Dynamic database credentials for read-only and read-write Postgres access
- Dynamic AWS credentials with lease display, renew, and revoke
- Sanitized Vault command timeline for developer learning
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import secrets
import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import hvac
from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)

try:
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised in unconfigured demo environments
    psycopg = None
    sql = None
    dict_row = None


# -------------------- App configuration --------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

VAULT_ADDR = os.environ.get("VAULT_ADDR", "")
VAULT_NAMESPACE = os.environ.get("VAULT_NAMESPACE", "admin")
TRANSIT_KEY = os.environ.get("VAULT_TRANSIT_KEY", "customer-data")
KV_TARGETS = {
    "secret/circleci-demo/demo-secrets": {
        "mount": "secret",
        "path": "circleci-demo/demo-secrets",
        "label": "secret/circleci-demo/demo-secrets",
    },
    "kv-v2/database/dev": {
        "mount": "kv-v2",
        "path": "database/dev",
        "label": "kv-v2/database/dev",
    },
}
DB_MOUNT = os.environ.get("VAULT_DB_MOUNT", "db").strip("/")
DB_READONLY_ROLE = os.environ.get("VAULT_DB_READONLY_ROLE", "readOnly")
DB_READWRITE_ROLE = os.environ.get("VAULT_DB_READWRITE_ROLE", "readWrite")
AWS_MOUNT = os.environ.get("VAULT_AWS_MOUNT", "aws").strip("/")
AWS_ROLE = os.environ.get("VAULT_AWS_ROLE", "ec2-iam-user-role")
VAULT_USERPASS_MOUNT = os.environ.get("VAULT_USERPASS_MOUNT", "userpass").strip("/")

PG_HOST = os.environ.get("PGHOST") or os.environ.get("RDS_HOST", "")
PG_PORT = int(os.environ.get("PGPORT") or os.environ.get("RDS_PORT", "5432"))
PG_DATABASE = os.environ.get("PGDATABASE") or os.environ.get("RDS_DATABASE", "postgres")
PG_SSLMODE = os.environ.get("PGSSLMODE") or os.environ.get("RDS_SSLMODE", "require")
PG_SCHEMA = os.environ.get("PGSCHEMA") or os.environ.get("RDS_SCHEMA", "public")
PG_TABLE = os.environ.get("PGTABLE") or os.environ.get("RDS_TABLE", "customers")

MAX_COMMAND_LOG = 80
TOKEN_STORE: Dict[str, Dict[str, Any]] = {}
COMMAND_LOG_STORE: Dict[str, List[Dict[str, Any]]] = {}
DB_CREDS_STORE: Dict[str, Dict[str, Dict[str, Any]]] = {}

DEMO_USERS = {
    "alice": {
        "label": "Read-only DB developer, KV updater",
    },
    "bob": {
        "label": "Read-write DB developer, KV updater",
    },
}


# -------------------- Generic helpers --------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def mask_value(value: Any, keep: int = 4) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}...{text[-keep:]}"


def require_identifier(name: str, fallback: str) -> str:
    candidate = (name or fallback).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
        raise ValueError(f"Invalid SQL identifier: {candidate!r}")
    return candidate


def active_tab(tab_name: str, current_tab: str) -> str:
    return "active" if tab_name == current_tab else ""


@app.context_processor
def inject_template_globals():
    return {
        "active_tab": active_tab,
        "token_status": token_status,
        "TRANSIT_KEY": TRANSIT_KEY,
        "DB_READONLY_ROLE": DB_READONLY_ROLE,
        "DB_READWRITE_ROLE": DB_READWRITE_ROLE,
        "AWS_ROLE": AWS_ROLE,
        "VAULT_USERPASS_MOUNT": VAULT_USERPASS_MOUNT,
        "PG_TABLE": f"{PG_SCHEMA}.{PG_TABLE}",
    }


def current_token_record() -> Optional[Dict[str, Any]]:
    ref = session.get("token_ref")
    return TOKEN_STORE.get(ref) if ref else None


def current_db_creds_cache() -> Dict[str, Dict[str, Any]]:
    ref = session.get("db_creds_ref")
    if not ref:
        ref = str(uuid.uuid4())
        session["db_creds_ref"] = ref
        DB_CREDS_STORE[ref] = {}
    return DB_CREDS_STORE.setdefault(ref, {})


def current_token() -> Optional[str]:
    record = current_token_record()
    return record.get("token", "") if record else None


def token_remaining_ttl(record: Optional[Dict[str, Any]] = None) -> Optional[int]:
    token_record = record or current_token_record()
    if not token_record or not token_record.get("expires_at"):
        return None
    return max(0, int(token_record["expires_at"] - time.time()))


def token_status() -> Dict[str, Any]:
    record = current_token_record()
    remaining = token_remaining_ttl(record)
    return {
        "remaining_ttl": remaining,
        "initial_ttl": record.get("initial_ttl", 0) if record else 0,
        "renewable": bool(record.get("renewable")) if record else False,
        "policies": record.get("policies", []) if record else [],
        "last_renewed_at": record.get("last_renewed_at", "") if record else "",
    }


def make_token_record(token: str, auth: Dict[str, Any]) -> Dict[str, Any]:
    ttl = int(auth.get("lease_duration") or 0)
    policies = auth.get("policies") or auth.get("token_policies") or []
    return {
        "token": token,
        "initial_ttl": ttl,
        "expires_at": time.time() + ttl if ttl else 0,
        "renewable": bool(auth.get("renewable")),
        "policies": sorted(set(policies)),
        "last_renewed_at": "",
    }


def ensure_token_renewed() -> None:
    record = current_token_record()
    if not record or not record.get("token"):
        raise RuntimeError("No Vault token is configured for this demo user.")
    initial_ttl = int(record.get("initial_ttl") or 0)
    remaining_ttl = token_remaining_ttl(record)
    if not initial_ttl or remaining_ttl is None:
        return
    if remaining_ttl <= 0:
        raise RuntimeError("Vault token expired. Please log in again.")
    if not record.get("renewable") or remaining_ttl > initial_ttl / 2:
        return

    # The app renews the user's Vault token before it gets too close to expiry so
    # every later Transit/KV/database/AWS request can keep using the same session.
    renew_client = hvac.Client(url=VAULT_ADDR, token=record["token"], namespace=VAULT_NAMESPACE)
    response = vault_call(
        "vault token renew",
        "POST /v1/auth/token/renew-self",
        lambda: renew_client.adapter.post("v1/auth/token/renew-self", json={}),
        preview=False,
    )
    auth = response.get("auth", {}) if isinstance(response, dict) else {}
    new_ttl = int(auth.get("lease_duration") or initial_ttl)
    record["initial_ttl"] = new_ttl
    record["expires_at"] = time.time() + new_ttl
    record["renewable"] = bool(auth.get("renewable", record.get("renewable")))
    record["policies"] = sorted(set(auth.get("policies") or auth.get("token_policies") or record.get("policies", [])))
    record["last_renewed_at"] = now_iso()
    session.modified = True


def current_vault_client() -> hvac.Client:
    # Every Vault interaction goes through a fresh hvac client built from the
    # current session token. The token itself is stored server-side, not in the UI.
    ensure_token_renewed()
    token = current_token()
    if not VAULT_ADDR:
        raise RuntimeError("VAULT_ADDR is not configured.")
    if not token:
        raise RuntimeError("No Vault token is configured for this demo user.")
    return hvac.Client(url=VAULT_ADDR, token=token, namespace=VAULT_NAMESPACE)


def command_log() -> List[Dict[str, Any]]:
    ref = session.get("command_log_ref")
    return list(COMMAND_LOG_STORE.get(ref, [])) if ref else []


def append_command(entry: Dict[str, Any]) -> None:
    ref = session.get("command_log_ref")
    if not ref:
        ref = str(uuid.uuid4())
        session["command_log_ref"] = ref
    log = COMMAND_LOG_STORE.get(ref, [])
    log.insert(0, entry)
    COMMAND_LOG_STORE[ref] = log[:MAX_COMMAND_LOG]
    session.modified = True


def set_command_preview(entry: Dict[str, Any]) -> None:
    session["command_preview"] = {
        "cli": entry.get("cli", ""),
        "http": entry.get("http", ""),
        "status": entry.get("status", ""),
        "elapsed_ms": entry.get("elapsed_ms", 0),
    }
    session.modified = True


def vault_call(cli: str, http: str, fn: Callable[[], Any], preview: bool = True) -> Any:
    # This wrapper is the single place where Vault calls are timed and recorded.
    # It powers the command log, the persistent "last command" preview, and captures
    # lease IDs or errors returned by Vault so the UI can explain what just happened.
    started = time.perf_counter()
    entry = {
        "timestamp": now_iso(),
        "actor": session.get("user", "anonymous"),
        "cli": cli,
        "http": http,
        "status": "success",
        "elapsed_ms": 0,
        "lease_id": "",
        "lease_duration": "",
        "error": "",
    }
    try:
        result = fn()
        if isinstance(result, dict):
            entry["lease_id"] = result.get("lease_id") or ""
            entry["lease_duration"] = result.get("lease_duration") or ""
        return result
    except Exception as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)[:180]
        raise
    finally:
        entry["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        append_command(entry)
        if preview:
            set_command_preview(entry)


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        try:
            ensure_token_renewed()
        except Exception as exc:
            token_ref = session.get("token_ref")
            log_ref = session.get("command_log_ref")
            db_creds_ref = session.get("db_creds_ref")
            if token_ref:
                TOKEN_STORE.pop(token_ref, None)
            if log_ref:
                COMMAND_LOG_STORE.pop(log_ref, None)
            if db_creds_ref:
                DB_CREDS_STORE.pop(db_creds_ref, None)
            session.clear()
            flash(f"Vault token is no longer usable: {exc}", "danger")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def read_secret_response_data(response: Dict[str, Any]) -> Dict[str, Any]:
    return response.get("data", {}) if isinstance(response, dict) else {}


def selected_kv_target(raw_target: Optional[str]) -> Tuple[str, Dict[str, str]]:
    target_key = raw_target if raw_target in KV_TARGETS else next(iter(KV_TARGETS))
    return target_key, KV_TARGETS[target_key]


def userpass_login(username: str, password: str) -> Dict[str, Any]:
    if not VAULT_ADDR:
        raise RuntimeError("VAULT_ADDR is not configured.")

    def call() -> Dict[str, Any]:
        # Userpass login exchanges the submitted demo credentials for a real Vault
        # client token. That token is then reused for every later capability in the app.
        login_client = hvac.Client(url=VAULT_ADDR, namespace=VAULT_NAMESPACE)
        return login_client.auth.userpass.login(
            username=username,
            password=password,
            mount_point=VAULT_USERPASS_MOUNT,
        )

    response = vault_call(
        f"vault login -method=userpass username={username} password=<redacted>",
        f"POST /v1/auth/{VAULT_USERPASS_MOUNT}/login/{username}",
        call,
    )
    token = response.get("auth", {}).get("client_token")
    if not token:
        raise RuntimeError("Vault userpass login succeeded but did not return a client token.")
    return make_token_record(token, response.get("auth", {}))


def parse_adapter_response(response: Any) -> Dict[str, Any]:
    if isinstance(response, dict):
        return response
    return response.json()


def kv_versions_from_metadata(metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"version": version, **details}
        for version, details in sorted(
            (metadata.get("versions", {}) or {}).items(),
            key=lambda item: int(item[0]),
            reverse=True,
        )
    ]


def kv_readable_version(metadata: Dict[str, Any]) -> Optional[int]:
    versions = metadata.get("versions", {}) or {}
    current_version = int(metadata.get("current_version") or 0)
    if current_version:
        current_details = versions.get(str(current_version), {})
        if not current_details.get("deletion_time") and not current_details.get("destroyed"):
            return current_version

    for version, details in sorted(versions.items(), key=lambda item: int(item[0]), reverse=True):
        if not details.get("deletion_time") and not details.get("destroyed"):
            return int(version)
    return None


def kv_load_secret_version(
    client: hvac.Client,
    mount_point: str,
    path: str,
    preview: bool,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]], Optional[int], int]:
    # KV v2 splits metadata and data into separate API paths. We read metadata first
    # so the UI can understand version history and gracefully fall back when the
    # latest version was soft-deleted but an older version is still readable.
    metadata_response = vault_call(
        f"vault kv metadata get {mount_point}/{path}",
        f"GET /v1/{mount_point}/metadata/{path}",
        lambda: client.secrets.kv.v2.read_secret_metadata(path=path, mount_point=mount_point),
        preview=False,
    )
    metadata = metadata_response.get("data", {})
    versions = kv_versions_from_metadata(metadata)
    current_version = int(metadata.get("current_version") or 0)
    readable_version = kv_readable_version(metadata)
    if not readable_version:
        return {}, metadata, versions, None, current_version

    cli_command = f"vault kv get {mount_point}/{path}"
    http_path = f"GET /v1/{mount_point}/data/{path}"
    if readable_version != current_version:
        cli_command = f"{cli_command} -version={readable_version}"
        http_path = f"{http_path}?version={readable_version}"

    # Once we know which version is safe to show, read that exact version from the
    # KV v2 data endpoint. This avoids surfacing deleted current versions as errors.
    secret_response = vault_call(
        cli_command,
        http_path,
        lambda: client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=mount_point,
            version=readable_version,
        ),
        preview=preview,
    )
    return secret_response, metadata, versions, readable_version, current_version


# -------------------- Vault Transit helpers --------------------

def transit_encrypt(plaintext: str) -> str:
    plaintext = plaintext or ""
    # Transit expects plaintext as base64. Vault performs the encryption and returns
    # a ciphertext envelope like "vault:vN:..." that the app stores in Postgres.
    b64_plain = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
    response = vault_call(
        f"vault write transit/encrypt/{TRANSIT_KEY} plaintext=<redacted>",
        f"POST /v1/transit/encrypt/{TRANSIT_KEY}",
        lambda: current_vault_client().secrets.transit.encrypt_data(
            name=TRANSIT_KEY,
            plaintext=b64_plain,
        ),
    )
    return response["data"]["ciphertext"]


def transit_decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    # Decrypt sends the stored Transit ciphertext back to Vault; the cleartext is
    # returned as base64 and decoded only in memory for display in the UI.
    response = vault_call(
        f"vault write transit/decrypt/{TRANSIT_KEY} ciphertext=<ciphertext>",
        f"POST /v1/transit/decrypt/{TRANSIT_KEY}",
        lambda: current_vault_client().secrets.transit.decrypt_data(
            name=TRANSIT_KEY,
            ciphertext=ciphertext,
        ),
    )
    b64_plain = response["data"]["plaintext"]
    return base64.b64decode(b64_plain).decode("utf-8")


def transit_batch_decrypt(ciphertexts: List[str]) -> List[str]:
    if not ciphertexts:
        return []

    def call() -> Dict[str, Any]:
        # Batch decrypt sends many ciphertexts in one API call. That keeps the demo
        # snappy and also shows the Vault Transit batch_input shape in the command log.
        client = current_vault_client()
        response = client.adapter.post(
            f"v1/transit/decrypt/{TRANSIT_KEY}",
            json={"batch_input": [{"ciphertext": ct} for ct in ciphertexts]},
        )
        return response if isinstance(response, dict) else response.json()

    response = vault_call(
        f"vault write transit/decrypt/{TRANSIT_KEY} batch_input=<redacted>",
        f"POST /v1/transit/decrypt/{TRANSIT_KEY}",
        call,
    )
    decoded = []
    for result in response.get("data", {}).get("batch_results", []):
        plaintext = result.get("plaintext", "")
        decoded.append(base64.b64decode(plaintext).decode("utf-8") if plaintext else "")
    return decoded


def transit_batch_rewrap(ciphertexts: List[str]) -> List[str]:
    if not ciphertexts:
        return []

    def call() -> Dict[str, Any]:
        # Rewrap asks Vault to move ciphertexts to the latest key version without
        # revealing cleartext to the application. Vault does the cryptographic work.
        client = current_vault_client()
        response = client.adapter.post(
            f"v1/transit/rewrap/{TRANSIT_KEY}",
            json={"batch_input": [{"ciphertext": ct} for ct in ciphertexts]},
        )
        return response if isinstance(response, dict) else response.json()

    response = vault_call(
        f"vault write transit/rewrap/{TRANSIT_KEY} batch_input=<redacted>",
        f"POST /v1/transit/rewrap/{TRANSIT_KEY}",
        call,
    )
    return [
        result.get("ciphertext", "")
        for result in response.get("data", {}).get("batch_results", [])
    ]


# -------------------- Dynamic Postgres helpers --------------------

def pg_available() -> bool:
    return psycopg is not None


def get_db_creds(role: str, preview: bool = True, force_refresh: bool = False) -> Dict[str, Any]:
    cache = current_db_creds_cache()
    cached = cache.get(role, {})
    expires_at = float(cached.get("expires_at") or 0)
    if not force_refresh and cached and expires_at > time.time():
        # Dynamic database credentials are leased by Vault. Reusing an unexpired
        # lease keeps the demo stable and avoids minting a new DB user on every refresh.
        if preview:
            set_command_preview({
                "cli": f"vault read {DB_MOUNT}/creds/{role}",
                "http": f"GET /v1/{DB_MOUNT}/creds/{role}",
                "status": "cached credentials reused; no new Vault request",
                "elapsed_ms": 0,
            })
        return {
            "username": cached.get("username", ""),
            "password": cached.get("password", ""),
            "lease_id": cached.get("lease_id", ""),
            "lease_duration": cached.get("lease_duration", ""),
        }

    # When no valid cached lease exists, ask Vault's database secrets engine to
    # generate a fresh username/password pair for the requested role.
    response = vault_call(
        f"vault read {DB_MOUNT}/creds/{role}",
        f"GET /v1/{DB_MOUNT}/creds/{role}",
        lambda: current_vault_client().secrets.database.generate_credentials(
            name=role,
            mount_point=DB_MOUNT,
        ),
        preview=preview,
    )
    data = read_secret_response_data(response)
    lease_duration = int(response.get("lease_duration") or 0)
    creds = {
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "lease_id": response.get("lease_id", ""),
        "lease_duration": lease_duration,
    }
    cache[role] = {
        **creds,
        "expires_at": time.time() + lease_duration if lease_duration else 0,
    }
    session.modified = True
    return creds


def pg_connect_with_creds(creds: Dict[str, Any]):
    if not pg_available():
        raise RuntimeError("The psycopg package is not installed. Run: pip install psycopg[binary]")
    if not PG_HOST:
        raise RuntimeError("PGHOST or RDS_HOST is not configured.")
    # Vault only brokers the database credential lease. The actual SQL connection
    # still goes directly from this app to Postgres using the leased username/password.
    return psycopg.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=creds["username"],
        password=creds["password"],
        sslmode=PG_SSLMODE,
        row_factory=dict_row,
    )


def customer_table() -> Tuple[str, str]:
    return require_identifier(PG_SCHEMA, "public"), require_identifier(PG_TABLE, "customers")


def select_customers(role: str, limit: int = 50, preview: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    # Read paths use whichever Vault DB role the page requested, usually readOnly
    # for browsing and readWrite only when the workflow explicitly needs it.
    creds = get_db_creds(role, preview=preview)
    schema_name, table_name = customer_table()
    with pg_connect_with_creds(creds) as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL(
                    """
                    SELECT id, name, age, address_cipher, ssn_cipher
                    FROM {}.{}
                    ORDER BY id DESC
                    LIMIT %s
                    """
                ).format(sql.Identifier(schema_name), sql.Identifier(table_name)),
                (limit,),
            )
            return list(cur.fetchall()), creds


def insert_customer_rw(name: str, age: Optional[int], address_cipher: str, ssn_cipher: str, *, preview: bool = True) -> Dict[str, Any]:
    # Inserts always require the Vault readWrite DB role because the leased user
    # needs INSERT privileges on the target table and sequence.
    creds = get_db_creds(DB_READWRITE_ROLE, preview=preview)
    schema_name, table_name = customer_table()
    with pg_connect_with_creds(creds) as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL(
                    """
                    INSERT INTO {}.{} (name, age, address_cipher, ssn_cipher)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """
                ).format(sql.Identifier(schema_name), sql.Identifier(table_name)),
                (name, age, address_cipher, ssn_cipher),
            )
            new_id = cur.fetchone()["id"]
            conn.commit()
    creds["new_id"] = new_id
    return creds


def update_customer_ciphertexts(updates: Iterable[Tuple[str, str, int]]) -> int:
    # Rewrap updates are also writes to Postgres, so they intentionally use the
    # readWrite database lease minted by Vault rather than the readOnly role.
    # Keep the Transit rewrap command visible while persisting its result.
    creds = get_db_creds(DB_READWRITE_ROLE, preview=False)
    schema_name, table_name = customer_table()
    count = 0
    with pg_connect_with_creds(creds) as conn:
        with conn.cursor() as cur:
            for address_cipher, ssn_cipher, row_id in updates:
                cur.execute(
                    sql.SQL(
                        """
                        UPDATE {}.{}
                        SET address_cipher = %s, ssn_cipher = %s
                        WHERE id = %s
                        """
                    ).format(sql.Identifier(schema_name), sql.Identifier(table_name)),
                    (address_cipher, ssn_cipher, row_id),
                )
                count += cur.rowcount
            conn.commit()
    return count


# -------------------- Routes --------------------

@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("transit"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user_config = DEMO_USERS.get(username)
        if not user_config:
            flash("Unknown demo user.", "danger")
            return render_template_string(LOGIN_HTML, users=DEMO_USERS)
        old_token_ref = session.get("token_ref")
        old_log_ref = session.get("command_log_ref")
        old_db_creds_ref = session.get("db_creds_ref")
        token_ref = str(uuid.uuid4())
        log_ref = str(uuid.uuid4())
        if old_token_ref:
            TOKEN_STORE.pop(old_token_ref, None)
        if old_log_ref:
            COMMAND_LOG_STORE.pop(old_log_ref, None)
        if old_db_creds_ref:
            DB_CREDS_STORE.pop(old_db_creds_ref, None)
        session.clear()
        session["user"] = username
        session["command_log_ref"] = log_ref
        COMMAND_LOG_STORE[log_ref] = []
        try:
            token_record = userpass_login(username, password)
        except Exception as exc:
            COMMAND_LOG_STORE.pop(log_ref, None)
            session.clear()
            flash(f"Vault userpass login failed: {exc}", "danger")
            return render_template_string(LOGIN_HTML, users=DEMO_USERS)
        TOKEN_STORE[token_ref] = token_record
        session["token_ref"] = token_ref
        flash("Logged in with Vault userpass.", "success")
        return redirect(url_for("transit"))
    return render_template_string(LOGIN_HTML, users=DEMO_USERS)


@app.route("/logout")
@login_required
def logout():
    token_ref = session.get("token_ref")
    log_ref = session.get("command_log_ref")
    db_creds_ref = session.get("db_creds_ref")
    if token_ref:
        TOKEN_STORE.pop(token_ref, None)
    if log_ref:
        COMMAND_LOG_STORE.pop(log_ref, None)
    if db_creds_ref:
        DB_CREDS_STORE.pop(db_creds_ref, None)
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/transit", methods=["GET", "POST"])
@login_required
def transit():
    rows: List[Dict[str, Any]] = []
    clear_rows: List[Dict[str, Any]] = []
    creds_summary: Dict[str, Any] = {}

    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "save":
                name = request.form.get("name", "").strip()
                age_raw = request.form.get("age", "").strip()
                address = request.form.get("address", "").strip()
                ssn = request.form.get("ssn", "").strip()
                if not name or not ssn:
                    flash("Name and SSN are required.", "warning")
                else:
                    age = int(age_raw) if age_raw else None
                    # Sensitive fields are encrypted by Vault Transit before the app
                    # asks Vault for a readWrite DB lease and stores the ciphertext.
                    address_cipher = transit_encrypt(address)
                    ssn_cipher = transit_encrypt(ssn)
                    creds = insert_customer_rw(name, age, address_cipher, ssn_cipher, preview=False)
                    flash(
                        f"Saved customer {creds['new_id']} using dynamic DB user {mask_value(creds['username'])}.",
                        "success",
                    )
            elif action == "rotate":
                # Rotating the Transit key creates a new key version in Vault. Existing
                # ciphertext is still decryptable, but new encrypt operations use the new version.
                vault_call(
                    f"vault write -f transit/keys/{TRANSIT_KEY}/rotate",
                    f"POST /v1/transit/keys/{TRANSIT_KEY}/rotate",
                    lambda: current_vault_client().secrets.transit.rotate_key(name=TRANSIT_KEY),
                )
                flash("Transit key rotated.", "success")
            elif action == "rewrap":
                # Single rewrap demonstrates the one-ciphertext-at-a-time Transit API:
                # read rows, ask Vault to rewrap each field, then write updated ciphertext back.
                rows, _ = select_customers(DB_READWRITE_ROLE, 500, preview=False)
                updates = []
                started = time.perf_counter()
                for row in rows:
                    new_address = vault_call(
                        f"vault write transit/rewrap/{TRANSIT_KEY} ciphertext=<ciphertext>",
                        f"POST /v1/transit/rewrap/{TRANSIT_KEY}",
                        lambda ct=row["address_cipher"]: current_vault_client().secrets.transit.rewrap_data(
                            name=TRANSIT_KEY, ciphertext=ct
                        ),
                    )["data"]["ciphertext"]
                    new_ssn = vault_call(
                        f"vault write transit/rewrap/{TRANSIT_KEY} ciphertext=<ciphertext>",
                        f"POST /v1/transit/rewrap/{TRANSIT_KEY}",
                        lambda ct=row["ssn_cipher"]: current_vault_client().secrets.transit.rewrap_data(
                            name=TRANSIT_KEY, ciphertext=ct
                        ),
                    )["data"]["ciphertext"]
                    updates.append((new_address, new_ssn, row["id"]))
                updated = update_customer_ciphertexts(updates)
                flash(f"Single rewrap updated {updated} rows in {time.perf_counter() - started:.3f}s.", "info")
            elif action == "rewrap_batch":
                # Batch rewrap performs the same migration to the newest key version,
                # but sends many ciphertexts to Vault in each request.
                rows, _ = select_customers(DB_READWRITE_ROLE, 500, preview=False)
                addresses = [row["address_cipher"] for row in rows]
                ssns = [row["ssn_cipher"] for row in rows]
                started = time.perf_counter()
                new_addresses = transit_batch_rewrap(addresses)
                new_ssns = transit_batch_rewrap(ssns)
                updates = [
                    (new_addresses[index], new_ssns[index], row["id"])
                    for index, row in enumerate(rows)
                    if index < len(new_addresses) and index < len(new_ssns)
                ]
                updated = update_customer_ciphertexts(updates)
                flash(f"Batch rewrap updated {updated} rows in {time.perf_counter() - started:.3f}s.", "info")
        except Exception as exc:
            flash(f"Transit/database action failed: {exc}", "danger")

    try:
        rows, creds_summary = select_customers(DB_READONLY_ROLE, 50, preview=False)
    except Exception as exc:
        flash(f"Read-only database query failed: {exc}", "danger")

    if request.args.get("view") == "clear" and rows:
        try:
            # The cleartext view intentionally decrypts only for rendering and never
            # writes plaintext back to the database.
            addresses = transit_batch_decrypt([row["address_cipher"] for row in rows])
            ssns = transit_batch_decrypt([row["ssn_cipher"] for row in rows])
            for index, row in enumerate(rows):
                clear_rows.append(
                    {
                        "id": row["id"],
                        "name": row["name"],
                        "age": row["age"],
                        "address": addresses[index] if index < len(addresses) else "",
                        "ssn": ssns[index] if index < len(ssns) else "",
                    }
                )
        except Exception as exc:
            flash(f"Batch decrypt failed: {exc}", "danger")

    return render_template_string(
        TRANSIT_HTML,
        tab="transit",
        rows=rows,
        clear_rows=clear_rows,
        creds_summary=creds_summary,
    )


@app.route("/database", methods=["GET", "POST"])
@login_required
def database():
    selected_role = request.form.get("role") or request.args.get("role") or DB_READONLY_ROLE
    action_result = ""
    rows: List[Dict[str, Any]] = []
    creds_summary: Dict[str, Any] = {}
    action_creds_summary: Dict[str, Any] = {}

    if request.method == "POST" and request.form.get("action") == "insert_sample":
        try:
            # This demo path combines two Vault features in sequence: Transit first
            # for field encryption, then database dynamic creds for the insert itself.
            address_cipher = transit_encrypt("1 Dynamic Way, Demo City, VA 20190")
            ssn_cipher = transit_encrypt("000-00-0000")
            creds = insert_customer_rw("Dynamic Credential Demo", 42, address_cipher, ssn_cipher)
            action_creds_summary = creds
            action_result = f"Inserted row {creds['new_id']} with {mask_value(creds['username'])}."
        except Exception as exc:
            action_result = f"Write failed: {exc}"

    try:
        rows, creds_summary = select_customers(selected_role, 25, preview=request.method == "GET")
    except Exception as exc:
        flash(f"Database query with role {selected_role} failed: {exc}", "danger")
    if action_creds_summary:
        creds_summary = action_creds_summary

    return render_template_string(
        DATABASE_HTML,
        tab="database",
        rows=rows,
        selected_role=selected_role,
        creds_summary=creds_summary,
        action_result=action_result,
    )


@app.route("/kv", methods=["GET", "POST"])
@login_required
def kv():
    secret_data: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    versions: List[Dict[str, Any]] = []
    selected_key = ""
    selected_target, kv_target = selected_kv_target(
        request.form.get("kv_target") or request.args.get("kv_target")
    )
    kv_mount = kv_target["mount"]
    kv_path = kv_target["path"]

    if request.method == "POST":
        action = request.form.get("action")
        try:
            client = current_vault_client()
            if action == "write":
                key = request.form.get("key", "").strip()
                value = request.form.get("value", "")
                if not key:
                    flash("KV key is required.", "warning")
                else:
                    try:
                        # Read the currently visible KV version first so the update acts
                        # like "merge one field into the existing secret" rather than replace it.
                        existing_response, _, _, _, _ = kv_load_secret_version(
                            client,
                            kv_mount,
                            kv_path,
                            preview=False,
                        )
                        updated_secret = dict(existing_response.get("data", {}).get("data", {}))
                    except Exception:
                        updated_secret = {}
                    updated_secret[key] = value
                    # KV v2 writes create a brand-new version; earlier versions remain
                    # available in metadata unless they are deleted or destroyed later.
                    vault_call(
                        f"vault kv put {kv_mount}/{kv_path} {key}=<redacted>",
                        f"POST /v1/{kv_mount}/data/{kv_path}",
                        lambda: client.secrets.kv.v2.create_or_update_secret(
                            path=kv_path,
                            mount_point=kv_mount,
                            secret=updated_secret,
                            cas=None,
                        ),
                    )
                    flash(f"KV secret updated at {kv_mount}/{kv_path}.", "success")
            elif action == "delete_latest":
                # Soft delete only marks the latest version deleted in Vault metadata.
                # The version can still be undeleted later unless it is destroyed.
                vault_call(
                    f"vault kv delete {kv_mount}/{kv_path}",
                    f"DELETE /v1/{kv_mount}/data/{kv_path}",
                    lambda: client.secrets.kv.v2.delete_latest_version_of_secret(
                        path=kv_path,
                        mount_point=kv_mount,
                    ),
                )
                flash("Latest KV version soft-deleted.", "info")
            elif action == "undelete":
                # Undelete re-enables reading a soft-deleted KV version by version number.
                version = int(request.form.get("version", "0"))
                vault_call(
                    f"vault kv undelete -versions={version} {kv_mount}/{kv_path}",
                    f"POST /v1/{kv_mount}/undelete/{kv_path}",
                    lambda: client.secrets.kv.v2.undelete_secret_versions(
                        path=kv_path,
                        mount_point=kv_mount,
                        versions=[version],
                    ),
                )
                flash(f"KV version {version} undeleted.", "success")
            elif action == "destroy":
                # Destroy is irreversible for that version in KV v2 and removes the
                # stored secret data while keeping version history metadata.
                version = int(request.form.get("version", "0"))
                vault_call(
                    f"vault kv destroy -versions={version} {kv_mount}/{kv_path}",
                    f"POST /v1/{kv_mount}/destroy/{kv_path}",
                    lambda: client.secrets.kv.v2.destroy_secret_versions(
                        path=kv_path,
                        mount_point=kv_mount,
                        versions=[version],
                    ),
                )
                flash(f"KV version {version} destroyed.", "warning")
        except Exception as exc:
            flash(f"KV action failed: {exc}", "danger")

    try:
        client = current_vault_client()
        # Page load reads KV through the helper above so deleted current versions can
        # fall back to the newest readable version instead of showing a hard error.
        response, metadata, versions, readable_version, current_version = kv_load_secret_version(
            client,
            kv_mount,
            kv_path,
            preview=request.method != "POST",
        )
        current_secret = response.get("data", {}).get("data") or {}
        if current_secret:
            secret_data = {key: "<redacted>" for key in current_secret.keys()}
            selected_key = next(iter(current_secret), "")
        if current_version and readable_version and readable_version != current_version:
            flash(
                f"Latest KV version {current_version} is deleted; showing version {readable_version}.",
                "info",
            )
    except Exception:
        try:
            client = current_vault_client()
            meta_response = vault_call(
                f"vault kv metadata get {kv_mount}/{kv_path}",
                f"GET /v1/{kv_mount}/metadata/{kv_path}",
                lambda: client.secrets.kv.v2.read_secret_metadata(path=kv_path, mount_point=kv_mount),
                preview=False,
            )
            metadata = meta_response.get("data", {})
            versions = kv_versions_from_metadata(metadata)
        except Exception:
            metadata = {}
            versions = []
        flash(f"KV read failed for {kv_mount}/{kv_path}.", "warning")

    return render_template_string(
        KV_HTML,
        tab="kv",
        kv_targets=KV_TARGETS,
        selected_target=selected_target,
        kv_mount=kv_mount,
        kv_path=kv_path,
        secret_data=secret_data,
        selected_key=selected_key,
        metadata=metadata,
        versions=versions,
    )


@app.route("/aws", methods=["GET", "POST"])
@login_required
def aws():
    aws_creds: Dict[str, Any] = {}
    if request.method == "POST":
        action = request.form.get("action")
        lease_id = request.form.get("lease_id", "")
        try:
            client = current_vault_client()
            if action == "renew" and lease_id:
                # Lease renew asks Vault to extend the lifetime of previously issued
                # AWS credentials without generating a different access key pair.
                vault_call(
                    "vault lease renew <lease-id>",
                    "PUT /v1/sys/leases/renew",
                    lambda: client.adapter.put("v1/sys/leases/renew", json={"lease_id": lease_id}),
                )
                flash("AWS credential lease renewed.", "success")
            elif action == "revoke" and lease_id:
                # Lease revoke tells Vault to invalidate credentials it created earlier.
                vault_call(
                    "vault lease revoke <lease-id>",
                    "PUT /v1/sys/leases/revoke",
                    lambda: client.adapter.put("v1/sys/leases/revoke", json={"lease_id": lease_id}),
                )
                flash("AWS credential lease revoked.", "warning")
            elif action == "get":
                # The AWS secrets engine generates temporary cloud credentials on demand
                # and returns the lease metadata that can later be renewed or revoked.
                response = vault_call(
                    f"vault read {AWS_MOUNT}/creds/{AWS_ROLE}",
                    f"GET /v1/{AWS_MOUNT}/creds/{AWS_ROLE}",
                    lambda: client.read(f"{AWS_MOUNT}/creds/{AWS_ROLE}"),
                )
                data = response.get("data", {})
                aws_creds = {
                    "access_key": mask_value(data.get("access_key")),
                    "secret_key": "<redacted>",
                    "security_token": "<redacted>" if data.get("security_token") else "",
                    "lease_id": response.get("lease_id", ""),
                    "lease_duration": response.get("lease_duration", ""),
                    "lease_renewable": response.get("renewable", False),
                }
                session["last_aws_lease_id"] = aws_creds["lease_id"]
        except Exception as exc:
            flash(f"AWS credentials action failed: {exc}", "danger")

    return render_template_string(
        AWS_HTML,
        tab="aws",
        aws_creds=aws_creds,
        last_aws_lease_id=session.get("last_aws_lease_id", ""),
    )


@app.route("/commands", methods=["GET", "POST"])
@login_required
def commands():
    if request.method == "POST":
        ref = session.get("command_log_ref")
        if ref:
            COMMAND_LOG_STORE[ref] = []
        flash("Command log cleared for this session.", "info")
        return redirect(url_for("commands"))
    return render_template_string(COMMANDS_HTML, tab="commands", logs=command_log())


@app.route("/session")
@login_required
def session_info():
    token = current_token()
    return render_template_string(
        SESSION_HTML,
        tab="session",
        user=session.get("user"),
        token_mask=mask_value(token),
        token_details=token_status(),
        vault_addr=VAULT_ADDR,
        vault_namespace=VAULT_NAMESPACE,
        pg_host=PG_HOST,
        pg_database=PG_DATABASE,
        pg_sslmode=PG_SSLMODE,
        psycopg_status="installed" if pg_available() else "missing",
    )


@app.route("/assets/cut-away.jpeg")
def cutaway_image():
    return send_from_directory(os.path.dirname(__file__), "cut-away.jpeg")


# -------------------- Templates --------------------

BASE_CSS = """
<style>
  :root {
    color-scheme: light;
    --bg: #f6f8fb;
    --panel: #ffffff;
    --text: #172033;
    --muted: #5e6b80;
    --line: #d8dee9;
    --accent: #1565c0;
    --ok: #0b6b3a;
    --danger: #a32222;
    --warn: #8a5200;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  }
  header {
    background: #101827;
    color: #fff;
    padding: 1rem 1.5rem;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: .8rem;
  }
  .brand-mark {
    width: 52px;
    height: 52px;
    border-radius: 10px;
    object-fit: cover;
    border: 1px solid rgba(255,255,255,.18);
    box-shadow: 0 8px 20px rgba(0,0,0,.18);
    background: rgba(255,255,255,.08);
    flex: 0 0 auto;
  }
  .app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }
  header h1 { margin: 0; font-size: 1.15rem; letter-spacing: 0; }
  .token-summary {
    display: flex;
    flex-wrap: wrap;
    gap: .4rem;
    align-items: center;
    font-size: .86rem;
  }
  .header-pill {
    display: inline-flex;
    align-items: center;
    gap: .25rem;
    padding: .22rem .5rem;
    border-radius: 999px;
    background: #243247;
    color: #f8fafc;
    border: 1px solid #3b4d68;
  }
  .header-pill strong { color: #b9dcff; }
  main { padding: 1.25rem; max-width: 1280px; margin: 0 auto; }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: .35rem;
    margin: 0 0 1rem;
    border-bottom: 1px solid var(--line);
  }
  .tabs a {
    display: inline-flex;
    align-items: center;
    padding: .55rem .8rem;
    color: var(--muted);
    text-decoration: none;
    border: 1px solid transparent;
    border-radius: 6px 6px 0 0;
    font-size: .95rem;
  }
  .tabs a.active {
    color: var(--accent);
    background: var(--panel);
    border-color: var(--line);
    border-bottom-color: var(--panel);
    margin-bottom: -1px;
  }
  .grid { display: grid; grid-template-columns: minmax(280px, 420px) 1fr; gap: 1rem; align-items: start; }
  .transit-controls { grid-template-columns: repeat(2, minmax(0, 1fr)); align-items: stretch; }
  .card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
  }
  h2 { margin: .1rem 0 1rem; font-size: 1.35rem; }
  h3 { margin: 0 0 .8rem; font-size: 1rem; }
  label { display: block; font-weight: 650; margin: .6rem 0 .25rem; }
  input, textarea, select, button {
    width: 100%;
    min-height: 2.35rem;
    border: 1px solid #b9c4d2;
    border-radius: 6px;
    padding: .5rem .65rem;
    font: inherit;
    background: #fff;
  }
  button {
    width: auto;
    cursor: pointer;
    color: #fff;
    background: var(--accent);
    border-color: var(--accent);
    font-weight: 650;
  }
  button.secondary { background: #415268; border-color: #415268; color: #fff; }
  button.warning { background: #7a4300; border-color: #7a4300; color: #fff; }
  button.danger { background: #8f1d1d; border-color: #8f1d1d; color: #fff; }
  button:hover { filter: brightness(.94); }
  button:focus-visible { outline: 3px solid #8ec5ff; outline-offset: 2px; }
  .actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .85rem; }
  table { width: 100%; border-collapse: collapse; background: #fff; }
  th, td {
    border-bottom: 1px solid #e7ebf1;
    text-align: left;
    vertical-align: top;
    padding: .5rem;
    font-size: .9rem;
  }
  th { color: #40516a; background: #f8fafc; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88rem; }
  .break { word-break: break-all; }
  .muted { color: var(--muted); }
  .flash { padding: .65rem .8rem; border-radius: 6px; margin-bottom: .75rem; border: 1px solid transparent; }
  .success { background: #eaf7ef; color: var(--ok); border-color: #bee7ce; }
  .danger { background: #fff0f0; color: var(--danger); border-color: #f4c2c2; }
  .warning { background: #fff8e8; color: var(--warn); border-color: #eed28f; }
  .info { background: #edf5ff; color: #174e86; border-color: #bdd7ef; }
  .pill { display: inline-block; padding: .15rem .45rem; border-radius: 999px; border: 1px solid var(--line); background: #f8fafc; }
  .status-success { color: var(--ok); font-weight: 700; }
  .status-error { color: var(--danger); font-weight: 700; }
  .vault-command-preview {
    display: grid;
    gap: .25rem;
    margin: 0 0 1rem;
    padding: .75rem .9rem;
    border: 1px solid #b6d5ff;
    border-radius: 8px;
    background: #eef6ff;
    color: #153e75;
  }
  .vault-command-preview .preview-row {
    display: grid;
    grid-template-columns: 5rem minmax(0, 1fr);
    gap: .55rem;
    align-items: baseline;
  }
  .vault-command-preview strong { color: #102f5f; }
  .vault-command-preview code {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .vault-command-preview .preview-meta { color: #415268; font-size: .85rem; }
  @media (max-width: 820px) {
    main { padding: .8rem; }
    .grid { grid-template-columns: 1fr; }
    .tabs a { flex: 1 1 auto; justify-content: center; }
    table { display: block; overflow-x: auto; }
    .vault-command-preview .preview-row { grid-template-columns: 1fr; gap: .15rem; }
    .app-header { align-items: flex-start; }
  }
</style>
"""

FLASHES = """
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for cat, msg in messages %}
      <div class="flash {{ cat }}">{{ msg }}</div>
    {% endfor %}
  {% endif %}
{% endwith %}
"""

NAV = """
{% set ts = token_status() %}
<header>
  <div class="app-header">
    <div class="brand">
      <img class="brand-mark" src="{{ url_for('cutaway_image') }}" alt="Vault cut-away illustration">
      <h1>Vault "Cut-away" Developer Demo</h1>
    </div>
    {% if session.get('user') %}
    <div class="token-summary">
      <span class="header-pill"><strong>Token TTL</strong> {{ ts.remaining_ttl if ts.remaining_ttl is not none else 'unknown' }}s</span>
      <span class="header-pill"><strong>Renewable</strong> {{ 'yes' if ts.renewable else 'no' }}</span>
      <span class="header-pill"><strong>Policies</strong> {{ ts.policies|join(', ') if ts.policies else 'none' }}</span>
    </div>
    {% endif %}
  </div>
</header>
<main>
<nav class="tabs">
  <a class="{{ active_tab('kv', tab) }}" href="{{ url_for('kv', reset_preview=1) }}">KV v2</a>
  <a class="{{ active_tab('database', tab) }}" href="{{ url_for('database', reset_preview=1) }}">Database</a>
  <a class="{{ active_tab('aws', tab) }}" href="{{ url_for('aws', reset_preview=1) }}">AWS</a>
  <a class="{{ active_tab('transit', tab) }}" href="{{ url_for('transit', reset_preview=1) }}">Transit</a>
  <a class="{{ active_tab('commands', tab) }}" href="{{ url_for('commands', reset_preview=1) }}">Command Log</a>
  <a class="{{ active_tab('session', tab) }}" href="{{ url_for('session_info', reset_preview=1) }}">Session</a>
  <a href="{{ url_for('logout') }}">Logout {{ session.get('user') }}</a>
</nav>
{# Tab navigation starts blank, including any automatic page-load calls. #}
{% if request.method == 'GET' and request.args.get('reset_preview') == '1' %}
  {% set discarded_preview = session.pop('command_preview', none) %}
{% endif %}
{% set preview = session.get('command_preview') %}
{% if preview %}
<div class="vault-command-preview">
  <div class="preview-row"><strong>Vault CLI</strong><code>{{ preview.cli }}</code></div>
  <div class="preview-row"><strong>Vault API</strong><code>{{ preview.http }}</code></div>
  <div class="preview-meta">Status: {{ preview.status }} · {{ preview.elapsed_ms }}ms</div>
</div>
{% endif %}
""" + FLASHES

END = "</main>"

LOGIN_HTML = BASE_CSS + """
<header>
  <div class="brand">
    <img class="brand-mark" src="{{ url_for('cutaway_image') }}" alt="Vault cut-away illustration">
    <h1>Vault "Cut-away" Developer Demo</h1>
  </div>
</header>
<main>
""" + FLASHES + """
<div class="grid">
  <section class="card">
    <h2>Login</h2>
    <form method="post">
      <label for="username">Vault userpass username</label>
      <input id="username" name="username" placeholder="alice or bob" autocomplete="username" required>
      <label for="password">Vault userpass password</label>
      <input id="password" type="password" name="password" autocomplete="current-password" required>
      <div class="actions"><button type="submit">Log In</button></div>
    </form>
  </section>
  <section class="card">
    <h3>Configured personas</h3>
    <table>
      <thead><tr><th>User</th><th>Persona</th><th>Vault auth path</th></tr></thead>
      <tbody>
        {% for name, config in users.items() %}
        <tr>
          <td>{{ name }}</td>
          <td>{{ config.label }}</td>
          <td class="mono">auth/{{ VAULT_USERPASS_MOUNT }}/login/{{ name }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <p class="muted">The app exchanges the submitted userpass credentials for a Vault client token, stores it server-side, and renders only a masked token on the Session tab.</p>
  </section>
</div>
</main>
"""

TRANSIT_HTML = BASE_CSS + NAV + """
<h2>Transit Encryption</h2>
<div class="grid transit-controls">
  <section class="card">
    <h3>Add encrypted customer</h3>
    <p class="muted">Encrypt customer details with Vault Transit before saving.</p>
    <details>
      <summary style="cursor: pointer;">Expand / collapse customer form</summary>
    <form method="post">
      <input type="hidden" name="action" value="save">
      <label for="name">Name</label>
      <input id="name" name="name" required>
      <label for="age">Age</label>
      <input id="age" name="age" type="number" min="0">
      <label for="address">Address</label>
      <textarea id="address" name="address" rows="3"></textarea>
      <label for="ssn">SSN</label>
      <input id="ssn" name="ssn" required>
      <div class="actions"><button type="submit">Encrypt and Save</button></div>
    </form>
    </details>
  </section>
  <section class="card">
    <h3>Key operations</h3>
    <p class="muted">All operations use Vault Transit key <span class="mono">{{ TRANSIT_KEY }}</span>.</p>
    <div class="actions">
      <form method="post"><input type="hidden" name="action" value="rotate"><button class="secondary" type="submit">Rotate Key</button></form>
      <form method="post"><input type="hidden" name="action" value="rewrap"><button class="secondary" type="submit">Rewrap Single</button></form>
      <form method="post"><input type="hidden" name="action" value="rewrap_batch"><button class="secondary" type="submit">Rewrap Batch</button></form>
      <a class="pill" href="{{ url_for('transit', view='clear') }}">Show cleartext via batch decrypt</a>
    </div>
    {% if creds_summary %}
      <p class="muted">Last read used dynamic DB user <span class="mono">{{ creds_summary.username[:4] }}...{{ creds_summary.username[-4:] }}</span>, TTL {{ creds_summary.lease_duration }}s.</p>
    {% endif %}
  </section>
</div>
{% if clear_rows %}
<section class="card">
  <h3>Cleartext view via Transit decrypt</h3>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Age</th><th>Address</th><th>SSN</th></tr></thead>
    <tbody>
      {% for row in clear_rows %}
      <tr><td>{{ row.id }}</td><td>{{ row.name }}</td><td>{{ row.age or '' }}</td><td>{{ row.address }}</td><td>{{ row.ssn }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
</section>
{% endif %}
<section class="card">
  <h3>Stored ciphertext in Postgres</h3>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Age</th><th>Address ciphertext</th><th>SSN ciphertext</th></tr></thead>
    <tbody>
      {% for row in rows %}
      <tr>
        <td>{{ row.id }}</td><td>{{ row.name }}</td><td>{{ row.age or '' }}</td>
        <td class="break mono">{{ row.address_cipher }}</td><td class="break mono">{{ row.ssn_cipher }}</td>
      </tr>
      {% else %}
      <tr><td colspan="5" class="muted">No rows loaded.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</section>
""" + END

DATABASE_HTML = BASE_CSS + NAV + """
<h2>Dynamic Database Credentials</h2>
<div class="grid">
  <section class="card">
    <h3>Query with a Vault DB role</h3>
    <form method="get">
      <label for="role">Role</label>
      <select id="role" name="role">
        <option value="{{ DB_READONLY_ROLE }}" {% if selected_role == DB_READONLY_ROLE %}selected{% endif %}>{{ DB_READONLY_ROLE }} read-only</option>
        <option value="{{ DB_READWRITE_ROLE }}" {% if selected_role == DB_READWRITE_ROLE %}selected{% endif %}>{{ DB_READWRITE_ROLE }} read-write</option>
      </select>
      <div class="actions"><button type="submit">Get Credentials and Query</button></div>
    </form>
    <form method="post">
      <input type="hidden" name="action" value="insert_sample">
      <div class="actions"><button class="secondary" type="submit">Insert Sample with Read-Write Role</button></div>
    </form>
    {% if action_result %}<p class="pill">{{ action_result }}</p>{% endif %}
  </section>
  <section class="card">
    <h3>Connection target</h3>
    <p><span class="muted">Table:</span> <span class="mono">{{ PG_TABLE }}</span></p>
    {% if creds_summary %}
      <p><span class="muted">Dynamic user:</span> <span class="mono">{{ creds_summary.username[:4] }}...{{ creds_summary.username[-4:] }}</span></p>
      <p><span class="muted">Lease TTL:</span> {{ creds_summary.lease_duration }}s</p>
      <p><span class="muted">Lease ID:</span> <span class="mono break">{{ creds_summary.lease_id }}</span></p>
    {% endif %}
  </section>
</div>
<section class="card">
  <h3>Query results</h3>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Age</th><th>Address ciphertext</th><th>SSN ciphertext</th></tr></thead>
    <tbody>
      {% for row in rows %}
      <tr><td>{{ row.id }}</td><td>{{ row.name }}</td><td>{{ row.age or '' }}</td><td class="mono break">{{ row.address_cipher }}</td><td class="mono break">{{ row.ssn_cipher }}</td></tr>
      {% else %}
      <tr><td colspan="5" class="muted">No rows loaded.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</section>
""" + END

KV_HTML = BASE_CSS + NAV + """
<h2>KV v2 Secrets</h2>
<div class="grid">
  <section class="card">
    <h3>Secrets Sync targets</h3>
    <form method="get">
      <label for="kv_target">KV secret</label>
      <select id="kv_target" name="kv_target">
        {% for target_key, target in kv_targets.items() %}
        <option value="{{ target_key }}" {% if selected_target == target_key %}selected{% endif %}>{{ target.label }}</option>
        {% endfor %}
      </select>
      <div class="actions"><button type="submit">Load Secret</button></div>
    </form>
    <p class="muted">Selected path: <span class="mono">{{ kv_mount }}/{{ kv_path }}</span></p>
  </section>
  <section class="card">
    <h3>Update selected secret</h3>
    <form method="post">
      <input type="hidden" name="action" value="write">
      <input type="hidden" name="kv_target" value="{{ selected_target }}">
      <label for="key">Key</label>
      <input id="key" name="key" value="{{ selected_key }}" required>
      <label for="value">Value</label>
      <input id="value" name="value" placeholder="value is redacted in the UI">
      <div class="actions"><button type="submit">Write Secret Version</button></div>
    </form>
  </section>
</div>
<section class="card">
    <h3>Current secret keys</h3>
    <table>
      <thead><tr><th>Key</th><th>Value</th></tr></thead>
      <tbody>
        {% for key, value in secret_data.items() %}
        <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
        {% else %}
        <tr><td colspan="2" class="muted">No readable current version.</td></tr>
        {% endfor %}
      </tbody>
    </table>
    <form method="post" class="actions">
      <input type="hidden" name="action" value="delete_latest">
      <input type="hidden" name="kv_target" value="{{ selected_target }}">
      <button class="warning" type="submit">Soft Delete Latest</button>
    </form>
</section>
<section class="card">
  <h3>Version metadata</h3>
  <table>
    <thead><tr><th>Version</th><th>Created</th><th>Deleted</th><th>Destroyed</th><th>Actions</th></tr></thead>
    <tbody>
      {% for version in versions %}
      <tr>
        <td>{{ version.version }}</td>
        <td>{{ version.created_time or '' }}</td>
        <td>{{ version.deletion_time or '' }}</td>
        <td>{{ version.destroyed }}</td>
        <td>
          <form method="post" class="actions">
            <input type="hidden" name="kv_target" value="{{ selected_target }}">
            <input type="hidden" name="version" value="{{ version.version }}">
            <button class="secondary" name="action" value="undelete" type="submit">Undelete</button>
            <button class="danger" name="action" value="destroy" type="submit">Destroy</button>
          </form>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="5" class="muted">No metadata loaded.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</section>
""" + END

AWS_HTML = BASE_CSS + NAV + """
<h2>Dynamic AWS Credentials</h2>
<div class="grid">
  <section class="card">
    <h3>Generate credentials</h3>
    <form method="post">
      <input type="hidden" name="action" value="get">
      <div class="actions"><button type="submit">Read AWS Credentials</button></div>
    </form>
    <p class="muted">Vault role: <span class="mono">{{ AWS_ROLE }}</span></p>
  </section>
  <section class="card">
    <h3>Lease actions</h3>
    <form method="post">
      <label for="lease_id">Lease ID</label>
      <input id="lease_id" name="lease_id" value="{{ aws_creds.lease_id or last_aws_lease_id }}">
      <div class="actions">
        <button class="secondary" name="action" value="renew" type="submit">Renew</button>
        <button class="warning" name="action" value="revoke" type="submit">Revoke</button>
      </div>
    </form>
  </section>
</div>
<section class="card">
  <h3>Credential summary</h3>
  <table>
    <tbody>
      <tr><th>Access key</th><td class="mono">{{ aws_creds.access_key or '' }}</td></tr>
      <tr><th>Secret key</th><td>{{ aws_creds.secret_key or '' }}</td></tr>
      <tr><th>Session token</th><td>{{ aws_creds.security_token or '' }}</td></tr>
      <tr><th>Lease ID</th><td class="mono break">{{ aws_creds.lease_id or '' }}</td></tr>
      <tr><th>Lease TTL</th><td>{{ aws_creds.lease_duration or '' }}</td></tr>
      <tr><th>Renewable</th><td>{{ aws_creds.lease_renewable }}</td></tr>
    </tbody>
  </table>
</section>
""" + END

COMMANDS_HTML = BASE_CSS + NAV + """
<h2>Command Log</h2>
<section class="card">
  <form method="post" class="actions"><button class="secondary" type="submit">Clear Command Log</button></form>
  <table>
    <thead><tr><th>Time</th><th>Actor</th><th>Status</th><th>CLI</th><th>HTTP API</th><th>Lease</th><th>Elapsed</th></tr></thead>
    <tbody>
      {% for log in logs %}
      <tr>
        <td class="mono">{{ log.timestamp }}</td>
        <td>{{ log.actor }}</td>
        <td class="status-{{ log.status }}">{{ log.status }}{% if log.error %}: {{ log.error }}{% endif %}</td>
        <td class="mono break">{{ log.cli }}</td>
        <td class="mono break">{{ log.http }}</td>
        <td class="mono break">{% if log.lease_id %}{{ log.lease_id }}<br>{{ log.lease_duration }}s{% endif %}</td>
        <td>{{ log.elapsed_ms }}ms</td>
      </tr>
      {% else %}
      <tr><td colspan="7" class="muted">No commands recorded yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</section>
""" + END

SESSION_HTML = BASE_CSS + NAV + """
<h2>Session</h2>
<section class="card">
  <table>
    <tbody>
      <tr><th>User</th><td>{{ user }}</td></tr>
      <tr><th>Vault address</th><td class="mono break">{{ vault_addr }}</td></tr>
      <tr><th>Vault namespace</th><td class="mono">{{ vault_namespace }}</td></tr>
      <tr><th>Vault auth method</th><td class="mono">userpass at {{ VAULT_USERPASS_MOUNT }}</td></tr>
      <tr><th>Vault token</th><td class="mono">{{ token_mask }}</td></tr>
      <tr><th>Token remaining TTL</th><td>{{ token_details.remaining_ttl if token_details.remaining_ttl is not none else 'unknown' }} seconds</td></tr>
      <tr><th>Token original TTL</th><td>{{ token_details.initial_ttl }} seconds</td></tr>
      <tr><th>Token renewable</th><td>{{ 'yes' if token_details.renewable else 'no' }}</td></tr>
      <tr><th>Token policies</th><td class="mono">{{ token_details.policies|join(', ') if token_details.policies else 'none' }}</td></tr>
      <tr><th>Last token renewal</th><td class="mono">{{ token_details.last_renewed_at or 'not renewed in this session' }}</td></tr>
      <tr><th>Postgres host</th><td class="mono break">{{ pg_host }}</td></tr>
      <tr><th>Postgres database</th><td class="mono">{{ pg_database }}</td></tr>
      <tr><th>Postgres SSL mode</th><td class="mono">{{ pg_sslmode }}</td></tr>
      <tr><th>psycopg</th><td>{{ psycopg_status }}</td></tr>
    </tbody>
  </table>
</section>
""" + END


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=True)
