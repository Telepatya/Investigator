"""Small SQLite-backed opaque browser sessions and OIDC transactions."""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from app import config as app_config


COOKIE_NAME = "investigator_session"
OIDC_BINDING_COOKIE_NAME = "investigator_oidc_binding_v2"
LEGACY_OIDC_BINDING_COOKIE_NAME = "investigator_oidc_binding"
LOGIN_LIMIT_WINDOW_SECONDS = 60
LOGIN_LIMIT_PER_CLIENT = 120
LOGIN_LIMIT_BUCKET_CAPACITY = 4096
ACTIVE_TRANSACTION_LIMIT = 1024
_db_lock = RLock()


def _db_path() -> Path:
    return app_config.DEFAULT_CONFIG_DIR / "auth.db"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.touch(exist_ok=True)
        os.chmod(path, 0o600)
    except OSError:
        # Windows ACLs and managed filesystem policies may not expose POSIX
        # modes; the file is still created below the application data root.
        pass
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 10000")
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            display_name TEXT,
            email TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            last_seen REAL NOT NULL,
            expires_at REAL NOT NULL,
            absolute_expires_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oidc_transactions (
            state_hash TEXT PRIMARY KEY,
            binding_hash TEXT,
            nonce TEXT NOT NULL,
            code_verifier TEXT NOT NULL,
            return_path TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oidc_login_limits (
            client_hash TEXT PRIMARY KEY,
            window_started_at REAL NOT NULL,
            attempts INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_oidc_transactions_expires ON oidc_transactions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_oidc_login_limits_window ON oidc_login_limits(window_started_at);
        """
    )
    # Old auth databases may have transactions created before browser binding
    # existed. Keep the database readable, but those rows cannot be consumed.
    transaction_columns = {
        str(row[1]) for row in db.execute("PRAGMA table_info(oidc_transactions)")
    }
    if "binding_hash" not in transaction_columns:
        db.execute("ALTER TABLE oidc_transactions ADD COLUMN binding_hash TEXT")
    return db


@contextmanager
def _database():
    db = _connect()
    try:
        yield db
        db.commit()
    finally:
        db.close()


@dataclass(frozen=True)
class UserSession:
    subject: str
    display_name: str | None
    email: str | None
    is_admin: bool
    created_at: float
    last_seen: float
    expires_at: float
    absolute_expires_at: float

    def public_dict(self) -> dict[str, object | None]:
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "email": self.email,
            "is_admin": self.is_admin,
        }


def _ensure_auth_policy(db: sqlite3.Connection, fingerprint: str) -> bool:
    row = db.execute(
        "SELECT value FROM auth_metadata WHERE key = 'policy_fingerprint'"
    ).fetchone()
    if row is not None and str(row["value"]) == fingerprint:
        return False

    # The initial read avoids taking SQLite's write lock on every request.
    # Recheck after acquiring it because another worker may have applied this
    # policy transition while this connection was waiting.
    db.execute("BEGIN IMMEDIATE")
    row = db.execute(
        "SELECT value FROM auth_metadata WHERE key = 'policy_fingerprint'"
    ).fetchone()
    if row is not None and str(row["value"]) == fingerprint:
        return False
    db.execute("DELETE FROM auth_sessions")
    db.execute("DELETE FROM oidc_transactions")
    db.execute(
        "INSERT INTO auth_metadata(key, value) VALUES ('policy_fingerprint', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (fingerprint,),
    )
    return True


def sync_auth_policy(fingerprint: str) -> bool:
    """Invalidate sessions and pending logins when the OIDC policy changes.

    The fingerprint is a digest of the effective policy, never the policy
    values themselves. SQLite serializes policy transitions across workers.
    """
    with _db_lock, _database() as db:
        return _ensure_auth_policy(db, fingerprint)


def sync_auth_policy_if_store_exists(fingerprint: str) -> bool:
    """Apply a disabled-policy transition without creating a default auth DB."""
    if not _db_path().is_file():
        return False
    return sync_auth_policy(fingerprint)


def create_transaction(
    *, nonce: str, code_verifier: str, browser_binding: str, return_path: str,
    expires_at: float, client_key: str | None = None,
) -> str | None:
    """Create a bounded, one-time login transaction.

    Calls are limited per direct network peer and the number of live
    transactions is capped. The peer limit is shared by clients behind the
    same reverse proxy. The limits and insert happen in one SQLite write
    transaction so concurrent workers cannot race past either bound.
    """
    now = time.time()
    client_hash = _hash(client_key or "unknown-client")
    with _db_lock, _database() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM oidc_transactions WHERE expires_at <= ?", (now,))
        db.execute(
            "DELETE FROM oidc_login_limits WHERE window_started_at <= ?",
            (now - LOGIN_LIMIT_WINDOW_SECONDS,),
        )
        active_count = int(
            db.execute("SELECT COUNT(*) FROM oidc_transactions").fetchone()[0]
        )
        if active_count >= ACTIVE_TRANSACTION_LIMIT:
            return None

        limit_row = db.execute(
            "SELECT window_started_at, attempts FROM oidc_login_limits WHERE client_hash = ?",
            (client_hash,),
        ).fetchone()
        if limit_row is None:
            bucket_count = int(
                db.execute("SELECT COUNT(*) FROM oidc_login_limits").fetchone()[0]
            )
            if bucket_count >= LOGIN_LIMIT_BUCKET_CAPACITY:
                return None
            db.execute(
                "INSERT INTO oidc_login_limits(client_hash, window_started_at, attempts) VALUES (?, ?, 1)",
                (client_hash, now),
            )
        elif now - float(limit_row["window_started_at"]) >= LOGIN_LIMIT_WINDOW_SECONDS:
            db.execute(
                "UPDATE oidc_login_limits SET window_started_at = ?, attempts = 1 WHERE client_hash = ?",
                (now, client_hash),
            )
        elif int(limit_row["attempts"]) >= LOGIN_LIMIT_PER_CLIENT:
            return None
        else:
            db.execute(
                "UPDATE oidc_login_limits SET attempts = attempts + 1 WHERE client_hash = ?",
                (client_hash,),
            )

        state = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO oidc_transactions(state_hash, binding_hash, nonce, code_verifier, return_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_hash(state), _hash(browser_binding), nonce, code_verifier, return_path, now, expires_at),
        )
    return state


def consume_transaction(state: str, browser_binding: str, now: float | None = None) -> dict[str, str] | None:
    current = time.time() if now is None else now
    with _db_lock, _database() as db:
        # Lock the database before reading so two worker processes cannot both
        # observe and consume the same one-time state value.
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT nonce, code_verifier, return_path, expires_at FROM oidc_transactions WHERE state_hash = ? AND binding_hash = ?",
            (_hash(state), _hash(browser_binding)),
        ).fetchone()
        if row is None:
            return None
        db.execute("DELETE FROM oidc_transactions WHERE state_hash = ?", (_hash(state),))
        if float(row["expires_at"]) <= current:
            return None
        return {
            "nonce": str(row["nonce"]),
            "code_verifier": str(row["code_verifier"]),
            "return_path": str(row["return_path"]),
        }


def create_session(
    *, subject: str, display_name: str | None, email: str | None, is_admin: bool,
    idle_seconds: int, absolute_seconds: int, now: float | None = None,
) -> tuple[str, UserSession]:
    current = time.time() if now is None else now
    token = secrets.token_urlsafe(48)
    session = UserSession(
        subject=subject,
        display_name=display_name,
        email=email,
        is_admin=is_admin,
        created_at=current,
        last_seen=current,
        expires_at=current + idle_seconds,
        absolute_expires_at=current + absolute_seconds,
    )
    with _db_lock, _database() as db:
        db.execute("DELETE FROM auth_sessions WHERE expires_at <= ? OR absolute_expires_at <= ?", (current, current))
        db.execute(
            "INSERT INTO auth_sessions(token_hash, subject, display_name, email, is_admin, created_at, last_seen, expires_at, absolute_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_hash(token), session.subject, session.display_name, session.email, int(session.is_admin), session.created_at, session.last_seen, session.expires_at, session.absolute_expires_at),
        )
    return token, session


def get_session(
    token: str | None, *, idle_seconds: int, now: float | None = None,
    policy_fingerprint: str | None = None,
) -> UserSession | None:
    if (not token or len(token) > 256) and policy_fingerprint is None:
        return None
    current = time.time() if now is None else now
    with _db_lock, _database() as db:
        if policy_fingerprint is not None:
            _ensure_auth_policy(db, policy_fingerprint)
        if not token or len(token) > 256:
            return None
        row = db.execute("SELECT * FROM auth_sessions WHERE token_hash = ?", (_hash(token),)).fetchone()
        if row is None:
            return None
        if float(row["expires_at"]) <= current or float(row["absolute_expires_at"]) <= current:
            db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_hash(token),))
            return None
        next_expiry = min(current + idle_seconds, float(row["absolute_expires_at"]))
        db.execute("UPDATE auth_sessions SET last_seen = ?, expires_at = ? WHERE token_hash = ?", (current, next_expiry, _hash(token)))
        return UserSession(
            subject=str(row["subject"]), display_name=row["display_name"], email=row["email"],
            is_admin=bool(row["is_admin"]), created_at=float(row["created_at"]), last_seen=current,
            expires_at=next_expiry, absolute_expires_at=float(row["absolute_expires_at"]),
        )


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with _db_lock, _database() as db:
        db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_hash(token),))


def clear_auth_state() -> None:
    """Test/development helper; never called by the application lifecycle."""
    with _db_lock, _database() as db:
        db.execute("DELETE FROM auth_sessions")
        db.execute("DELETE FROM oidc_transactions")
