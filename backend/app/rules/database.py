"""Versioned SQLite persistence for global detection-rule state.

Detection rules are application-wide, not per-case, so their state lives in its own
database at ``~/.investigator/rules/rules.db`` rather than in any case's ``case.db``.
The schema follows the versioned ladder used by ``app.reverse.database`` — an
explicit ``rules_schema_version`` row, stepwise guarded migrations, and a refusal to
open a database written by a newer build — because this store is expected to outlive
several schema changes.

Two rules govern how this database relates to a case database, and they run one way
only:

* Global state decides what the engine *runs*. A globally disabled rule is filtered
  out before a detection run starts, so it never produces a finding.
* A case's ``disabled_rules`` decides what the analyst *sees*, unchanged, via
  ``app.detect.overrides.apply_overrides``.

Neither is ever written into the other. A globally disabled rule leaves the case's
own suppression list untouched, so re-enabling globally and rebuilding restores both
the finding and any per-case suppression that was already on it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import get_rules_dir
from app.store.database import SerializedWriteSession

RULES_SCHEMA_VERSION = 1

# Sentinel row id for the singleton state table.
STATE_ROW_ID = 1


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RulesBase(DeclarativeBase):
    pass


class BuiltinRuleOverride(RulesBase):
    """Analyst changes to a built-in rule.

    Rows exist only for rules that were actually touched, so a fresh install reads
    an empty table and the engine keeps using its module-level rule tables verbatim.
    """

    __tablename__ = "builtin_rule_overrides"

    rule_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity_override: Mapped[str | None] = mapped_column(String(16), nullable=True)
    techniques_override: Mapped[list | None] = mapped_column(JSON, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CustomRule(RulesBase):
    """An analyst-authored or imported Sigma rule."""

    __tablename__ = "custom_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    slug: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    yaml_source: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    # ok | error — a rule that fails to compile is stored and reported, never run.
    compile_status: Mapped[str] = mapped_column(String(16), default="ok", index=True)
    compile_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    compiled_meta: Mapped[dict] = mapped_column(JSON, default=dict)
    # gui | yaml | import | fork
    origin: Mapped[str] = mapped_column(String(32), default="yaml")
    source_builtin_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class RulesState(RulesBase):
    """Singleton row carrying the revision counter used as the cache key."""

    __tablename__ = "rules_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    builtin_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_engine: Engine | None = None
_factory: sessionmaker | None = None
_lock = RLock()


def rules_db_path() -> Path:
    return get_rules_dir() / "rules.db"


def rules_db_exists() -> bool:
    """Whether any global rule state has ever been written.

    ``load_profile`` calls this first so a default installation costs a single
    ``stat`` per detection run rather than opening a database.
    """
    try:
        return rules_db_path().exists()
    except OSError:
        return False


def _configure_connection(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
    finally:
        cursor.close()


def init_rules_db() -> sessionmaker:
    global _engine, _factory
    with _lock:
        if _factory is not None:
            return _factory
        path = rules_db_path().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"check_same_thread": False, "timeout": 30.0},
            pool_pre_ping=True,
        )
        event.listen(_engine, "connect", _configure_connection)
        writer_lock = RLock()
        _factory = sessionmaker(
            bind=_engine,
            class_=SerializedWriteSession,
            write_lock=writer_lock,
            autoflush=False,
            expire_on_commit=False,
        )
        RulesBase.metadata.create_all(_engine)
        with _engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS rules_schema_version (version INTEGER NOT NULL)"
            )
            row = conn.exec_driver_sql("SELECT version FROM rules_schema_version LIMIT 1").first()
            if row is None:
                conn.exec_driver_sql(
                    "INSERT INTO rules_schema_version(version) VALUES (?)",
                    (RULES_SCHEMA_VERSION,),
                )
            elif int(row[0]) > RULES_SCHEMA_VERSION:
                raise RuntimeError(
                    "Rules database was created by a newer Investigator version"
                )
            elif int(row[0]) < RULES_SCHEMA_VERSION:
                # Future migrations land here as `if version < N:` blocks that are
                # safe to re-run, then a single version write at the end.
                conn.exec_driver_sql(
                    "UPDATE rules_schema_version SET version = ?", (RULES_SCHEMA_VERSION,)
                )
            conn.exec_driver_sql(
                "INSERT OR IGNORE INTO rules_state(id, revision, builtin_fingerprint) "
                "VALUES (?, 1, '')",
                (STATE_ROW_ID,),
            )
        return _factory


def get_rules_session():
    return init_rules_db()()


def dispose_rules_db() -> None:
    global _engine, _factory
    with _lock:
        engine = _engine
        _engine = None
        _factory = None
    if engine is not None:
        engine.dispose()
