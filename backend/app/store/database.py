"""SQLAlchemy database models and per-case engine cache."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class CaseMeta(Base):
    __tablename__ = "case_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    value: Mapped[str] = mapped_column(Text)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str | None] = mapped_column(String(256), index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    entity: Mapped[str | None] = mapped_column(String(512), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    # Human-readable provenance for a non-default severity (which detector or
    # flagged entity raised it). NULL = base severity assigned at ingest.
    severity_reason: Mapped[str | None] = mapped_column(Text, default=None)
    summary: Mapped[str] = mapped_column(Text)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class Process(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(256), index=True)
    path: Mapped[str | None] = mapped_column(String(1024))
    cmdline: Mapped[str | None] = mapped_column(Text)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    session_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    extra: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(128))
    ai_verdict: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemoryResult(Base):
    __tablename__ = "memory_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plugin: Mapped[str] = mapped_column(String(64), index=True)
    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[str] = mapped_column(String(16), default="info")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    summary: Mapped[str] = mapped_column(Text)
    timeline_narrative: Mapped[str] = mapped_column(Text, default="")
    findings_analysis: Mapped[list] = mapped_column(JSON, default=list)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_ENGINE_CACHE: dict[Path, tuple[Engine, sessionmaker]] = {}
_ENGINE_LOCK = Lock()
_INITIALIZED: set[Path] = set()


def _normalize_db_path(db_path: str | Path) -> Path:
    return Path(db_path).expanduser().resolve()


def get_engine(db_path: str | Path) -> Engine:
    path = _normalize_db_path(db_path)
    init_db(path)
    with _ENGINE_LOCK:
        return _ENGINE_CACHE[path][0]


def init_db(db_path: str | Path) -> sessionmaker:
    path = _normalize_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _ENGINE_LOCK:
        cached = _ENGINE_CACHE.get(path)
        if cached:
            return cached[1]
        engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"check_same_thread": False, "timeout": 30.0},
        )
        event.listen(engine, "connect", _configure_sqlite_connection)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        _ENGINE_CACHE[path] = (engine, factory)

    if path not in _INITIALIZED:
        _initialize_schema(path, engine)
    return factory


def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=30000")
        # WAL lets readers proceed while a long ingest transaction is writing;
        # without it, case-stat queries 500 with "database is locked" mid-ingest.
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Bigger page cache and in-memory temp store speed up the large batch
        # inserts and index maintenance during ingest; mmap reduces read syscalls
        # for the stat/timeline queries. Durability is unchanged (still WAL+NORMAL).
        cursor.execute("PRAGMA cache_size=-65536")   # ~64 MiB page cache
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=268435456")  # 256 MiB
    finally:
        cursor.close()


def _initialize_schema(path: Path, engine: Engine) -> None:
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        # Lightweight migration for case DBs created before severity provenance existed.
        existing_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(events)")}
        if "severity_reason" not in existing_cols:
            conn.exec_driver_sql("ALTER TABLE events ADD COLUMN severity_reason TEXT")
        conn.exec_driver_sql(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                summary, entity, source, category, content='events', content_rowid='id'
            )
            """
        )
        conn.commit()
    _INITIALIZED.add(path)


def dispose_db(db_path: str | Path) -> None:
    path = _normalize_db_path(db_path)
    with _ENGINE_LOCK:
        cached = _ENGINE_CACHE.pop(path, None)
        _INITIALIZED.discard(path)
    if cached:
        cached[0].dispose()


def dispose_all_db_engines() -> None:
    with _ENGINE_LOCK:
        engines = [engine for engine, _factory in _ENGINE_CACHE.values()]
        _ENGINE_CACHE.clear()
        _INITIALIZED.clear()
    for engine in engines:
        engine.dispose()


def compact_db(db_path: str | Path) -> None:
    """Reclaim SQLite/WAL disk space after large evidence purges."""
    path = _normalize_db_path(db_path)
    dispose_db(path)
    if not path.exists():
        return
    conn = sqlite3.connect(str(path), timeout=30.0)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
    finally:
        conn.close()


def sync_fts(session, event_id: int) -> None:
    event = session.get(Event, event_id)
    if not event:
        return
    session.execute(
        __import__("sqlalchemy").text(
            "INSERT INTO events_fts(rowid, summary, entity, source, category) "
            "VALUES (:id, :summary, :entity, :source, :category)"
        ),
        {
            "id": event.id,
            "summary": event.summary or "",
            "entity": event.entity or "",
            "source": event.source or "",
            "category": event.category or "",
        },
    )
