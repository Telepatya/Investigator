"""SQLAlchemy database models and per-case engine cache."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, RLock

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


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
    # Server-assigned upload basename; display source may repeat across archives.
    upload_name: Mapped[str | None] = mapped_column(String(256), index=True)
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
    upload_name: Mapped[str | None] = mapped_column(String(256), index=True)
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
    upload_name: Mapped[str | None] = mapped_column(String(256), index=True)
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
    timeline_entries: Mapped[list] = mapped_column(JSON, default=list)
    findings_analysis: Mapped[list] = mapped_column(JSON, default=list)
    suppression_revision: Mapped[int] = mapped_column(Integer, default=0)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(160), default="New chat")
    memo: Mapped[str | None] = mapped_column(Text, default=None)
    memo_upto: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chat_id: Mapped[str | None] = mapped_column(String(32), index=True)
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_ENGINE_CACHE: dict[Path, tuple[Engine, sessionmaker]] = {}
_ENGINE_LOCK = Lock()
_INITIALIZED: set[Path] = set()
_WRITE_LOCKS: dict[Path, RLock] = {}


def _is_write_statement(statement) -> bool:
    """Return whether an execute() statement can mutate the case database."""
    if any(
        bool(getattr(statement, flag, False))
        for flag in ("is_insert", "is_update", "is_delete")
    ):
        return True
    text_value = getattr(statement, "text", None)
    if not isinstance(text_value, str):
        return False
    first = text_value.lstrip().split(None, 1)[0].lower() if text_value.strip() else ""
    return first in {"insert", "update", "delete", "replace", "create", "alter", "drop", "vacuum"}


class SerializedWriteSession(Session):
    """A normal SQLAlchemy session with a per-database writer gate.

    SQLite WAL permits concurrent readers but still has one writer. Holding this
    lock from the first flush/DML statement through commit or rollback prevents
    independent background jobs from interleaving write transactions and
    surfacing transient ``database is locked`` errors.
    """

    def __init__(self, *args, write_lock: RLock, **kwargs):
        super().__init__(*args, **kwargs)
        self._write_lock = write_lock
        self._owns_write_lock = False

    def _acquire_write_lock(self) -> None:
        if not self._owns_write_lock:
            self._write_lock.acquire()
            self._owns_write_lock = True

    def acquire_write_lock(self) -> None:
        """Lock before a read-modify-write sequence begins."""
        self._acquire_write_lock()

    def _release_write_lock(self) -> None:
        if self._owns_write_lock:
            self._owns_write_lock = False
            self._write_lock.release()

    def flush(self, objects=None) -> None:
        if self.new or self.dirty or self.deleted:
            self._acquire_write_lock()
        return super().flush(objects)

    def execute(self, statement, params=None, *, execution_options=None, bind_arguments=None, **kw):
        if _is_write_statement(statement):
            self._acquire_write_lock()
        return super().execute(
            statement,
            params,
            execution_options=execution_options,
            bind_arguments=bind_arguments,
            **kw,
        )

    def commit(self) -> None:
        if self.new or self.dirty or self.deleted:
            self._acquire_write_lock()
        try:
            return super().commit()
        finally:
            self._release_write_lock()

    def rollback(self) -> None:
        try:
            return super().rollback()
        finally:
            self._release_write_lock()

    def close(self) -> None:
        try:
            return super().close()
        finally:
            self._release_write_lock()


def _normalize_db_path(db_path: str | Path) -> Path:
    return Path(db_path).expanduser().resolve()


def acquire_session_write_lock(session: Session) -> None:
    """Acquire the case writer gate before reading state that will be changed."""
    acquire = getattr(session, "acquire_write_lock", None)
    if acquire is not None:
        acquire()


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
            pool_pre_ping=True,
        )
        event.listen(engine, "connect", _configure_sqlite_connection)
        write_lock = _WRITE_LOCKS.setdefault(path, RLock())
        factory = sessionmaker(
            bind=engine,
            class_=SerializedWriteSession,
            write_lock=write_lock,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
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
        if "upload_name" not in existing_cols:
            conn.exec_driver_sql("ALTER TABLE events ADD COLUMN upload_name TEXT")
        process_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(processes)")}
        if "upload_name" not in process_cols:
            conn.exec_driver_sql("ALTER TABLE processes ADD COLUMN upload_name TEXT")
        conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_events_upload_name ON events (upload_name)")
        conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_processes_upload_name ON processes (upload_name)")
        memory_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(memory_results)")}
        if "upload_name" not in memory_cols:
            conn.exec_driver_sql("ALTER TABLE memory_results ADD COLUMN upload_name TEXT")
        conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_memory_results_upload_name ON memory_results (upload_name)")
        report_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(reports)")}
        if "timeline_entries" not in report_cols:
            conn.exec_driver_sql("ALTER TABLE reports ADD COLUMN timeline_entries JSON DEFAULT '[]'")
        if "suppression_revision" not in report_cols:
            conn.exec_driver_sql("ALTER TABLE reports ADD COLUMN suppression_revision INTEGER DEFAULT 0")
        chat_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(chat_history)")}
        if "chat_id" not in chat_cols:
            conn.exec_driver_sql("ALTER TABLE chat_history ADD COLUMN chat_id TEXT")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_chat_history_chat_id ON chat_history (chat_id)"
        )
        legacy_count = conn.exec_driver_sql(
            "SELECT COUNT(*) FROM chat_history WHERE chat_id IS NULL"
        ).scalar_one()
        if legacy_count:
            conn.exec_driver_sql(
                """
                INSERT OR IGNORE INTO chat_sessions(
                    id, title, memo, memo_upto, created_at, updated_at
                )
                SELECT
                    'legacy', 'Previous chat',
                    (SELECT value FROM case_meta WHERE key = 'chat_memo'),
                    COALESCE(CAST((SELECT value FROM case_meta WHERE key = 'chat_memo_upto') AS INTEGER), 0),
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                """
            )
            conn.exec_driver_sql(
                "UPDATE chat_history SET chat_id = 'legacy' WHERE chat_id IS NULL"
            )
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
