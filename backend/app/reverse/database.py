"""Versioned SQLite persistence for Reverse workspaces."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import get_reverse_dir
from app.store.database import SerializedWriteSession

SCHEMA_VERSION = 6


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ReverseBase(DeclarativeBase):
    pass


class ReverseProject(ReverseBase):
    __tablename__ = "reverse_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    linked_case_id: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="ready", index=True)
    analysis_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    active_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ReverseArtifact(ReverseBase):
    __tablename__ = "reverse_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reverse_projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    relative_path: Mapped[str] = mapped_column(String(512), unique=True)
    artifact_type: Mapped[str] = mapped_column(String(32), index=True)
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    file_size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReverseRun(ReverseBase):
    __tablename__ = "reverse_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reverse_projects.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(255))
    temperature: Mapped[float] = mapped_column(default=0.2)
    max_tokens: Mapped[int] = mapped_column(Integer, default=4096)
    max_turns: Mapped[int] = mapped_column(Integer, default=25)
    turns_used: Mapped[int] = mapped_column(Integer, default=0)
    awaiting_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    iocs_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_signature_status: Mapped[str] = mapped_column(String(32), default="pending")
    report_signature_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_verification_status: Mapped[str] = mapped_column(String(32), default="pending")
    report_verification_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_verification_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_verification_details: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReverseMessage(ReverseBase):
    __tablename__ = "reverse_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reverse_projects.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    phase: Mapped[str] = mapped_column(String(32), default="analysis", index=True)
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReverseAuditEvent(ReverseBase):
    __tablename__ = "reverse_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReverseProvenanceEntry(ReverseBase):
    __tablename__ = "reverse_provenance"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReverseToolApproval(ReverseBase):
    __tablename__ = "reverse_tool_approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reverse_projects.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[str] = mapped_column(String(64))
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_engine: Engine | None = None
_factory: sessionmaker | None = None
_lock = RLock()


def reverse_db_path() -> Path:
    return get_reverse_dir() / "reverse.db"


def _configure_connection(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
    finally:
        cursor.close()


def init_reverse_db() -> sessionmaker:
    global _engine, _factory
    with _lock:
        if _factory is not None:
            return _factory
        path = reverse_db_path().resolve()
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
        ReverseBase.metadata.create_all(_engine)
        with _engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS reverse_schema_version (version INTEGER NOT NULL)"
            )
            row = conn.exec_driver_sql("SELECT version FROM reverse_schema_version LIMIT 1").first()
            if row is None:
                conn.exec_driver_sql(
                    "INSERT INTO reverse_schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
                )
            elif int(row[0]) > SCHEMA_VERSION:
                raise RuntimeError("Reverse database was created by a newer Investigator version")
            elif int(row[0]) < SCHEMA_VERSION:
                version = int(row[0])
                if version < 2:
                    columns = {
                        str(item[1])
                        for item in conn.exec_driver_sql("PRAGMA table_info(reverse_runs)")
                    }
                    if "report_signature_status" not in columns:
                        conn.exec_driver_sql(
                            "ALTER TABLE reverse_runs ADD COLUMN "
                            "report_signature_status VARCHAR(32) NOT NULL DEFAULT 'pending'"
                        )
                    if "report_signature_error" not in columns:
                        conn.exec_driver_sql(
                            "ALTER TABLE reverse_runs ADD COLUMN report_signature_error TEXT"
                        )
                    conn.exec_driver_sql(
                        "UPDATE reverse_runs SET report_signature_status = 'signed' "
                        "WHERE EXISTS ("
                        "SELECT 1 FROM reverse_provenance p "
                        "WHERE p.project_id = reverse_runs.project_id "
                        "AND p.event_type = 'report.signed' "
                        "AND p.signature IS NOT NULL "
                        "AND json_extract(p.payload, '$.run_id') = reverse_runs.id"
                        ")"
                    )
                    version = 2
                if version < 3:
                    columns = {
                        str(item[1])
                        for item in conn.exec_driver_sql("PRAGMA table_info(reverse_runs)")
                    }
                    additions = {
                        "report_verification_status": (
                            "VARCHAR(32) NOT NULL DEFAULT 'pending'"
                        ),
                        "report_verification_summary": "TEXT",
                        "report_verification_error": "TEXT",
                        "report_verification_details": "JSON NOT NULL DEFAULT '{}'",
                    }
                    for name, sql_type in additions.items():
                        if name not in columns:
                            conn.exec_driver_sql(
                                f"ALTER TABLE reverse_runs ADD COLUMN {name} {sql_type}"
                            )
                    version = 3
                if version < 4:
                    for tool_id in ("write_python_tool", "run_python_tool"):
                        conn.exec_driver_sql(
                            "INSERT INTO reverse_tool_approvals "
                            "(project_id, tool_id, approved, created_at) "
                            "SELECT id, ?, 1, CURRENT_TIMESTAMP FROM reverse_projects "
                            "WHERE NOT EXISTS ("
                            "SELECT 1 FROM reverse_tool_approvals approvals "
                            "WHERE approvals.project_id = reverse_projects.id "
                            "AND approvals.tool_id = ?"
                            ")",
                            (tool_id, tool_id),
                        )
                    version = 4
                if version < 5:
                    for tool_id in ("run_cmd", "read_file", "write_file", "list_dir"):
                        conn.exec_driver_sql(
                            "INSERT INTO reverse_tool_approvals "
                            "(project_id, tool_id, approved, created_at) "
                            "SELECT id, ?, 1, CURRENT_TIMESTAMP FROM reverse_projects "
                            "WHERE NOT EXISTS ("
                            "SELECT 1 FROM reverse_tool_approvals approvals "
                            "WHERE approvals.project_id = reverse_projects.id "
                            "AND approvals.tool_id = ?"
                            ")",
                            (tool_id, tool_id),
                        )
                    version = 5
                if version < 6:
                    conn.exec_driver_sql(
                        "DELETE FROM reverse_tool_approvals "
                        "WHERE tool_id NOT IN ('run_cmd', 'read_file', 'write_file', 'list_dir')"
                    )
                    version = 6
                conn.exec_driver_sql("UPDATE reverse_schema_version SET version = ?", (version,))
        return _factory


def get_reverse_session():
    return init_reverse_db()()


def dispose_reverse_db() -> None:
    global _engine, _factory
    with _lock:
        engine = _engine
        _engine = None
        _factory = None
    if engine is not None:
        engine.dispose()
