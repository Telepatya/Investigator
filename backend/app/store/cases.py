"""Case registry and database access."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import time
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.config import case_db_path, get_cases_dir
from app.store.database import (
    CaseMeta,
    ChatHistory,
    ChatSession,
    Event,
    Report,
    dispose_db,
    init_db,
    sync_fts,
)


REGISTRY_FILE = "registry.json"
_CASE_ID_RE = re.compile(r"^[0-9a-f]{8}$", re.IGNORECASE)
_REGISTRY_LOCK = RLock()
logger = logging.getLogger(__name__)


def _registry_path() -> Path:
    return get_cases_dir() / REGISTRY_FILE


def _load_registry() -> dict:
    with _REGISTRY_LOCK:
        path = _registry_path()
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {"cases": {}}


def _save_registry(data: dict) -> None:
    with _REGISTRY_LOCK:
        path = _registry_path()
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(temp, path)


def _remove_readonly(func, path, _exc_info) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        raise


def _rmtree_with_retries(path: Path, attempts: int = 5, delay: float = 0.15) -> None:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            shutil.rmtree(path, ignore_errors=False, onerror=_remove_readonly)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(delay * (attempt + 1))
    if last_error:
        raise last_error


def create_case(name: str, description: str = "") -> dict:
    case_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    case_dir = get_cases_dir() / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "uploads").mkdir(exist_ok=True)

    init_db(str(case_db_path(case_id)))

    with _REGISTRY_LOCK:
        registry = _load_registry()
        registry["cases"][case_id] = {
            "id": case_id,
            "name": name,
            "description": description,
            "status": "created",
            "created_at": now,
            "updated_at": now,
            "has_memory_dump": False,
            "ai_summary": None,
        }
        _save_registry(registry)
        return registry["cases"][case_id]


def list_cases() -> list[dict]:
    registry = _load_registry()
    cases = []
    for case_id, meta in registry.get("cases", {}).items():
        stats = get_case_stats(case_id)
        cases.append({**meta, **stats})
    cases.sort(key=lambda c: c.get("updated_at", ""), reverse=True)
    return cases


def get_case(case_id: str) -> dict | None:
    registry = _load_registry()
    meta = registry.get("cases", {}).get(case_id)
    if not meta:
        return None
    return {**meta, **get_case_stats(case_id)}


def update_case_meta(case_id: str, *, include_stats: bool = True, **kwargs) -> dict | None:
    with _REGISTRY_LOCK:
        registry = _load_registry()
        if case_id not in registry.get("cases", {}):
            return None
        registry["cases"][case_id].update(kwargs)
        registry["cases"][case_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_registry(registry)
        meta = dict(registry["cases"][case_id])
    if not include_stats:
        return meta
    return {**meta, **get_case_stats(case_id)}


def recover_interrupted_case_operations() -> list[str]:
    """Release transient case states left behind by a stopped backend.

    Ingestion and analysis jobs live only in the backend process. At startup no
    such job can still be active, so persisted busy states are necessarily stale.
    """
    with _REGISTRY_LOCK:
        registry = _load_registry()
        recovered: list[str] = []
        now = datetime.now(timezone.utc).isoformat()
        for case_id, meta in registry.get("cases", {}).items():
            if meta.get("status") not in {"ingesting", "analyzing"}:
                continue
            meta["status"] = "ready"
            meta["updated_at"] = now
            recovered.append(case_id)
        if recovered:
            _save_registry(registry)
        return recovered


def case_exists(case_id: str) -> bool:
    if not _CASE_ID_RE.fullmatch(case_id or ""):
        return False
    return case_id in _load_registry().get("cases", {})


def delete_case(case_id: str) -> bool:
    with _REGISTRY_LOCK:
        registry = _load_registry()
        if case_id not in registry.get("cases", {}):
            return False

        case_dir = get_cases_dir() / case_id
        dispose_db(case_db_path(case_id))
        if case_dir.exists():
            _rmtree_with_retries(case_dir)

        del registry["cases"][case_id]
        _save_registry(registry)
        return True


def get_session(case_id: str) -> Session:
    db_path = case_db_path(case_id)
    factory = init_db(db_path)
    return factory()


def cleanup_orphan_case_dirs() -> list[dict[str, str]]:
    """Remove app-created case directories that are absent from the registry."""
    cases_dir = get_cases_dir()
    registered = set(_load_registry().get("cases", {}))
    removed: list[dict[str, str]] = []
    for case_dir in cases_dir.iterdir():
        if not case_dir.is_dir():
            continue
        case_id = case_dir.name
        if case_id in registered or not _CASE_ID_RE.match(case_id):
            continue
        if not ((case_dir / "case.db").exists() or (case_dir / "uploads").is_dir()):
            continue
        try:
            dispose_db(case_dir / "case.db")
            _rmtree_with_retries(case_dir)
            removed.append({"case_id": case_id, "status": "removed"})
        except OSError as exc:
            removed.append({"case_id": case_id, "status": "failed", "error": str(exc)})
    return removed


def cleanup_stale_case_artifacts() -> list[dict[str, str]]:
    """Remove stale derived/upload artifacts inside registered case directories."""
    cases_dir = get_cases_dir()
    registered = set(_load_registry().get("cases", {}))
    removed: list[dict[str, str]] = []
    for case_id in registered:
        if not _CASE_ID_RE.match(case_id):
            continue
        case_dir = cases_dir / case_id
        if not case_dir.is_dir():
            continue
        uploads = case_dir / "uploads"
        upload_stems = set()
        upload_zip_stems = set()
        if uploads.is_dir():
            for path in uploads.iterdir():
                if not path.is_file():
                    continue
                upload_stems.add(path.stem)
                if path.suffix.lower() == ".zip":
                    upload_zip_stems.add(path.stem)

            for extracted in uploads.glob("*_extracted"):
                if not extracted.is_dir():
                    continue
                stem = extracted.name[:-10]
                if stem in upload_zip_stems:
                    continue
                try:
                    _rmtree_with_retries(extracted)
                    removed.append({
                        "case_id": case_id,
                        "kind": "stale_zip_extract",
                        "path": str(extracted),
                        "status": "removed",
                    })
                except OSError as exc:
                    removed.append({
                        "case_id": case_id,
                        "kind": "stale_zip_extract",
                        "path": str(extracted),
                        "status": "failed",
                        "error": str(exc),
                    })

        mem_root = case_dir / "derived" / "memprocfs"
        if mem_root.is_dir():
            for derived in mem_root.iterdir():
                if not derived.is_dir():
                    continue
                if derived.name in upload_stems:
                    continue
                try:
                    _rmtree_with_retries(derived)
                    removed.append({
                        "case_id": case_id,
                        "kind": "stale_memprocfs_derived",
                        "path": str(derived),
                        "status": "removed",
                    })
                except OSError as exc:
                    removed.append({
                        "case_id": case_id,
                        "kind": "stale_memprocfs_derived",
                        "path": str(derived),
                        "status": "failed",
                        "error": str(exc),
                    })
            try:
                if mem_root.exists() and not any(mem_root.iterdir()):
                    mem_root.rmdir()
                derived_root = case_dir / "derived"
                if derived_root.exists() and not any(derived_root.iterdir()):
                    derived_root.rmdir()
            except OSError:
                logger.debug("Could not remove empty derived-artifact directories", exc_info=True)
    return removed


def get_case_stats(case_id: str) -> dict:
    if not case_db_path(case_id).exists():
        return {
            "event_count": 0,
            "finding_count": 0,
            "active_finding_count": 0,
            "process_count": 0,
        }
    session = get_session(case_id)
    try:
        # One round trip instead of several: list_cases polls this per case every
        # few seconds, so collapsing the counts matters at N cases.
        #
        # active_finding_count excludes suppressed findings. A suppressed finding
        # (disabled rule or marked-benign) keeps its row but has its original
        # severity stashed in evidence['suppressed_from'] by apply_overrides, which
        # runs on every detection pass and on every suppression toggle -- so the
        # presence of that key is an up-to-date marker we can count in SQL.
        event_count, finding_count, active_finding_count, process_count = session.execute(
            text(
                "SELECT (SELECT COUNT(*) FROM events), "
                "(SELECT COUNT(*) FROM findings), "
                "(SELECT COUNT(*) FROM findings "
                "  WHERE json_extract(evidence, '$.suppressed_from') IS NULL), "
                "(SELECT COUNT(*) FROM processes)"
            )
        ).one()
        return {
            "event_count": event_count,
            "finding_count": finding_count,
            "active_finding_count": active_finding_count,
            "process_count": process_count,
        }
    finally:
        session.close()


def add_event(session: Session, **kwargs) -> Event:
    event = Event(**kwargs)
    session.add(event)
    session.flush()
    sync_fts(session, event.id)
    return event


def add_events_bulk(session: Session, rows: Iterable[dict]) -> None:
    """Insert many events plus their FTS rows in two statements.

    Shared by the artifact-ingest and memory-forensics batch paths so the
    contentless-external events_fts table stays in sync with a single
    executemany rather than a get+insert per row.
    """
    events = [Event(**row) for row in rows]
    if not events:
        return
    session.add_all(events)
    session.flush()
    session.execute(
        text(
            "INSERT INTO events_fts(rowid, summary, entity, source, category) "
            "VALUES (:id, :summary, :entity, :source, :category)"
        ),
        [
            {
                "id": event.id,
                "summary": event.summary or "",
                "entity": event.entity or "",
                "source": event.source or "",
                "category": event.category or "",
            }
            for event in events
        ],
    )


def _fts_filter_sql(category: str | None, severity: str | None) -> tuple[str, str, dict]:
    """Build the optional JOIN + WHERE clauses (and params) that apply the
    category/severity filters to an FTS query, so text search still respects the
    category/severity dropdowns instead of ignoring them."""
    join = ""
    conds = ""
    params: dict[str, object] = {}
    if category or severity:
        join = "JOIN events e ON e.id = events_fts.rowid"
        if category:
            conds += " AND e.category = :category"
            params["category"] = category
        if severity:
            conds += " AND e.severity = :severity"
            params["severity"] = severity
    return join, conds, params


def search_events(
    session: Session,
    query: str,
    limit: int = 50,
    offset: int = 0,
    category: str | None = None,
    severity: str | None = None,
) -> list[Event]:
    join, conds, params = _fts_filter_sql(category, severity)
    params.update({"q": query, "limit": limit, "offset": offset})
    rows = session.execute(
        text(
            f"""
            SELECT events_fts.rowid AS id FROM events_fts {join}
            WHERE events_fts MATCH :q{conds}
            ORDER BY rank
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    ).all()
    ids = [r[0] for r in rows if r[0]]
    if not ids:
        return []
    # One SELECT ... IN instead of a get() per hit; reorder to the FTS rank order.
    by_id = {e.id: e for e in session.scalars(select(Event).where(Event.id.in_(ids)))}
    return [by_id[i] for i in ids if i in by_id]


def count_search_events(
    session: Session,
    query: str,
    category: str | None = None,
    severity: str | None = None,
) -> int:
    """Total number of events matching an FTS query and the active category/
    severity filters (ignores paging limit)."""
    join, conds, params = _fts_filter_sql(category, severity)
    params["q"] = query
    return session.scalar(
        text(
            f"SELECT COUNT(*) FROM events_fts {join} "
            f"WHERE events_fts MATCH :q{conds}"
        ),
        params,
    ) or 0


def get_latest_report(session: Session) -> Report | None:
    return session.scalars(select(Report).order_by(Report.generated_at.desc())).first()


def get_meta(session: Session, key: str) -> str | None:
    row = session.scalars(select(CaseMeta).where(CaseMeta.key == key)).first()
    return row.value if row else None


def set_meta(session: Session, key: str, value: str) -> None:
    row = session.scalars(select(CaseMeta).where(CaseMeta.key == key)).first()
    if row:
        row.value = value
    else:
        session.add(CaseMeta(key=key, value=value))
    session.flush()  # autoflush is off; make the write visible to same-session reads


def create_chat_session(session: Session, title: str = "New chat") -> ChatSession:
    chat = ChatSession(
        id=uuid.uuid4().hex[:12],
        title=(title or "New chat").strip()[:160] or "New chat",
    )
    session.add(chat)
    session.flush()
    return chat


def get_chat_session(session: Session, chat_id: str) -> ChatSession | None:
    return session.get(ChatSession, chat_id)


def list_chat_sessions(session: Session) -> list[dict]:
    chats = list(session.scalars(
        select(ChatSession).order_by(ChatSession.updated_at.desc(), ChatSession.created_at.desc())
    ))
    result = []
    for chat in chats:
        count = session.scalar(
            select(func.count(ChatHistory.id)).where(ChatHistory.chat_id == chat.id)
        ) or 0
        last = session.scalars(
            select(ChatHistory)
            .where(ChatHistory.chat_id == chat.id)
            .order_by(ChatHistory.id.desc())
            .limit(1)
        ).first()
        result.append({
            "id": chat.id,
            "title": chat.title,
            "message_count": count,
            "preview": (last.content or "")[:160] if last else "",
            "created_at": chat.created_at.isoformat(),
            "updated_at": chat.updated_at.isoformat(),
        })
    return result


def delete_chat_session(session: Session, chat_id: str) -> bool:
    chat = session.get(ChatSession, chat_id)
    if not chat:
        return False
    session.execute(delete(ChatHistory).where(ChatHistory.chat_id == chat_id))
    session.delete(chat)
    return True


def save_chat(session: Session, chat_id: str, role: str, content: str) -> None:
    chat = session.get(ChatSession, chat_id)
    if not chat:
        raise ValueError("Chat session not found")
    session.add(ChatHistory(chat_id=chat_id, role=role, content=content))
    chat.updated_at = datetime.now(timezone.utc)
    if role == "user" and chat.title == "New chat":
        first_line = " ".join((content or "").strip().splitlines()).strip()
        chat.title = first_line[:80] or "New chat"


def get_chat_history(session: Session, chat_id: str, limit: int = 20) -> list[ChatHistory]:
    return list(
        session.scalars(
            select(ChatHistory)
            .where(ChatHistory.chat_id == chat_id)
            .order_by(ChatHistory.id.desc())
            .limit(limit)
        )
    )[::-1]
