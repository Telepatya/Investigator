"""Case registry and database access."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import case_db_path, get_cases_dir, load_config
from app.store.database import (
    CaseMeta,
    ChatHistory,
    Event,
    Finding,
    MemoryResult,
    Process,
    Report,
    dispose_db,
    init_db,
    sync_fts,
)


REGISTRY_FILE = "registry.json"
_CASE_ID_RE = re.compile(r"^[0-9a-f]{8}$", re.IGNORECASE)


def _registry_path() -> Path:
    return get_cases_dir() / REGISTRY_FILE


def _load_registry() -> dict:
    path = _registry_path()
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"cases": {}}


def _save_registry(data: dict) -> None:
    path = _registry_path()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
    registry = _load_registry()
    if case_id not in registry.get("cases", {}):
        return None
    registry["cases"][case_id].update(kwargs)
    registry["cases"][case_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_registry(registry)
    if not include_stats:
        return registry["cases"][case_id]
    return {**registry["cases"][case_id], **get_case_stats(case_id)}


def delete_case(case_id: str) -> bool:
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
                pass
    return removed


def get_case_stats(case_id: str) -> dict:
    if not case_db_path(case_id).exists():
        return {"event_count": 0, "finding_count": 0, "process_count": 0}
    session = get_session(case_id)
    try:
        event_count = session.scalar(select(func.count()).select_from(Event)) or 0
        finding_count = session.scalar(select(func.count()).select_from(Finding)) or 0
        process_count = session.scalar(select(func.count()).select_from(Process)) or 0
        return {
            "event_count": event_count,
            "finding_count": finding_count,
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


def search_events(session: Session, query: str, limit: int = 50) -> list[Event]:
    rows = session.execute(
        text(
            """
            SELECT e.* FROM events e
            JOIN events_fts fts ON e.id = fts.rowid
            WHERE events_fts MATCH :q
            ORDER BY rank
            LIMIT :limit
            """
        ),
        {"q": query, "limit": limit},
    ).mappings().all()
    return [session.get(Event, r["id"]) for r in rows if r["id"]]


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


def save_chat(session: Session, role: str, content: str) -> None:
    session.add(ChatHistory(role=role, content=content))


def get_chat_history(session: Session, limit: int = 20) -> list[ChatHistory]:
    return list(
        session.scalars(
            select(ChatHistory).order_by(ChatHistory.created_at.desc()).limit(limit)
        )
    )[::-1]
