"""Manage uploaded evidence files: list them with ingestion stats, delete them
together with their derived data, and re-ingest them."""

from __future__ import annotations

import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import bindparam, delete as sqldelete, func, select, text

from app.config import case_uploads_path
from app.ingest.parsers import PARSABLE_EXTENSIONS, _source_from_member
from app.ingest.pipeline import MEMORY_EXTENSIONS
from app.memory.forensics import memprocfs_artifact_dir, remove_memprocfs_artifacts
from app.store import cases as case_store
from app.store.cases import _rmtree_with_retries
from app.store.database import Event, Finding, MemoryResult, Process, compact_db


def _kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in MEMORY_EXTENSIONS:
        return "memory"
    if suffix == ".zip":
        return "archive"
    if suffix in (".evtx",):
        return "eventlog"
    if suffix in (".txt", ".log"):
        return "textlog"
    if suffix in PARSABLE_EXTENSIONS:
        return "artifact"
    return "other"


def _sources_for_file(path: Path) -> list[str]:
    """Event `source` values that ingestion derived from this file."""
    suffix = path.suffix.lower()
    if suffix in MEMORY_EXTENSIONS:
        return [f"mem-{path.stem}"]
    if suffix == ".zip":
        try:
            with zipfile.ZipFile(path) as zf:
                return sorted({
                    _source_from_member(Path(i.filename))
                    for i in zf.infolist()
                    if not i.is_dir() and Path(i.filename).suffix.lower() in PARSABLE_EXTENSIONS
                })
        except (zipfile.BadZipFile, OSError):
            return []
    if suffix in PARSABLE_EXTENSIONS:
        return [path.name]
    return []


def _effective_sources(session, path: Path) -> list[str]:
    """Sources for this file, falling back to the legacy stem naming for data
    ingested before sources used the full filename."""
    sources = _sources_for_file(path)
    if not sources or path.suffix.lower() in MEMORY_EXTENSIONS or path.suffix.lower() == ".zip":
        return sources
    count = session.scalar(
        select(func.count()).select_from(Event).where(Event.source.in_(sources))
    ) or 0
    if count == 0:
        return [path.stem]
    return sources


def list_evidence(case_id: str) -> list[dict[str, Any]]:
    uploads = case_uploads_path(case_id)
    session = case_store.get_session(case_id)
    try:
        items: list[dict[str, Any]] = []
        for path in sorted(uploads.iterdir()):
            if path.is_dir():
                continue  # extracted zip contents
            kind = _kind(path)
            sources = _effective_sources(session, path)
            stat = path.stat()

            event_count = 0
            process_count = 0
            memory_count = 0
            if kind == "memory":
                process_count = session.scalar(
                    select(func.count()).select_from(Process)
                    .where(Process.session_id == f"mem-{path.stem}")
                ) or 0
                memory_count = session.scalar(
                    select(func.count()).select_from(MemoryResult)
                ) or 0
            elif sources:
                event_count = session.scalar(
                    select(func.count()).select_from(Event).where(Event.source.in_(sources))
                ) or 0

            items.append({
                "name": path.name,
                "kind": kind,
                "size": stat.st_size,
                "uploaded_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "sources": sources,
                "event_count": event_count,
                "process_count": process_count,
                "memory_result_count": memory_count,
            })
        return items
    finally:
        session.close()


def _resolve(case_id: str, name: str) -> Path | None:
    uploads = case_uploads_path(case_id)
    path = (uploads / Path(name).name).resolve()
    if not str(path).startswith(str(uploads.resolve())) or not path.is_file():
        return None
    return path


def purge_file_data(case_id: str, path: Path) -> dict[str, int]:
    """Remove all DB data derived from one evidence file, then rebuild findings."""
    session = case_store.get_session(case_id)
    removed = {"events": 0, "processes": 0, "memory_results": 0, "derived_artifacts": 0}
    remove_derived = False
    try:
        sources = _effective_sources(session, path)
        kind = _kind(path)

        if kind == "memory":
            removed["processes"] = session.execute(
                sqldelete(Process).where(Process.session_id == f"mem-{path.stem}")
            ).rowcount
            # memory results are not attributed per-dump; clear them with the dump
            removed["memory_results"] = session.execute(sqldelete(MemoryResult)).rowcount
            prefix = f"mem-{path.stem}:%"
            session.execute(
                text(
                    "DELETE FROM events_fts WHERE rowid IN "
                    "(SELECT id FROM events WHERE source IN :sources "
                    "OR source LIKE :prefix OR source LIKE 'memory:%')"
                ).bindparams(bindparam("sources", expanding=True)),
                {"sources": sources, "prefix": prefix},
            )
            removed["events"] = session.execute(
                text(
                    "DELETE FROM events WHERE source IN :sources "
                    "OR source LIKE :prefix OR source LIKE 'memory:%'"
                ).bindparams(bindparam("sources", expanding=True)),
                {"sources": sources, "prefix": prefix},
            ).rowcount
            case_store.update_case_meta(case_id, include_stats=False, has_memory_dump=False)
            remove_derived = True
        elif sources:
            session.execute(
                text("DELETE FROM events_fts WHERE rowid IN "
                     "(SELECT id FROM events WHERE source IN :sources)")
                .bindparams(bindparam("sources", expanding=True)),
                {"sources": sources},
            )
            removed["events"] = session.execute(
                sqldelete(Event).where(Event.source.in_(sources))
            ).rowcount

        # findings are not linked to sources; rebuild them from remaining data
        session.execute(sqldelete(Finding))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    if remove_derived:
        derived_dir = memprocfs_artifact_dir(case_id, path.stem)
        existed = derived_dir.exists()
        remove_memprocfs_artifacts(case_id, path.stem)
        removed["derived_artifacts"] = 1 if existed else 0

    compact_db(case_store.case_db_path(case_id))

    from app.detect.engine import run_detections_sync
    run_detections_sync(case_id)
    return removed


def delete_evidence(case_id: str, name: str) -> dict[str, Any] | None:
    path = _resolve(case_id, name)
    if not path:
        return None
    removed = purge_file_data(case_id, path)
    if path.suffix.lower() == ".zip":
        extracted = path.parent / f"{path.stem}_extracted"
        if extracted.is_dir():
            _rmtree_with_retries(extracted)
    path.unlink(missing_ok=True)
    return {"ok": True, "removed": removed}


def prepare_reingest(case_id: str, name: str) -> Path | None:
    """Purge a file's derived data so it can be ingested again. Returns the path."""
    path = _resolve(case_id, name)
    if not path:
        return None
    purge_file_data(case_id, path)
    return path
