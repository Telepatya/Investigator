"""Manage uploaded evidence files: list them with ingestion stats, delete them
together with their derived data, and re-ingest them."""

from __future__ import annotations

import logging
import os
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, column, delete as sqldelete, func, or_, select, table

from app.config import UPLOAD_STAGING_PREFIX, case_uploads_path
from app.ingest.parsers import PARSABLE_EXTENSIONS, _source_from_member
from app.memory.forensics import memprocfs_artifact_dir, remove_memprocfs_artifacts
from app.memory.identity import is_memory_upload, memory_upload_key
from app.store import cases as case_store
from app.store.cases import _rmtree_with_retries
from app.store.database import Event, Finding, MemoryResult, Process, compact_db

logger = logging.getLogger(__name__)


class LegacyEvidenceAttributionError(ValueError):
    """Legacy rows cannot safely be assigned to one of several uploaded files."""


def _event_filter(session, path: Path):
    """Select exact upload rows plus only unambiguous legacy display sources."""
    sources = _effective_sources(session, path)
    legacy = and_(Event.upload_name.is_(None), Event.source.in_(sources))
    has_legacy = session.scalar(select(Event.id).where(legacy).limit(1)) is not None
    if has_legacy:
        other_sources: set[str] = set()
        for other in path.parent.iterdir():
            if other == path or not other.is_file() or other.name.startswith(UPLOAD_STAGING_PREFIX):
                continue
            other_sources.update(_sources_for_file(other))
            if other.suffix.lower() in PARSABLE_EXTENSIONS:
                other_sources.add(other.stem)
        if set(sources) & other_sources:
            raise LegacyEvidenceAttributionError(
                "Legacy events share source names with another upload. Preserve this "
                "case and import the evidence into a new case before deleting or "
                "re-ingesting either file."
            )
    return or_(Event.upload_name == path.name, legacy)


def _memory_filters(session, path: Path):
    legacy_events = and_(Event.upload_name.is_(None), or_(
        Event.source == f"mem-{path.stem}",
        Event.source.startswith(f"mem-{path.stem}:", autoescape=True),
        Event.source.startswith("memory:"),
    ))
    legacy_processes = and_(Process.upload_name.is_(None), Process.session_id == f"mem-{path.stem}")
    legacy_results = MemoryResult.upload_name.is_(None)
    others = [other for other in path.parent.iterdir() if other != path and other.is_file() and _kind(other) == "memory"]
    has_legacy = any(session.scalar(select(model.id).where(predicate).limit(1)) is not None
                     for model, predicate in ((Event, legacy_events), (Process, legacy_processes), (MemoryResult, legacy_results)))
    if others and has_legacy:
        raise LegacyEvidenceAttributionError(
            "Legacy memory results cannot be assigned to one of several dumps. "
            "Preserve this case and re-ingest the original evidence into a new case before replacing or deleting a dump."
        )
    return (
        or_(Event.upload_name == path.name, legacy_events),
        or_(Process.upload_name == path.name, legacy_processes),
        or_(MemoryResult.upload_name == path.name, legacy_results),
    )


def validate_purge_attribution(case_id: str, path: Path) -> None:
    """Validate an existing upload before a replacement changes its bytes."""
    if not path.is_file():
        return
    session = case_store.get_session(case_id)
    try:
        if _kind(path) == "memory":
            _memory_filters(session, path)
        else:
            _event_filter(session, path)
    finally:
        session.close()

def sanitize_upload_filename(filename: str | None) -> str | None:
    """Reduce a client-supplied filename to a bare basename so an upload can
    never escape the case uploads directory. Both separators are normalized so a
    Windows-style traversal ("..\\..\\x") is neutralized on POSIX too. Returns
    None for empty or dot-only names, which callers should reject."""
    name = Path((filename or "").replace("\\", "/")).name
    if not name or name in (".", ".."):
        return None
    return name


def _kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if is_memory_upload(path):
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
    if is_memory_upload(path):
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
    attributed = list(session.scalars(select(Event.source).where(Event.upload_name == path.name).distinct()))
    if attributed:
        return attributed
    sources = _sources_for_file(path)
    if not sources or is_memory_upload(path) or path.suffix.lower() == ".zip":
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
            if path.is_dir() or path.name.startswith(UPLOAD_STAGING_PREFIX):
                continue  # extracted zip contents
            kind = _kind(path)
            sources = _effective_sources(session, path)
            stat = path.stat()

            event_count = 0
            process_count = 0
            memory_count = 0
            attribution_warning = None
            if kind == "memory":
                try:
                    event_filter, process_filter, result_filter = _memory_filters(session, path)
                except LegacyEvidenceAttributionError:
                    event_filter = Event.upload_name == path.name
                    process_filter = Process.upload_name == path.name
                    result_filter = MemoryResult.upload_name == path.name
                    attribution_warning = "Legacy memory results have ambiguous upload attribution; counts include only attributed rows."
                event_count = session.scalar(select(func.count()).select_from(Event).where(event_filter)) or 0
                process_count = session.scalar(
                    select(func.count()).select_from(Process)
                    .where(process_filter)
                ) or 0
                memory_count = session.scalar(
                    select(func.count()).select_from(MemoryResult).where(result_filter)
                ) or 0
            else:
                # Ambiguous legacy counts must not be shown as a precise per-file
                # count. Exact attribution remains available for new uploads.
                try:
                    event_filter = _event_filter(session, path)
                except LegacyEvidenceAttributionError:
                    event_filter = Event.upload_name == path.name
                    attribution_warning = "Legacy events have ambiguous upload attribution; count includes only attributed events."
                event_count = session.scalar(
                    select(func.count()).select_from(Event).where(event_filter)
                ) or 0
                process_count = session.scalar(
                    select(func.count()).select_from(Process).where(Process.upload_name == path.name)
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
                "attribution_warning": attribution_warning,
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
        kind = _kind(path)

        if kind == "memory":
            event_filter, process_filter, result_filter = _memory_filters(session, path)
            removed["processes"] = session.execute(sqldelete(Process).where(process_filter)).rowcount
            removed["memory_results"] = session.execute(sqldelete(MemoryResult).where(result_filter)).rowcount
            fts = table("events_fts", column("rowid"))
            session.execute(sqldelete(fts).where(fts.c.rowid.in_(select(Event.id).where(event_filter))))
            removed["events"] = session.execute(sqldelete(Event).where(event_filter)).rowcount
            other_dumps = any(other != path and other.is_file() and _kind(other) == "memory" for other in path.parent.iterdir())
            case_store.update_case_meta(case_id, include_stats=False, has_memory_dump=other_dumps)
            remove_derived = True
        else:
            event_filter = _event_filter(session, path)
            event_ids = select(Event.id).where(event_filter)
            # FTS is an external-content table. Delete its matching rowids while
            # the content rows still exist, using the same trusted predicate.
            fts = table("events_fts", column("rowid"))
            session.execute(sqldelete(fts).where(fts.c.rowid.in_(event_ids)))
            removed["events"] = session.execute(
                sqldelete(Event).where(event_filter)
            ).rowcount
            removed["processes"] = session.execute(
                sqldelete(Process).where(Process.upload_name == path.name)
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
        keys = [memory_upload_key(path.name)]
        if not any(other != path and other.is_file() and other.stem == path.stem and _kind(other) == "memory" for other in path.parent.iterdir()):
            keys.append(path.stem)
        for key in keys:
            derived_dir = memprocfs_artifact_dir(case_id, key)
            existed = derived_dir.exists()
            remove_memprocfs_artifacts(case_id, key)
            removed["derived_artifacts"] += int(existed)

    compact_db(case_store.case_db_path(case_id))

    from app.detect.engine import run_detections_sync
    run_detections_sync(case_id)
    return removed


def replace_file_data(case_id: str, destination: Path, staged: Path) -> dict[str, int]:
    """Atomically replace one upload and purge rows from its prior generation.

    The database transaction is committed only after both same-directory file
    renames succeed.  If a delete, rename, or commit fails, the transaction is
    rolled back and the original evidence file is restored from its private
    backup before the error is returned to the ingestion manager.
    """
    if not destination.is_file() or not staged.is_file():
        raise FileNotFoundError("Evidence replacement inputs are no longer available")
    if destination.parent.resolve() != staged.parent.resolve():
        raise ValueError("Evidence replacement must remain in the upload directory")

    backup = destination.parent / f"{UPLOAD_STAGING_PREFIX}{uuid.uuid4().hex}.previous"
    session = case_store.get_session(case_id)
    removed = {"events": 0, "processes": 0, "memory_results": 0, "derived_artifacts": 0}
    kind = _kind(destination)
    committed = False
    moved_original = False
    try:
        if kind == "memory":
            event_filter, process_filter, result_filter = _memory_filters(session, destination)
            removed["processes"] = session.execute(sqldelete(Process).where(process_filter)).rowcount
            removed["memory_results"] = session.execute(sqldelete(MemoryResult).where(result_filter)).rowcount
        else:
            event_filter = _event_filter(session, destination)
            removed["processes"] = session.execute(
                sqldelete(Process).where(Process.upload_name == destination.name)
            ).rowcount

        fts = table("events_fts", column("rowid"))
        session.execute(sqldelete(fts).where(fts.c.rowid.in_(select(Event.id).where(event_filter))))
        removed["events"] = session.execute(sqldelete(Event).where(event_filter)).rowcount
        os.replace(destination, backup)
        moved_original = True
        os.replace(staged, destination)
        try:
            session.commit()
        except BaseException:
            session.rollback()
            # Replacing the new destination directly with the backup is one
            # atomic same-filesystem operation and cannot expose a missing file.
            os.replace(backup, destination)
            moved_original = False
            raise
        committed = True
    except BaseException:
        session.rollback()
        if moved_original and backup.exists():
            os.replace(backup, destination)
        raise
    finally:
        try:
            session.close()
        except Exception:
            if not committed:
                raise
            logger.warning("Could not close the committed evidence-replacement session", exc_info=True)
        if committed:
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove private evidence-replacement backup %s", backup)

    # These directories contain only reproducible derivatives. Cleanup occurs
    # after the file/database commit and cannot invalidate that committed pair.
    try:
        if kind == "memory":
            keys = [memory_upload_key(destination.name)]
            if not any(
                other != destination
                and other.is_file()
                and not other.name.startswith(UPLOAD_STAGING_PREFIX)
                and other.stem == destination.stem
                and _kind(other) == "memory"
                for other in destination.parent.iterdir()
            ):
                keys.append(destination.stem)
            for key in keys:
                derived_dir = memprocfs_artifact_dir(case_id, key)
                existed = derived_dir.exists()
                remove_memprocfs_artifacts(case_id, key)
                removed["derived_artifacts"] += int(existed)
        elif kind == "archive":
            extracted = destination.parent / f"{destination.stem}_extracted"
            if extracted.is_dir():
                _rmtree_with_retries(extracted)
    except Exception:
        logger.warning(
            "Could not remove all stale derived artifacts for %s",
            destination.name,
            exc_info=True,
        )

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
