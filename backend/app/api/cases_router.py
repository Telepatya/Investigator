"""Case management, upload, ingestion, and data query endpoints."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

import aiofiles
from fastapi import APIRouter, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy import delete as sqldelete, func, select, update as sqlupdate

from app.api.security import authorize_ws
from app.config import (
    UPLOAD_STAGING_PREFIX,
    case_dir_path,
    case_upload_file_path,
    case_uploads_path,
    validate_case_id_component,
)
from app.detect import overrides
from app.detect.entity_graph import build_entity_graph, entity_dossier
from app.detect.process_tree import build_tree, list_sessions, process_dossier
from app.ingest import evidence as evidence_store
from app.ingest.pipeline import manager
from app.memory.explorer import (
    MemoryExplorerError,
    archive_vfs_selection,
    extract_process_image,
    extract_process_module,
    extract_vfs_file,
    list_memory_dumps,
    list_process_handles,
    list_process_modules,
    list_vfs,
)
from app.models.schemas import CaseCreate
from app.store import cases as case_store
from app.store.database import Event, Finding, MemoryResult
from app.store.operations import coordinator

router = APIRouter(prefix="/api/cases", tags=["cases"])
_MEMORY_SESSION_RE = re.compile(r"^mem-[A-Za-z0-9][A-Za-z0-9_. ()%-]{0,254}$")
_UPLOAD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ ()%+-]{0,254}$")


def _validated_case_id(case_id: str) -> str:
    try:
        validated = validate_case_id_component(case_id)
    except ValueError as exc:
        raise HTTPException(404, "Case not found") from exc
    if not case_store.case_exists(validated):
        raise HTTPException(404, "Case not found")
    return validated


def _safe_upload_name(filename: str | None) -> str:
    """Validate/normalize a client filename to a safe basename or 400."""
    name = evidence_store.sanitize_upload_filename(filename)
    if name is None or not _UPLOAD_NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid filename")
    return name


def _upload_destination(case_id: str, filename: str | None) -> tuple[str, Path]:
    """Resolve an upload to a direct child of its validated case directory."""
    validated_case_id = _validated_case_id(case_id)
    safe_name = _safe_upload_name(filename)
    try:
        destination = case_upload_file_path(validated_case_id, safe_name)
    except ValueError as exc:
        raise HTTPException(400, "Invalid filename") from exc
    # Re-verify containment at the request boundary so the resolved write target
    # cannot escape the case uploads directory before it reaches a file sink.
    uploads_root = os.path.realpath(case_uploads_path(validated_case_id))
    if not os.path.realpath(destination).startswith(uploads_root + os.sep):
        raise HTTPException(400, "Invalid filename")
    return safe_name, destination


def _validated_memory_session_id(session_id: str) -> str:
    if not _MEMORY_SESSION_RE.fullmatch(session_id):
        raise HTTPException(400, "Invalid memory session")
    return session_id


def _memory_file_response(
    case_id: str, local: Path, media_type: str = "application/octet-stream",
) -> FileResponse:
    """Serve only regular files generated inside the validated case directory."""
    case_root = case_dir_path(_validated_case_id(case_id))
    try:
        resolved = local.resolve(strict=True)
    except OSError as exc:
        raise HTTPException(404, "Generated file not found") from exc
    try:
        resolved.relative_to(case_root)
    except ValueError as exc:
        raise HTTPException(500, "Generated file escaped the case directory") from exc
    if not resolved.is_file():
        raise HTTPException(404, "Generated file not found")
    return FileResponse(
        str(resolved), media_type=media_type, filename=resolved.name,
    )


@router.get("")
def get_cases() -> list[dict]:
    return case_store.list_cases()


@router.post("")
def create_case(body: CaseCreate) -> dict:
    return case_store.create_case(body.name, body.description)


@router.get("/{case_id}")
def get_case(case_id: str) -> dict:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.delete("/{case_id}")
async def delete_case(case_id: str) -> dict:
    if not await asyncio.to_thread(case_store.case_exists, case_id):
        raise HTTPException(404, "Case not found")
    async with coordinator.run(case_id, "case deletion"):
        _discard_case_uploads(case_id)
        if not await asyncio.to_thread(case_store.delete_case, case_id):
            raise HTTPException(404, "Case not found")
    return {"ok": True}


# Upload ceilings so a single file or a runaway case cannot exhaust local disk.
# Memory dumps are legitimately huge, so the per-file cap is generous and both
# limits are overridable via the environment for large-RAM targets.
MAX_UPLOAD_BYTES = int(os.environ.get("INVESTIGATOR_MAX_UPLOAD_BYTES", str(64 * 1024 ** 3)))
MAX_CASE_BYTES = int(os.environ.get("INVESTIGATOR_MAX_CASE_BYTES", str(256 * 1024 ** 3)))


@dataclass
class _ChunkUploadState:
    part_path: Path
    total_chunks: int
    next_index: int
    bytes_written: int
    file_type: str
    mem_forensic_timeline: bool
    mem_eventlogs: bool


_CHUNK_UPLOADS: dict[tuple[str, str], _ChunkUploadState] = {}


def _uploads_total_bytes(case_id: str) -> int:
    """Return committed evidence bytes, excluding private staging files."""
    total = 0
    for path in case_uploads_path(case_id).iterdir():
        try:
            if path.is_file() and not path.name.startswith(UPLOAD_STAGING_PREFIX):
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _remove_partial(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _staging_path(destination: Path, suffix: str) -> Path:
    return destination.parent / f"{UPLOAD_STAGING_PREFIX}{uuid.uuid4().hex}.{suffix}"


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def _discard_chunk_upload(case_id: str, safe_name: str) -> None:
    state = _CHUNK_UPLOADS.pop((case_id, safe_name), None)
    if state is not None:
        _remove_partial(state.part_path)


def _discard_case_uploads(case_id: str) -> None:
    for state_key in [key for key in _CHUNK_UPLOADS if key[0] == case_id]:
        state = _CHUNK_UPLOADS.pop(state_key)
        _remove_partial(state.part_path)


def _append_staged_chunk(part_path: Path, chunk_path: Path, expected_size: int) -> None:
    """Append one validated chunk, restoring the prior length on write failure."""
    try:
        with open(part_path, "ab") as part, open(chunk_path, "rb") as chunk:
            shutil.copyfileobj(chunk, part, length=4 * 1024 * 1024)
    except BaseException:
        try:
            with open(part_path, "r+b") as part:
                part.truncate(expected_size)
        except OSError:
            pass
        raise


def _truncate_file(path: Path, size: int) -> None:
    with open(path, "r+b") as handle:
        handle.truncate(size)


async def _stage_upload(
    upload: UploadFile,
    target: Path,
    *,
    existing_file_bytes: int,
    other_case_bytes: int,
) -> int:
    """Stream to a private file while enforcing projected file and case sizes."""
    request_bytes = 0
    async with aiofiles.open(target, "wb") as out:
        while True:
            chunk = await upload.read(4 * 1024 * 1024)
            if not chunk:
                break
            projected_file_bytes = existing_file_bytes + request_bytes + len(chunk)
            if projected_file_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "Upload exceeds the per-file size limit")
            if other_case_bytes + projected_file_bytes > MAX_CASE_BYTES:
                raise HTTPException(
                    413, "Case storage limit reached; delete evidence before uploading more",
                )
            await out.write(chunk)
            request_bytes += len(chunk)
    return request_bytes


@router.post("/{case_id}/upload")
async def upload_file(
    case_id: str,
    file: UploadFile,
    file_type: str = "artifact",
    mem_forensic_timeline: bool = False,
    mem_eventlogs: bool = False,
) -> dict:
    validated_case_id = _validated_case_id(case_id)
    safe_name = _safe_upload_name(file.filename)
    async with coordinator.run(validated_case_id, "evidence upload"):
        safe_name, dest = _upload_destination(validated_case_id, safe_name)
        _discard_chunk_upload(validated_case_id, safe_name)
        staging = _staging_path(dest, "part")
        committed = False
        try:
            total = await asyncio.to_thread(_uploads_total_bytes, validated_case_id)
            replaced_size = await asyncio.to_thread(_file_size, dest)
            await _stage_upload(
                file,
                staging,
                existing_file_bytes=0,
                other_case_bytes=max(total - replaced_size, 0),
            )
            await asyncio.to_thread(os.replace, staging, dest)
            committed = True
        finally:
            if not committed:
                await asyncio.to_thread(_remove_partial, staging)

    # kick off ingestion in the background
    memory_options = {
        "forensic_timeline": bool(mem_forensic_timeline),
        "eventlogs": bool(mem_eventlogs),
    }
    asyncio.create_task(manager.run_ingestion(validated_case_id, dest, file_type, memory_options))
    return {"ok": True, "filename": safe_name, "path": str(dest)}


@router.post("/{case_id}/upload-chunk")
async def upload_chunk(
    case_id: str,
    file: UploadFile,
    filename: str,
    chunk_index: int,
    total_chunks: int,
    file_type: str = "artifact",
    mem_forensic_timeline: bool = False,
    mem_eventlogs: bool = False,
) -> dict:
    """Chunked upload for multi-GB memory dumps."""
    if total_chunks < 1 or chunk_index < 0 or chunk_index >= total_chunks:
        raise HTTPException(400, "Invalid chunk sequence")
    validated_case_id = _validated_case_id(case_id)
    safe_name = _safe_upload_name(filename)
    complete = False
    async with coordinator.run(validated_case_id, "chunked evidence upload"):
        safe_name, dest = _upload_destination(validated_case_id, safe_name)
        state_key = (validated_case_id, safe_name)
        if chunk_index == 0:
            _discard_chunk_upload(*state_key)
            part_path = _staging_path(dest, "parts")
            await asyncio.to_thread(part_path.touch)
            state = _ChunkUploadState(
                part_path=part_path,
                total_chunks=total_chunks,
                next_index=0,
                bytes_written=0,
                file_type=file_type,
                mem_forensic_timeline=bool(mem_forensic_timeline),
                mem_eventlogs=bool(mem_eventlogs),
            )
            _CHUNK_UPLOADS[state_key] = state
        else:
            state = _CHUNK_UPLOADS.get(state_key)
            if state is None:
                raise HTTPException(409, "Chunk received out of order; restart the upload")

        metadata = (
            total_chunks,
            file_type,
            bool(mem_forensic_timeline),
            bool(mem_eventlogs),
        )
        expected_metadata = (
            state.total_chunks,
            state.file_type,
            state.mem_forensic_timeline,
            state.mem_eventlogs,
        )
        if metadata != expected_metadata:
            raise HTTPException(409, "Upload metadata changed; restart the upload")
        if chunk_index != state.next_index:
            raise HTTPException(
                409, f"Expected chunk {state.next_index}; received chunk {chunk_index}",
            )

        request_staging = _staging_path(dest, "chunk")
        try:
            total = await asyncio.to_thread(_uploads_total_bytes, validated_case_id)
            replaced_size = await asyncio.to_thread(_file_size, dest)
            chunk_bytes = await _stage_upload(
                file,
                request_staging,
                existing_file_bytes=state.bytes_written,
                other_case_bytes=max(total - replaced_size, 0),
            )
            if chunk_bytes == 0:
                raise HTTPException(400, "Upload chunks must not be empty")
            await asyncio.to_thread(
                _append_staged_chunk,
                state.part_path,
                request_staging,
                state.bytes_written,
            )
            if chunk_index + 1 == state.total_chunks:
                try:
                    await asyncio.to_thread(os.replace, state.part_path, dest)
                except BaseException:
                    await asyncio.to_thread(_truncate_file, state.part_path, state.bytes_written)
                    raise
                _CHUNK_UPLOADS.pop(state_key, None)
                complete = True
            else:
                state.bytes_written += chunk_bytes
                state.next_index += 1
        finally:
            await asyncio.to_thread(_remove_partial, request_staging)

    if complete:
        memory_options = {
            "forensic_timeline": state.mem_forensic_timeline,
            "eventlogs": state.mem_eventlogs,
        }
        asyncio.create_task(
            manager.run_ingestion(validated_case_id, dest, state.file_type, memory_options),
        )
        return {"ok": True, "complete": True, "filename": safe_name}
    return {"ok": True, "complete": False, "chunk_index": chunk_index}


@router.get("/{case_id}/evidence")
def list_evidence(case_id: str) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    return {"files": evidence_store.list_evidence(case_id)}


@router.delete("/{case_id}/evidence/{name}")
async def delete_evidence(case_id: str, name: str) -> dict:
    if not await asyncio.to_thread(case_store.get_case, case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
    async with coordinator.run(case_id, "evidence deletion"):
        safe_name = evidence_store.sanitize_upload_filename(name)
        if safe_name:
            _discard_chunk_upload(case_id, safe_name)
        result = await loop.run_in_executor(None, evidence_store.delete_evidence, case_id, name)
    if result is None:
        raise HTTPException(404, "Evidence file not found")
    return result


@router.post("/{case_id}/evidence/{name}/reingest")
async def reingest_evidence(case_id: str, name: str, file_type: str = "artifact") -> dict:
    if not await asyncio.to_thread(case_store.get_case, case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
    async with coordinator.run(case_id, "evidence preparation"):
        path = await loop.run_in_executor(None, evidence_store.prepare_reingest, case_id, name)
    if path is None:
        raise HTTPException(404, "Evidence file not found")
    asyncio.create_task(manager.run_ingestion(case_id, path, file_type))
    return {"ok": True, "filename": path.name}


@router.get("/{case_id}/ingestion-status")
async def ingestion_status(case_id: str) -> dict:
    status = manager.get_status(case_id)
    return status or {"case_id": case_id, "phase": "idle", "percent": 0, "message": "", "done": True}


@router.websocket("/{case_id}/ingestion-ws")
async def ingestion_ws(websocket: WebSocket, case_id: str) -> None:
    if not await authorize_ws(websocket, case_id):
        return
    await websocket.accept()
    queue = manager.subscribe(case_id)
    try:
        # send current status immediately
        current = manager.get_status(case_id)
        if current:
            await websocket.send_json(current)
        while True:
            payload = await queue.get()
            await websocket.send_json(payload)
            if payload.get("done"):
                # keep open a moment for final message delivery
                pass
    except WebSocketDisconnect:
        return
    finally:
        manager.unsubscribe(case_id, queue)


# --- Data queries ---

@router.get("/{case_id}/events")
def get_events(
    case_id: str,
    q: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    session = case_store.get_session(case_id)
    try:
        from app.detect import manual
        if manual.ensure_manual_findings_applied(session):
            session.commit()
        stmt = select(Event)
        count_stmt = select(func.count()).select_from(Event)
        if category:
            stmt = stmt.where(Event.category == category)
            count_stmt = count_stmt.where(Event.category == category)
        if severity:
            stmt = stmt.where(Event.severity == severity)
            count_stmt = count_stmt.where(Event.severity == severity)
        if q and q.strip():
            # Plain case-insensitive "contains" match (not FTS token/prefix
            # matching, which made "g" and "github" behave differently), applied
            # on top of the category/severity filters so they combine.
            like = f"%{q.strip()}%"
            cond = (
                Event.summary.ilike(like)
                | Event.entity.ilike(like)
                | Event.source.ilike(like)
                | Event.category.ilike(like)
                | Event.severity_reason.ilike(like)
            )
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)
        stmt = stmt.order_by(Event.timestamp.desc().nullslast()).limit(limit).offset(offset)
        events = list(session.scalars(stmt))
        # Count reflects the active filters so the UI's "showing X of N" is correct.
        total = session.scalar(count_stmt) or 0
        return {
            "total": total,
            "events": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "host": e.host, "source": e.source, "category": e.category,
                    "entity": e.entity, "severity": e.severity,
                    "severity_reason": e.severity_reason, "summary": e.summary,
                    "raw": e.raw,
                }
                for e in events
            ],
        }
    finally:
        session.close()


@router.get("/{case_id}/events/{event_id}")
def get_event(case_id: str, event_id: int) -> dict:
    if not case_store.case_exists(case_id):
        raise HTTPException(404, "Case not found")
    session = case_store.get_session(case_id)
    try:
        event = session.get(Event, event_id)
        if event is None:
            raise HTTPException(404, "Event not found")
        return {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "host": event.host,
            "source": event.source,
            "category": event.category,
            "entity": event.entity,
            "severity": event.severity,
            "severity_reason": event.severity_reason,
            "summary": event.summary,
            "raw": event.raw,
        }
    finally:
        session.close()


_SEVERITY_LADDER = ["info", "low", "medium", "high", "critical"]


@router.get("/{case_id}/timeline")
def get_timeline(
    case_id: str,
    limit: int = 2000,
    sources: str | None = None,
    categories: str | None = None,
    q: str | None = None,
    min_severity: str = "info",
    include_facets: bool = True,
) -> dict:
    session = case_store.get_session(case_id)
    try:
        from app.detect import manual
        if manual.ensure_manual_findings_applied(session):
            session.commit()
        filters = [Event.timestamp.isnot(None)]
        if sources is not None:
            wanted = [s for s in sources.split(",") if s]
            filters.append(Event.source.in_(wanted))
        if categories is not None:
            wanted_cats = [c for c in categories.split(",") if c]
            filters.append(Event.category.in_(wanted_cats))
        if min_severity in _SEVERITY_LADDER and min_severity != "info":
            allowed = _SEVERITY_LADDER[_SEVERITY_LADDER.index(min_severity):]
            filters.append(Event.severity.in_(allowed))
        if q and q.strip():
            like = f"%{q.strip()}%"
            filters.append(
                Event.summary.ilike(like)
                | Event.entity.ilike(like)
                | Event.source.ilike(like)
                | Event.category.ilike(like)
                | Event.severity_reason.ilike(like)
            )
        stmt = select(
            Event.id,
            Event.timestamp,
            Event.summary,
            Event.category,
            Event.severity,
            Event.severity_reason,
            Event.source,
        ).where(*filters)
        total_matching = session.scalar(select(func.count()).select_from(Event).where(*filters)) or 0
        events = list(session.execute(stmt.order_by(Event.timestamp).limit(limit)))
        source_rows = []
        category_rows = []
        if include_facets:
            # These case-wide facets are stable across filter changes. The client
            # requests them once, then omits them from rapid search/filter refreshes.
            source_rows = session.execute(
                select(Event.source, func.count())
                .where(Event.timestamp.isnot(None))
                .group_by(Event.source)
                .order_by(func.count().desc())
            ).all()
            category_rows = session.execute(
                select(Event.category, func.count())
                .where(Event.timestamp.isnot(None))
                .group_by(Event.category)
                .order_by(func.count().desc())
            ).all()
            total = sum(r[1] for r in source_rows)
        else:
            total = session.scalar(
                select(func.count()).select_from(Event).where(Event.timestamp.isnot(None))
            ) or 0
        return {
            "total": total,
            "total_matching": total_matching,
            "sources": [{"name": r[0], "count": r[1]} for r in source_rows],
            "categories": [{"name": r[0], "count": r[1]} for r in category_rows],
            "events": [
                {
                    "id": e.id,
                    "start": e.timestamp.isoformat() if e.timestamp else None,
                    "content": (e.summary or "")[:120],
                    "group": e.category,
                    "severity": e.severity,
                    "severity_reason": e.severity_reason,
                    "source": e.source,
                }
                for e in events
            ],
        }
    finally:
        session.close()


@router.get("/{case_id}/categories")
def get_categories(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        rows = session.execute(
            select(Event.category, func.count()).group_by(Event.category)
        ).all()
        return {"categories": [{"name": r[0], "count": r[1]} for r in rows]}
    finally:
        session.close()


@router.get("/{case_id}/findings")
def get_findings(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        findings = list(session.scalars(select(Finding)))
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda f: order.get(f.severity, 0), reverse=True)
        disabled = overrides.get_disabled_rules(session)
        benign = overrides.get_benign_keys(session)
        out = [_serialize_finding(session, f, disabled, benign) for f in findings]
        return {"findings": out, "disabled_rules": sorted(disabled)}
    finally:
        session.close()


def _serialize_finding(session, f: Finding, disabled=None, benign=None) -> dict:
    disabled = overrides.get_disabled_rules(session) if disabled is None else disabled
    benign = overrides.get_benign_keys(session) if benign is None else benign
    rid = overrides.rule_id_for(f.title, f.source)
    reason = overrides.is_suppressed(f.title, f.source, f.evidence, disabled, benign)
    ev = f.evidence or {}
    return {
        "id": f.id, "title": f.title, "description": f.description,
        "severity": f.severity, "mitre_techniques": f.mitre_techniques,
        "evidence": f.evidence, "source": f.source, "ai_verdict": f.ai_verdict,
        "created_at": f.created_at.isoformat(), "rule_id": rid,
        "suppressed": reason is not None, "suppressed_reason": reason,
        "suppression_details": overrides.get_suppression_details(session, f),
        "benign": overrides.finding_key(f.title, f.evidence) in benign,
        "rule_disabled": rid in disabled,
        "manual": bool(f.source == "manual" or ev.get("manual")),
        "manual_id": ev.get("manual_id"),
    }


@router.get("/{case_id}/findings/{finding_id}")
def get_finding(case_id: str, finding_id: int) -> dict:
    session = case_store.get_session(case_id)
    try:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        return _serialize_finding(session, finding)
    finally:
        session.close()


@router.post("/{case_id}/findings/{finding_id}/benign")
def set_finding_benign(case_id: str, finding_id: int, body: dict) -> dict:
    """Mark a single finding benign (severity -> info) or restore it."""
    benign = bool(body.get("benign", True))
    session = case_store.get_session(case_id)
    try:
        f = session.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "Finding not found")
        manual_finding = bool(f.source == "manual" or (f.evidence or {}).get("manual"))
        overrides.set_finding_benign(
            session,
            overrides.finding_key(f.title, f.evidence),
            benign,
            actor="analyst",
            rationale=str(body.get("rationale") or "Analyst marked this finding benign"),
        )
        if manual_finding:
            from app.detect import manual
            manual.apply_manual_findings(session)
        overrides.apply_overrides(session)
        session.commit()
        return {"ok": True, "finding_id": finding_id, "benign": benign}
    finally:
        session.close()


@router.post("/{case_id}/rules/disable")
def set_rule_disabled(case_id: str, body: dict) -> dict:
    """Disable a detection rule (all its findings -> info) or re-enable it."""
    rule_id = str(body.get("rule_id") or "").strip()
    if not rule_id:
        raise HTTPException(400, "rule_id required")
    disabled = bool(body.get("disabled", True))
    session = case_store.get_session(case_id)
    try:
        rules = overrides.set_rule_disabled(session, rule_id, disabled)
        overrides.apply_overrides(session)
        session.commit()
        return {"ok": True, "rule_id": rule_id, "disabled": disabled, "disabled_rules": sorted(rules)}
    finally:
        session.close()


@router.post("/{case_id}/findings/manual")
def add_manual_finding(case_id: str, body: dict) -> dict:
    """Analyst-created finding for an event or entity, tagged manual and
    persisted so it survives detection rebuilds."""
    from app.detect import manual
    if not case_store.case_exists(case_id):
        raise HTTPException(404, "Case not found")
    title = str(body.get("title") or "").strip()
    severity = str(body.get("severity") or "").strip().lower()
    if not title:
        raise HTTPException(400, "title required")
    if severity not in manual.SEVERITIES:
        raise HTTPException(400, "invalid severity")
    mitre = body.get("mitre_techniques")
    ref_type = str(body.get("ref_type") or "")
    ref_id = str(body.get("ref_id") or "")
    ref_label = str(body.get("ref_label") or "")
    session = case_store.get_session(case_id)
    try:
        # Decide which map node this finding materialises, and what to link it to.
        # Entity flags target the entity itself; event flags derive the node and
        # its correlations from the referenced event so a new node is not floating.
        node_type = ""
        node_value = ""
        links: list = []
        if ref_type == "entity":
            node_type = str(body.get("entity_type") or "")
            node_value = str(body.get("ref_entity") or ref_label)
        elif ref_type == "event" and ref_id.isdigit():
            ev = session.get(Event, int(ref_id))
            if ev is not None:
                node_type, node_value, links = manual.derive_event_node(ev)
        item = manual.add_manual_finding(
            session,
            title=title,
            severity=severity,
            description=str(body.get("description") or ""),
            mitre_techniques=mitre if isinstance(mitre, list) else [],
            ref_type=ref_type,
            ref_id=ref_id,
            ref_label=ref_label,
            node_type=node_type,
            node_value=node_value,
            links=links,
        )
        manual.apply_manual_findings(session)
        overrides.apply_overrides(session)
        session.commit()
        return {"ok": True, "manual_id": item["id"]}
    finally:
        session.close()


@router.delete("/{case_id}/findings/manual/{manual_id}")
def delete_manual_finding(case_id: str, manual_id: str) -> dict:
    """Remove an analyst-created finding (does not touch detector findings)."""
    from app.detect import manual
    if not case_store.case_exists(case_id):
        raise HTTPException(404, "Case not found")
    session = case_store.get_session(case_id)
    try:
        removed = manual.remove_manual_finding(session, manual_id)
        manual.apply_manual_findings(session)
        overrides.apply_overrides(session)
        session.commit()
        return {"ok": True, "removed": removed}
    finally:
        session.close()


@router.post("/{case_id}/detections/run")
async def run_detections(case_id: str, rebuild: bool = True) -> dict:
    if not await asyncio.to_thread(case_store.get_case, case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
    from app.detect.engine import run_detections_sync

    def _run() -> int:
        if rebuild:
            from app.detect import manual
            session = case_store.get_session(case_id)
            try:
                manual.restore_manual_event_severities(session)
                session.execute(sqldelete(Finding))
                session.execute(
                    sqlupdate(Event)
                    .where(
                        (Event.severity_reason.like("Detection:%"))
                        | (Event.severity_reason.like("Context:%"))
                        | (Event.severity_reason.like("Flagged-entity match:%"))
                    )
                    .values(severity="info", severity_reason=None)
                )
                session.commit()
            finally:
                session.close()
        return run_detections_sync(case_id)

    async with coordinator.run(case_id, "detection rebuild"):
        added = await loop.run_in_executor(None, _run)
    return {"ok": True, "added": added, "rebuild": rebuild}


@router.get("/{case_id}/attack-matrix")
def get_attack_matrix(case_id: str) -> dict:
    from app.detect.rules import MITRE_TECHNIQUE_NAMES
    session = case_store.get_session(case_id)
    try:
        findings = list(session.scalars(select(Finding)))
        counts: dict[str, dict] = {}
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for f in findings:
            for t in f.mitre_techniques:
                if t not in counts:
                    counts[t] = {
                        "technique": t,
                        "name": MITRE_TECHNIQUE_NAMES.get(t, t),
                        "count": 0, "max_severity": "info",
                    }
                counts[t]["count"] += 1
                if order.get(f.severity, 0) > order.get(counts[t]["max_severity"], 0):
                    counts[t]["max_severity"] = f.severity
        return {"techniques": list(counts.values())}
    finally:
        session.close()


@router.get("/{case_id}/processes/sessions")
def get_process_sessions(case_id: str) -> dict:
    return {"sessions": list_sessions(case_id)}


@router.get("/{case_id}/processes/tree")
def get_process_tree(case_id: str, session_id: str | None = None) -> dict:
    return build_tree(case_id, session_id)


@router.get("/{case_id}/processes/{session_id}/{pid}")
def get_process_dossier(case_id: str, session_id: str, pid: int) -> dict:
    dossier = process_dossier(case_id, session_id, pid)
    if not dossier:
        raise HTTPException(404, "Process not found")
    return dossier


@router.get("/{case_id}/entities")
def get_entities(
    case_id: str,
    types: str | None = None,
    min_severity: str = "info",
    max_nodes: int = 300,
) -> dict:
    type_list = [t for t in types.split(",") if t] if types else None
    return build_entity_graph(case_id, entity_types=type_list, min_severity=min_severity, max_nodes=max_nodes)


@router.get("/{case_id}/entity-dossier")
def get_entity_dossier(case_id: str, entity_id: str) -> dict:
    dossier = entity_dossier(case_id, entity_id)
    if not dossier:
        raise HTTPException(404, "Entity not found")
    return dossier


@router.get("/{case_id}/memory")
def get_memory_results(case_id: str, plugin: str | None = None) -> dict:
    session = case_store.get_session(case_id)
    try:
        stmt = select(MemoryResult)
        if plugin:
            stmt = stmt.where(MemoryResult.plugin == plugin)
        results = list(session.scalars(stmt))
        plugins = session.execute(
            select(MemoryResult.plugin, func.count()).group_by(MemoryResult.plugin)
        ).all()
        return {
            "plugins": [{"name": r[0], "count": r[1]} for r in plugins],
            "results": [
                {
                    "id": m.id, "plugin": m.plugin, "pid": m.pid,
                    "process_name": m.process_name, "summary": m.summary,
                    "data": m.data, "severity": m.severity,
                }
                for m in results
            ],
        }
    finally:
        session.close()


@router.get("/{case_id}/memory/dumps")
def get_memory_dumps(case_id: str) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    return {"dumps": list_memory_dumps(case_id)}


@router.get("/{case_id}/memory/{session_id}/vfs")
def get_memory_vfs(case_id: str, session_id: str, path: str = "/") -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        return list_vfs(case_id, session_id, path)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/vfs/download")
def download_memory_vfs_file(case_id: str, session_id: str, path: str) -> FileResponse:
    validated_case_id = _validated_case_id(case_id)
    validated_session_id = _validated_memory_session_id(session_id)
    try:
        local = extract_vfs_file(validated_case_id, validated_session_id, path)
        return _memory_file_response(validated_case_id, local)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.post("/{case_id}/memory/{session_id}/vfs/archive")
def archive_memory_vfs(case_id: str, session_id: str, body: dict) -> FileResponse:
    validated_case_id = _validated_case_id(case_id)
    validated_session_id = _validated_memory_session_id(session_id)
    paths = body.get("paths") if isinstance(body, dict) else None
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise HTTPException(400, "Expected JSON body with string paths")
    try:
        local = archive_vfs_selection(validated_case_id, validated_session_id, paths)
        return _memory_file_response(validated_case_id, local, media_type="application/zip")
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/modules")
def get_memory_process_modules(case_id: str, session_id: str, pid: int) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        return list_process_modules(case_id, session_id, pid)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/handles")
def get_memory_process_handles(
    case_id: str,
    session_id: str,
    pid: int,
    type: str | None = None,
    limit: int = 300,
    offset: int = 0,
) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        return list_process_handles(case_id, session_id, pid, handle_type=type, limit=limit, offset=offset)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/download")
def download_memory_process(case_id: str, session_id: str, pid: int, kind: str = "image") -> FileResponse:
    validated_case_id = _validated_case_id(case_id)
    validated_session_id = _validated_memory_session_id(session_id)
    try:
        local = extract_process_image(validated_case_id, validated_session_id, pid, kind=kind)
        return _memory_file_response(validated_case_id, local)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/modules/download")
def download_memory_process_module(
    case_id: str,
    session_id: str,
    pid: int,
    base: str | None = None,
    name: str | None = None,
) -> FileResponse:
    validated_case_id = _validated_case_id(case_id)
    validated_session_id = _validated_memory_session_id(session_id)
    try:
        local = extract_process_module(
            validated_case_id, validated_session_id, pid, base=base, name=name,
        )
        return _memory_file_response(validated_case_id, local)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
