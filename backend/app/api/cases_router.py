"""Case management, upload, ingestion, and data query endpoints."""

from __future__ import annotations

import asyncio

import aiofiles
from fastapi import APIRouter, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy import delete as sqldelete, func, select, update as sqlupdate

from app.config import case_uploads_path
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

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
async def get_cases() -> list[dict]:
    return case_store.list_cases()


@router.post("")
async def create_case(body: CaseCreate) -> dict:
    return case_store.create_case(body.name, body.description)


@router.get("/{case_id}")
async def get_case(case_id: str) -> dict:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.delete("/{case_id}")
async def delete_case(case_id: str) -> dict:
    if not case_store.delete_case(case_id):
        raise HTTPException(404, "Case not found")
    return {"ok": True}


@router.post("/{case_id}/upload")
async def upload_file(
    case_id: str,
    file: UploadFile,
    file_type: str = "artifact",
    mem_forensic_timeline: bool = False,
    mem_eventlogs: bool = False,
) -> dict:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    uploads = case_uploads_path(case_id)
    dest = uploads / file.filename
    async with aiofiles.open(dest, "wb") as out:
        while True:
            chunk = await file.read(4 * 1024 * 1024)
            if not chunk:
                break
            await out.write(chunk)

    # kick off ingestion in the background
    memory_options = {
        "forensic_timeline": bool(mem_forensic_timeline),
        "eventlogs": bool(mem_eventlogs),
    }
    asyncio.create_task(manager.run_ingestion(case_id, dest, file_type, memory_options))
    return {"ok": True, "filename": file.filename, "path": str(dest)}


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
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    uploads = case_uploads_path(case_id)
    dest = uploads / filename
    mode = "wb" if chunk_index == 0 else "ab"
    async with aiofiles.open(dest, mode) as out:
        while True:
            chunk = await file.read(4 * 1024 * 1024)
            if not chunk:
                break
            await out.write(chunk)

    if chunk_index + 1 >= total_chunks:
        memory_options = {
            "forensic_timeline": bool(mem_forensic_timeline),
            "eventlogs": bool(mem_eventlogs),
        }
        asyncio.create_task(manager.run_ingestion(case_id, dest, file_type, memory_options))
        return {"ok": True, "complete": True, "filename": filename}
    return {"ok": True, "complete": False, "chunk_index": chunk_index}


@router.get("/{case_id}/evidence")
async def list_evidence(case_id: str) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    return {"files": evidence_store.list_evidence(case_id)}


@router.delete("/{case_id}/evidence/{name}")
async def delete_evidence(case_id: str, name: str) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, evidence_store.delete_evidence, case_id, name)
    if result is None:
        raise HTTPException(404, "Evidence file not found")
    return result


@router.post("/{case_id}/evidence/{name}/reingest")
async def reingest_evidence(case_id: str, name: str, file_type: str = "artifact") -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
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
        pass
    finally:
        manager.unsubscribe(case_id, queue)


# --- Data queries ---

@router.get("/{case_id}/events")
async def get_events(
    case_id: str,
    q: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    session = case_store.get_session(case_id)
    try:
        if q:
            try:
                from app.llm.orchestrator import _fts_query
                fts_query = _fts_query(q)
                events = case_store.search_events(session, fts_query, limit=limit)
                total = case_store.count_search_events(session, fts_query)
            except Exception:
                events = []
                total = 0
        else:
            stmt = select(Event)
            count_stmt = select(func.count()).select_from(Event)
            if category:
                stmt = stmt.where(Event.category == category)
                count_stmt = count_stmt.where(Event.category == category)
            if severity:
                stmt = stmt.where(Event.severity == severity)
                count_stmt = count_stmt.where(Event.severity == severity)
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


_SEVERITY_LADDER = ["info", "low", "medium", "high", "critical"]


@router.get("/{case_id}/timeline")
async def get_timeline(
    case_id: str,
    limit: int = 2000,
    sources: str | None = None,
    q: str | None = None,
    min_severity: str = "info",
) -> dict:
    session = case_store.get_session(case_id)
    try:
        stmt = select(Event).where(Event.timestamp.isnot(None))
        if sources is not None:
            wanted = [s for s in sources.split(",") if s]
            stmt = stmt.where(Event.source.in_(wanted))
        if min_severity in _SEVERITY_LADDER and min_severity != "info":
            allowed = _SEVERITY_LADDER[_SEVERITY_LADDER.index(min_severity):]
            stmt = stmt.where(Event.severity.in_(allowed))
        if q and q.strip():
            like = f"%{q.strip()}%"
            stmt = stmt.where(
                Event.summary.ilike(like)
                | Event.entity.ilike(like)
                | Event.source.ilike(like)
                | Event.category.ilike(like)
                | Event.severity_reason.ilike(like)
            )
        total_matching = session.scalar(
            select(func.count()).select_from(stmt.subquery())
        ) or 0
        events = list(session.scalars(stmt.order_by(Event.timestamp).limit(limit)))
        # Aggregate over ALL timestamped events so the source filter always lists
        # every evidence source, not just those inside the returned page.
        source_rows = session.execute(
            select(Event.source, func.count())
            .where(Event.timestamp.isnot(None))
            .group_by(Event.source)
            .order_by(func.count().desc())
        ).all()
        total = sum(r[1] for r in source_rows)
        return {
            "total": total,
            "total_matching": total_matching,
            "sources": [{"name": r[0], "count": r[1]} for r in source_rows],
            "events": [
                {
                    "id": e.id,
                    "start": e.timestamp.isoformat() if e.timestamp else None,
                    "content": (e.summary or "")[:120],
                    "group": e.category,
                    "severity": e.severity,
                    "severity_reason": e.severity_reason,
                    "source": e.source,
                    "raw": e.raw,
                }
                for e in events
            ],
        }
    finally:
        session.close()


@router.get("/{case_id}/categories")
async def get_categories(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        rows = session.execute(
            select(Event.category, func.count()).group_by(Event.category)
        ).all()
        return {"categories": [{"name": r[0], "count": r[1]} for r in rows]}
    finally:
        session.close()


@router.get("/{case_id}/findings")
async def get_findings(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        findings = list(session.scalars(select(Finding)))
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda f: order.get(f.severity, 0), reverse=True)
        return {
            "findings": [
                {
                    "id": f.id, "title": f.title, "description": f.description,
                    "severity": f.severity, "mitre_techniques": f.mitre_techniques,
                    "evidence": f.evidence, "source": f.source, "ai_verdict": f.ai_verdict,
                    "created_at": f.created_at.isoformat(),
                }
                for f in findings
            ],
        }
    finally:
        session.close()


@router.post("/{case_id}/detections/run")
async def run_detections(case_id: str, rebuild: bool = True) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    loop = asyncio.get_running_loop()
    from app.detect.engine import run_detections_sync

    def _run() -> int:
        if rebuild:
            session = case_store.get_session(case_id)
            try:
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

    added = await loop.run_in_executor(None, _run)
    return {"ok": True, "added": added, "rebuild": rebuild}


@router.get("/{case_id}/attack-matrix")
async def get_attack_matrix(case_id: str) -> dict:
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
async def get_process_sessions(case_id: str) -> dict:
    return {"sessions": list_sessions(case_id)}


@router.get("/{case_id}/processes/tree")
async def get_process_tree(case_id: str, session_id: str | None = None) -> dict:
    return build_tree(case_id, session_id)


@router.get("/{case_id}/processes/{session_id}/{pid}")
async def get_process_dossier(case_id: str, session_id: str, pid: int) -> dict:
    dossier = process_dossier(case_id, session_id, pid)
    if not dossier:
        raise HTTPException(404, "Process not found")
    return dossier


@router.get("/{case_id}/entities")
async def get_entities(
    case_id: str,
    types: str | None = None,
    min_severity: str = "info",
    max_nodes: int = 300,
) -> dict:
    type_list = [t for t in types.split(",") if t] if types else None
    return build_entity_graph(case_id, entity_types=type_list, min_severity=min_severity, max_nodes=max_nodes)


@router.get("/{case_id}/entity-dossier")
async def get_entity_dossier(case_id: str, entity_id: str) -> dict:
    dossier = entity_dossier(case_id, entity_id)
    if not dossier:
        raise HTTPException(404, "Entity not found")
    return dossier


@router.get("/{case_id}/memory")
async def get_memory_results(case_id: str, plugin: str | None = None) -> dict:
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
async def get_memory_dumps(case_id: str) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    return {"dumps": list_memory_dumps(case_id)}


@router.get("/{case_id}/memory/{session_id}/vfs")
async def get_memory_vfs(case_id: str, session_id: str, path: str = "/") -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        return list_vfs(case_id, session_id, path)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/vfs/download")
async def download_memory_vfs_file(case_id: str, session_id: str, path: str) -> FileResponse:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        local = extract_vfs_file(case_id, session_id, path)
        return FileResponse(local, media_type="application/octet-stream", filename=local.name)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.post("/{case_id}/memory/{session_id}/vfs/archive")
async def archive_memory_vfs(case_id: str, session_id: str, body: dict) -> FileResponse:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    paths = body.get("paths") if isinstance(body, dict) else None
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise HTTPException(400, "Expected JSON body with string paths")
    try:
        local = archive_vfs_selection(case_id, session_id, paths)
        return FileResponse(local, media_type="application/zip", filename=local.name)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/modules")
async def get_memory_process_modules(case_id: str, session_id: str, pid: int) -> dict:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        return list_process_modules(case_id, session_id, pid)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/handles")
async def get_memory_process_handles(
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
async def download_memory_process(case_id: str, session_id: str, pid: int, kind: str = "image") -> FileResponse:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        local = extract_process_image(case_id, session_id, pid, kind=kind)
        return FileResponse(local, media_type="application/octet-stream", filename=local.name)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.get("/{case_id}/memory/{session_id}/processes/{pid}/modules/download")
async def download_memory_process_module(
    case_id: str,
    session_id: str,
    pid: int,
    base: str | None = None,
    name: str | None = None,
) -> FileResponse:
    if not case_store.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        local = extract_process_module(case_id, session_id, pid, base=base, name=name)
        return FileResponse(local, media_type="application/octet-stream", filename=local.name)
    except MemoryExplorerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
