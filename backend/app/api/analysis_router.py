"""LLM analysis, report, and chat endpoints."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.llm.orchestrator import analyze_case, chat_stream, investigate_entity_stream
from app.store import cases as case_store
from app.detect import overrides
from app.store.database import Event, Finding, Report
from app.store.operations import coordinator

router = APIRouter(prefix="/api/cases", tags=["analysis"])
logger = logging.getLogger(__name__)

# Track running analysis jobs and progress listeners
_analysis_listeners: dict[str, list[asyncio.Queue]] = {}
_analysis_running: set[str] = set()


def _broadcast_analysis(case_id: str, payload: dict) -> None:
    for q in _analysis_listeners.get(case_id, []):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            logger.debug("Dropped analysis update for a full listener queue")


@router.post("/{case_id}/analyze")
async def start_analysis(case_id: str) -> dict:
    case = await asyncio.to_thread(case_store.get_case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if case_id in _analysis_running:
        return {"ok": True, "already_running": True}
    _analysis_running.add(case_id)

    async def _run() -> None:
        async def emit(phase: str, message: str, percent: float) -> None:
            _broadcast_analysis(case_id, {
                "case_id": case_id, "phase": phase, "message": message,
                "percent": percent, "done": phase in {"done", "error"},
            })

        active = coordinator.snapshot(case_id).get("active")
        if active:
            await emit("queued", f"Waiting for {active} to finish", 0)
        try:
            async with coordinator.run(case_id, "AI analysis"):
                if not await asyncio.to_thread(case_store.case_exists, case_id):
                    await emit("error", "Analysis cancelled because the case no longer exists", 100)
                    return
                await analyze_case(case_id, emit=emit)
        except Exception as e:
            _broadcast_analysis(case_id, {
                "case_id": case_id, "phase": "error", "message": str(e),
                "percent": 100, "done": True, "error": str(e),
            })
        finally:
            _analysis_running.discard(case_id)

    asyncio.create_task(_run())
    return {"ok": True, "started": True}


@router.websocket("/{case_id}/analyze-ws")
async def analyze_ws(websocket: WebSocket, case_id: str) -> None:
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    _analysis_listeners.setdefault(case_id, []).append(queue)
    try:
        await websocket.send_json({
            "case_id": case_id, "phase": "connected",
            "message": "running" if case_id in _analysis_running else "idle",
            "percent": 0, "done": False,
        })
        while True:
            payload = await queue.get()
            await websocket.send_json(payload)
    except WebSocketDisconnect:
        return
    finally:
        if queue in _analysis_listeners.get(case_id, []):
            _analysis_listeners[case_id].remove(queue)


@router.get("/{case_id}/report")
def get_report(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        report = session.scalars(
            select(Report).order_by(Report.generated_at.desc())
        ).first()
        if not report:
            return {"exists": False}
        timeline_entries = []
        for item in report.timeline_entries or []:
            if not isinstance(item, dict):
                continue
            event_refs = []
            for event_id in item.get("event_ids") or []:
                event = session.get(Event, event_id)
                if event:
                    event_refs.append({
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "summary": event.summary,
                        "severity": event.severity,
                        "source": event.source,
                    })
            finding_refs = []
            for finding_id in item.get("finding_ids") or []:
                finding = session.get(Finding, finding_id)
                if finding:
                    finding_refs.append({
                        "id": finding.id, "title": finding.title,
                        "severity": finding.severity,
                        "suppressed": overrides.get_suppression_details(session, finding) is not None,
                    })
            timeline_entries.append({**item, "event_refs": event_refs, "finding_refs": finding_refs})
        current_revision = overrides.get_suppression_revision(session)
        return {
            "exists": True,
            "case_id": case_id,
            "summary": report.summary,
            "timeline_narrative": report.timeline_narrative,
            "timeline_entries": timeline_entries,
            "findings_analysis": report.findings_analysis,
            "stale": int(report.suppression_revision or 0) != current_revision,
            "generated_at": report.generated_at.isoformat(),
        }
    finally:
        session.close()


@router.websocket("/{case_id}/chat-ws")
async def chat_ws(websocket: WebSocket, case_id: str) -> None:
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            question = data.get("message", "")
            history = data.get("history", [])
            if not question:
                continue
            await websocket.send_json({"type": "start"})
            try:
                async for chunk in chat_stream(case_id, question, history):
                    if isinstance(chunk, dict):
                        # pre-typed events (e.g. {"type": "tool", ...}) pass through
                        await websocket.send_json(chunk)
                    else:
                        await websocket.send_json({"type": "chunk", "content": chunk})
            except Exception as e:
                await websocket.send_json({"type": "error", "content": str(e)})
            await websocket.send_json({"type": "done"})
    except WebSocketDisconnect:
        return


@router.websocket("/{case_id}/investigate-entity-ws")
async def investigate_entity_ws(websocket: WebSocket, case_id: str) -> None:
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            entity_id = data.get("entity_id", "")
            if not entity_id:
                continue
            await websocket.send_json({"type": "start"})
            try:
                async for chunk in investigate_entity_stream(case_id, entity_id):
                    await websocket.send_json({"type": "chunk", "content": chunk})
            except Exception as e:
                await websocket.send_json({"type": "error", "content": str(e)})
            await websocket.send_json({"type": "done"})
    except WebSocketDisconnect:
        return


@router.get("/{case_id}/chat-history")
def get_chat_history(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        history = case_store.get_chat_history(session, limit=50)
        try:
            memo = case_store.get_meta(session, "chat_memo")
        except Exception:
            memo = None
        return {
            "messages": [
                {"role": h.role, "content": h.content, "created_at": h.created_at.isoformat()}
                for h in history
            ],
            "memo": memo,
        }
    finally:
        session.close()
