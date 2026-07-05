"""LLM analysis, report, and chat endpoints."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.llm.orchestrator import analyze_case, chat_stream, investigate_entity_stream
from app.store import cases as case_store
from app.store.database import Report

router = APIRouter(prefix="/api/cases", tags=["analysis"])

# Track running analysis jobs and progress listeners
_analysis_listeners: dict[str, list[asyncio.Queue]] = {}
_analysis_running: set[str] = set()


def _broadcast_analysis(case_id: str, payload: dict) -> None:
    for q in _analysis_listeners.get(case_id, []):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass


@router.post("/{case_id}/analyze")
async def start_analysis(case_id: str) -> dict:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if case_id in _analysis_running:
        return {"ok": True, "already_running": True}

    async def _run() -> None:
        _analysis_running.add(case_id)

        async def emit(phase: str, message: str, percent: float) -> None:
            _broadcast_analysis(case_id, {
                "case_id": case_id, "phase": phase, "message": message,
                "percent": percent, "done": phase == "done",
            })

        try:
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
        pass
    finally:
        if queue in _analysis_listeners.get(case_id, []):
            _analysis_listeners[case_id].remove(queue)


@router.get("/{case_id}/report")
async def get_report(case_id: str) -> dict:
    session = case_store.get_session(case_id)
    try:
        report = session.scalars(
            select(Report).order_by(Report.generated_at.desc())
        ).first()
        if not report:
            return {"exists": False}
        return {
            "exists": True,
            "case_id": case_id,
            "summary": report.summary,
            "timeline_narrative": report.timeline_narrative,
            "findings_analysis": report.findings_analysis,
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
        pass


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
        pass


@router.get("/{case_id}/chat-history")
async def get_chat_history(case_id: str) -> dict:
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
