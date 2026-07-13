"""Build process tree structures for the process-map UI."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.store import cases as case_store
from app.store.database import Event, MemoryResult, Process


def list_sessions(case_id: str) -> list[dict[str, Any]]:
    session = case_store.get_session(case_id)
    try:
        rows = session.execute(
            select(Process.session_id, __import__("sqlalchemy").func.count())
            .group_by(Process.session_id)
        ).all()
        return [{"session_id": r[0], "process_count": r[1]} for r in rows]
    finally:
        session.close()


def build_tree(case_id: str, session_id: str | None = None) -> dict[str, Any]:
    session = case_store.get_session(case_id)
    try:
        if session_id is None:
            first = session.scalars(select(Process.session_id)).first()
            session_id = first or "default"

        procs = list(session.scalars(
            select(Process).where(Process.session_id == session_id)
        ))

        nodes: dict[int, dict[str, Any]] = {}
        for p in procs:
            nodes[p.pid] = {
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "path": p.path,
                "cmdline": p.cmdline,
                "start_time": p.start_time.isoformat() if p.start_time else None,
                "flags": p.flags or [],
                "severity": p.severity,
                "children": [],
            }

        roots: list[dict[str, Any]] = []
        for pid, node in nodes.items():
            ppid = node["ppid"]
            if ppid is not None and ppid in nodes and ppid != pid:
                nodes[ppid]["children"].append(node)
            else:
                roots.append(node)

        flat = [
            {k: v for k, v in n.items() if k != "children"} for n in nodes.values()
        ]
        return {
            "case_id": case_id,
            "session_id": session_id,
            "roots": roots,
            "flat": flat,
        }
    finally:
        session.close()


def process_dossier(case_id: str, session_id: str, pid: int) -> dict[str, Any]:
    session = case_store.get_session(case_id)
    try:
        proc = session.scalars(
            select(Process).where(Process.session_id == session_id, Process.pid == pid)
        ).first()
        if not proc:
            return {}
        mem = list(session.scalars(select(MemoryResult).where(MemoryResult.pid == pid)))
        related_events = list(session.scalars(
            select(Event).where(Event.raw["PID"].as_string() == str(pid)).limit(50)
        ))
        # network events referencing this pid
        return {
            "process": {
                "pid": proc.pid, "ppid": proc.ppid, "name": proc.name,
                "path": proc.path, "cmdline": proc.cmdline,
                "start_time": proc.start_time.isoformat() if proc.start_time else None,
                "flags": proc.flags or [], "severity": proc.severity,
                "extra": proc.extra or {},
            },
            "memory_results": [
                {"plugin": m.plugin, "summary": m.summary, "severity": m.severity, "data": m.data}
                for m in mem
            ],
            "events": [
                {"summary": e.summary, "category": e.category, "severity": e.severity,
                 "timestamp": e.timestamp.isoformat() if e.timestamp else None}
                for e in related_events
            ],
        }
    finally:
        session.close()
