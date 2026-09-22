"""Atomic handoff of one MemProcFS process minidump into Reverse."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select

from app.config import case_dir_path
from app.memory.explorer import (
    MemoryExplorerError,
    export_process_handles,
    extract_process_image,
    list_process_modules,
    resolve_memory_dump,
)
from app.store import cases as case_store
from app.store.database import Event, Finding, MemoryResult, Process

from .database import ReverseProject, get_reverse_session
from .store import (
    add_audit,
    append_provenance,
    create_project,
    contained_source_file,
    delete_project,
    import_artifact,
    project_dir,
)

MAX_DIGEST_BYTES = 16 * 1024
TASKING = (
    "Prove or disprove process hollowing for the attached process minidump. "
    "Identify and reverse the replacement image if present, evaluate thread instruction "
    "pointers and module/memory mappings, and cite the attached case evidence. Treat case "
    "findings and analyst statements as hypotheses that require verification."
)
_PID_KEYS = {
    "pid", "processid", "process_id", "sourcepid", "source_pid", "targetpid",
    "target_pid", "parentprocessid", "initiatingprocessid", "ownerpid", "ppid",
}
_SESSION_KEYS = {"session_id", "sessionid", "memory_session_id"}


class ProcessHandoffError(RuntimeError):
    pass


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _basename(value: str | None) -> str:
    return str(value or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _values_for_keys(value: Any, keys: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in keys:
                found.extend(item if isinstance(item, list) else [item])
            found.extend(_values_for_keys(item, keys))
    elif isinstance(value, list):
        for item in value:
            found.extend(_values_for_keys(item, keys))
    return found


def _pids(value: Any) -> set[int]:
    output: set[int] = set()
    for item in _values_for_keys(value, _PID_KEYS):
        try:
            output.add(int(str(item), 0))
        except (TypeError, ValueError):
            continue
    return output


def _sessions(value: Any) -> set[str]:
    return {str(item) for item in _values_for_keys(value, _SESSION_KEYS) if str(item)}


def _record_process(proc: Process) -> dict[str, Any]:
    return {
        "row_id": proc.id,
        "session_id": proc.session_id,
        "pid": proc.pid,
        "ppid": proc.ppid,
        "name": proc.name,
        "path": proc.path,
        "cmdline": proc.cmdline,
        "start_time": _iso(proc.start_time),
        "flags": proc.flags or [],
        "severity": proc.severity,
        "extra": _json_safe(proc.extra or {}),
    }


def _record_event(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.id,
        "timestamp": _iso(event.timestamp),
        "host": event.host,
        "source": event.source,
        "category": event.category,
        "entity": event.entity,
        "severity": event.severity,
        "summary": event.summary,
        "raw": _json_safe(event.raw or {}),
    }


def _record_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "mitre_techniques": finding.mitre_techniques or [],
        "evidence": _json_safe(finding.evidence or {}),
        "source": finding.source,
        "ai_verdict": finding.ai_verdict,
        "created_at": _iso(finding.created_at),
        "claim_status": "hypothesis_requiring_verification",
    }


def _matches_process_value(value: Any, processes: Iterable[Process]) -> bool:
    rendered = json.dumps(_json_safe(value), ensure_ascii=False).lower()
    for proc in processes:
        candidates = {str(proc.name or "").lower(), str(proc.path or "").lower()}
        candidates.discard("")
        if any(candidate in rendered for candidate in candidates):
            return True
    return False


def _memory_result_matches(row: MemoryResult, proc: Process) -> bool:
    data = row.data or {}
    sessions = _sessions(data)
    if sessions and proc.session_id not in sessions:
        return False
    if row.pid != proc.pid:
        return False
    return not row.process_name or _basename(row.process_name) == _basename(proc.name)


def _digest_line(lines: list[str], line: str) -> bool:
    candidate = "\n".join([*lines, line]).encode("utf-8")
    if len(candidate) > MAX_DIGEST_BYTES:
        return False
    lines.append(line)
    return True


def _build_digest(context: dict[str, Any]) -> str:
    identity = context["process"]
    counts = context["evidence_counts"]
    lines = [
        "PROCESS MEMORY CASE CONTEXT (UNTRUSTED LEADS; VERIFY AGAINST THE MINIDUMP)",
        f"Selected process: {identity['name']} pid {identity['pid']} session {identity['session_id']}",
        f"Path: {identity.get('path') or 'unknown'}",
        f"Command line: {identity.get('cmdline') or 'unknown'}",
        f"Flags: {', '.join(identity.get('flags') or []) or 'none'}; severity: {identity.get('severity')}",
        "Evidence counts: " + ", ".join(f"{key}={counts[key]}" for key in sorted(counts)),
        "Case findings and analyst statements below are hypotheses, not established conclusions.",
    ]
    omitted = 0
    sections = (
        ("Finding", [
            f"[{item['severity']}] {item['title']}: {item['description']}"
            for item in context["findings"]
            if item["severity"] in {"high", "critical"}
        ]),
        ("Memory", [
            f"[{item['severity']}] {item['plugin']}: {item['summary']}"
            for item in context["memory_results"]
        ]),
        ("Relationship", [
            f"{item['relation']}: {item['process']['name']} pid {item['process']['pid']}"
            for item in context["direct_process_relationships"]
        ]),
        ("Module", [
            f"{item.get('name') or item.get('path') or 'unknown'} base={item.get('base_hex') or item.get('base')} size={item.get('size')}"
            for item in context["modules"]
        ]),
    )
    for label, items in sections:
        for item in items:
            if not _digest_line(lines, f"{label}: {item}"):
                omitted += 1
    if omitted:
        marker = f"Digest omitted {omitted} additional summaries; full records are in /workspace/context/."
        while lines and len("\n".join([*lines, marker]).encode("utf-8")) > MAX_DIGEST_BYTES:
            lines.pop()
            omitted += 1
            marker = f"Digest omitted {omitted} additional summaries; full records are in /workspace/context/."
        lines.append(marker)
    return "\n".join(lines)


def build_process_context(
    case_id: str,
    session_id: str,
    pid: int,
    *,
    modules: list[dict[str, Any]],
    handles: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    session = case_store.get_session(case_id)
    try:
        selected_rows = list(session.scalars(select(Process).where(
            Process.session_id == session_id, Process.pid == int(pid)
        ).order_by(Process.id)))
        if not selected_rows:
            raise ProcessHandoffError("Memory-backed process not found")
        selected = selected_rows[0]
        session_processes = list(session.scalars(select(Process).where(
            Process.session_id == session_id
        ).order_by(Process.id)))
        parent_rows = [p for p in session_processes if p.pid == selected.ppid]
        child_rows = [p for p in session_processes if p.ppid == selected.pid and p.pid != selected.pid]
        related_pids = {selected.pid}
        related_pids.update(p.pid for p in parent_rows + child_rows)
        related_pids.update(
            int(item["target_pid"]) for item in handles
            if item.get("target_pid") is not None and str(item.get("target_pid")).isdigit()
        )
        all_events = list(session.scalars(select(Event).order_by(Event.id)))
        # An event that directly joins another process PID to the selected PID
        # is the evidence-backed injector/accessor one-hop boundary.
        for event in all_events:
            raw = event.raw or {}
            sessions = _sessions(raw)
            event_pids = _pids(raw)
            if (not sessions or session_id in sessions) and selected.pid in event_pids:
                related_pids.update(event_pids)
        direct_processes = [
            p for p in session_processes if p.pid in related_pids and p.pid != selected.pid
        ]
        relevant_processes = [selected, *direct_processes]

        actions: list[dict[str, Any]] = []
        for event in all_events:
            raw = event.raw or {}
            sessions = _sessions(raw)
            if sessions and session_id not in sessions:
                continue
            event_pids = _pids(raw)
            if event_pids & related_pids:
                actions.append(_record_event(event))
                continue
            if (
                (event.source or "").startswith("memory:")
                and _matches_process_value({"entity": event.entity, "raw": raw}, relevant_processes)
            ):
                actions.append(_record_event(event))

        memory_rows = [
            row for row in session.scalars(select(MemoryResult).order_by(MemoryResult.id))
            if _memory_result_matches(row, selected)
        ]
        findings = []
        for finding in session.scalars(select(Finding).order_by(Finding.id)):
            evidence = finding.evidence or {}
            sessions = _sessions(evidence)
            if sessions and session_id not in sessions:
                continue
            if _pids(evidence) & related_pids or _matches_process_value(evidence, relevant_processes):
                findings.append(_record_finding(finding))

        relationships = []
        for proc in direct_processes:
            relation = "related"
            if proc.pid == selected.ppid:
                relation = "parent"
            elif proc.ppid == selected.pid:
                relation = "child"
            elif proc.pid in {int(h["target_pid"]) for h in handles if str(h.get("target_pid", "")).isdigit()}:
                relation = "handle_target"
            relationships.append({"relation": relation, "process": _record_process(proc)})

        context: dict[str, Any] = {
            "schema": "investigator.process-reverse-context.v1",
            "scope": "selected_pid_plus_one_hop",
            "trust": {
                "case_findings": "hypotheses_requiring_verification",
                "analyst_statements": "hypotheses_requiring_verification",
                "minidump": "primary_static_evidence",
            },
            "source": {
                "case_id": case_id,
                "session_id": session_id,
                "pid": pid,
                "vfs_path": f"/pid/{pid}/minidump/minidump.dmp",
                "kind": "memprocfs_process_minidump",
            },
            "process": _record_process(selected),
            "duplicate_process_records": [_record_process(item) for item in selected_rows[1:]],
            "direct_process_relationships": relationships,
            "findings": findings,
            "memory_results": [
                {
                    "id": row.id,
                    "plugin": row.plugin,
                    "process_name": row.process_name,
                    "summary": row.summary,
                    "severity": row.severity,
                    "data": _json_safe(row.data or {}),
                    "claim_status": "observation_requiring_minidump_verification",
                }
                for row in memory_rows
            ],
            "modules": _json_safe(modules),
            "direct_relationship_summary": [
                {
                    "event_id": item["event_id"],
                    "category": item["category"],
                    "severity": item["severity"],
                    "summary": item["summary"],
                }
                for item in actions
            ],
            "evidence_counts": {
                "selected_process_records": len(selected_rows),
                "direct_processes": len(direct_processes),
                "findings": len(findings),
                "memory_results": len(memory_rows),
                "modules": len(modules),
                "actions": len(actions),
                "handles": len(handles),
            },
        }
        context["context_digest"] = _build_digest(context)
        return context, actions, [_json_safe(item) for item in handles]
    finally:
        session.close()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _sha256(path: Path, *, source_root: Path) -> str:
    path = contained_source_file(path, source_root)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def handoff_process_to_reverse(case_id: str, session_id: str, pid: int) -> dict[str, Any]:
    if not case_store.case_exists(case_id):
        raise ProcessHandoffError("Case not found")
    project = None
    try:
        # Every live collection is bound to the exact requested session/PID.
        minidump = extract_process_image(
            case_id, session_id, pid, kind="minidump", exact_vfs_path=True
        )
        module_result = list_process_modules(case_id, session_id, pid)
        handles = export_process_handles(case_id, session_id, pid)
        context, actions, handles = build_process_context(
            case_id,
            session_id,
            pid,
            modules=module_result.get("modules") or [],
            handles=handles,
        )
        proc = context["process"]
        dump = resolve_memory_dump(case_id, session_id)
        case_root = case_dir_path(case_id)
        minidump_hash = _sha256(minidump, source_root=case_root)
        source_metadata = {
            "case_id": case_id,
            "session_id": session_id,
            "pid": pid,
            "process_name": proc["name"],
            "vfs_path": f"/pid/{pid}/minidump/minidump.dmp",
            "source_kind": "memprocfs_process_minidump",
            "hashes": {"minidump_sha256": minidump_hash},
        }
        project = create_project(
            f"{proc['name']} pid {pid} memory",
            description=(
                f"MemProcFS process minidump from case {case_id}, session {session_id}, pid {pid}. "
                "Review the prefilled task before starting analysis."
            ),
            linked_case_id=case_id,
        )
        with get_reverse_session() as db:
            row = db.get(ReverseProject, project.id)
            if row:
                row.analysis_note = TASKING
                db.commit()
        with tempfile.TemporaryDirectory(prefix="handoff-", dir=project_dir(project.id) / "staging") as tmp:
            root = Path(tmp)
            context_path = root / "process-context.json"
            actions_path = root / "process-actions.jsonl"
            handles_path = root / "process-handles.jsonl"
            _write_json(context_path, context)
            _write_jsonl(actions_path, actions)
            _write_jsonl(handles_path, handles)
            imported = [
                import_artifact(
                    project.id,
                    minidump,
                    source_root=case_root,
                    name=minidump.name,
                    artifact_type="upload",
                    content_type="application/octet-stream",
                    source_metadata=source_metadata,
                ),
                import_artifact(
                    project.id,
                    context_path,
                    source_root=root,
                    name=context_path.name,
                    artifact_type="context",
                    content_type="application/json",
                    source_metadata={**source_metadata, "source_kind": "process_context"},
                ),
                import_artifact(
                    project.id,
                    actions_path,
                    source_root=root,
                    name=actions_path.name,
                    artifact_type="context",
                    content_type="application/x-ndjson",
                    source_metadata={**source_metadata, "source_kind": "process_actions"},
                ),
                import_artifact(
                    project.id,
                    handles_path,
                    source_root=root,
                    name=handles_path.name,
                    artifact_type="context",
                    content_type="application/x-ndjson",
                    source_metadata={**source_metadata, "source_kind": "process_handles"},
                ),
            ]
        details = {
            "case_id": case_id,
            "session_id": session_id,
            "pid": pid,
            "process_name": proc["name"],
            "source_dump_name": dump.filename,
            "artifact_ids": [item.id for item in imported],
            "artifact_hashes": {item.name: item.sha256 for item in imported},
            "evidence_counts": context["evidence_counts"],
        }
        with get_reverse_session() as db:
            add_audit(project.id, "process.handoff_ready", details, db=db)
            append_provenance(project.id, "process.handoff_ready", details, db=db)
            db.commit()
        return {"project_id": project.id, "status": "ready", "artifact_ids": details["artifact_ids"]}
    except (MemoryExplorerError, ProcessHandoffError):
        if project is not None:
            delete_project(project.id)
        raise
    except Exception as exc:
        if project is not None:
            delete_project(project.id)
        raise ProcessHandoffError(f"Could not prepare Reverse handoff: {exc}") from exc
