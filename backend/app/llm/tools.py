"""Provider-agnostic case-query tools and a strict-JSON tool-calling loop.

Providers expose only `complete(messages)`, so tool use is emulated: the model
replies with one JSON object per turn ({"tool": ..., "args": ...} or
{"final": ...}) and tool results are fed back as user messages.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Awaitable, Callable

from sqlalchemy import Integer, case as sa_case, cast
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.store import cases as case_store
from app.detect import overrides
from app.store.database import Event, Finding, MemoryResult, Process

MAX_RESULT_CHARS = 8000
logger = logging.getLogger(__name__)
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def fts_query(question: str) -> str:
    """Build a safe FTS5 MATCH query from free text."""
    tokens = re.findall(r"[A-Za-z0-9_.\\-]+", question)
    tokens = [t for t in tokens if len(t) > 2][:8]
    if not tokens:
        return "the"
    return " OR ".join(f'"{t}"' for t in tokens)


# --- arg coercion helpers -------------------------------------------------

def _opt_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _opt_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _limit(v: Any, cap: int) -> int:
    n = _opt_int(v)
    if n is None:
        return cap
    return max(1, min(n, cap))


def _sev_min(v: Any) -> int | None:
    s = _opt_str(v)
    if not s:
        return None
    return _SEV_RANK.get(s.lower())


def _parse_dt(v: Any) -> datetime | None:
    s = _opt_str(v)
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sev_rank_expr(col):
    return sa_case(*[(col == s, r) for s, r in _SEV_RANK.items()], else_=0)


def _cap(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...(truncated)"


def _event_line(e: Event) -> str:
    return json.dumps({
        "id": e.id, "ts": e.timestamp.isoformat() if e.timestamp else None,
        "sev": e.severity, "cat": e.category, "src": e.source,
        "host": e.host, "entity": e.entity, "summary": (e.summary or "")[:200],
    }, default=str)


# --- tools ----------------------------------------------------------------

def search_events(session: Session, args: dict) -> str:
    query = _opt_str(args.get("query"))
    if not query:
        return "ERROR: 'query' is required."
    limit = _limit(args.get("limit"), 25)
    try:
        events = case_store.search_events(session, fts_query(query), limit=limit)
    except Exception as e:
        return f"ERROR: search failed: {e}"
    return _cap("\n".join(_event_line(e) for e in events) or "No matching events.")


def get_case_overview(session: Session, args: dict) -> str:
    event_count = session.scalar(select(func.count()).select_from(Event)) or 0
    process_count = session.scalar(select(func.count()).select_from(Process)) or 0
    memory_count = session.scalar(select(func.count()).select_from(MemoryResult)) or 0
    first_ts, last_ts = session.execute(select(func.min(Event.timestamp), func.max(Event.timestamp))).one()
    categories = session.execute(
        select(Event.category, func.count()).group_by(Event.category).order_by(func.count().desc()).limit(15)
    ).all()
    sources = session.execute(
        select(Event.source, func.count()).group_by(Event.source).order_by(func.count().desc()).limit(15)
    ).all()
    disabled = overrides.get_disabled_rules(session)
    benign = overrides.get_benign_keys(session)
    findings = list(session.scalars(select(Finding)))
    active = sum(
        overrides.is_suppressed(f.title, f.source, f.evidence, disabled, benign) is None
        for f in findings
    )
    all_processes = list(session.scalars(select(Process)))
    by_session_pid = {(p.session_id, p.pid): p for p in all_processes}
    ranked_processes = sorted(
        all_processes,
        key=lambda p: (
            _SEV_RANK.get(p.severity, 0),
            bool(re.match(r"^[a-zA-Z]:\\Windows\\[^\\]+\.exe$", p.path or "", re.IGNORECASE)),
            bool(p.flags or []),
        ),
        reverse=True,
    )
    process_leads = []
    seen_processes: set[tuple[int, str]] = set()
    for process in ranked_processes:
        key = (process.pid, (process.name or "").lower())
        if key in seen_processes:
            continue
        if _SEV_RANK.get(process.severity, 0) < 2 and not (process.flags or []):
            continue
        parent = by_session_pid.get((process.session_id, process.ppid)) if process.ppid else None
        seen_processes.add(key)
        process_leads.append({
            "pid": process.pid, "ppid": process.ppid, "name": process.name,
            "path": process.path, "severity": process.severity, "flags": process.flags or [],
            "parent": parent.name if parent else None,
            "start_time": process.start_time.isoformat() if process.start_time else None,
        })
        if len(process_leads) >= 12:
            break
    service_leads = []
    for event in session.scalars(select(Event).where(Event.category == "persistence").limit(200)):
        raw = event.raw or {}
        binary = str(raw.get("DriverpathOrCmdline") or raw.get("binary") or raw.get("ImagePath") or "")
        pid = _opt_int(raw.get("PID"))
        if binary or pid:
            service_leads.append({
                "event_id": event.id,
                "service": raw.get("ServiceName") or raw.get("service") or event.entity,
                "pid": pid, "binary": binary, "user": raw.get("User"),
                "severity": event.severity,
            })
        if len(service_leads) >= 12:
            break
    notable_handles = []
    pipe_object_groups: dict[str, dict[str, Any]] = {}
    process_name_by_pid = {p.pid: p.name for p in all_processes}
    # Scan a wider, severity-ordered slice so cross-process pipe sharing is derived
    # deterministically; the displayed handle list stays bounded independently.
    for event in session.scalars(
        select(Event)
        .where(func.lower(Event.summary).like("%remcom_%"))
        .order_by(_sev_rank_expr(Event.severity).desc(), Event.id)
        .limit(60)
    ):
        raw = event.raw or {}
        pid = _opt_int(raw.get("PID"))
        name = str(raw.get("Name") or raw.get("Description") or "")
        device = str(raw.get("Device") or "")
        if device.lower() == "namedpipe" and name:
            name = "\\NamedPipe" + (name if name.startswith("\\") else "\\" + name)
        process_name = raw.get("Process") or event.entity or process_name_by_pid.get(pid)
        object_id = str(raw.get("Object") or "")
        if len(notable_handles) < 16:
            notable_handles.append({
                "event_id": event.id, "pid": pid, "process": process_name,
                "type": raw.get("Type"), "name": name, "device": device,
                "object": object_id or None, "severity": event.severity,
            })
        if object_id and process_name:
            group = pipe_object_groups.setdefault(object_id, {
                "object": object_id, "name": name, "processes": set(), "event_ids": [],
            })
            group["processes"].add(str(process_name))
            group["event_ids"].append(event.id)
    shared_pipe_objects = [
        {**group, "processes": sorted(group["processes"]), "event_ids": group["event_ids"][:12]}
        for group in pipe_object_groups.values() if len(group["processes"]) > 1
    ][:12]
    return _cap(json.dumps({
        "events": event_count, "processes": process_count, "memory_results": memory_count,
        "active_findings": active, "suppressed_findings": len(findings) - active,
        "time_range": [first_ts.isoformat() if first_ts else None, last_ts.isoformat() if last_ts else None],
        "categories": dict(categories), "sources": dict(sources),
        "shared_named_pipe_objects": shared_pipe_objects,
        "notable_handle_patterns": notable_handles,
        "service_process_leads": service_leads,
        "suspicious_process_leads": process_leads,
    }, default=str), 12000)


def get_event(session: Session, args: dict) -> str:
    event_id = _opt_int(args.get("event_id"))
    if event_id is None:
        return "ERROR: 'event_id' is required."
    event = session.get(Event, event_id)
    if not event:
        return "No matching event."
    return _cap(json.dumps({
        "id": event.id, "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "severity": event.severity, "category": event.category, "source": event.source,
        "host": event.host, "entity": event.entity, "summary": event.summary,
        "raw": event.raw,
    }, default=str), 20000)


def filter_events(session: Session, args: dict) -> str:
    q = select(Event)
    category = _opt_str(args.get("category"))
    if category:
        q = q.where(Event.category == category)
    sev = _sev_min(args.get("severity_min"))
    if sev is not None:
        q = q.where(Event.severity.in_([s for s, r in _SEV_RANK.items() if r >= sev]))
    ent = _opt_str(args.get("entity_substring"))
    if ent:
        q = q.where(Event.entity.ilike(f"%{ent}%"))
    src = _opt_str(args.get("source_substring"))
    if src:
        q = q.where(Event.source.ilike(f"%{src}%"))
    since = _parse_dt(args.get("since"))
    if since:
        q = q.where(Event.timestamp >= since)
    until = _parse_dt(args.get("until"))
    if until:
        q = q.where(Event.timestamp <= until)
    q = q.order_by(_sev_rank_expr(Event.severity).desc(), Event.timestamp)
    rows = list(session.scalars(q.limit(_limit(args.get("limit"), 25))))
    return _cap("\n".join(_event_line(e) for e in rows) or "No matching events.")


def get_process(session: Session, args: dict) -> str:
    pid = _opt_int(args.get("pid"))
    name = _opt_str(args.get("name_substring"))
    if pid is None and not name:
        return "ERROR: provide 'pid' or 'name_substring'."
    q = select(Process)
    if pid is not None:
        q = q.where(Process.pid == pid)
    if name:
        q = q.where(Process.name.ilike(f"%{name}%"))
    procs = list(session.scalars(q.limit(8)))
    if not procs:
        return "No matching processes."
    lines = []
    for p in procs:
        parent = None
        if p.ppid is not None:
            parent = session.scalars(
                select(Process).where(Process.pid == p.ppid).limit(1)
            ).first()
        children = list(session.scalars(select(Process).where(Process.ppid == p.pid).limit(10)))
        lines.append(json.dumps({
            "pid": p.pid, "ppid": p.ppid, "name": p.name, "path": p.path,
            "cmdline": (p.cmdline or "")[:200],
            "start_time": p.start_time.isoformat() if p.start_time else None,
            "flags": p.flags, "severity": p.severity,
            "parent": f"{parent.name} (pid {parent.pid})" if parent else None,
            "children": [f"{c.name} (pid {c.pid})" for c in children],
        }, default=str))
    return _cap("\n".join(lines))


def get_memory_results(session: Session, args: dict) -> str:
    q = select(MemoryResult)
    pid = _opt_int(args.get("pid"))
    if pid is not None:
        q = q.where(MemoryResult.pid == pid)
    plugin = _opt_str(args.get("plugin"))
    if plugin:
        q = q.where(MemoryResult.plugin.ilike(f"%{plugin}%"))
    sev = _sev_min(args.get("severity_min"))
    if sev is not None:
        q = q.where(MemoryResult.severity.in_([s for s, r in _SEV_RANK.items() if r >= sev]))
    q = q.order_by(_sev_rank_expr(MemoryResult.severity).desc())
    rows = list(session.scalars(q.limit(_limit(args.get("limit"), 20))))
    lines = []
    for m in rows:
        # data carries the correlation basis (exit_time, corroborating[], pid_reuse)
        lines.append(json.dumps({
            "id": m.id, "plugin": m.plugin, "pid": m.pid, "process": m.process_name,
            "sev": m.severity, "summary": (m.summary or "")[:200],
            "data": json.dumps(m.data, default=str)[:400],
        }, default=str))
    return _cap("\n".join(lines) or "No matching memory results.")


def get_findings(session: Session, args: dict) -> str:
    q = select(Finding)
    sev = _sev_min(args.get("severity_min"))
    if sev is not None:
        q = q.where(Finding.severity.in_([s for s, r in _SEV_RANK.items() if r >= sev]))
    q = q.order_by(_sev_rank_expr(Finding.severity).desc())
    include_suppressed = bool(args.get("include_suppressed", False))
    disabled = overrides.get_disabled_rules(session)
    benign = overrides.get_benign_keys(session)
    rows = list(session.scalars(q))
    if not include_suppressed:
        rows = [
            f for f in rows
            if overrides.is_suppressed(f.title, f.source, f.evidence, disabled, benign) is None
        ]
    rows.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    rows = rows[:_limit(args.get("limit"), 20)]
    lines = []
    for f in rows:
        lines.append(json.dumps({
            "id": f.id, "title": f.title, "sev": f.severity, "mitre": f.mitre_techniques,
            "suppression": overrides.get_suppression_details(session, f),
            "description": (f.description or "")[:250],
            "evidence": json.dumps(f.evidence, default=str)[:300],
        }, default=str))
    return _cap("\n".join(lines) or "No matching findings.")


def get_finding(session: Session, args: dict) -> str:
    finding_id = _opt_int(args.get("finding_id"))
    if finding_id is None:
        return "ERROR: 'finding_id' is required."
    finding = session.get(Finding, finding_id)
    if not finding:
        return "No matching finding."
    return _cap(json.dumps({
        "id": finding.id, "title": finding.title, "severity": finding.severity,
        "description": finding.description, "mitre": finding.mitre_techniques,
        "source": finding.source, "evidence": finding.evidence,
        "suppression": overrides.get_suppression_details(session, finding),
    }, default=str), 5000)


def _suppress_finding(session: Session, args: dict) -> str:
    finding_id = _opt_int(args.get("finding_id"))
    finding = session.get(Finding, finding_id) if finding_id is not None else None
    if not finding:
        return "ERROR: finding not found."
    if finding.source == "manual" or bool((finding.evidence or {}).get("manual")):
        return "ERROR: analyst-created findings cannot be suppressed by AI."
    if str(args.get("confidence") or "").lower() != "high":
        return "ERROR: automatic suppression requires confidence='high'."
    rationale = str(args.get("rationale") or "").strip()
    if len(rationale) < 20:
        return "ERROR: provide a specific rationale of at least 20 characters."
    refs = args.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        return "ERROR: at least one valid event or memory_result evidence reference is required."
    valid_refs: list[dict] = []
    for ref in refs[:20]:
        if not isinstance(ref, dict):
            continue
        ref_type = str(ref.get("type") or "")
        ref_id = _opt_int(ref.get("id"))
        model = Event if ref_type == "event" else MemoryResult if ref_type == "memory_result" else None
        if model is not None and ref_id is not None and session.get(model, ref_id):
            valid_refs.append({"type": ref_type, "id": ref_id})
    if not valid_refs:
        return "ERROR: no supplied evidence reference exists in this case."
    overrides.set_finding_benign(
        session, overrides.finding_key(finding.title, finding.evidence), True,
        actor="ai", rationale=rationale, confidence="high", evidence_refs=valid_refs,
    )
    overrides.apply_overrides(session)
    session.commit()
    return json.dumps({
        "mutation": "finding_suppressed", "finding_id": finding.id,
        "rationale": rationale, "evidence_refs": valid_refs,
    })


def _get_entity_context(case_id: str | None, args: dict) -> str:
    if not case_id:
        return "ERROR: entity context is unavailable."
    entity_id = _opt_str(args.get("entity_id"))
    if not entity_id:
        return "ERROR: 'entity_id' is required."
    from app.detect.entity_graph import entity_dossier
    dossier = entity_dossier(case_id, entity_id, action_limit=_limit(args.get("limit"), 100))
    if not dossier:
        return "No matching entity."
    compact = {
        "entity": dossier.get("entity"),
        "neighbors": (dossier.get("neighbors") or [])[:30],
        "findings": (dossier.get("findings") or [])[:30],
        "actions": (dossier.get("actions") or [])[:100],
        "action_total": dossier.get("action_total"),
        "memory_processes": [
            {
                "session_id": p.get("session_id"), "pid": p.get("pid"), "ppid": p.get("ppid"),
                "name": p.get("name"), "path": p.get("path"), "flags": p.get("flags"),
                "severity": p.get("severity"), "memory_results": (p.get("memory_results") or [])[:15],
                "handles_on_demand": p.get("handles_on_demand", False),
            }
            for p in (dossier.get("memory_processes") or [])[:8]
        ],
    }
    return _cap(json.dumps(compact, default=str), 9000)


def _get_process_handles(session: Session, case_id: str | None, args: dict) -> str:
    pid = _opt_int(args.get("pid"))
    if pid is None:
        return "ERROR: 'pid' is required."
    limit = _limit(args.get("limit"), 80)
    rows = list(session.scalars(
        select(Event).where(
            func.lower(Event.source).like("%handle%"),
            cast(func.json_extract(Event.raw, "$.PID"), Integer) == pid,
        ).limit(2000)
    ))
    if not rows and case_id:
        process = session.scalars(
            select(Process).where(Process.pid == pid, Process.session_id.like("mem-%")).limit(1)
        ).first()
        if process:
            try:
                from app.memory.explorer import list_process_handles
                list_process_handles(case_id, process.session_id, pid, limit=limit)
                session.expire_all()
                rows = list(session.scalars(
                    select(Event).where(
                        Event.category == "handle", Event.source == "memory:handles",
                        Event.entity == process.name,
                    ).limit(2000)
                ))
            except Exception:
                logger.debug("On-demand process-handle collection failed", exc_info=True)
                rows = []
    handles = []
    counts: dict[str, int] = {}
    for event in rows:
        raw = event.raw or {}
        if _opt_int(raw.get("PID")) != pid:
            continue
        kind = str(raw.get("Type") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
        name = str(raw.get("Name") or raw.get("Description") or raw.get("TargetProcess") or "")
        device = str(raw.get("Device") or "")
        if device.lower() == "namedpipe" and name:
            name = "\\NamedPipe" + (name if name.startswith("\\") else "\\" + name)
        risk = str(raw.get("risk") or "none")
        reasons = list(raw.get("risk_reasons") or [])
        if "remcom_" in name.lower():
            risk = "medium" if risk == "none" else risk
            if "RemCom remote-execution named pipe" not in reasons:
                reasons.append("RemCom remote-execution named pipe")
        target_pid = _opt_int(raw.get("TargetPID"))
        target_process = raw.get("TargetProcess")
        if kind.lower() == "process":
            parsed_target = re.search(r"\bPID\s+(\d+)\s*(?:-\s*(.+))?", name, re.IGNORECASE)
            if parsed_target and (target_pid is None or target_pid == pid):
                target_pid = int(parsed_target.group(1))
                target_process = (parsed_target.group(2) or target_process or "").strip() or None
        handles.append({
            "event_id": event.id, "type": kind, "name": name or None,
            "access": raw.get("Access"), "target_pid": target_pid,
            "target_process": target_process, "risk": risk,
            "risk_reasons": reasons, "object": raw.get("Object"), "source": event.source,
        })
    handles.sort(key=lambda h: (
        _SEV_RANK.get(str(h["risk"]), 0),
        "remcom_" in str(h["name"] or "").lower(),
        bool(h["target_pid"]), bool(h["name"]),
    ), reverse=True)
    return _cap(json.dumps({
        "pid": pid, "total": len(handles), "type_counts": counts,
        "handles": handles[:limit],
    }, default=str), 9000)


def count_events(session: Session, args: dict) -> str:
    group_by = (_opt_str(args.get("group_by")) or "category").lower()
    col = {"category": Event.category, "severity": Event.severity, "source": Event.source}.get(group_by)
    if col is None:
        return "ERROR: group_by must be one of category|severity|source."
    rows = session.execute(
        select(col, func.count()).group_by(col).order_by(func.count().desc())
    ).all()
    return _cap("\n".join(f"{k or '(none)'}: {n}" for k, n in rows[:40]) or "No events.")


def list_downloads(session: Session, args: dict) -> str:
    """List distinct download records from events and correlated findings."""
    from app.detect.engine import _download_evidence

    limit = _limit(args.get("limit"), 500)
    path_filter = (_opt_str(args.get("path_substring")) or "").lower()
    events = session.scalars(
        select(Event)
        .where(func.lower(Event.source).like("%evidenceofdownload%"))
        .order_by(Event.timestamp, Event.id)
    )
    by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def add_download(
        path: str, url: str | None, *, event_id: int | None = None,
        finding_id: int | None = None, timestamp: str | None = None,
    ) -> None:
        if path_filter and path_filter not in path.lower():
            return
        key = (path.lower(), (url or "").lower())
        existing = by_key.get(key)
        if existing:
            if finding_id is not None:
                existing["finding_id"] = finding_id
            if event_id is not None:
                existing["event_id"] = event_id
            return
        by_key[key] = {
            "event_id": event_id,
            "finding_id": finding_id,
            "timestamp": timestamp,
            "path": path,
            "url": url,
        }

    for event in events:
        path, url = _download_evidence(event, event.raw or {})
        if not path:
            continue
        add_download(
            path, url, event_id=event.id,
            timestamp=event.timestamp.isoformat() if event.timestamp else None,
        )

    # Correlation findings retain the chosen artifact event and origin URL. This
    # is important when a large browser-artifact source crowds a notable binary
    # out of a bounded event query or when provenance exists only in the finding.
    for finding in session.scalars(select(Finding)):
        evidence = finding.evidence or {}
        if evidence.get("artifact_kind") != "download":
            continue
        path = str(evidence.get("artifact_path") or "").strip()
        if not path:
            continue
        add_download(
            path,
            str(evidence.get("origin_url") or "").strip() or None,
            event_id=_opt_int(evidence.get("artifact_event_id")),
            finding_id=finding.id,
        )

    notable_re = re.compile(
        r"\.(?:exe|msi|dll|sys|ps1|bat|cmd|vbs|scr|com|zip|7z|rar|gz|iso|cab)$",
        re.IGNORECASE,
    )
    downloads = sorted(
        by_key.values(),
        key=lambda item: (
            not bool(notable_re.search(str(item["path"]))),
            not bool(item["url"]),
            str(item["path"]).lower(),
        ),
    )
    total = len(downloads)
    selected = downloads[:limit]
    while True:
        payload = {
            "total_count": total,
            "returned_count": len(selected),
            "truncated": len(selected) < total,
            "downloads": selected,
        }
        text = json.dumps(payload, default=str)
        if len(text) <= 40000 or not selected:
            return text
        selected.pop()


_TOOLS: dict[str, Callable[[Session, dict], str]] = {
    "get_case_overview": get_case_overview,
    "get_event": get_event,
    "search_events": search_events,
    "filter_events": filter_events,
    "get_process": get_process,
    "get_memory_results": get_memory_results,
    "get_findings": get_findings,
    "get_finding": get_finding,
    "list_downloads": list_downloads,
    "count_events": count_events,
}


def execute_tool(
    session: Session, name: str, args: dict, *, case_id: str | None = None,
    allow_suppression: bool = False,
) -> str:
    try:
        if name == "get_entity_context":
            return _get_entity_context(case_id, args)
        if name == "get_process_handles":
            return _get_process_handles(session, case_id, args)
        if name == "suppress_finding":
            if not allow_suppression:
                return "ERROR: suppression is not allowed in this workflow."
            return _suppress_finding(session, args)
        fn = _TOOLS.get(name)
        if not fn:
            return (
                f"ERROR: unknown tool '{name}'. Available: "
                f"{', '.join([*_TOOLS, 'get_entity_context', 'get_process_handles', 'suppress_finding'])}."
            )
        return fn(session, args or {})
    except Exception as e:
        return f"ERROR: {name} failed: {e}"


def describe_call(name: str, args: dict) -> str:
    """One-line human description of a tool call (for progress/UI events)."""
    if name == "get_case_overview":
        return "reviewed the case evidence inventory"
    if name == "get_event":
        return f"opened event #{args.get('event_id', '')}"
    if name == "get_finding":
        return f"opened finding #{args.get('finding_id', '')}"
    if name == "get_entity_context":
        return "reviewed an entity and its connections"
    if name == "get_process_handles":
        return f"reviewed handles for pid {args.get('pid', '')}"
    if name == "suppress_finding":
        return f"requested suppression of finding #{args.get('finding_id', '')}"
    if name == "search_events":
        return f"searched events for '{args.get('query', '')}'"
    if name == "filter_events":
        parts = [f"{k}={v}" for k, v in args.items() if v not in (None, "")]
        return "filtered events" + (f" ({', '.join(parts[:4])})" if parts else "")
    if name == "get_process":
        return f"looked up process {args.get('pid') or args.get('name_substring') or ''}".strip()
    if name == "get_memory_results":
        return "checked memory analysis results"
    if name == "get_findings":
        return "reviewed recorded findings"
    if name == "list_downloads":
        return "listed downloaded files and origin URLs"
    if name == "count_events":
        return f"counted events by {args.get('group_by', 'category')}"
    return f"ran {name}"


# --- JSON action loop -----------------------------------------------------

def _extract_json_object(text: str) -> str | None:
    """Return the first balanced {...} block, respecting string literals."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def parse_action(text: str) -> dict | None:
    """Parse a {"tool": ...} / {"final": ...} action; None means plain text."""
    blob = _extract_json_object(text.strip())
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and ("tool" in data or "final" in data):
        return data
    return None


async def _complete(provider, messages: list[dict[str, str]]) -> str:
    result = await provider.complete(messages, stream=False)
    if isinstance(result, str):
        return result
    chunks = []
    async for c in result:
        chunks.append(c)
    return "".join(chunks)


async def run_tool_loop(
    session: Session,
    provider,
    system_prompt: str,
    user_prompt: str,
    max_iters: int = 6,
    on_tool: Callable[[str, dict], Awaitable[None]] | None = None,
    case_id: str | None = None,
    allow_suppression: bool = False,
) -> tuple[str, list[dict]]:
    """Run the JSON action loop; returns (final_text, tool_trace).

    tool_trace items: {"tool", "args", "result_preview", "result"}.
    Degrades gracefully: unparseable output is treated as the final answer.
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    trace: list[dict[str, Any]] = []
    text = ""
    for _ in range(max_iters):
        text = await _complete(provider, messages)
        action = parse_action(text)
        if action is None:
            return text.strip(), trace
        if "final" in action:
            return str(action["final"]), trace
        name = str(action.get("tool") or "")
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        result = execute_tool(
            session, name, args, case_id=case_id, allow_suppression=allow_suppression,
        )
        trace.append({
            "tool": name, "args": args,
            "result_preview": result[:200], "result": result,
        })
        if on_tool:
            try:
                await on_tool(name, args)
            except Exception:
                logger.debug("Tool progress callback failed", exc_info=True)
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content": f"TOOL RESULT ({name}): {result}"})
    # budget exhausted while the model was still calling tools: force an answer
    messages.append({
        "role": "user",
        "content": 'Tool budget exhausted. Reply now with {"final": "<your complete answer>"}.',
    })
    try:
        text = await _complete(provider, messages)
        action = parse_action(text)
        if action and "final" in action:
            return str(action["final"]), trace
    except Exception:
        logger.debug("Forced final tool-loop response failed", exc_info=True)
    return text.strip(), trace
