"""Provider-agnostic case-query tools and a strict-JSON tool-calling loop.

Providers expose only `complete(messages)`, so tool use is emulated: the model
replies with one JSON object per turn ({"tool": ..., "args": ...} or
{"final": ...}) and tool results are fed back as user messages.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Awaitable, Callable

from sqlalchemy import case as sa_case
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.store import cases as case_store
from app.store.database import Event, Finding, MemoryResult, Process

MAX_RESULT_CHARS = 3000
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
        "ts": e.timestamp.isoformat() if e.timestamp else None,
        "sev": e.severity, "cat": e.category, "src": e.source,
        "entity": e.entity, "summary": (e.summary or "")[:200],
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
            "plugin": m.plugin, "pid": m.pid, "process": m.process_name,
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
    rows = list(session.scalars(q.limit(_limit(args.get("limit"), 20))))
    lines = []
    for f in rows:
        lines.append(json.dumps({
            "title": f.title, "sev": f.severity, "mitre": f.mitre_techniques,
            "description": (f.description or "")[:250],
            "evidence": json.dumps(f.evidence, default=str)[:300],
        }, default=str))
    return _cap("\n".join(lines) or "No matching findings.")


def count_events(session: Session, args: dict) -> str:
    group_by = (_opt_str(args.get("group_by")) or "category").lower()
    col = {"category": Event.category, "severity": Event.severity, "source": Event.source}.get(group_by)
    if col is None:
        return "ERROR: group_by must be one of category|severity|source."
    rows = session.execute(
        select(col, func.count()).group_by(col).order_by(func.count().desc())
    ).all()
    return _cap("\n".join(f"{k or '(none)'}: {n}" for k, n in rows[:40]) or "No events.")


_TOOLS: dict[str, Callable[[Session, dict], str]] = {
    "search_events": search_events,
    "filter_events": filter_events,
    "get_process": get_process,
    "get_memory_results": get_memory_results,
    "get_findings": get_findings,
    "count_events": count_events,
}


def execute_tool(session: Session, name: str, args: dict) -> str:
    fn = _TOOLS.get(name)
    if not fn:
        return f"ERROR: unknown tool '{name}'. Available: {', '.join(_TOOLS)}."
    try:
        return fn(session, args or {})
    except Exception as e:
        return f"ERROR: {name} failed: {e}"


def describe_call(name: str, args: dict) -> str:
    """One-line human description of a tool call (for progress/UI events)."""
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
        result = execute_tool(session, name, args)
        trace.append({
            "tool": name, "args": args,
            "result_preview": result[:200], "result": result,
        })
        if on_tool:
            try:
                await on_tool(name, args)
            except Exception:
                pass
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
        pass
    return text.strip(), trace
