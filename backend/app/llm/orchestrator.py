"""LLM orchestrator: map-reduce evidence analysis, report generation, per-finding verdicts, chat."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import select

from app.config import load_config
from app.detect import overrides
from app.llm import prompts
from app.llm.base import get_provider
from app.llm.tools import describe_call, fts_query as _fts_query, get_case_overview, run_tool_loop
from app.store import cases as case_store
from app.store.database import ChatHistory, Event, Finding, MemoryResult, Process, Report

MAX_EVIDENCE_ROWS_PER_BATCH = 40
logger = logging.getLogger(__name__)
MAX_CATEGORIES = 12
MEMO_THRESHOLD_CHARS = 6000  # un-summarized history beyond the raw tail triggers a memo update
MEMO_KEEP_RAW = 6  # newest messages always sent raw, never folded into the memo
MAX_CHAT_TOOL_CONTEXT_CHARS = 60000
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_FINDING_TOPIC_WORDS = {
    "beacon", "cobalt", "credential", "dkom", "execution", "handle", "hollowing",
    "injection", "network", "persistence", "pipe", "remcom", "service", "unlinking",
}
_FINDING_STOP_WORDS = {
    "a", "an", "and", "by", "detected", "detection", "for", "in", "indicator",
    "indicators", "of", "on", "potential", "suspicious", "the", "via", "with",
}

# Imperative suppression requests only. Anchored to an action verb so a bare
# question ("is finding 5 a false positive?", "could this be benign?") never
# authorizes the AI to suppress -- suppression is a mutation, so the gate must
# not fire on inquiry. suppress_finding still enforces evidence + high confidence
# and is reversible/auditable, so this stays a coarse secondary guard.
_SUPPRESSION_INTENT_RE = re.compile(
    r"\b(?:"
    r"suppress"
    r"|dismiss\s+(?:this\s+|that\s+)?finding"
    r"|ignore\s+(?:this\s+|that\s+)?finding"
    r"|mark\s+(?:it|this|that|finding\s*#?\d+)\s+(?:as\s+)?benign"
    r"|flag\s+(?:it|this|that|finding\s*#?\d+)\s+(?:as\s+)?benign"
    r"|treat\s+(?:it|this|that|finding\s*#?\d+)\s+as\s+(?:benign|(?:a\s+)?false[- ]positive)"
    r")",
    re.IGNORECASE,
)


def _requests_suppression(question: str) -> bool:
    """True only when the analyst issues an imperative suppression request."""
    return bool(_SUPPRESSION_INTENT_RE.search(question or ""))


def _json_lines(rows: list[dict[str, Any]], limit: int = MAX_EVIDENCE_ROWS_PER_BATCH) -> str:
    out = []
    for row in rows[:limit]:
        try:
            out.append(json.dumps(row, default=str)[:800])
        except Exception:
            out.append(str(row)[:800])
    return "\n".join(out)


async def _complete(messages: list[dict[str, str]]) -> str:
    provider = get_provider()
    result = await provider.complete(messages, stream=False)
    if isinstance(result, str):
        return result
    # drain async iterator just in case
    chunks = []
    async for c in result:
        chunks.append(c)
    return "".join(chunks)


async def _retry_plain_text_answer(provider, messages: list[dict[str, str]]) -> str:
    """Retry a provider response that contained no displayable text."""
    retry_messages = [*messages, {
        "role": "user",
        "content": (
            "Your previous response contained no displayable text. Answer the USER QUESTION now "
            "using the supplied case context and gathered tool results. Return plain text or "
            "Markdown only. Do not call functions, request more tools, or emit JSON tool calls."
        ),
    }]
    result = await provider.complete(retry_messages, stream=False)
    if isinstance(result, str):
        return result.strip()
    chunks: list[str] = []
    async for chunk in result:
        chunks.append(chunk)
    return "".join(chunks).strip()


def _chat_tool_context(gathered: list[dict]) -> str:
    if not gathered:
        return ""
    context = "\n\nADDITIONAL DATA PULLED FROM THE CASE DATABASE:\n" + "\n\n".join(
        f"[{item['tool']} {json.dumps(item['args'], default=str)}]\n"
        f"{item.get('result', item['result_preview'])}"
        for item in gathered
    )
    return context[:MAX_CHAT_TOOL_CONTEXT_CHARS]


async def _complete_json(messages: list[dict[str, str]], parser, *, repair: bool = True):
    """Complete and parse JSON, retrying once when the model wraps or malforms it.

    Local models routinely add prose or fences around JSON, or drop a brace. The
    single repair round asks the model to re-emit only the JSON object/array before
    the caller falls back to deterministic defaults. `parser` returns a falsy value
    (``{}``/``[]``) when the text is unusable, which is what triggers the retry."""
    raw = await _complete(messages)
    parsed = parser(raw)
    if parsed or not repair:
        return parsed
    repair_messages = messages + [
        {"role": "assistant", "content": raw[:6000]},
        {"role": "user", "content": (
            "Your previous reply could not be parsed as the requested JSON. "
            "Return ONLY the JSON described earlier — no prose, markdown, or code fences."
        )},
    ]
    return parser(await _complete(repair_messages))


def _split_findings(session, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    disabled = overrides.get_disabled_rules(session)
    benign = overrides.get_benign_keys(session)
    active, suppressed = [], []
    for finding in findings:
        target = suppressed if overrides.is_suppressed(
            finding.title, finding.source, finding.evidence, disabled, benign
        ) else active
        target.append(finding)
    return active, suppressed


def _finding_entity(finding: Finding) -> str:
    evidence = finding.evidence or {}
    return str(
        evidence.get("entity") or evidence.get("process") or evidence.get("service")
        or evidence.get("pid") or ""
    ).strip().lower()


def _finding_tokens(title: str, description: str = "") -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", f"{title} {description[:400]}".lower())
        if len(token) > 2 and token not in _FINDING_STOP_WORDS
    }


def _semantically_matches(
    title: str, description: str, entity: str, existing: Finding
) -> bool:
    candidate = _finding_tokens(title, description)
    current = _finding_tokens(existing.title, existing.description or "")
    common_topics = (candidate & current) & _FINDING_TOPIC_WORDS
    same_entity = bool(entity) and entity == _finding_entity(existing)
    if same_entity and common_topics:
        return True
    union = candidate | current
    existing_entity = _finding_entity(existing)
    compatible_entity = same_entity or not entity or not existing_entity
    return compatible_entity and bool(union) and len(candidate & current) / len(union) >= 0.68


def _context_findings(findings: list[Finding], limit: int) -> list[Finding]:
    """Keep deterministic findings and collapse repeated AI paraphrases."""
    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity, 0),
            f.source != "ai-analysis",
            -(f.id or 0),
        ),
        reverse=True,
    )
    kept: list[Finding] = []
    for finding in ordered:
        if finding.source == "ai-analysis" and any(
            _semantically_matches(
                finding.title, finding.description or "", _finding_entity(finding), existing
            )
            for existing in kept
        ):
            continue
        kept.append(finding)
        if len(kept) >= limit:
            break
    return kept


def _finding_context(findings: list[Finding], *, suppressed: bool = False, limit: int = 60) -> str:
    lines = []
    for finding in _context_findings(findings, limit):
        reason = (finding.evidence or {}).get("suppressed_reason") if suppressed else None
        lines.append(
            f"- [finding:{finding.id}] ({finding.severity.upper()}) {finding.title} "
            f"[{', '.join(finding.mitre_techniques)}]"
            + (f" SUPPRESSED: {reason or 'analyst override'}" if suppressed else "")
            + f": {finding.description[:300]}"
        )
    return "\n".join(lines) or ("None." if suppressed else "No active findings.")


def _sample_events(events: list[Event], active_findings: list[Finding], limit: int = 60) -> list[Event]:
    """Bounded, diverse evidence selection without spending model calls on map summaries."""
    linked_ids: set[int] = set()
    priority_entities: set[str] = set()
    for finding in active_findings:
        evidence = finding.evidence or {}
        if isinstance(evidence.get("event_id"), int):
            linked_ids.add(int(evidence["event_id"]))
        for event_id in evidence.get("event_ids") or []:
            if isinstance(event_id, int):
                linked_ids.add(event_id)
        entity = _finding_entity(finding)
        if entity:
            priority_entities.add(entity)
    ranked = sorted(
        events,
        key=lambda e: (e.id in linked_ids, _SEVERITY_RANK.get(e.severity, 0), bool(e.timestamp)),
        reverse=True,
    )
    chosen: list[Event] = []
    seen: set[tuple] = set()
    for event in ranked:
        propagated = (event.severity_reason or "").lower().startswith(
            ("flagged-entity match:", "context:")
        )
        entity_match = (event.entity or "").strip().lower() in priority_entities
        relevant_category = event.category in {
            "handle", "memory", "network", "persistence", "process", "service",
        }
        if event.id not in linked_ids and (
            propagated
            or (
                _SEVERITY_RANK.get(event.severity, 0) < 2
                and not (entity_match and relevant_category)
            )
        ):
            continue
        signature = (
            event.category, event.source, (event.entity or "").lower(),
            (event.summary or "")[:120].lower(),
        )
        if signature in seen and event.id not in linked_ids:
            continue
        seen.add(signature)
        chosen.append(event)
        if len(chosen) >= max(1, limit - 10):
            break
    chronological = sorted(
        (
            e for e in events
            if e.timestamp
            and _SEVERITY_RANK.get(e.severity, 0) >= 2
            and not (e.severity_reason or "").lower().startswith(
                ("flagged-entity match:", "context:")
            )
        ),
        key=lambda e: e.timestamp,
    )
    if chronological:
        step = max(1, len(chronological) // 10)
        for event in chronological[::step]:
            if event not in chosen:
                chosen.append(event)
            if len(chosen) >= limit:
                break
    return sorted(chosen[:limit], key=lambda e: (e.timestamp is None, e.timestamp, e.id))


def _event_context(events: list[Event]) -> str:
    return "\n".join(json.dumps({
        "id": e.id, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "severity": e.severity, "category": e.category, "source": e.source,
        "host": e.host, "entity": e.entity, "summary": (e.summary or "")[:240],
    }, default=str) for e in events) or "No candidate events."


def _parse_json_object(text: str) -> dict[str, Any]:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        value = json.loads(text[start:end + 1])
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def _parse_report_package(text: str) -> dict[str, Any]:
    """Parse the REPORT_PACKAGE object, treating a payload with none of the expected
    keys as unusable so `_complete_json` triggers a repair round."""
    obj = _parse_json_object(text)
    if any(key in obj for key in ("summary", "timeline_entries", "finding_verdicts")):
        return obj
    return {}


def _validated_timeline(raw: Any, candidates: list[Event], active_findings: list[Finding]) -> list[dict]:
    if not isinstance(raw, list):
        return []
    events = {event.id: event for event in candidates if event.timestamp}
    finding_ids = {finding.id for finding in active_findings}
    entries: list[dict] = []
    for item in raw[:20]:
        if not isinstance(item, dict):
            continue
        event_ids = []
        for value in item.get("event_ids") or []:
            try:
                event_id = int(value)
            except (TypeError, ValueError):
                continue
            if event_id in events and event_id not in event_ids:
                event_ids.append(event_id)
        if not event_ids:
            continue
        cited = [events[event_id] for event_id in event_ids]
        cited.sort(key=lambda event: event.timestamp)
        valid_finding_ids = []
        for value in item.get("finding_ids") or []:
            try:
                finding_id = int(value)
            except (TypeError, ValueError):
                continue
            if finding_id in finding_ids and finding_id not in valid_finding_ids:
                valid_finding_ids.append(finding_id)
        confidence = str(item.get("confidence") or "medium").lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"
        entries.append({
            "id": f"timeline-{len(entries) + 1}",
            "title": str(item.get("title") or "Notable activity")[:200],
            "description": str(item.get("description") or "")[:1200],
            "confidence": confidence,
            "start": cited[0].timestamp.isoformat(),
            "end": cited[-1].timestamp.isoformat(),
            "event_ids": event_ids[:8],
            "finding_ids": valid_finding_ids[:8],
        })
    entries.sort(key=lambda item: item["start"])
    return entries


def _fallback_timeline(candidates: list[Event], active_findings: list[Finding]) -> list[dict]:
    """Always provide a useful structured timeline even if a local model returns invalid JSON."""
    finding_by_event: dict[int, list[int]] = defaultdict(list)
    for finding in active_findings:
        event_id = (finding.evidence or {}).get("event_id")
        if isinstance(event_id, int):
            finding_by_event[event_id].append(finding.id)
    important = [
        event for event in candidates
        if event.timestamp and (_SEVERITY_RANK.get(event.severity, 0) >= 2 or event.id in finding_by_event)
    ]
    if not important:
        important = [event for event in candidates if event.timestamp][:10]
    return [{
        "id": f"timeline-{index + 1}",
        "title": event.category.replace("_", " ").title(),
        "description": event.summary[:1200],
        "confidence": "high",
        "start": event.timestamp.isoformat(), "end": event.timestamp.isoformat(),
        "event_ids": [event.id], "finding_ids": finding_by_event.get(event.id, [])[:8],
    } for index, event in enumerate(important[:20])]


async def analyze_case(case_id: str, emit=None) -> dict[str, Any]:
    """Full map-reduce analysis. `emit` is an optional async callback(phase, message)."""
    async def _emit(phase: str, message: str, percent: float = -1.0) -> None:
        if emit:
            await emit(phase, message, percent)

    session = case_store.get_session(case_id)
    try:
        case_store.update_case_meta(case_id, include_stats=False, status="analyzing")

        cfg = load_config().llm
        # Build a deterministic compact evidence map; this replaces up to twelve
        # category-specific LLM calls while retaining source and time diversity.
        events = list(session.scalars(select(Event)))
        by_category: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            by_category[e.category].append(e)
        summaries: list[str] = []
        categories = sorted(by_category.keys(), key=lambda c: -len(by_category[c]))[:MAX_CATEGORIES]
        for idx, category in enumerate(categories):
            evs = by_category[category]
            evs_sorted = sorted(
                evs,
                key=lambda e: _SEVERITY_RANK.get(e.severity, 0),
                reverse=True,
            )
            rows = [{"id": e.id, "summary": e.summary[:180], "entity": e.entity,
                     "severity": e.severity, "ts": e.timestamp.isoformat() if e.timestamp else None}
                    for e in evs_sorted[:8]]
            await _emit("map", f"Indexing {category} ({len(evs)} events)",
                        (idx / max(len(categories), 1)) * 50)
            summaries.append(f"[{category}] count={len(evs)} representative records:\n{_json_lines(rows, 8)}")

        findings = list(session.scalars(select(Finding).order_by(Finding.severity)))
        active_findings, suppressed_findings = _split_findings(session, findings)
        findings_text = _finding_context(active_findings)
        suppressed_text = _finding_context(suppressed_findings, suppressed=True, limit=40)

        memory_results = list(session.scalars(
            select(MemoryResult).where(MemoryResult.severity.in_(["high", "critical"]))
        ))
        memory_text = "\n".join(
            f"- [memory:{m.id}] ({m.severity.upper()}) [{m.plugin}] {m.summary[:300]} "
            f"data={json.dumps(m.data, default=str)[:700]}"
            for m in memory_results[:40]
        ) or "No high-severity memory findings."

        # --- REDUCE: correlate (tool-assisted, falls back to single-shot) ---
        await _emit("reduce", "Cross-correlating evidence into attack narrative", 60)
        correlation_prompt = prompts.CORRELATION.format(
            overview=get_case_overview(session, {}),
            findings=findings_text,
            suppressed=suppressed_text,
            summaries="\n\n".join(summaries) or "No summaries.",
            memory=memory_text,
        )
        correlation = ""
        try:
            async def _on_reduce_tool(name: str, args: dict) -> None:
                await _emit("reduce", f"Correlating: querying case data ({describe_call(name, args)})", 62)

            correlation, _ = await run_tool_loop(
                session, get_provider(),
                prompts.SYSTEM_ANALYST + "\n\n" + prompts.TOOLS_PROTOCOL,
                correlation_prompt + prompts.TOOL_TASK_NOTE,
                max_iters=cfg.analysis_max_tool_calls, on_tool=_on_reduce_tool,
                case_id=case_id, allow_suppression=True,
            )
        except Exception:
            correlation = ""
        if not correlation.strip():
            correlation = await _complete([
                {"role": "system", "content": prompts.SYSTEM_ANALYST},
                {"role": "user", "content": correlation_prompt},
            ])

        # --- Extract structured findings from the AI's correlated analysis ---
        await _emit("findings", "Extracting AI findings", 68)
        try:
            findings = list(session.scalars(select(Finding)))
            new_findings = await _extract_ai_findings(session, findings, correlation)
            if new_findings:
                await _emit("findings", f"AI recorded {len(new_findings)} new finding(s)", 72)
                findings = list(session.scalars(select(Finding).order_by(Finding.severity)))
        except Exception:
            # never fail the whole analysis because finding extraction misbehaved
            pass

        active_findings, suppressed_findings = _split_findings(session, findings)
        severity_counts: dict[str, int] = defaultdict(int)
        for f in active_findings:
            severity_counts[f.severity] += 1

        await _emit("report", "Building evidence-backed report and timeline", 82)
        candidates = _sample_events(events, active_findings)
        package = await _complete_json([
            {"role": "system", "content": prompts.SYSTEM_ANALYST},
            {"role": "user", "content": prompts.REPORT_PACKAGE.format(
                overview=get_case_overview(session, {}), correlation=correlation[:10000],
                findings=_finding_context(active_findings, limit=30),
                suppressed=_finding_context(suppressed_findings, suppressed=True, limit=30),
                events=_event_context(candidates),
            )},
        ], _parse_report_package)
        summary_text = str(package.get("summary") or "").strip()
        if not summary_text:
            summary_text = await _complete([
                {"role": "system", "content": prompts.SYSTEM_ANALYST},
                {"role": "user", "content": prompts.FINAL_REPORT.format(
                    correlation=correlation, severity_counts=dict(severity_counts),
                )},
            ])
        timeline_entries = _validated_timeline(
            package.get("timeline_entries"), candidates, active_findings
        )
        if not timeline_entries:
            timeline_entries = _fallback_timeline(candidates, active_findings)
        timeline_narrative = "\n\n".join(
            f"{entry['start']} — {entry['title']}: {entry['description']}"
            for entry in timeline_entries
        )
        by_id = {finding.id: finding for finding in active_findings}
        verdicts: dict[int, str] = {}
        for item in (package.get("finding_verdicts") or [])[:15]:
            if not isinstance(item, dict):
                continue
            try:
                finding = by_id.get(int(item.get("finding_id")))
            except (TypeError, ValueError):
                finding = None
            verdict = str(item.get("verdict") or "").strip()
            if not finding or not verdict:
                continue
            verdicts[finding.id] = verdict[:3000]
        findings_analysis: list[dict[str, Any]] = []
        for finding in _context_findings(active_findings, 15):
            verdict = verdicts.get(finding.id)
            if verdict:
                finding.ai_verdict = verdict
                basis = "ai-verdict"
            else:
                verdict = f"Evidence recorded in this finding: {finding.description}"
                basis = "finding-evidence"
            findings_analysis.append({
                "id": finding.id, "title": finding.title,
                "severity": finding.severity, "verdict": verdict[:3000], "basis": basis,
            })
        session.commit()

        # --- Persist report ---
        report = Report(
            summary=summary_text,
            timeline_narrative=timeline_narrative,
            timeline_entries=timeline_entries,
            findings_analysis=findings_analysis,
            suppression_revision=overrides.get_suppression_revision(session),
        )
        session.add(report)
        session.commit()

        case_store.update_case_meta(
            case_id, include_stats=False, status="ready", ai_summary=summary_text[:1000],
        )
        await _emit("done", "Analysis complete", 100)
        return {
            "summary": summary_text,
            "timeline_narrative": timeline_narrative,
            "timeline_entries": timeline_entries,
            "findings_analysis": findings_analysis,
            "correlation": correlation,
        }
    except Exception as e:
        case_store.update_case_meta(case_id, include_stats=False, status="error")
        raise
    finally:
        session.close()


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _parse_json_array(text: str) -> list[dict[str, Any]]:
    """Pull a JSON array out of an LLM response that may be wrapped in prose/fences."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


async def _extract_ai_findings(
    session, existing_findings: list[Finding], correlation: str
) -> list[Finding]:
    """Ask the LLM to turn its correlated analysis into structured findings and persist them."""
    existing_text = "\n".join(f"- {f.title}" for f in existing_findings[:80]) or "None"
    items = await _complete_json([
        {"role": "system", "content": prompts.SYSTEM_ANALYST},
        {"role": "user", "content": prompts.EXTRACT_FINDINGS.format(
            correlation=correlation[:8000], existing=existing_text,
        )},
    ], _parse_json_array)

    existing_titles = {f.title.strip().lower() for f in existing_findings}
    created: list[Finding] = []
    for item in items[:12]:
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        if not title or not description:
            continue
        entity = str(item.get("entity") or "").strip() or None
        if title.lower() in existing_titles or any(
            _semantically_matches(title, description, (entity or "").lower(), existing)
            for existing in existing_findings
        ):
            continue
        severity = str(item.get("severity") or "medium").strip().lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        techniques = item.get("mitre_techniques") or []
        if not isinstance(techniques, list):
            techniques = []
        techniques = [str(t).strip() for t in techniques if str(t).strip()][:8]
        finding = Finding(
            title=title[:500],
            description=description[:2000],
            severity=severity,
            mitre_techniques=techniques,
            evidence={"entity": entity, "derived_from": "ai-correlation"},
            source="ai-analysis",
        )
        session.add(finding)
        existing_titles.add(title.lower())
        existing_findings.append(finding)
        created.append(finding)

    if created:
        session.commit()
    return created


async def chat_stream(case_id: str, question: str, history: list[dict[str, str]]) -> AsyncIterator[str | dict]:
    """Retrieval-augmented chat with a tool-gathering phase, then a streamed answer.

    Yields str chunks (answer text) and dicts (pre-typed websocket events like
    {"type": "tool", ...}) — the router forwards dicts as-is.
    """
    session = case_store.get_session(case_id)
    try:
        # Retrieve context: FTS search on the question + top findings
        try:
            matched = case_store.search_events(session, _fts_query(question), limit=25)
        except Exception:
            matched = []
        if not matched:
            matched = list(session.scalars(
                select(Event).where(Event.severity.in_(["high", "critical"])).limit(25)
            ))

        findings = list(session.scalars(select(Finding)))
        active_findings, suppressed_findings = _split_findings(session, findings)
        active_findings = sorted(
            active_findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True
        )[:25]
        suppressed_findings = sorted(
            suppressed_findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True
        )[:25]
        processes = list(session.scalars(
            select(Process).where(Process.severity.in_(["high", "critical", "medium"])).limit(25)
        ))
        memory = list(session.scalars(
            select(MemoryResult).where(MemoryResult.severity.in_(["high", "critical"])).limit(20)
        ))

        findings_text = _finding_context(active_findings, limit=25)
        suppressed_text = _finding_context(suppressed_findings, suppressed=True, limit=25)
        events_text = "\n".join(
            f"- [event:{e.id}] {e.timestamp.isoformat() if e.timestamp else 'n/a'} "
            f"({e.severity}) {e.summary[:200]}"
            for e in matched
        ) or "None"
        processes_text = "\n".join(
            f"- {p.name} (pid {p.pid}, ppid {p.ppid}) flags={p.flags} sev={p.severity} cmd={(p.cmdline or '')[:150]}"
            for p in processes
        ) or "None"
        memory_text = "\n".join(
            f"- [{m.plugin}] ({m.severity}) {m.summary[:200]}" for m in memory
        ) or "None"

        context = prompts.CHAT_CONTEXT.format(
            overview=get_case_overview(session, {}), findings=findings_text,
            suppressed=suppressed_text, events=events_text,
            processes=processes_text, memory=memory_text, question=question,
        )

        try:
            memo = case_store.get_meta(session, "chat_memo")
        except Exception:
            memo = None

        # --- Phase 1: tool-driven data gathering (non-streamed) ---
        gathered: list[dict] = []
        try:
            queue: asyncio.Queue = asyncio.Queue()

            async def _on_chat_tool(name: str, args: dict) -> None:
                queue.put_nowait(describe_call(name, args))

            explicit_suppression = _requests_suppression(question)
            cfg = load_config().llm
            gather_prompt = prompts.CHAT_GATHER + "\n\n" + prompts.TOOLS_PROTOCOL
            if not explicit_suppression:
                gather_prompt += "\n\nSuppression is not authorized for this request; use read-only tools only."
            task = asyncio.create_task(run_tool_loop(
                session, get_provider(),
                gather_prompt,
                context,
                max_iters=cfg.chat_max_tool_calls, on_tool=_on_chat_tool,
                case_id=case_id, allow_suppression=explicit_suppression,
            ))
            while not (task.done() and queue.empty()):
                try:
                    desc = await asyncio.wait_for(queue.get(), timeout=0.2)
                    yield {"type": "tool", "content": desc}
                except asyncio.TimeoutError:
                    continue
            _, gathered = await task
            for call in gathered:
                try:
                    mutation = json.loads(call.get("result") or "")
                except (TypeError, json.JSONDecodeError):
                    mutation = None
                if isinstance(mutation, dict) and mutation.get("mutation") == "finding_suppressed":
                    yield {"type": "finding_suppressed", **mutation}
        except Exception:
            gathered = []

        tool_context = _chat_tool_context(gathered)

        # --- Phase 2: streamed final answer ---
        system_content = prompts.CHAT_SYSTEM
        if memo:
            system_content += (
                "\n\nRunning investigation memo (earlier conversation):\n" + memo
            )
        messages = [{"role": "system", "content": system_content}]
        for h in history[-6:]:
            if h.get("role") in ("user", "assistant"):
                messages.append({"role": h["role"], "content": h["content"]})
        messages.append({"role": "user", "content": context + tool_context})

        case_store.save_chat(session, "user", question)
        session.commit()

        provider = get_provider()
        result = await provider.complete(messages, stream=True)
        full = []
        if isinstance(result, str):
            full.append(result)
            yield result
        else:
            async for chunk in result:
                full.append(chunk)
                yield chunk

        if not "".join(full).strip():
            retry_text = await _retry_plain_text_answer(provider, messages)
            if not retry_text:
                retry_text = (
                    "The model returned no text after gathering the evidence. "
                    "Please retry the question; the retrieved case records were not modified."
                )
            full.append(retry_text)
            yield retry_text

        case_store.save_chat(session, "assistant", "".join(full))
        session.commit()

        try:
            await _update_chat_memo(session)
        except Exception:
            logger.debug("Chat memo update failed", exc_info=True)
    finally:
        session.close()


async def _update_chat_memo(session) -> None:
    """Fold older un-summarized chat history into a compact running memo."""
    upto = int(case_store.get_meta(session, "chat_memo_upto") or 0)
    rows = list(session.scalars(
        select(ChatHistory).where(ChatHistory.id > upto).order_by(ChatHistory.id)
    ))
    candidates = rows[:-MEMO_KEEP_RAW] if len(rows) > MEMO_KEEP_RAW else []
    if not candidates:
        return
    if sum(len(r.content or "") for r in candidates) < MEMO_THRESHOLD_CHARS:
        return
    memo = case_store.get_meta(session, "chat_memo") or "None yet."
    exchanges = "\n".join(
        f"{r.role.upper()}: {(r.content or '')[:800]}" for r in candidates
    )[:12000]
    updated = await _complete([
        {"role": "system", "content": prompts.SYSTEM_ANALYST},
        {"role": "user", "content": prompts.CHAT_MEMO.format(memo=memo, exchanges=exchanges)},
    ])
    if updated.strip():
        case_store.set_meta(session, "chat_memo", updated.strip()[:4000])
        case_store.set_meta(session, "chat_memo_upto", str(candidates[-1].id))
        session.commit()


async def investigate_entity_stream(case_id: str, entity_id: str) -> AsyncIterator[str]:
    """Stream an AI investigation of a single entity built from its action trace."""
    from app.detect.entity_graph import entity_dossier

    dossier = await asyncio.to_thread(entity_dossier, case_id, entity_id)
    if not dossier:
        yield "Entity not found in this case."
        return

    ent = dossier["entity"]
    neighbors = "\n".join(
        f"- {n['direction']} · {n['verb']} · {n['entity']['type']} {n['entity']['value']} "
        f"(x{n['count']}, {n['severity']})"
        for n in dossier["neighbors"][:40]
    ) or "None"
    findings = "\n".join(
        f"- ({f['severity']}) {f['title']} [{', '.join(f['techniques'])}]"
        for f in dossier["findings"][:30]
    ) or "None"
    actions = "\n".join(
        f"{a['timestamp'] or 'n/a'} [{a['severity']}] ({a['category']}) {a['summary'][:200]}"
        for a in dossier["actions"][:120]
    ) or "No recorded actions."

    prompt = prompts.INVESTIGATE_ENTITY.format(
        etype=ent["type"], evalue=ent["value"], severity=ent["severity"],
        first_seen=ent["first_seen"], last_seen=ent["last_seen"],
        neighbors=neighbors, findings=findings, actions=actions,
    )
    provider = get_provider()
    session = case_store.get_session(case_id)
    gathered: list[dict] = []
    try:
        prompt += "\n\nCOMPACT CASE INVENTORY:\n" + get_case_overview(session, {})
        _ready, gathered = await run_tool_loop(
            session, provider,
            prompts.CHAT_GATHER + "\n\n" + prompts.TOOLS_PROTOCOL
            + "\n\nThis entity workflow does not modify findings. Query the selected entity, connected entities, and underlying records (handle inventories may be fetched and cached on demand); never suppress findings.",
            prompt, max_iters=load_config().llm.entity_max_tool_calls,
            case_id=case_id, allow_suppression=False,
        )
    except Exception:
        gathered = []
    finally:
        session.close()
    if gathered:
        prompt += "\n\nADDITIONAL VERIFIED CASE DATA:\n" + "\n\n".join(
            f"[{call['tool']} {json.dumps(call['args'], default=str)}]\n{call.get('result', '')}"
            for call in gathered
        )[:12000]
    prompt += "\n\nCite exact records using [[event:123]] and [[finding:5]] whenever IDs are available."
    result = await provider.complete(
        [{"role": "system", "content": prompts.SYSTEM_ANALYST},
         {"role": "user", "content": prompt}],
        stream=True,
    )
    if isinstance(result, str):
        yield result
    else:
        async for chunk in result:
            yield chunk
