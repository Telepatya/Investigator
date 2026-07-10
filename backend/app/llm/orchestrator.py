"""LLM orchestrator: map-reduce evidence analysis, report generation, per-finding verdicts, chat."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import select

from app.llm import prompts
from app.llm.base import get_provider
from app.llm.tools import describe_call, fts_query as _fts_query, run_tool_loop
from app.store import cases as case_store
from app.store.database import ChatHistory, Event, Finding, MemoryResult, Process, Report

MAX_EVIDENCE_ROWS_PER_BATCH = 40
MAX_CATEGORIES = 12
TOOL_VERDICT_FINDINGS = 10  # top-N findings that get tool-assisted verdicts
MEMO_THRESHOLD_CHARS = 6000  # un-summarized history beyond the raw tail triggers a memo update
MEMO_KEEP_RAW = 6  # newest messages always sent raw, never folded into the memo


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


async def analyze_case(case_id: str, emit=None) -> dict[str, Any]:
    """Full map-reduce analysis. `emit` is an optional async callback(phase, message)."""
    async def _emit(phase: str, message: str, percent: float = -1.0) -> None:
        if emit:
            await emit(phase, message, percent)

    session = case_store.get_session(case_id)
    try:
        case_store.update_case_meta(case_id, include_stats=False, status="analyzing")

        # --- MAP: summarize events grouped by category ---
        events = list(session.scalars(select(Event)))
        by_category: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            by_category[e.category].append(e)

        summaries: list[str] = []
        categories = sorted(by_category.keys(), key=lambda c: -len(by_category[c]))[:MAX_CATEGORIES]
        for idx, category in enumerate(categories):
            evs = by_category[category]
            # prioritize higher-severity events in the batch
            evs_sorted = sorted(
                evs,
                key=lambda e: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(e.severity, 0),
                reverse=True,
            )
            rows = [{"summary": e.summary, "entity": e.entity, "severity": e.severity,
                     "ts": e.timestamp.isoformat() if e.timestamp else None} for e in evs_sorted]
            source = evs[0].source if evs else category
            await _emit("map", f"Summarizing {category} ({len(evs)} events)",
                        (idx / max(len(categories), 1)) * 50)
            prompt = prompts.ARTIFACT_SUMMARY.format(
                category=category, source=source, evidence=_json_lines(rows)
            )
            summary = await _complete([
                {"role": "system", "content": prompts.SYSTEM_ANALYST},
                {"role": "user", "content": prompt},
            ])
            summaries.append(f"[{category}] {summary}")

        # --- Gather findings + memory ---
        findings = list(session.scalars(select(Finding).order_by(Finding.severity)))
        findings_text = "\n".join(
            f"- ({f.severity.upper()}) {f.title} [{', '.join(f.mitre_techniques)}]: {f.description[:300]}"
            for f in findings[:60]
        ) or "No deterministic findings."

        memory_results = list(session.scalars(
            select(MemoryResult).where(MemoryResult.severity.in_(["high", "critical"]))
        ))
        memory_text = "\n".join(
            f"- ({m.severity.upper()}) [{m.plugin}] {m.summary[:300]}"
            for m in memory_results[:40]
        ) or "No high-severity memory findings."

        # --- REDUCE: correlate (tool-assisted, falls back to single-shot) ---
        await _emit("reduce", "Cross-correlating evidence into attack narrative", 60)
        correlation_prompt = prompts.CORRELATION.format(
            findings=findings_text,
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
                max_iters=8, on_tool=_on_reduce_tool,
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
            new_findings = await _extract_ai_findings(session, findings, correlation)
            if new_findings:
                await _emit("findings", f"AI recorded {len(new_findings)} new finding(s)", 72)
                findings = list(session.scalars(select(Finding).order_by(Finding.severity)))
        except Exception:
            # never fail the whole analysis because finding extraction misbehaved
            pass

        # --- Severity counts ---
        severity_counts: dict[str, int] = defaultdict(int)
        for f in findings:
            severity_counts[f.severity] += 1

        # --- Final executive summary ---
        await _emit("report", "Writing executive summary", 75)
        summary_text = await _complete([
            {"role": "system", "content": prompts.SYSTEM_ANALYST},
            {"role": "user", "content": prompts.FINAL_REPORT.format(
                correlation=correlation,
                severity_counts=dict(severity_counts),
            )},
        ])

        # --- Timeline narrative ---
        await _emit("report", "Composing timeline narrative", 85)
        key_events = sorted(
            [e for e in events if e.severity in ("high", "critical", "medium") and e.timestamp],
            key=lambda e: e.timestamp,
        )[:60]
        timeline_rows = [
            f"{e.timestamp.isoformat()} [{e.severity}] {e.summary[:200]}" for e in key_events
        ]
        timeline_narrative = ""
        if timeline_rows:
            timeline_narrative = await _complete([
                {"role": "system", "content": prompts.SYSTEM_ANALYST},
                {"role": "user", "content": prompts.TIMELINE_NARRATIVE.format(
                    events="\n".join(timeline_rows)
                )},
            ])

        # --- Per-finding verdicts (top severity findings) ---
        await _emit("report", "Generating per-finding verdicts", 92)
        findings_analysis: list[dict[str, Any]] = []
        priority = sorted(
            findings,
            key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0),
            reverse=True,
        )[:15]
        for idx, f in enumerate(priority):
            verdict_prompt = prompts.FINDING_VERDICT.format(
                title=f.title, severity=f.severity,
                techniques=", ".join(f.mitre_techniques),
                description=f.description[:600],
                evidence=json.dumps(f.evidence, default=str)[:600],
            )
            verdict = ""
            if idx < TOOL_VERDICT_FINDINGS:
                try:
                    async def _on_verdict_tool(name: str, args: dict, _title=f.title) -> None:
                        await _emit(
                            "report",
                            f"Verdict for {_title[:60]}: querying case data ({describe_call(name, args)})",
                            92,
                        )

                    verdict, _ = await run_tool_loop(
                        session, get_provider(),
                        prompts.SYSTEM_ANALYST + "\n\n" + prompts.TOOLS_PROTOCOL,
                        verdict_prompt + prompts.VERDICT_TOOL_NOTE,
                        max_iters=4, on_tool=_on_verdict_tool,
                    )
                except Exception:
                    verdict = ""
            if not verdict.strip():
                verdict = await _complete([
                    {"role": "system", "content": prompts.SYSTEM_ANALYST},
                    {"role": "user", "content": verdict_prompt},
                ])
            f.ai_verdict = verdict
            findings_analysis.append({
                "id": f.id, "title": f.title, "severity": f.severity, "verdict": verdict,
            })
        session.commit()

        # --- Persist report ---
        report = Report(
            summary=summary_text,
            timeline_narrative=timeline_narrative,
            findings_analysis=findings_analysis,
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
    response = await _complete([
        {"role": "system", "content": prompts.SYSTEM_ANALYST},
        {"role": "user", "content": prompts.EXTRACT_FINDINGS.format(
            correlation=correlation[:8000], existing=existing_text,
        )},
    ])

    existing_titles = {f.title.strip().lower() for f in existing_findings}
    created: list[Finding] = []
    for item in _parse_json_array(response)[:12]:
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        if not title or not description:
            continue
        if title.lower() in existing_titles:
            continue
        severity = str(item.get("severity") or "medium").strip().lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        techniques = item.get("mitre_techniques") or []
        if not isinstance(techniques, list):
            techniques = []
        techniques = [str(t).strip() for t in techniques if str(t).strip()][:8]
        entity = str(item.get("entity") or "").strip() or None

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

        findings = list(session.scalars(
            select(Finding).order_by(Finding.severity).limit(25)
        ))
        processes = list(session.scalars(
            select(Process).where(Process.severity.in_(["high", "critical", "medium"])).limit(25)
        ))
        memory = list(session.scalars(
            select(MemoryResult).where(MemoryResult.severity.in_(["high", "critical"])).limit(20)
        ))

        findings_text = "\n".join(
            f"- ({f.severity}) {f.title} [{', '.join(f.mitre_techniques)}]: {f.description[:250]}"
            for f in findings
        ) or "None"
        events_text = "\n".join(
            f"- {e.timestamp.isoformat() if e.timestamp else 'n/a'} ({e.severity}) {e.summary[:200]}"
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
            findings=findings_text, events=events_text,
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

            task = asyncio.create_task(run_tool_loop(
                session, get_provider(),
                prompts.CHAT_GATHER + "\n\n" + prompts.TOOLS_PROTOCOL,
                context,
                max_iters=5, on_tool=_on_chat_tool,
            ))
            while not (task.done() and queue.empty()):
                try:
                    desc = await asyncio.wait_for(queue.get(), timeout=0.2)
                    yield {"type": "tool", "content": desc}
                except asyncio.TimeoutError:
                    continue
            _, gathered = await task
        except Exception:
            gathered = []

        tool_context = ""
        if gathered:
            tool_context = "\n\nADDITIONAL DATA PULLED FROM THE CASE DATABASE:\n" + "\n\n".join(
                f"[{t['tool']} {json.dumps(t['args'], default=str)}]\n{t.get('result', t['result_preview'])}"
                for t in gathered
            )
            tool_context = tool_context[:12000]

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

        case_store.save_chat(session, "assistant", "".join(full))
        session.commit()

        try:
            await _update_chat_memo(session)
        except Exception:
            pass  # memo failure must never break chat
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
