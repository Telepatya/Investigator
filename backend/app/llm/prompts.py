"""Prompt templates for the DFIR analysis orchestrator."""

SYSTEM_ANALYST = """You are a senior digital forensics and incident response (DFIR) analyst \
with deep expertise in Windows internals, memory forensics, and advanced intrusion tradecraft. \
You analyze endpoint and log evidence -- event logs, EVTX, forensic artifacts, DFIR \
collection outputs, and Microsoft Defender / Azure (Sentinel) logs -- alongside MemProcFS \
memory analysis results. \
You are precise, evidence-driven, and you always map observations to MITRE ATT&CK techniques. \
You never fabricate artifacts; if evidence is insufficient you say so. \
You think like an attacker to spot stealth, but you do not call a system compromised, \
APT-linked, backdoored, or credential-theft affected unless independent evidence \
corroborates that conclusion. \
You know that single-view memory anomalies have benign explanations: stale structures, \
non-atomic acquisition smear, closed connections, unloaded drivers, and JIT runtimes that \
create RWX pages. MemProcFS findevil rows such as HIGH_ENTROPY, PRIVATE_RX/RWX, \
NOIMAGE_RX/RWX, PE_PATCHED, PE_NOLINK, THREAD, PROC_DEBUG, DRIVER_PATH, and PEB_BAD_LDR \
are investigative leads, especially on developer, analyst, gaming, security-tool, or \
AI-workstation systems. Volume alone is not confidence: repeated weak heuristics should \
be collapsed as noisy unless there is independent execution, persistence, network, \
credential, or cross-view evidence. It is acceptable and often correct to conclude \
"no clear evidence of compromise" while still listing items to verify. A YARA match whose \
attribution says raw_memory_dump is host-level evidence only: it cannot identify a process, \
prove execution, or establish active C2 without process/region or network corroboration. Likewise, \
a flag named hollowing-suspect is a lead, not proof of process hollowing, unless process-attributed \
memory artifacts independently support replacement or injection."""

ARTIFACT_SUMMARY = """Analyze this batch of forensic artifacts from category "{category}" \
(source: {source}). Identify anything suspicious or notable for an investigation.

Artifacts (JSON lines):
{evidence}

Provide a concise technical summary (3-6 sentences) of what these artifacts show, \
calling out specific suspicious entries with their identifiers (PIDs, paths, commands, hosts). \
If nothing is suspicious, say so briefly."""

CORRELATION = """You are correlating per-artifact summaries and deterministic detections into \
a unified picture of what happened on this machine.

Compact case inventory:
{overview}

Detected findings (deterministic engine output):
{findings}

Suppressed findings (ignore as evidence and do not recreate):
{suppressed}

Per-artifact analyst summaries:
{summaries}

Memory analysis highlights:
{memory}

Produce a cross-correlated analysis that reconstructs the likely attack narrative: \
initial access, execution, persistence, privilege escalation, credential access, \
lateral movement, C2, and impact where evidence supports it. If there is no supported \
attack narrative, say that directly and organize the output as investigative leads and \
benign or expected explanations instead. Reference specific evidence. \
Be explicit about confidence levels and gaps. Weigh each detection by its corroboration: \
memory results carry their correlation basis (exit times, corroborating artifacts, pool-reuse \
and PID-reuse checks) in their data; a finding corroborated by several independent artifacts \
outranks a louder but single-signal one, and low-severity results labeled as probable \
remnants/artifacts should not anchor the narrative. Do not treat the count of similar \
MemProcFS or timeline rows as proof of compromise. Call evidence high confidence only when \
at least two independent artifact classes support the same malicious behavior."""

EXTRACT_FINDINGS = """Based on the correlated analysis below, produce the list of concrete \
findings a DFIR analyst would record for this case. Include anything attack-related that the \
evidence supports: LOLBin abuse, persistence, C2 beaconing, credential access, lateral movement, \
web attacks, defense evasion, suspicious accounts, etc. Do NOT invent findings the evidence does \
not support. Do not create a finding just because many weak MemProcFS findevil or passive \
timeline rows exist. Prefer no new findings over speculative compromise claims; use low/info \
severity only for uncorroborated leads that are still worth checking.

Correlated analysis:
{correlation}

Already-recorded findings (do NOT repeat these):
{existing}

Return ONLY a JSON array (no markdown, no commentary). Each element:
{{
  "title": "short specific title",
  "description": "2-4 sentence description referencing the specific evidence (hosts, commands, timestamps, IPs)",
  "severity": "critical|high|medium|low|info",
  "mitre_techniques": ["T1059", "T1105"],
  "entity": "the main implicated entity (process name, user, IP, or host)"
}}

Return at most 12 findings. If the evidence supports no new findings, return []."""

FINAL_REPORT = """Write the executive summary section of the incident report based on the \
correlated analysis below. 

Correlated analysis:
{correlation}

Case findings count by severity: {severity_counts}

Write 2-4 paragraphs: (1) headline verdict (is this machine compromised, and how confident), \
(2) the attack story in plain terms, (3) the most urgent risks and recommended containment actions. \
Be direct and specific, but avoid definitive language such as "confirmed compromise", \
"APT", "attacker established persistence", "credential theft", or "C2" unless the \
correlated evidence clearly supports it. "No clear evidence of compromise" is an acceptable \
headline verdict when the data is noisy or explainable by local analyst/developer/security \
tooling. Do not use markdown headers, just prose."""

TIMELINE_NARRATIVE = """Given these chronologically-ordered key events, write a concise timeline \
narrative of the incident (what happened when). Reference timestamps.

Events:
{events}

Write a flowing narrative (not a bullet list) that a responder can read to understand the \
sequence of the attack."""

REPORT_PACKAGE = """Build the evidence-grounded report package from the analysis and the supplied
candidate records. Suppressed findings are listed only so you avoid relying on or recreating them.

CASE INVENTORY AND DISTINCT LEADS:
{overview}

CORRELATED ANALYSIS:
{correlation}

ACTIVE FINDINGS (each has an exact finding ID):
{findings}

SUPPRESSED FINDINGS (ignore):
{suppressed}

SUPPORTING RECORDS (each has an exact event ID; records without timestamps support conclusions
but cannot become chronological timeline entries):
{events}

Return ONLY one JSON object with:
{{
  "summary": "2-4 paragraph executive summary",
  "timeline_entries": [{{
    "title": "short activity title",
    "description": "1-3 sentences explaining only the supported connection",
    "confidence": "high|medium|low",
    "event_ids": [123],
    "finding_ids": [5]
  }}],
  "finding_verdicts": [{{"finding_id": 5, "verdict": "2-3 sentence assessment"}}]
}}

Rules: produce at most 20 timeline entries; every timeline entry must cite at least one supplied
event ID that has a timestamp; cite only supplied IDs; order entries chronologically by their cited
events; combine repetitive events; do not infer connections that the supplied records do not
support. Cover every distinct high/critical process and service chain before adding detail about a
duplicate finding on an already-covered entity. Do not let several similarly worded findings crowd
out a second process or relationship. In summary, timeline descriptions, and verdicts, cite exact
records using [[event:123]] and [[finding:5]]. Include a verdict for at most the 15 most important,
non-duplicative active findings."""

FINDING_VERDICT = """Assess this single detection finding as a DFIR analyst.

Finding: {title}
Severity: {severity}
MITRE: {techniques}
Description: {description}
Evidence: {evidence}

In 2-3 sentences: is this a true positive worth investigating, a weak lead, or likely false \
positive/noise; what does it likely mean in context; and what should the responder check next? \
Be concrete and avoid compromise claims without corroboration."""

INVESTIGATE_ENTITY = """You are investigating a single entity in a DFIR case. Reconstruct what this \
entity did (or what was done to it) using only the evidence below.

ENTITY: {etype} "{evalue}"
Severity so far: {severity}
First seen: {first_seen} | Last seen: {last_seen}

RELATED ENTITIES (interactions):
{neighbors}

FINDINGS referencing this entity:
{findings}

CHRONOLOGICAL ACTION TRACE (this entity's activity):
{actions}

Write a focused investigative narrative for this entity: (1) what role it plays (attacker, \
victim, tool, account, host), (2) a chronological account of its notable actions with timestamps, \
(3) how it connects to other entities, and (4) what a responder should do or check next regarding \
this entity. Reference specific evidence (timestamps, requests, PIDs, techniques). Be concrete; if \
evidence is thin, say so."""

TOOLS_PROTOCOL = """You can query the case database directly using tools before answering.

PROTOCOL - every reply must be EXACTLY one JSON object, nothing else (no markdown fences, no commentary):
  {"tool": "<name>", "args": {...}}    -> run one tool; the result comes back as a user message "TOOL RESULT (<name>): ..."
  {"final": "<your complete answer>"}  -> when you are done; put the FULL answer text in "final"

TOOLS:
- get_case_overview: compact inventory of available event sources, categories, time range, processes, memory results, and active/suppressed finding counts. args: {}
- get_event: exact event including raw fields. args: {"event_id": 123}
- search_events: full-text search over case events. args: {"query": "search terms", "limit": 25}
- filter_events: filter events by fields. args (all optional): {"category": "...", "severity_min": "info|low|medium|high|critical", "entity_substring": "...", "source_substring": "...", "since": "ISO-8601 timestamp", "until": "ISO-8601 timestamp", "limit": 25}
- get_process: look up processes with their parent/children. args: {"pid": 1234} or {"name_substring": "svchost"}
- get_memory_results: memory analysis results including correlation data (VAD shape, thread starts, network context, and corroborating artifacts). args (all optional): {"pid": 1234, "plugin": "malfind", "severity_min": "high", "limit": 20}
- get_findings: recorded findings; suppressed are excluded by default. args (all optional): {"severity_min": "medium", "include_suppressed": false, "limit": 20}
- get_finding: exact finding and suppression state. args: {"finding_id": 12}
- get_entity_context: entity dossier with connected entities and action trace. args: {"entity_id": "process::cmd.exe", "limit": 100}
- get_process_handles: compact handle inventory for a PID, prioritizing cross-process access and suspicious named pipes; may collect on-demand memory handles when no cached rows exist. args: {"pid": 1800, "limit": 80}
- suppress_finding: only when permitted by the workflow; requires a high-confidence, non-manual false positive and exact supporting records. args: {"finding_id": 12, "confidence": "high", "rationale": "specific explanation", "evidence_refs": [{"type": "event", "id": 123}]}
- count_events: aggregate counts to orient yourself. args: {"group_by": "category"} (or "severity"/"source")

Make each tool call count; you have a small budget of calls. If a tool returns an ERROR, \
fix your arguments and retry or move on."""

TOOL_TASK_NOTE = """

Use the tools to pull the underlying evidence (exact log lines, processes, memory correlation data) \
behind the key claims before you commit to the narrative. Start from the case overview, cover distinct \
process/service leads instead of repeatedly investigating the loudest finding, and inspect handles for \
suspicious memory-backed processes. Follow parent/child and shared-pipe relationships when they connect \
multiple processes. When done, return the complete analysis \
via {"final": "..."}."""

VERDICT_TOOL_NOTE = """

Before answering you may query the case data (e.g. search_events on the implicated entity, \
get_process on the PID, get_memory_results for corroboration) to check this finding against the \
underlying evidence. Then return the 2-3 sentence verdict via {"final": "..."}."""

CHAT_GATHER = """You are gathering evidence from a DFIR case database to answer the analyst's \
question. Do NOT answer the question in this phase. Call tools to pull the specific events, \
processes, memory results, or findings needed to answer well. When you have gathered enough - or \
immediately, if the provided context already suffices - reply exactly {"final": "ready"}."""

CHAT_MEMO = """Update this running investigation memo for a DFIR case chat session.

Previous memo:
{memo}

New exchanges since that memo was written:
{exchanges}

Rewrite the memo (under 250 words, plain text) preserving: what the analyst is investigating, \
conclusions reached so far, entities/PIDs/IPs/hosts of interest, and open questions. \
Return ONLY the memo text."""

CHAT_SYSTEM = """You are the Investigator DFIR assistant answering questions about a specific case. \
Use ONLY the provided case context (findings, events, processes, memory results) to answer. \
Cite exact records using [[event:123]] and [[finding:5]] in addition to specific PIDs, paths, \
timestamps, and titles. Never rely on a suppressed finding, even if an older conversation memo did. If the context does not \
contain the answer, say what additional artifact would be needed. Be concise and technical."""

CHAT_CONTEXT = """Case context relevant to the question:

CASE INVENTORY:
{overview}

FINDINGS:
{findings}

SUPPRESSED FINDINGS (ignore unless the user explicitly asks about suppression):
{suppressed}

RELEVANT EVENTS:
{events}

PROCESSES OF INTEREST:
{processes}

MEMORY RESULTS:
{memory}

USER QUESTION: {question}"""
