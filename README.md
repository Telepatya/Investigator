# Investigator — DFIR & Memory Forensics GUI (with AI support)

**Made by Roei.f**

> **Public Beta — v0.1.2**
>
> This is pre-release software for evaluation and analyst-assisted investigation.
> Interfaces and stored data may change before 1.0; validate conclusions against
> the underlying evidence before relying on them.

A fully local DFIR workstation. Ingest endpoint and log evidence — event logs, EVTX, forensic artifacts, DFIR collections (e.g. Velociraptor), and Microsoft Defender / Azure logs — plus raw memory dumps, run MemProcFS + YARA + a deterministic detection engine, and let a configurable LLM (local Ollama, or remote OpenAI / OpenRouter / Anthropic / Gemini) reconstruct the machine's story — a full timeline, interactive process and entity maps, MITRE ATT&CK coverage, and a written incident summary.

Everything runs on your machine. API keys are stored in your OS credential vault, never on disk in plaintext.

## Showcase Video (Click to watch)
[![Watch the full showcase video](main.png)](https://vimeo.com/1209614692)

## Table of contents

- [Features](#features)
- [Supported evidence](#supported-evidence)
- [Quick start](#quick-start)
- [Configure the AI](#configure-the-ai)
- [Working a case](#working-a-case)
- [How analysis works](#how-analysis-works)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Development](#development)
- [Dependency security](#dependency-security)
- [Demo, support, and releases](#demo-support-and-releases)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [A note on detections](#a-note-on-detections)

## Features

- **Bring your own AI.** Ollama (on-device) with live model discovery, or OpenAI, OpenRouter, Anthropic, and Google Gemini with per-provider model catalogs and a built-in connection tester.
- **Broad evidence ingestion.** Offline-collector ZIPs (e.g. Velociraptor), JSON/JSONL artifact results, CSV, EVTX/event logs, and Microsoft Defender / Azure (Sentinel) log exports are parsed and normalized into a unified event model with full-text search. Events and logs can also be fed in manually.
- **Memory forensics.** MemProcFS process, module, VAD, thread, handle, network, service, and driver maps feed deterministic injection, hollowing, suspicious-service, network, and driver heuristics. Executable private-memory candidates are checked against VAD shape, module load order, live thread start addresses, network context, and machine-wide prevalence before escalation.
- **APT hunting.** YARA sweep of memory using a bundled C2 / offensive-tooling ruleset (Cobalt Strike, Meterpreter, Sliver/Covenant/Havoc, Mimikatz, Rubeus, reflective loaders, shellcode markers) plus your own rules directory.
- **Deterministic detection engine.** LOLBins, suspicious parent/child chains, masquerading, execution from staging directories, persistence, log clearing, and C2 beaconing — every finding mapped to MITRE ATT&CK before the LLM ever runs.
- **AI orchestration.** Map-reduce analysis over the evidence produces an executive summary, a timeline narrative, and per-finding verdicts. During correlation, verdicts, and chat, the model can query the case database itself (full-text event search, process trees, memory correlation data, findings, download path/URL inventories, and aggregates) through a provider-agnostic tool loop. Each chat turn receives a compact index of the latest report, Evidence-backed Timeline, and current findings, then verifies material claims against fresh underlying records before answering. Responses render as structured Markdown, event/finding citations open one-click evidence drawers, and case-scoped saved chats each keep their own recent history and rolling memo. Chats can be created, switched, and deleted independently.
- **Analyst workstation UI.** Responsive glass-panel workspace with system-aware light/dark themes, a persistent case shell, expandable current-case event search, reusable detail drawers, subtle loading/interaction animation, and case-scoped busy states.
- **Investigation views.** A server-filtered chronological timeline, deterministic layered entity map, overview dashboard, memory explorer, findings and event tables, evidence management, report export, and streaming AI chat. Timeline and entity-map bundles load only when those routes are opened.
- **Analyst findings.** Events and entities can be promoted to durable manual findings. Event flags carry their chosen severity into the referenced event and exact-entity-related timeline activity, while benign/delete actions restore the prior parser or detector severity.
- **Reverse workspaces.** Upload suspicious binaries to standalone or case-linked workspaces for network-isolated, non-root static analysis. Reverse reuses the configured LLM, preserves a signed provenance chain, and supports reports, IOC extraction, replay, and follow-up chat without intentionally executing samples.

| Entity map | Timeline |
| --- | --- |
| <img src="entitymap.png" alt="Interactive entity map with process relationships" width="460"> | <img src="timeline.png" alt="Investigation timeline view" width="460"> |

## Supported evidence

Investigator ingests a wide range of endpoint and log evidence. Anything below is parsed and
normalized into the unified event/process/entity model, so it shows up in search, the timeline,
the entity map, and the detection engine. Sources with a dedicated mapping get rich, typed
summaries; **any other JSON / JSONL / CSV artifact rows still ingest generically** (timestamp,
host, entity, and summary are extracted from common field names), so uncommon collectors and
artifacts populate the case even without a purpose-built parser.

### File formats

| Format | Extensions | Notes |
| --- | --- | --- |
| Collection archive | `.zip` | Offline-collector bundles (e.g. Velociraptor); parsable members are auto-extracted, the artifact name becomes the event source, and member timestamps are preserved for timestamp inference. |
| Structured data | `.json`, `.jsonl`, `.csv` | JSON is auto-sniffed for array vs. one-object-per-line (JSONL); UTF-8/BOM tolerant. |
| Windows event logs | `.evtx` | Parsed natively, and also recognized when exported as JSON/JSONL (e.g. `Windows.EventLogs.*` rows with a nested `System` envelope). |
| Text / web logs | `.txt`, `.log` | Web access logs (CLF/Combined) and Linux syslog / auth.log / auditd lines are parsed field-by-field; other lines ingest one event per line. |
| Memory dumps | `.raw`, `.dmp`, `.mem`, `.vmem`, `.bin`, `.img`, `.lime`, `.dd` | Also extensionless dumps named `PhysicalMemory` / `memory` / `ram`. Analyzed with MemProcFS + YARA (optional). |

### Windows event logs (typed mapping)

- **Sysmon (Operational):** 1 process create, 3 network connect, 5 process terminate, 7 image/DLL load, 8 CreateRemoteThread, 10 ProcessAccess, 11 file create, 12 / 13 / 14 registry add / set / rename, 22 DNS query.
- **Security:** 4688 / 4689 process create / exit; 4624 / 4625 logon success / failure; 4634 / 4647 logoff; 4648 explicit-credential logon; 4672 special privileges; 4720 / 4722 / 4724 / 4725 / 4726 / 4728 / 4732 / 4756 account and group management; 4697 service install; 4698 / 4702 scheduled-task create / update; 1102 security log cleared.
- **System:** 7045 service install.
- **PowerShell (Operational):** 4104 script-block logging.
- **Task Scheduler (Operational):** 106 task registered.
- Logon types are decoded (interactive, network, service, batch, unlock, remote-interactive / RDP, cached, new-credentials). Event IDs are always gated by channel/provider so IDs are never confused across logs. Unmapped event IDs are still ingested as generic event-log entries.

### Microsoft Defender / Azure (Sentinel) Advanced Hunting

Advanced Hunting exports (from the Defender portal or Log Analytics / Sentinel, JSON or CSV) are
normalized onto the same schema as Sysmon/EVTX, so all detection, correlation, process-tree, and
timeline machinery works over them unchanged. Recognized tables:

`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`,
`DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, `DeviceNetworkInfo`, `DeviceInfo`
(plus generic `AdvancedHunting` results). Both portal and Log Analytics timestamp columns
(`TimeGenerated`, `Timestamp [UTC]`, …) are recognized, including the locale 12-hour format
(`7/8/2026, 11:57:31.123 AM`) used by portal-grid CSV exports. Log Analytics **"Export to JSON"**
files (the columnar `{"tables":[{"columns":…,"rows":…}]}` envelope) are flattened automatically,
even when metadata or statistics properties appear before `tables`.

Additional Sentinel tables beyond Advanced Hunting are also mapped:

- **`SecurityEvent`** (Windows events via AMA/MMA) — reuses the Windows EventID classifier, so the
  same 4624/4625/4720/7045/1102/4698/4826 detections fire; the `EventData` XML column is flattened
  and the channel is synthesized when absent.
- **`Syslog`** (Linux logs forwarded to Sentinel) — shares the Linux classifier below, so a
  `Failed password` line produces the same detection whether it arrived here or as `/var/log/auth.log`.
- **`SigninLogs` / `AuditLogs`** (Entra ID) — sign-ins and directory changes land on the timeline;
  repeated failed sign-ins raise brute-force findings and risky sign-ins (`RiskLevelDuringSignIn`) are flagged.

### Linux logs

Linux endpoint logs normalize onto the same schema and drive a Linux-specific detection set:

- **syslog / auth.log / secure** (`.log`, `.txt`) — RFC3164 (year inferred from file mtime), RFC5424,
  and ISO-prefixed rsyslog lines. ZIP ingestion preserves the member timestamp before RFC3164 year
  inference. sshd, sudo, useradd/usermod/groupadd, and cron activity are typed.
- **auditd `audit.log`** — records sharing an audit id are merged into one event; `EXECVE` argv is
  reconstructed (numeric arg order, hex-encoded args decoded) so command-line detections apply, and
  `PATH` records surface persistence-file writes. Native `ADD_USER`, `ADD_GROUP`, and group-management
  records are promoted to the same account-action fields as syslog messages.
- **journald** — `journalctl -o json` (JSONL) with `__REALTIME_TIMESTAMP`, `MESSAGE`, `_CMDLINE`, etc.
  Journald field signatures take precedence over filename-based Sentinel table hints, so a journal
  export named `syslog.jsonl` retains its message and microsecond timestamp.

Detections cover SSH/pam brute force and brute-force-followed-by-success (the success must occur at
or after the latest observed failure), root logins, account and privileged-group changes,
cron/systemd/rc/ld.so.preload/authorized_keys persistence, and suspicious shell one-liners
(download-piped-to-shell, `/dev/tcp` and netcat/socat reverse shells, base64-decoded payloads, and
shell-history tampering), each mapped to ATT&CK.

> Timestamps are computed at ingest, so fixing a parser does not retroactively repair a case ingested
> earlier. Re-ingest the evidence file (Evidence page) to pick up the corrected timeline.

### Forensic artifacts

- **NTFS USN journal** (`$UsnJrnl:$J`) — reason bits decoded; old/new names correlated by MFT `FileReferenceNumber` into single rename leads.
- **Process listings** (pslist / pstree / processes rows) — promoted to first-class process entities with parent/child links.
- **Download evidence** (`Windows.Detection.EvidenceOfDownload`, `Zone.Identifier` / `HostUrl`) — correlated into download-source → file → process chains.
- **Any other artifact rows** (MFT, prefetch, Amcache, registry, services, scheduled tasks, etc.) ingest generically via timestamp/host/entity extraction.

### Web and application logs

- Apache / Nginx access logs in **Common Log Format** and **Combined Log Format** — method, path, status, client IP, user, referer, and user-agent are extracted into a `weblog` category.
- Any other line-based text log is ingested one event per line for search and timeline.

### Memory analysis (MemProcFS + YARA, optional)

Process list (`pslist`) and hidden/terminated candidates (`psscan`), VAD map, threads, handles,
loaded modules and drivers, network endpoints (`netscan`), services (`svcscan`), injection
candidates (`malfind`), module-linkage checks (`ldrmodules`), MemProcFS forensic CSVs (`findevil`,
timeline), and YARA scan hits — all cross-correlated and, where possible, attached back to concrete
processes, modules, files, services, or connections.

## Quick start

```bash
# From the project root
python run.py
```

On Windows you can also just double-click **`run.bat`** (it calls `run.py`).

This creates the Python virtual environment, installs locked dependencies, builds the frontend, and opens the app at `http://localhost:8400`.

Options:

```bash
python run.py --dev                  # backend + Vite dev server with hot reload (frontend on :5173)
python run.py --port 9000            # use a different port
python run.py --skip-build           # skip rebuilding the frontend
python run.py --allow-unlocked-deps  # temporary local fallback if Python lock files aren't generated yet
python run.py --build-reverse-sandbox # explicitly build the optional Docker static-analysis image
```

The **Reverse** tab works as a local workspace manager without Docker. Running
static binary analysis additionally requires Docker Desktop (Linux containers)
and the explicitly built `investigator-reverse:latest` image. Normal startup
never downloads or builds that image. Reverse projects and artifacts are stored
under `~/.investigator/reverse/`; private provenance and provider keys remain in
the operating-system credential vault. Reverse uses an adaptive
malware-analysis prompt and one-operation loop (`run_cmd`, `read_file`,
`write_file`, and `list_dir`) instead of a fixed checklist or rigid report
template. Findings cite expandable `[trace:<message-id>]` evidence, and a
goal-driven reviewer may request more analysis or revise unsupported report
language before publishing. Reports expose complete, partial, or blocked
analysis outcomes separately from review warnings and signature integrity; every
published report is signed even when review is unavailable or leaves warnings.
Follow-up chat uses the same tool-capable
12-turn loop, so it can inspect the sealed artifacts instead of answering
solely from report text.
Review and signature status are visible on the Report tab and can be retried
independently. Unfinished reports can resume the same investigation from either
the workspace or report view; the previously published signed bytes are retained
as a downloadable snapshot while the continuation runs.
Reverse also persists semantic attempt history and normalized failure fingerprints.
Two matching failures, or three operations that add no new evidence, activate a
diagnostic pivot that asks the analyst model to validate bounds, headers, sizes,
hashes, or runtime compatibility before retrying the stalled method. Substantive
`ANALYSIS CHECKPOINT` responses are saved without prematurely entering report
review. The sandbox includes a bounded `pyinstaller-inspect` analyzer that validates
CArchive layout, safely extracts selected entries, and uses `xdis` for cross-version
Python bytecode disassembly without importing or executing the sample.
When built-in analyzers are insufficient, approved Reverse projects also let the
model create Python parsers/decoders and run them against the sealed sample
inside the same networkless, non-root sandbox. This does not enable a shell,
subprocesses, native loading, or intentional sample execution.

<details>
<summary><strong>Manual start</strong> (without the launcher)</summary>

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --no-deps -r requirements-memory.lock
.\.venv\Scripts\python.exe -m app.main   # serves API on :8400 (and the built UI if present)

# in another terminal, for UI development:
cd frontend
npm ci
npm run dev                               # http://localhost:5173, proxies /api to :8400
```

</details>

## Configure the AI

Open **Settings**:

- **Ollama (local):** point at your Ollama server URL (default `http://localhost:11434`); the model dropdown is populated live from your installed models.
- **OpenAI / OpenRouter / Anthropic / Gemini:** paste your API key (stored in the OS keyring), click **Test**, then pick a model. OpenRouter uses its OpenAI-compatible API at `https://openrouter.ai/api/v1` by default.

With Ollama, no case data ever leaves your machine. With a remote provider, only the evidence excerpts included in prompts are sent to that provider — Settings shows an explicit warning while a remote provider is selected.

Chat uses a bounded tool-gathering phase followed by a plain-text answer phase. If a
provider returns only a structured function-call part instead of displayable text,
Investigator retries once with an explicit plain-text-only instruction rather than
silently saving an empty answer.

## Working a case

1. **Create a case.**
2. **Upload evidence** — drop a log or artifact collection (ZIP / JSON / JSONL / CSV / EVTX, including Velociraptor collections and Defender/Azure log exports) or a memory dump (`.raw`, `.dmp`, `.mem`, `.vmem`, `.lime`, ...). Ingestion, detection, and memory analysis run automatically with live progress. Multi-file artifact uploads are parsed serially per case and share one detection pass after the final queued file; files that produce zero events do not trigger a redundant detection run.
3. **Run AI analysis** — correlates everything into a report, timeline narrative, and per-finding verdicts.
4. **Explore** the **Overview**, **Timeline**, **Entity Map**, **Memory**, **Findings**, and **Events** tabs, export the **Report**, or interrogate the case in **AI Chat**.

The magnifying-glass control in the workspace header expands into a current-case event search. Results stay in place under the field; double-click a result to open its full raw event drawer. Timeline events also open on double-click. In Entity Map, a single click opens the entity dossier, while double-click expands or compacts one-hop relationships in focus mode.

Manual findings are analyst intent, not destructive edits to source evidence. The app stores the finding and the event's previous severity separately. Removing the finding or marking it benign restores the previous severity; detection rebuilds restore their baseline first and then reapply active manual findings.

Cases and configuration live under `~/.investigator/` — one self-contained SQLite database per case.
If the backend is stopped during ingestion or AI analysis, startup recovery changes
the stale transient case state back to `ready`; background jobs themselves are not
resumed across process restarts.

## How analysis works

Investigator is built around **correlation-first analysis**. Raw evidence is normalized into common tables for events, processes, memory findings, detections, entities, and report evidence. The deterministic engine then links those records by time, process identity, command line, file path, network endpoint, user, service name, registry key, memory session, and MITRE ATT&CK technique.

<p align="center">
  <img src="correlation1.png" alt="Investigator correlation and analysis view" width="920">
</p>

Correlation exists to reduce noisy one-off alerts:

- A single suspicious command, YARA match, handle, network connection, or memory anomaly is treated as a **lead**, not a verdict.
- Confidence increases when **independent sources agree** — a process tree plus a Sysmon event, a memory VAD plus a thread start address, a YARA match plus extracted process/module details, or persistence plus later execution.
- Benign developer and forensic tooling stays low-confidence or contextual unless there is stronger evidence of compromise.

The LLM layer runs **after** deterministic parsing and detection. It receives normalized findings, source events, memory context, process trees, entity relationships, and database search tools; during report generation and chat it can query the case database for supporting rows before writing conclusions. Reports are intentionally cautious: each finding describes what was observed, what it may indicate, what evidence supports it, and what follow-up would confirm or dismiss it. Always take AI verdicts and output with a grain of salt.

Because evidence is untrusted input, automated analysis is advisory only: it can **propose** suppressing a finding but never applies it — suppression is always an analyst action. A case with no ingested evidence is reported as **"not assessed"**, never "clean", so an empty case is never mistaken for a safe one.

Memory correlation combines MemProcFS process, module, VAD, thread, handle, service, driver, network, forensic CSV, event log, and YARA outputs. Where possible, memory findings are attached back to concrete entities — a process, module, file, service, registry item, command line, or connection. If the source can't be confidently resolved, Investigator keeps the finding as a standalone memory result instead of inventing a relationship.

## Requirements

- **Required:** 64-bit Python 3.11 or 3.12, the hashed core Python lock,
  and a current Edge, Chrome, or Firefox browser.
- **Required only for a source/frontend build:** Node.js 22 and its bundled npm.
  Node is not required by the Windows release archive because its frontend is
  prebuilt.
- **Optional capabilities:** `memprocfs` and `yara-python` for raw-memory and
  YARA analysis; Ollama or a configured remote AI provider for reports/chat; and
  custom YARA rules. Log ingestion, search, correlation, and deterministic
  detection remain available without them.

See [docs/SUPPORT.md](docs/SUPPORT.md) for the authoritative supported OS,
toolchain, required-dependency, and optional-dependency matrix.

## Architecture

**→ Full architecture guide: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — system diagrams, the evidence lifecycle, module-by-module breakdown, data model, API surface, and security model.

The short version:

- **Backend** (`backend/app`): FastAPI + SQLAlchemy, one SQLite database per case with FTS5 search. A per-case async operation coordinator serializes ingestion, analysis, detection rebuilds, and deletion; a per-database writer gate serializes SQLite write transactions while WAL keeps reads available. CPU/blocking graph and dossier work is moved off the event loop.
- **Frontend** (`frontend/src`): React + TypeScript + Vite + Tailwind, with tokenized light/dark themes, React Flow, vis-timeline, Recharts, and TanStack Query. Query keys and transient UI state are case-scoped, long operations remain visible through WebSockets, and heavy visualization routes are code-split.

## Development

```bash
# Backend tests
cd backend
python -m venv .venv && .venv/bin/pip install --require-hashes --no-deps -r requirements-dev.lock
.venv/bin/ruff check app tests
.venv/bin/python -m unittest discover -s tests

# Frontend with hot reload (backend must be running)
cd frontend
npm ci
npm run dev
```

CI runs the backend lint + test suite (Ruff, `unittest`, `pip-audit`) and the frontend type-check + build on every push and pull request. See [SECURITY.md](SECURITY.md) for the vulnerability-reporting policy.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing parser or detection
behavior. Real case evidence is never accepted as a test fixture.

## Dependency security

Investigator installs reproducible dependencies from lock files, not floating package ranges. Human-edited Python dependencies live in:

- `backend/requirements.in` — core backend
- `backend/requirements-memory.in` — MemProcFS and YARA memory-forensics extras
- `backend/requirements-dev.in` — development and CI tools

Regenerate and commit the hashed locks after changing any dependency:

```powershell
cd backend
python -m pip install uv
.\scripts\update-locks.ps1    # or ./scripts/update-locks.sh
```

The launcher installs the complete compiled dependency closure from
`backend/requirements-memory.lock` with `pip --require-hashes --no-deps` and
re-runs the install only when that lock file changes. `--no-deps` prevents pip
from re-resolving newly published transitive versions outside the lock. The
frontend uses the committed `frontend/package-lock.json` and installs with
`npm ci`.

Use `python run.py --allow-unlocked-deps` only as a temporary local workaround while creating the first lock files — never for releases or normal installs.

## Demo, support, and releases

The [synthetic demonstration case](demo/synthetic-case/README.md) imports nine
generated Defender-style events and exercises filesystem, process, persistence,
network, injection, and logon paths without real evidence.

- [Supported OS and dependency matrix](docs/SUPPORT.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
- [Case-database migration policy](docs/MIGRATIONS.md)
- [Changelog](CHANGELOG.md) and [versioned release notes](docs/releases/v0.1.2.md)
- [Release, signed-tag, checksum, SBOM, and verification procedure](docs/RELEASING.md)

Official releases are published only from GitHub-verified signed tags. Each
release includes a reproducible Windows ZIP, SHA-256 checksum manifest,
CycloneDX SBOM, and versioned notes.

## Roadmap

The proposed [v0.2.0 roadmap](ROADMAP.md) covers benchmark infrastructure,
profile-guided optimization, local privacy-preserving metrics, a top-level
universal Exclusions feature for automatically suppressing matching findings
across cases without deleting evidence, and case manifests with SHA-256
evidence hashing for verifiable chain-of-custody.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, parser/detection review
requirements, and the mandatory [sanitized-fixture method](docs/TEST_FIXTURES.md).
Project behavior is governed by the [Code of Conduct](CODE_OF_CONDUCT.md) and
[maintainer/review policy](MAINTAINERS.md). Use the structured bug, parser-error,
false-positive, and feature-request forms when opening an issue.

## A note on detections

The deterministic engine and bundled YARA rules are heuristic, tuned to surface candidate activity for analyst review. Treat AI output as an assistive lead, not ground truth — always confirm against the raw evidence, which is one click away throughout the UI.

## Credits

Investigator DFIR is made by **Roei.f**.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify,
and distribute this software under its terms. It is provided "as is", without
warranty of any kind; see the LICENSE and [NOTICE](NOTICE) files for details.
