# Investigator — AI-Powered Velociraptor & Memory Forensics

**Made by Roei.f**

A fully local DFIR workstation. Ingest Velociraptor(Events & Artifacts) collections and raw memory dumps, run MemProcFS + YARA + a deterministic detection engine, and let a configurable LLM (local Ollama or remote OpenAI / Gemini / Claude) reconstruct the machine's story — a full timeline, interactive process maps, MITRE ATT&CK coverage, and a written incident Summary.

Everything runs on your machine. API keys are stored in your OS credential vault, never on disk in plaintext.

<p align="center">
  <img src="main.png" alt="Investigator main case overview" width="920">
</p>

## Features

- **Bring your own AI.** Ollama (on-device) with live model discovery, or OpenAI, Anthropic, and Google Gemini with per-provider model catalogs and a connection tester.
- **Velociraptor ingestion.** Offline-collector ZIPs, JSON/JSONL artifact results, CSV, and EVTX are parsed and normalized into a unified event model with full-text search (Can also be fed Events, Logs and such Manually).
- **Memory forensics.** MemProcFS process, module, VAD, thread, handle, network, service, and driver maps feed deterministic injection, hollowing, suspicious service, network, and driver heuristics. Executable private-memory candidates are checked against VAD shape, module load order, live thread start addresses, network context, and machine-wide prevalence before escalation.
- **APT hunting.** YARA sweep of memory using a bundled C2 / offensive-tooling ruleset (Cobalt Strike, Meterpreter, Sliver/Covenant/Havoc, Mimikatz, Rubeus, reflective loaders, shellcode markers) plus your own rules directory.
- **Deterministic detection engine.** LOLBins, suspicious parent/child chains, masquerading, execution from staging directories, persistence, log clearing, and C2 beaconing — every finding mapped to MITRE ATT&CK before the LLM ever runs.
- **AI orchestration.** Map-reduce analysis over the evidence produces an executive summary, a timeline narrative, and per-finding verdicts. During correlation, verdicts, and chat the model can query the case database itself (full-text event search, process trees, memory correlation data, findings, aggregates) through a provider-agnostic tool loop — it pulls the actual log lines behind a claim before committing to it. A retrieval-augmented chat answers questions using the case's own data and keeps a compact rolling memo of long conversations so context truncation doesn't lose the investigation thread.
- **Slick UI.** Dark, glassmorphic React interface: cases dashboard, overview with verdict banner and ATT&CK heat map, zoomable timeline, interactive React Flow process map with per-process dossiers, memory results, findings, event explorer, report export, and streaming AI chat.

## Screenshots

| Entity map | Timeline |
| --- | --- |
| <img src="entitymap.png" alt="Interactive entity map with process relationships" width="460"> | <img src="timeline.png" alt="Investigation timeline view" width="460"> |

## Quick start

```bash
# From the project root
python run.py
```

On Windows you can also just double-click **`run.bat`** (it calls `run.py`).

This creates the Python virtual environment, installs dependencies, builds the frontend, and opens the app at `http://localhost:8400`.

Options:

```bash
python run.py --dev          # backend + Vite dev server with hot reload (frontend on :5173)
python run.py --port 9000    # use a different port
python run.py --skip-build   # skip rebuilding the frontend
```

### Manual start

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.main   # serves API on :8400 (and the built UI if present)

# in another terminal, for UI development:
cd frontend
npm install
npm run dev                               # http://localhost:5173, proxies /api to :8400
```

## Configure the AI

Open **Settings**:

- **Ollama (local):** point at your Ollama server URL (default `http://localhost:11434`); the model dropdown is populated live from installed models.
- **OpenAI / Anthropic / Gemini:** paste your API key (stored in the OS keyring), click **Test**, then pick a model.

## Using it

1. Create a case.
2. **Upload evidence** — drop a Velociraptor collection (ZIP / JSON / JSONL / CSV / EVTX) or a memory dump (`.raw`, `.dmp`, `.mem`, `.vmem`, `.lime`). Ingestion, detection, and memory analysis run automatically with live progress.
3. **Run AI analysis** — correlates everything into a report, timeline narrative, and per-finding verdicts.
4. Explore the **Overview**, **Timeline**, **Process Map**, **Memory**, **Findings**, and **Events** tabs, export the **Report**, or interrogate the case in **AI Chat**.

## Correlation model

Investigator is built around correlation-first analysis. Raw evidence is normalized into common tables for events, processes, memory findings, detections, entities, and report evidence. The deterministic engine then links those records by time, process identity, command line, file path, network endpoint, user, service name, registry key, memory session, and MITRE ATT&CK technique.

<p align="center">
  <img src="correlation1.png" alt="Investigator correlation and analysis view" width="920">
</p>

Correlation is used to reduce noisy one-off alerts. A single suspicious command, YARA match, handle, network connection, or memory anomaly is treated as a lead. Confidence increases when independent sources agree, such as a process tree plus Sysmon event, a memory VAD plus thread start address, a YARA match plus extracted process/module details, or persistence plus later execution. Benign developer and forensic tooling should usually stay as low-confidence or contextual unless there is stronger evidence of compromise.

The LLM layer runs after deterministic parsing and detection. It receives normalized findings, source events, memory context, process trees, entity relationships, and database search tools. During report generation and chat, the model can query the case database for supporting rows before writing conclusions. This is intended to make the report cautious: findings should describe what was observed, what it may indicate, what evidence supports it, and what follow-up would confirm or dismiss it - Always Take AI Verdicts & Output with a grain of salt.

Memory correlation combines MemProcFS process, module, VAD, thread, handle, service, driver, network, forensic CSV, event log, and YARA outputs. When possible, memory findings are attached back to concrete entities such as a process, module, file, service, registry item, command line, or connection. If the source cannot be confidently resolved, Investigator keeps the finding as a standalone memory result instead of inventing a relationship.

## Requirements

- Python 3.11+
- Node.js 18+
- Optional but recommended: `memprocfs` and `yara-python` (installed automatically by `run.py`). Without them, Velociraptor artifact analysis still works; raw memory-dump parsing and YARA scanning are skipped and reported in the UI health status.

## Architecture

- **Backend** (`backend/app`): FastAPI + SQLAlchemy (one SQLite DB per case with FTS5). Modules: `ingest/` (parsers + pipeline), `memory/` (MemProcFS runner, YARA scanner, analysis pipeline), `detect/` (rules, detection engine, process-tree builder), `llm/` (provider abstraction, prompts, orchestrator), `api/` (routers), `store/` (case registry + models).
- **Frontend** (`frontend/src`): React + TypeScript + Vite + Tailwind, React Flow, vis-timeline, Recharts, TanStack Query.

Cases and config live under `~/.investigator/`.

## Credits

Investigator DFIR is made by Roei.f.

## Note on detections

The deterministic engine and bundled YARA rules are heuristic and tuned to surface candidate activity for analyst review. Treat AI output as an assistive lead, not ground truth — always confirm against the raw evidence, which is one click away throughout the UI.
