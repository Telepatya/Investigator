# Security Policy

## Supported Versions

Investigator `0.1.0` is a public beta. Security fixes are applied to the current
`main` branch and the latest `0.1.x` release only. Pre-beta snapshots and older
development commits are not supported.

| Version | Supported | Status |
| --- | --- | --- |
| `0.1.x` | Yes | Public beta |
| `< 0.1` | No | Development snapshots |

## Reporting A Vulnerability

Please report security issues privately rather than opening a public issue with
exploit details, credentials, forensic evidence, or sensitive logs.

**How to report privately:** use GitHub's private vulnerability reporting on this
repository — open the **Security** tab and choose **Report a vulnerability**
(**Security → Advisories → Report a vulnerability**). This opens a private
advisory visible only to the maintainer and you; no public disclosure or email
address is required. If private reporting is not available to you, open a public
issue that says only "requesting a private security contact" with **no exploit
details**, and a private channel will be arranged.

Please include:

- A short description of the issue.
- Affected component or file path, if known.
- Reproduction steps or proof of concept, when safe to share.
- Any relevant environment details.

You can expect an initial acknowledgement within a few days. Please allow a
reasonable period for a fix before any public disclosure.

Public issues are fine for general hardening ideas, dependency-update requests,
or documentation improvements that do not expose a vulnerability.

## Dependency Security

Investigator uses locked dependencies for reproducible installs.

- Python runtime installs use the complete compiled closure in
  `backend/requirements-memory.lock` with `pip --require-hashes --no-deps`, so
  installation cannot re-resolve a newly published transitive version.
- Python lock files are generated from `backend/requirements*.in` using
  `backend/scripts/update-locks.ps1` or `backend/scripts/update-locks.sh`.
- Frontend installs use `npm ci` from the committed
  `frontend/package-lock.json`.
- Dependency updates should be reviewed through pull requests after CI,
  dependency review, audits, and CodeQL complete.

Dependency changes can affect evidence parsing, MemProcFS compatibility, LLM
request/response handling, cryptography, and OS keyring behavior, so they should
not be auto-merged without review.

## Sensitive Data Handling

Investigator is a DFIR tool and may process highly sensitive data. Do not commit
real case material, credentials, memory dumps, event logs, packet captures, disk
images, API keys, or generated case databases.

The repository ignores common local secret and forensic evidence formats,
including `.env`, key files, memory dumps, EVTX files, disk images, packet
captures, archives, case databases, uploads, and derived artifacts. Contributors
should still review `git status` and staged diffs before every push.

API keys configured in the application are stored in the operating system
credential vault, not in the repository.

## Filesystem Boundaries

Externally supplied path components are validated before filesystem access:

- Case IDs are eight hexadecimal characters and must exist in the case registry.
- Upload names are reduced to a basename, checked against a conservative allowlist,
  resolved, and accepted only as direct children of that case's `uploads/` directory.
- Memory session IDs use an allowlist that excludes directory separators and traversal
  components. MemProcFS VFS paths are normalized separately and reject drive paths,
  NUL bytes, `.` segments, and `..` segments.
- Extracted process/module/VFS downloads are resolved before serving and must be
  regular files contained by the validated case root.

These checks belong at the API boundary even when a lower-level parser or extractor
also sanitizes its inputs. New download/upload routes must reuse the same containment
rules rather than constructing paths directly from route or form values.

## Network Exposure And Local-Only Model

Investigator is a single-user, loopback-only application. It binds to `127.0.0.1`
and has no built-in authentication. Binding to loopback alone does **not** protect
it from a hostile web page in the user's browser or from DNS rebinding, so the
backend enforces origin/host controls, centralized in `backend/app/api/security.py`:

- **Host allowlist.** `TrustedHostMiddleware` compares each request's `Host`
  header (port stripped) against `ALLOWED_HOSTS` (`localhost`, `127.0.0.1`) and
  rejects anything else with `400`. This blocks DNS rebinding, where an attacker
  domain resolves to `127.0.0.1`: the rebound request still carries the attacker's
  hostname in `Host` and is refused.
- **CORS allowlist.** Cross-origin HTTP reads are limited to the built app on
  `INVESTIGATOR_PORT` and the Vite dev server on `:5173`.
- **HTTP Origin validation.** CORS does not stop a browser from sending a simple
  cross-origin write such as `multipart/form-data`. Every `POST`, `PUT`, `PATCH`,
  and `DELETE` with a present `Origin` is therefore rejected unless it matches
  the frontend allowlist. Non-browser clients may omit `Origin`.
- **WebSocket origin validation.** CORS does not apply to WebSocket handshakes, so
  every WebSocket route validates the browser `Origin` against the same allowlist
  (and the target case's existence) *before* accepting. A missing `Origin` denotes
  a non-browser client and is not a cross-site vector; any present-but-unlisted
  origin (including a rebound attacker page or `null`) is refused.

**Changing the bind address.** If you deliberately expose the backend on a
non-loopback hostname, you must add that hostname to `ALLOWED_HOSTS` **and** to
`allowed_origins()` in `backend/app/api/security.py` — the two lists must stay
aligned, or the app will reject its own traffic. Exposing this app beyond loopback
also means exposing an unauthenticated DFIR tool; add authentication and transport
security (e.g. a reverse proxy) before doing so.

## Resource Limits

Untrusted uploads and archives are bounded so they cannot exhaust local disk or
memory:

- Per-file and projected per-case upload caps (`INVESTIGATOR_MAX_UPLOAD_BYTES`
  and `INVESTIGATOR_MAX_CASE_BYTES`; defaults are generous because memory dumps
  are legitimately large). Quota decisions and writes are serialized per case,
  and ordinary replacements are staged then atomically committed so a rejected
  or interrupted upload cannot destroy the previous evidence file.
- Chunked uploads retain private partial state and require the exact next index,
  stable total-chunk count, and stable ingestion options. Each request chunk is
  validated before append; skipped, duplicate, empty, oversized, or mismatched
  chunks cannot complete or modify the accepted prefix. Partial staging files
  are hidden from evidence listings and removed during startup recovery.
- ZIP extraction limits the parsable-member count, per-member and total expanded
  size, and rejects decompression-bomb members by their real expanded/compressed
  ratio. Declared archive sizes are attacker-controlled, so the extraction write
  loop — not the ZIP header — is authoritative.

## AI Analysis Boundaries

Evidence is attacker-controlled and enters LLM prompts as data. To keep the model
advisory:

- **Automated analysis cannot suppress findings.** The analysis tool loop runs
  read-only with respect to analyst conclusions, so a prompt injection in a log
  cannot bury a legitimate finding. The model may *propose* suppression; only an
  analyst applies one, via the UI or an explicit chat request.
- **Empty cases are never reported clean.** A case with no ingested evidence is
  reported as "not assessed", not "clean", in both the report and the dashboard.
- **Remote providers are explicit.** With Ollama, no case data leaves the machine.
  With a remote provider, only prompt/tool excerpts are sent, and the settings UI
  warns that evidence will leave the machine.

## Case Isolation And Concurrency

Investigator is designed as a single local backend process with one SQLite
database per case. Case IDs received from API routes are validated against the
case registry before a database session is created — `get_session()` raises
`CaseNotFoundError` (surfaced as `404`) for any unregistered id, before the case
directory or database file is created — so a stale or crafted ID cannot create an
orphan database directory through any route.

Two independent synchronization layers protect case integrity:

- The per-case operation coordinator serializes ingestion, memory analysis, AI
  analysis, detection rebuilds, and deletion. A queued operation rechecks that
  the case still exists after it acquires the operation slot.
- Multi-file artifact ingestion defers whole-case detection until the final queued
  file and skips it when no queued file produced events. This avoids repeated long
  detection passes and keeps the busy state accurate for the complete queue.
- The per-database writer gate serializes SQLite write transactions. Code that
  performs a metadata read-modify-write must acquire the gate before reading,
  not only when flushing, to prevent lost JSON metadata updates.

SQLite WAL keeps case reads available while a writer is active. Running multiple
independent backend processes against the same `~/.investigator/cases` directory
is not supported because the operation coordinator and writer gate are
process-local.

Persisted `ingesting` and `analyzing` values are transient UI states, not durable
jobs. Startup recovery changes them to `ready` because an interrupted process-local
operation cannot still be running after a backend restart.

## Evidence Integrity And Analyst Overrides

Raw evidence remains inspectable and analyst actions must retain provenance.
Manual findings are persisted separately from detector output and materialized
into the findings table. When a manual event finding raises timeline severity,
the previous event severity and reason are preserved as a reversible baseline.
Marking the finding benign or deleting it restores that baseline; detection
rebuilds restore baselines before recalculation and reapply active analyst intent
afterward.

File and process correlation must use normalized exact full paths when a full
path is available, including normalization of Windows device prefixes such as
`\\.\C:\...`. A same basename in a different directory is not sufficient
evidence of identity. Basename fallback is allowed only for basename-only,
unambiguous entities.

Frontend caches and transient state are also case-scoped. Search results,
drawers, timeline filters, and Entity Map focus state must be cleared when the
case route changes to prevent accidental cross-case display.

## Repository Protection

The project is intended to use:

- CodeQL/code scanning for Python and JavaScript/TypeScript.
- Secret scanning with push protection.
- Dependency Review on pull requests.
- Branch protection for `main`.
- Required CI checks for backend, frontend, dependency review, and CodeQL.

These protections are enforced through repository settings and the workflows in
`.github/workflows/`.
