# Security Policy

## Supported Versions

Security fixes are applied to the current `main` branch. If release branches or
tagged versions are introduced later, this section will be updated with their
support status.

## Reporting A Vulnerability

Please report security issues privately rather than opening a public issue with
exploit details, credentials, forensic evidence, or sensitive logs. Include:

- A short description of the issue.
- Affected component or file path, if known.
- Reproduction steps or proof of concept, when safe to share.
- Any relevant environment details.

Public issues are fine for general hardening ideas, dependency-update requests,
or documentation improvements that do not expose a vulnerability.

## Dependency Security

Investigator uses locked dependencies for reproducible installs.

- Python runtime installs use `backend/requirements-memory.lock` with
  `pip --require-hashes`.
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

## Case Isolation And Concurrency

Investigator is designed as a single local backend process with one SQLite
database per case. Case IDs received from API routes must be validated against
the case registry before a database session is created; otherwise a stale or
crafted ID could create an orphan database directory.

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
