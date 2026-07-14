# Investigator Roadmap

Planned scope for **v0.2.0**. This is a planning document, not a release-date
commitment.

> **Guiding principle:** evidence correctness, reversibility, and analyst
> visibility come before raw speed or automation.

## v0.2.0 at a glance

| # | Workstream | Goal |
|---|------------|------|
| 1 | [Benchmark infrastructure](#1-benchmark-infrastructure) | Make performance measurable and repeatable |
| 2 | [Profile-guided optimization](#2-profile-guided-optimization) | ≥ 20% faster in two confirmed high-cost workflows |
| 3 | [Local metrics & diagnostics](#3-local-metrics--diagnostics) | Operational visibility, fully local, zero telemetry |
| 4 | [Universal Exclusions](#4-universal-exclusions) | Application-wide finding suppression that is auditable and reversible |
| 5 | [Case manifests & evidence hashing](#5-case-manifests--evidence-hashing) | Verifiable evidence integrity and an exportable chain-of-custody record per case |

---

## 1. Benchmark infrastructure

**Goal:** a maintained benchmark suite under `backend/benchmarks/` that anyone
can run with one command and compare across commits.

Benchmarks use synthetic, redistributable corpora — never real case material —
and run without remote AI providers.

**Covers:**

- Ingestion — JSONL, CSV, EVTX-derived JSON, Linux logs, mixed ZIPs
- Normalization and bulk database insertion at three corpus sizes
- Deterministic detection rebuilds over benign, suspicious, and mixed corpora
- Query paths — timeline, full-text search, case statistics, entity graph, finding serialization
- MemProcFS artifact normalization (no real memory image required)
- Frontend build size and large-table render timings, where reliably measurable

Each run emits machine-readable JSON (commit, platform, runtime versions,
corpus version, operation count, wall time, throughput, peak memory). CI runs a
short smoke benchmark to protect harness correctness; full runs are scheduled
or manual, so noisy shared-runner timings never gate a merge.

**Done when:**

- [ ] One documented command runs the full local suite
- [ ] Synthetic corpora are deterministic and versioned
- [ ] Two commits can be compared with a generated summary report
- [ ] A >10% regression in the reference environment requires an explanation or explicit baseline update

## 2. Profile-guided optimization

**Goal:** at least a **20% improvement in two confirmed high-cost workflows**
on the reference machine — with no unexplained regression above 10% elsewhere
and no change to the expected finding corpus.

Optimization work starts only after a benchmark and profile identify a real
bottleneck. Parser and detector semantics must never change in a
performance-only PR.

**Candidate areas:**

- Streaming parsers and reduced per-record allocation
- Batched SQLite writes, indexes, FTS sync, and query shapes
- Eliminating repeated JSON decoding and re-normalization
- Detection indexes instead of repeated whole-case scans
- Entity graph and timeline payload construction
- Bounded concurrency for CPU-bound and blocking work
- Frontend: bundle splitting, memoization, virtualization, fewer refetches

Every optimization PR includes before/after benchmark output, profile
evidence, correctness tests, and its memory/complexity tradeoffs.

## 3. Local metrics & diagnostics

**Goal:** a Diagnostics view showing what the app is doing and how long it
takes — **fully local**. Investigator never phones home, never uploads
metrics, and never puts evidence values in metric labels.

**Measures:**

- Ingestion — duration, records read/accepted/skipped, events per second, parser errors
- Detection — duration by phase, findings created/suppressed, rule-family counts
- Operations — queue wait time and active duration
- Database — size, event/finding/entity counts, selected query latency
- Entity graph, timeline, and memory-analysis generation times
- AI requests — duration, provider/model, tool calls, token counts (never prompts, responses, keys, or evidence excerpts)

Metrics are filterable by case and operation, exportable as sanitized JSON,
and clearable without touching case evidence. Retention is bounded and
configurable.

**Done when:**

- [ ] Metric names, units, labels, and retention are documented and versioned
- [ ] High-cardinality evidence values never become labels
- [ ] Exports contain no raw evidence or secrets
- [ ] Overhead stays under 3% on the reference ingestion benchmark

## 4. Universal Exclusions

**Goal:** a top-level **Exclusions** tab (alongside Cases and Settings) for
application-wide suppression rules that apply to existing and future cases —
every suppression auditable, every rule reversible.

### Rules

Each rule has a stable ID, display name, **required analyst reason**, enabled
state, and timestamps, plus:

- **Match mode:** exact, case-insensitive contains, or glob (regex is deferred until it can be safely bounded and validated)
- **Field scope:** title, description, source/rule, entity, host, path, command line, or any textual finding field
- **Conditions:** one or more strings with explicit *all* / *any* behavior
- **Optional constraints:** finding source and severity
- **Audit data:** match count, last match time, affected cases

Matching uses documented Unicode case-folding and path normalization so
behavior is deterministic across parsers.

### Behavior

When any detector, memory analyzer, or AI analysis materializes a finding,
enabled exclusions are evaluated after normal severity and provenance are
assigned. A match suppresses the finding while preserving its original
severity, the rule ID, the matched fields/conditions, and a timestamp.

Key guarantees:

- **Reversible.** Disabling or deleting a rule restores prior severities unless another active suppression applies.
- **Deterministic.** Detection rebuilds and restarts produce the same result.
- **Non-destructive.** Raw events are never deleted or skipped; suppressed findings stay visible behind an *Include suppressed* control, and their evidence remains searchable everywhere.
- **Human-only.** AI analysis cannot create, edit, enable, or delete exclusions. Manual analyst findings are never auto-suppressed unless a rule explicitly opts into that source.

### UX and safety

The tab supports create/edit/duplicate/enable/disable/delete, plus:

- **Preview before saving** — which findings and cases would match
- Warnings for empty, very short, or unusually broad patterns
- Match counts with drill-down to affected findings, and a test field for candidate findings
- Export/import with schema validation and conflict handling
- A full audit history of every change and automatic suppression

Applying or removing a rule across cases runs as a background operation with
progress and per-case failure reporting; retries are safe and idempotent.

**Done when:**

- [ ] A string rule suppresses matching findings in existing cases *and* newly created ones
- [ ] Preview counts equal the findings actually changed on enable
- [ ] Disabling a rule restores original severities and analyst overrides
- [ ] Overlapping rules keep a finding suppressed until every matching rule is inactive
- [ ] Every suppression traces back to a rule and an analyst reason
- [ ] Migration, restart, rebuild, import/export, and malformed-rule tests pass

## 5. Case manifests & evidence hashing

**Goal:** every evidence file gets a **SHA-256 recorded at ingest**, and every
case carries a versioned manifest that can be exported and re-verified — a
local chain-of-custody record for the evidence the case is built on.

**Covers:**

- **Hashing at ingest.** SHA-256 (streamed, bounded memory) computed when a
  file is uploaded or ingested, before parsing, and stored with size, original
  filename, and ingest timestamp
- **Case manifest.** A versioned JSON document per case listing each evidence
  file with its hash, size, detected kind/parsers, record counts, and status,
  plus case metadata and the app version that produced it
- **Lifecycle tracking.** Evidence deletion and re-ingest (both existing
  flows) append manifest entries instead of erasing history, so the record
  shows what was removed and when
- **Verification.** An on-demand integrity check re-hashes evidence on disk
  and reports each file as verified, modified, or missing — run as a
  background operation with progress, since memory images can be large
- **Export.** The manifest exports as schema-validated JSON suitable for case
  handoff, and the report export can reference it
- **Backfill.** Existing cases gain hashes through an explicit, resumable
  operation — never silently on open

Hashing is for integrity, not detection: a mismatch flags the file for the
analyst, and never deletes evidence or blocks the case from opening.

**Done when:**

- [ ] Every newly ingested evidence file has a recorded SHA-256, size, and timestamp
- [ ] The exported manifest validates against a documented schema and matches the case's evidence list
- [ ] Verification correctly reports a deliberately modified and a deleted evidence file
- [ ] Deletion and re-ingest of evidence leave an auditable manifest trail
- [ ] Backfill on a pre-v0.2.0 case is explicit, resumable, and idempotent
- [ ] Hashing a multi-gigabyte file streams with bounded memory and reports progress

---

## Delivery sequence

| Milestone | Focus | Delivers |
|-----------|-------|----------|
| **A** | Measurement foundation | Benchmark runner, synthetic corpora, result schema, comparison report, timing primitives, baselines |
| **B** | Optimization | Profiles of reference workflows, confirmed bottleneck fixes, before/after results with detection-equivalence tests |
| **C** | Evidence integrity | Hashing at ingest, manifest schema and store, verification operation, backfill for existing cases |
| **D** | Exclusions backend | Global rule store, deterministic matcher, re-evaluation coordinator, audit model, preview API |
| **E** | Exclusions, manifest & metrics UI | Exclusions tab, rule editor, preview and drill-down, import/export, manifest export and verification views, Diagnostics views |
| **F** | Release hardening | Full regression report, smoke tests, documentation, signed artifacts, checksums, SBOM |

## Out of scope for v0.2.0

- Deleting or refusing to ingest evidence based on an exclusion
- Cloud-hosted telemetry or automatic metric upload
- Multi-user or organization-wide exclusion policy sync
- AI-authored or auto-enabled exclusion rules
- Unbounded regular-expression matching
- Quarantining, deleting, or refusing to open a case over a hash mismatch — integrity failures are reported to the analyst, not acted on automatically
- Any performance change that weakens validation, provenance, or detection coverage
