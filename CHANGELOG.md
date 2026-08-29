# Changelog

All notable changes are recorded here. Release-specific installation, support,
migration, and verification details live in `docs/releases/`.

## Unreleased

### Added

- OpenRouter is available as a remote AI provider, with secure per-provider API
  key storage, live model discovery, connection testing, and configurable API
  endpoint support through its OpenAI-compatible interface.
- A **Rules** page (top-level, between Reverse and Settings) lists every detection
  rule the engine runs — 324 built-in rules catalogued from the detection tables,
  plus any custom rules — and lets each one be enabled or disabled, with a
  severity override on built-ins. Changes apply to new analyses; rebuild a case's
  detections to apply them to existing findings.
- Custom detection rules can be written in Sigma, through a GUI form or a YAML
  editor, validated before saving, and imported or exported as Sigma bundles.
  Rules are parsed with pySigma so public Sigma rules can be used as written, and
  are compiled to in-memory matchers rather than evaluated as generated code.
- Built-in rules can be forked into an editable Sigma approximation, which
  disables the original and states plainly that the fork is an approximation to
  review. Stateful correlation and threshold detections are marked as not
  forkable rather than silently producing a rule that cannot express them.
- Global rule state is stored in a new versioned database at
  `~/.investigator/rules/rules.db`. Back it up with the rest of `~/.investigator/`;
  see `docs/MIGRATIONS.md`.
- Sigma parsing adds `pysigma` and its dependencies (`jq`, `diskcache`, `jinja2`,
  `markupsafe`, `pyparsing`, `types-pyyaml`, `diskcache-stubs`) to the locked
  backend requirements. `jq` is a native extension; it ships wheels for Windows
  x64, macOS, and Linux, but not for 32-bit or ARM64 Windows.
- If `pysigma` is unavailable, the backend still starts and every built-in rule
  remains listed, togglable, and re-prioritisable. Only authoring, validating,
  importing, and forking custom Sigma rules is disabled, with the reason shown on
  the Rules page and reported as `sigma` in `/api/health`.
- CI now fails when `requirements.in` and the lock files disagree.

### Fixed

- The backend failed to start with `ModuleNotFoundError: No module named 'sigma'`
  because `pysigma` was added to `requirements.in` without regenerating the lock
  files, and installs run `pip --require-hashes --no-deps` against the locks. All
  three locks now include it, and a missing rule dependency can no longer stop the
  application from starting.

### Changed

- Disabling a detection rule globally now removes it from the rule set before a
  run, so it costs nothing instead of producing a finding that is demoted
  afterwards. The existing per-case rule suppression is unchanged and still
  demotes findings reversibly.
- Analyst-supplied regular expressions in rules are bounded: a pattern is
  measured against adversarial input and rejected if it backtracks
  catastrophically, and matching is capped by subject length.

### Fixed

- Updated the locked `cryptography`, `pyasn1`, React Router, PostCSS, and Nano ID
  dependencies to patched releases after repository audit findings.
- Reverse completion is now goal-driven instead of artifact-specific: overlays,
  entry points, MiniDumps, wording, headings, and completion markers no longer
  trigger host-side finalization rejections. Substantive drafts persist across
  extensions, and declining more turns publishes the best supported partial or
  blocked report rather than a limitations-only replacement.
- Reverse reports now separate complete, partial, and blocked analysis outcomes
  from passed, passed-with-warnings, and failed review status. The reviewer can
  request targeted continued analysis or up to two evidence-preserving report
  revisions, and every published report is signed regardless of review warnings.
- Material findings and structured IOCs can cite stable `[trace:<message-id>]`
  evidence. Project-scoped evidence responses include the recorded operation,
  retained bounded output, truncation metadata, success state, and output hash;
  the Reverse UI exposes citations, objective coverage, unresolved work, review
  history, and signature integrity independently.
- Partial, blocked, and warning-bearing Reverse reports now expose a Continue
  investigation action. Continuing resumes the same evidence state, adds turns
  when its tranche is exhausted, and preserves the currently published signed
  report as a downloadable content-addressed snapshot until replacement bytes
  are reviewed and signed.
- Reverse now detects analysis mistakes through persisted semantic attempts,
  normalized failure fingerprints, and evidence novelty. Two equivalent failures
  or three no-evidence operations activate a visible diagnostic pivot, while
  `ANALYSIS CHECKPOINT` preserves findings without prematurely reviewing a report.
- The sandbox adds bounded PyInstaller CArchive inspection with cookie-end package
  base calculation, TOC/entry/compression invariants, selected extraction, runtime
  compatibility warnings, and cross-version bytecode disassembly through `xdis`.

- Reverse follow-up chat now strips completion control markers in any supported
  position, retries marker-only replies, and prevents sandbox tool-call payloads
  (including legacy saved messages) from appearing as assistant answers.
- Reverse analysis now pauses for explicit turn-extension approval when it
  exhausts its turn budget or stops making progress without a final response,
  instead of converting the last sandbox tool request into a corrupted report.
- Reverse report finalization now recognizes Markdown completion headings and
  preserves the preceding substantive report when a model follows it with a
  bare completion marker; marker-only output can no longer create an empty report.
- Reverse analysis and follow-up chat prompts now explicitly teach the model
  the two-turn `write_file` then `run_cmd python3` workflow for custom static
  parsers, with a concrete base64 example and sandbox safety constraints.
- Gemini requests now use the SDK's asynchronous client with a five-minute
  request timeout, keeping status polling and Stop responsive. Transient provider
  deadlines pause Reverse runs for resume, while oversized transcript echoes are
  rejected before parsing embedded tool calls.
- Memory-backed process dossiers now download MemProcFS's WinDbg-compatible
  `minidump/minidump.dmp` as the full process dump instead of treating the
  sparse `memory.vmem` address-space view as the primary process dump.
- Sparse `memory.vmem` process downloads have been removed. Minidump downloads
  are requested only for the selected PID, and a failed PID now reports an
  inline error without navigating away or affecting other process selections.
- Reverse report finalization now persists exact report bytes before signing,
  uses Windows-compatible compact Ed25519 credentials, supports RSA key
  compatibility and signing retries, and cannot fail a completed analysis when
  the OS credential vault is unavailable.
- Reverse analysis now uses an adaptive prompt, a one-operation command/file
  loop, completion/blocking logic, a permissive report generator, and a separate
  IOC-enumeration pass instead of a fixed PE checklist or rigid report contract.
  The final verifier records findings without rewriting or shortening the
  report. Follow-up chat now uses the same guarded 12-turn tool loop instead of
  answering from report text alone.

### Added

- Native Reverse workspaces with optional case links, shared LLM settings,
  versioned SQLite history, signed provenance, reports/IOCs/chat/replay, and an
  explicitly built, networkless static-analysis sandbox.
- `run_cmd`, `read_file`, `write_file`, and `list_dir` Reverse tools plus a
  broad static-analysis argv allowlist. Model-authored Python helpers
  run through a restricted interpreter that denies networking, subprocesses,
  native loading, root-filesystem reads, and sample mutation.
- A proposed v0.2.0 roadmap covering optimization, benchmarks, local metrics,
  audited universal finding exclusions, and case manifests with SHA-256
  evidence hashing.

## 0.1.2 - 2026-07-14

### Fixed

- Fresh Windows installs now consume the compiled hashed Python lock with
  `--no-deps`, preventing pip from re-resolving a newly published transitive
  dependency outside the lock. A subsequent `pip check` still validates the
  installed dependency closure.

## 0.1.1 - 2026-07-14

### Added

- Contribution, fixture-sanitization, conduct, maintainer, and review policies.
- Structured bug, parser-error, false-positive, and feature-request forms.
- Canonical labels and an automated label synchronization workflow.
- Reproducible Windows release archive, checksum, CycloneDX SBOM, signed-tag
  gate, and GitHub release workflow.
- Supported-platform/dependency matrix, migration policy, known limitations, and
  a small synthetic demonstration case.

These changes are staged for the first artifact-bearing release, `v0.1.1`; see
[its versioned notes](docs/releases/v0.1.1.md). The earlier `v0.1.0` tag is an
unsigned historical source tag and was not published as a GitHub Release.

## 0.1.0 - 2026-07-14

### Added

- Public-beta local DFIR application with Windows, Linux, Defender/Sentinel,
  generic structured-data, text-log, and optional memory-forensics ingestion.
- Deterministic detections, process/entity correlation, timelines, findings,
  report generation, and configurable local or remote AI assistance.
- One-command launcher, locked Python and npm dependencies, CI, CodeQL,
  dependency review, and the initial security policy.

### Compatibility

- Case data is pre-1.0 and forward-migrated on open. Back up before upgrading.
- Parser fixes require re-ingestion of the original evidence.

See [the versioned v0.1.0 notes](docs/releases/v0.1.0.md) for the complete
release contract.
