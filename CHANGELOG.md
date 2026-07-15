# Changelog

All notable changes are recorded here. Release-specific installation, support,
migration, and verification details live in `docs/releases/`.

## Unreleased

### Fixed

- Reverse report finalization now persists exact report bytes before signing,
  uses Windows-compatible compact Ed25519 credentials, supports RSA key
  compatibility and signing retries, and cannot fail a completed analysis when
  the OS credential vault is unavailable.
- Reverse analysis now faithfully uses ForensicBuddy's adaptive prompt,
  one-operation command/file loop, completion/blocking logic, permissive report
  generator, and separate IOC-enumeration pass instead of a fixed PE checklist or
  rigid report contract. The final verifier records findings without rewriting or
  shortening the report. Follow-up chat now uses ForensicBuddy's guarded 12-turn
  tool loop instead of answering from report text alone.

### Added

- Native Reverse workspaces with optional case links, shared LLM settings,
  versioned SQLite history, signed provenance, reports/IOCs/chat/replay, and an
  explicitly built, networkless static-analysis sandbox.
- ForensicBuddy-compatible `run_cmd`, `read_file`, `write_file`, and `list_dir`
  tools plus a broad static-analysis argv allowlist. Model-authored Python helpers
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
