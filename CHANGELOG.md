# Changelog

All notable changes are recorded here. Release-specific installation, support,
migration, and verification details live in `docs/releases/`.

## Unreleased

No changes yet.

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
