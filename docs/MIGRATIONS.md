# Case-database migration policy

Investigator stores each case as a separate SQLite database under
`~/.investigator/cases/<case-id>/case.db`, with uploaded and derived evidence in
the same case directory. During the `0.x` beta, the schema may change between
minor releases.

## Current behavior

On first open, the backend creates missing tables and indexes and applies the
small, idempotent compatibility migrations implemented in
`backend/app/store/database.py`. Migrations are forward-only. There is no
supported database downgrade and no automatic rollback.

Parser and detection changes are different from schema migrations: normalized
events are computed at ingestion time. Upgrade code does not reinterpret old
rows. Re-ingest the original evidence to receive parser corrections and rebuild
detections when release notes instruct you to do so.

## User procedure before upgrading

1. Stop Investigator and confirm no `python -m app.main` process is using the
   case directory.
2. Copy the complete `~/.investigator/` directory to separate storage, including
   `case.db`, `case.db-wal`, `case.db-shm`, `uploads/`, `derived/`, and
   `config.json`. Do not copy an actively written SQLite database.
3. Keep the previous application release until important cases have been opened
   and checked with the new version.
4. Start the new version and open a non-critical or synthetic case first.
5. Verify case metadata, event counts, findings, report access, and evidence
   downloads before continuing work.

## Project guarantees

- Release notes identify every schema-affecting change and whether a backup,
  re-ingestion, detection rebuild, or manual action is required.
- A migration must be transactional or safely repeatable after interruption.
- Migrations must not silently delete source uploads or analyst findings.
- A destructive or non-automatic migration requires a dedicated tool, dry-run
  output, recovery instructions, and a release-note warning.
- Migration tests must start from the previous supported schema, run twice, and
  verify retained provenance and analyst overrides.

Until 1.0, the project supports migration from the immediately previous minor
release to the current release. Users skipping releases should upgrade one minor
at a time unless the target release notes explicitly say direct migration is
supported. Downgrading an already-opened database is unsupported; restore the
pre-upgrade backup instead.

If a migration cannot complete, stop using the affected case, retain the backup
and failing database, and file a bug without attaching either database. Share
only a synthetic schema reproducer through the fixture process.
