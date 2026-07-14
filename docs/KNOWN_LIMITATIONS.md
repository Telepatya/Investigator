# Known limitations

These limitations apply to the `0.1.x` public beta and are part of the release
acceptance criteria.

- Investigator is a single-user loopback application with no authentication.
  Do not bind it to a LAN or the Internet without adding authentication and TLS.
- Only one backend process may operate on a case directory. The operation and
  writer coordinators are process-local.
- Case databases migrate forward on open and cannot be downgraded. Back up the
  entire application data directory before upgrading; see
  [MIGRATIONS.md](MIGRATIONS.md).
- Parser and normalization fixes do not rewrite existing rows. Original evidence
  must be re-ingested, and detection changes may require a rebuild.
- The Windows release is a reproducible application archive, not an MSI. It
  requires a supported 64-bit Python installation and installs locked Python
  packages on first launch.
- Raw-memory support depends on optional MemProcFS and YARA Python packages and
  compatible platform wheels. Unsupported profiles or damaged images may yield
  partial results.
- EVTX, collector, and vendor schemas evolve. Unknown rows ingest generically
  where possible and may lack rich fields or detections.
- Detection and YARA output is heuristic and may contain false positives or miss
  activity. It is an analyst lead, not proof of compromise or absence of one.
- AI output may be incomplete or incorrect. Remote AI providers receive the
  evidence excerpts included in requests; use Ollama when data must remain local.
- Background ingestion and analysis jobs do not resume after a process restart.
- Release validation covers Windows 11 x86-64 and core source operation on
  Ubuntu 24.04 x86-64. Other systems are community best effort.
- The synthetic demonstration case proves import, normalization, and a few
  correlation paths; it is not a benchmark, comprehensive parser corpus, or
  representation of a real incident.

Resolved limitations should be removed here in the same pull request that adds
tests and a changelog entry. Newly discovered limitations that can affect
evidence interpretation must be added to the next versioned release notes.
