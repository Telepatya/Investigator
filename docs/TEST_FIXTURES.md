# Contributing sanitized test fixtures

Forensic exports routinely contain personal data, credentials, internal network
details, customer identifiers, and adversary-controlled text. Investigator only
accepts fixtures that are synthetic or irreversibly transformed into a minimal
example. Merely changing a hostname is not sufficient sanitization.

## Preferred method: generate the record

Build the smallest record from the public format specification and the parser
fields needed by the test. Fixed values make the fixture reviewable:

| Data type | Safe example |
| --- | --- |
| Host | `EXAMPLE-WKS` |
| User | `analyst` or `example-user` |
| Domain | `example.invalid` |
| IPv4 | `192.0.2.10`, `198.51.100.20`, `203.0.113.30` |
| IPv6 | `2001:db8::10` |
| Windows path | `C:\Users\analyst\AppData\Local\Temp\sample.exe` |
| Linux path | `/home/example-user/tmp/sample` |
| Timestamp | a fixed UTC time, such as `2026-01-15T10:00:00Z` |
| Hash | an obvious generated value that is not copied from evidence |

Use `.invalid` for domains that must never resolve. Do not use a real benign or
malicious domain merely because it is publicly known.

## Transforming a real format example

Only use a transformed derivative when the format cannot be reproduced from its
specification. Before contributing it:

1. Confirm that you are authorized to create and publish the derivative.
2. Extract only the one or two records and fields required to reproduce the
   behavior. Rebuild the container rather than copying it wholesale.
3. Replace names, emails, SIDs, GUIDs, case and tenant IDs, machine IDs, serial
   numbers, timestamps, paths, command arguments, URLs, domains, IP addresses,
   ports when identifying, hashes, tokens, certificates, comments, and free text.
4. Remove embedded payloads, environment blocks, alternate streams, slack data,
   ZIP comments and paths, extended attributes, and original file metadata.
5. Search the result for the original organization, users, hosts, domains,
   address ranges, and identifiers. Inspect binary/container metadata with an
   appropriate format tool.
6. Ask a second person with authorization to review the transformed fixture
   when it originated from a real case.

Do not contribute a transformed real memory image, case database, EVTX file,
packet capture, disk image, collector archive, credential store, browser profile,
or executable. Express the minimum parser condition as generated JSON, JSONL,
CSV, or text instead. If that loses the bug, open an issue without the sample and
ask a maintainer for a private, time-bounded reproduction path.

## Fixture manifest

Place stable parser fixtures under `backend/tests/fixtures/<component>/`. Include
a sibling `<fixture>.manifest.yml` containing:

```yaml
provenance: synthetic       # synthetic or transformed-with-permission
generator: manual
format: Defender Advanced Hunting JSONL
purpose: Exercise DeviceProcessEvents command-line mapping
expected_records: 1
contains_real_case_data: false
reviewed_by: contributor-github-handle
```

The manifest is an auditable declaration, not proof of sanitization. A test must
load the fixture through the public parser entry point and assert exact relevant
fields. Parser-error fixes should include malformed or missing-field behavior;
detection fixes should include both suspicious and benign inputs.

## Final staged-diff check

Review fixture contents directly rather than relying on `.gitignore`:

```powershell
git status --short
git diff --cached --stat
git diff --cached -- . ":(exclude)frontend/package-lock.json" ":(exclude)backend/*.lock"
rg -n -i "password|passwd|secret|token|authorization|api[_-]?key|BEGIN .*PRIVATE KEY" backend/tests/fixtures demo
```

The search is a prompt for human review and cannot prove that data is safe.
When in doubt, omit the fixture. Maintainers may remove a fixture immediately if
its provenance or sanitization becomes uncertain.
