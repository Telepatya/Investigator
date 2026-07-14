# Contributing to Investigator

Thank you for helping improve Investigator. Contributions may affect forensic
interpretation, so reproducibility and evidence provenance matter as much as
code quality.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security vulnerabilities must be reported through the private process in
[SECURITY.md](SECURITY.md), not a public issue.

## Before opening a pull request

1. Search existing issues and choose the bug, parser-error, false-positive, or
   feature-request form.
2. For a non-trivial change, describe the intended behavior and test approach
   in an issue before investing in a large implementation.
3. Branch from `main` and keep the change focused. Do not mix dependency
   refreshes, formatting sweeps, and behavior changes.
4. Add or update tests. Parser and detection changes need both a positive case
   and a nearby benign/negative case.
5. Run the relevant checks below and review `git diff` and `git status` for
   evidence, secrets, case databases, and generated files.

## Development setup

Python dependencies are changed in `backend/requirements*.in`; generated lock
files must not be edited by hand. JavaScript dependencies are changed through
`frontend/package.json` and `frontend/package-lock.json`.

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --no-deps -r requirements-dev.lock
.\.venv\Scripts\ruff.exe check app tests
.\.venv\Scripts\python.exe -m unittest discover -s tests -v

# Frontend
cd ..\frontend
npm ci
npm run build
```

On Linux or macOS, use `.venv/bin/python` and `.venv/bin/ruff`. If a dependency
changes, regenerate every affected Python lock with
`backend/scripts/update-locks.ps1` or `backend/scripts/update-locks.sh` and run
the dependency audits described in [SECURITY.md](SECURITY.md).

## Parser changes

A parser pull request should state:

- the producer, export path, format, and version of the input;
- which timestamp, host, source, category, entity, summary, and raw fields are
  expected after normalization;
- how malformed, partial, or unfamiliar records behave;
- whether existing cases must be re-ingested; and
- the sanitized fixture and regression test that prove the behavior.

Do not silently reinterpret an existing field. If a new mapping changes
detection behavior, call that out and include detection assertions.

## Detection changes and false positives

Detection pull requests must identify the rule, explain the forensic rationale,
and include representative positive and negative examples. Prefer multiple
independent signals over broad string matching. Document expected ATT&CK
mapping, severity, and known benign software that resembles the activity.

Never weaken a rule solely to satisfy one unexplained sample. A false-positive
fix should retain a regression case for the benign activity and a positive case
that ensures the malicious behavior still fires.

## Sanitized test fixtures

Real case material is not accepted. Follow the complete procedure in
[docs/TEST_FIXTURES.md](docs/TEST_FIXTURES.md). In short:

1. Prefer generating a minimal synthetic record from the format specification.
2. If a real record is essential, obtain permission to contribute a transformed
   derivative and replace every identifier, timestamp, path, user, host, domain,
   IP address, credential, token, hash, and free-text field.
3. Use reserved examples such as `example.invalid`, `EXAMPLE-WKS`, and the
   documentation networks `192.0.2.0/24`, `198.51.100.0/24`, and
   `203.0.113.0/24`.
4. Remove irrelevant records and container metadata. Do not submit databases,
   memory dumps, EVTX files, archives, packet captures, or collector bundles
   derived from a real investigation.
5. Add a fixture manifest and a test that states the exact expected parse or
   detection result.
6. Review the staged diff as plain text. If sanitization cannot be confidently
   verified, do not contribute the fixture.

## Pull request expectations

The pull request description must explain the problem, solution, validation,
user-visible changes, fixture provenance, and case-database impact. All required
CI checks must pass. Maintainers may request smaller commits, additional benign
corpus coverage, or an explicit migration note before review.

Review and merge policy is documented in [MAINTAINERS.md](MAINTAINERS.md).
Release-affecting changes must update [CHANGELOG.md](CHANGELOG.md), the support
or limitation documents when applicable, and follow
[docs/RELEASING.md](docs/RELEASING.md).

## Documentation-only changes

Documentation fixes are welcome and usually do not need a linked issue. Verify
all relative links and commands. Do not present an optional dependency, an
experimental parser, or an untested operating system as supported.
