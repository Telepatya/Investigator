# Maintainers and review expectations

The repository owner is the current release maintainer. GitHub `CODEOWNERS`
identifies the account responsible for review requests. Additional maintainers
should be added here and to `.github/CODEOWNERS` in the same pull request, with
their scope and decision authority stated explicitly.

## Maintainer responsibilities

Maintainers are expected to:

- triage new issues, apply component and validation labels, and request a safe
  reproducer when needed;
- protect reporter and case confidentiality and move vulnerability details to
  the private security process;
- review parser and detection accuracy, not only implementation style;
- keep required CI, dependency review, CodeQL, and branch protection enabled;
- maintain release notes, support/limitations matrices, migration guidance,
  checksums, SBOMs, and signed release tags; and
- disclose conflicts of interest and recuse themselves when impartial review is
  not possible.

Targets are an initial issue response within seven days, a first substantive
pull-request review within ten days, and a security acknowledgement within the
window documented in [SECURITY.md](SECURITY.md). These are service targets, not
guarantees; urgent response is reserved for exploitable security or evidence
integrity problems.

## Review requirements

Every non-trivial change requires at least one approving maintainer who did not
author the change and all required checks passing. The reviewer verifies:

- the behavior is scoped and the forensic claim is justified;
- positive, malformed-input, and benign/negative coverage is appropriate;
- fixtures satisfy [docs/TEST_FIXTURES.md](docs/TEST_FIXTURES.md);
- no evidence, credentials, or generated case data is present;
- user-facing behavior and dependencies are documented; and
- migration, compatibility, and release-note impacts are addressed.

Changes to security boundaries, case-database migrations, release automation,
or broad detection logic need an explicit domain review. When only one
maintainer exists, that maintainer may merge such a change after CI passes, but
must document the self-review and risk in the pull request. Emergency fixes may
be merged before the normal review window only when the reason and follow-up
validation are recorded.

Maintainers use squash or rebase merges to keep `main` linear unless preserving
separate commits materially helps auditability. Force-pushes and deletion or
movement of published release tags are prohibited. Stale pull requests may be
closed after advance notice and can be reopened when work resumes.

## Triage labels

- `validation`: a reproducer or maintainer confirmation is still needed.
- `parser`: parsing, normalization, or evidence-format behavior.
- `detection`: deterministic rule, correlation, severity, or ATT&CK mapping.
- `security`: private or safely disclosed security hardening work.
- `good first issue`: narrowly scoped, documented, and safe for a new
  contributor.

The canonical definitions are in `.github/labels.json` and are synchronized by
the Labels workflow.

## Release authority

Only a release maintainer may sign and push a release tag or publish/withdraw a
GitHub release. A second person should verify checksums and the signature when
another maintainer is available. Follow [docs/RELEASING.md](docs/RELEASING.md)
without skipping the clean-tree, migration, demonstration-case, or artifact
verification steps.
