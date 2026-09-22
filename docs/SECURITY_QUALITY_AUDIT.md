# Security and quality audit — 2026-09-22

## Scope and delivery

Audit baseline: `5a4149865aca87d82acd15f6f51c7f4a66bf7120`, including 16 committed SSO changes ahead of remote `main` (`b6340fa2015a1ae6744532f1dbe0199d86772726`). Work branch: `codex/security-quality-audit`.

The audit covered the tracked Python backend, React frontend, optional Reverse sandbox, dependency inputs/locks, launcher, release tooling and CI configuration. Review combined manual source inspection, targeted synthetic regression tests, full project gates and registry/advisory checks. It did not involve real case evidence, production endpoints, real provider credentials or executing malware samples.

Implementation used Astra because the requested Luna model was unavailable. Sol performed planning and separate implementation review. Automated agent review does not replace required maintainer approval.

Final local validation is complete. The exact independently reviewed revision and hosted CI state are recorded in the draft PR.

## Findings

Each finding has an issue in the private repository. Issues remain open until the relevant changes are merged; an implementation in the draft PR is not a released fix.

| Issue | Finding | Status |
| --- | --- | --- |
| [#60](https://github.com/Telepatya/Investigator/issues/60) | Bound Reverse tool-output collection | Implemented; pending merge |
| [#61](https://github.com/Telepatya/Investigator/issues/61) | Reject incomplete memory/VFS exports | Implemented; pending merge |
| [#62](https://github.com/Telepatya/Investigator/issues/62) | Release MemProcFS lock on initialization failure | Implemented; pending merge |
| [#63](https://github.com/Telepatya/Investigator/issues/63) | Constrain provider destinations and credential forwarding | Implemented; pending merge |
| [#64](https://github.com/Telepatya/Investigator/issues/64) | Enforce runtime regex deadlines | Implemented; pending merge |
| [#65](https://github.com/Telepatya/Investigator/issues/65) | Enforce rule quota on edits and enabling | Implemented; pending merge |
| [#66](https://github.com/Telepatya/Investigator/issues/66) | Remove unused dependencies/imports and stale references | Implemented; pending merge |
| [#67](https://github.com/Telepatya/Investigator/issues/67) | Preserve Windows environment in missing-Sigma test | Implemented; pending merge |
| [#68](https://github.com/Telepatya/Investigator/issues/68) | Update AnyIO | Implemented; pending merge |
| [#69](https://github.com/Telepatya/Investigator/issues/69) | Update pip | Implemented; pending merge |
| [#70](https://github.com/Telepatya/Investigator/issues/70) | Unpatched diskcache advisory | Unresolved upstream advisory |
| [#71](https://github.com/Telepatya/Investigator/issues/71) | Add browser anti-framing/content headers | Implemented; pending merge |
| [#72](https://github.com/Telepatya/Investigator/issues/72) | Bound API request bodies, queries and WebSocket input | Implemented; pending merge |
| [#73](https://github.com/Telepatya/Investigator/issues/73) | Separate ZIP upload attribution | Implemented; pending merge |
| [#74](https://github.com/Telepatya/Investigator/issues/74) | Seal sandbox evidence under independent ownership | Implemented; pending merge |
| [#75](https://github.com/Telepatya/Investigator/issues/75) | Restore mobile navigation | Implemented; pending merge |
| [#76](https://github.com/Telepatya/Investigator/issues/76) | Repair dialog labels, keyboard dismissal and focus | Implemented; pending merge |
| [#77](https://github.com/Telepatya/Investigator/issues/77) | Remove external font requests | Implemented; pending merge |
| [#78](https://github.com/Telepatya/Investigator/issues/78) | Repair packaged dependency entry point | Implemented; pending merge |
| [#79](https://github.com/Telepatya/Investigator/issues/79) | Invalidate frontend build cache for all inputs | Implemented; pending merge |
| [#80](https://github.com/Telepatya/Investigator/issues/80) | Isolate multiple memory dumps | Implemented; pending merge |
| [#81](https://github.com/Telepatya/Investigator/issues/81) | Make detection rebuild atomic | Implemented; pending merge |
| [#82](https://github.com/Telepatya/Investigator/issues/82) | Update baseline-browser-mapping | Implemented; pending merge |
| [#83](https://github.com/Telepatya/Investigator/issues/83) | Update Browserslist | Implemented; pending merge |
| [#84](https://github.com/Telepatya/Investigator/issues/84) | Bound multipart uploads before temporary-file allocation | Implemented; pending merge |
| [#85](https://github.com/Telepatya/Investigator/issues/85) | Require HTTPS for hosted remote provider endpoints | Implemented; pending merge |
| [#86](https://github.com/Telepatya/Investigator/issues/86) | Make same-name evidence replacement atomic across files and attributed rows | Implemented; pending merge |
| [#87](https://github.com/Telepatya/Investigator/issues/87) | Bound and coalesce ingestion progress listener queues | Implemented; pending merge |
| [#89](https://github.com/Telepatya/Investigator/issues/89) | Make dependency-lock CI invocation portable on Linux runners | Implemented; pending merge |
| [#90](https://github.com/Telepatya/Investigator/issues/90) | Restore supported dependency review for pull requests | External repository configuration pending |
| [#91](https://github.com/Telepatya/Investigator/issues/91) | Restore CodeQL analysis and update workflows to Node 24 actions | Code update implemented; repository setting pending |

## Authorization and trust boundaries

The declared SSO model is one organization-wide shared pool of cases, rules and Reverse projects. All allowed organization members share those resources; there is no per-case owner or tenant-role boundary. Route inspection found no IDOR relative to that declared contract. This conclusion is not a claim of per-user isolation. Product HTTP routes and WebSockets use centralized authentication; child resource lookups were checked against their case database or Reverse project.

The provider changes distinguish the trusted local analyst from an organization member. SSO provider destinations must match operator-approved bases; validation runs when saving settings and when constructing/sending provider requests. Redirect and environment-proxy inheritance are disabled in these transports. Local custom Ollama/provider operation is retained. See [SSO configuration](SSO.md).

Reverse keeps its non-root analyzer process, network isolation, dropped capabilities, read-only container root and no host mounts. Trusted staging gives inputs/context independent ownership. The sandbox protocol changes require rebuilding the optional Reverse image; the image was not rebuilt or executed during this audit because the Docker engine was unavailable.

Evidence attribution changes are additive. New rows identify their upload independently of display source; distinct memory uploads receive stable distinct keys. Ambiguous legacy attribution is refused for destructive operations rather than guessed. See [migration guidance](MIGRATIONS.md).

## Dependency evidence and residual risk

Python release identities and committed SHA-256 hashes were checked against official PyPI metadata, including core, memory, developer and Reverse locks. Current scans were reconciled with GitHub advisory metadata. An npm audit result of zero did not cover the Browserslist and baseline-browser-mapping advisories identified by GitHub; those packages were addressed separately.

`diskcache 5.6.3` remains in pySigma's required dependency closure. The [unsafe deserialization advisory](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v) has no patched release. Supported Investigator Sigma operations do not invoke the optional cache-using validators; the relevant code path is covered separately by a regression test. That applicability evidence does not fix the installed package or make the dependency audit pass. Issue [#70](https://github.com/Telepatya/Investigator/issues/70) remains open, and no scanner exception was added.

Removed packages were verified unused before removal. Optional integrations were retained. Locks were regenerated rather than edited by hand.

## Verification

The final local preflight after all repairs completed with 473 backend tests
passing and one opt-in live-Docker test skipped. Ruff, Python bytecode
compilation, `pip check`, dependency lock checks, `git diff --check`, a clean
frontend `npm ci`, frontend type checking/build, and the frontend auth-gate test
passed. Registry verification covered 138 unique pinned Python releases and 204
locked npm releases; no missing, yanked, hash-mismatched, or integrity-mismatched
release was found. The exact reviewed commit and hosted CI state are recorded in
the pull request because review evidence applies to a specific revision.

Browser smoke checks used the actual built frontend with an isolated read-only synthetic API fixture, not the application backend: navigation at 390×844 and 1440×900; Case and Reverse create dialogs; Rules editor/import dialogs; labels, keyboard focus, Escape and opener restoration. The 390-pixel layout had no horizontal overflow in the inspected dialog. No external HTTP font/script/link references remained in the initial document. The temporary fixture service and browser tab were stopped after verification.

The published draft PR repeated lock freshness, installation, `pip check`,
compilation, Ruff, all 473 backend tests, frontend build/audits, and repository
policy checks successfully. Its remaining failed checks are the unpatched
`diskcache` advisory (#70), unavailable dependency review (#90), and CodeQL
result publication while code scanning is disabled (#91).

A source credential-pattern scan found no matching private-key blocks or common credential prefixes in the tracked source. This was a limited pattern scan, not an exhaustive secret/history audit.

## Explicit limitations

- The unpatched diskcache dependency prevents a clean dependency-security result.
- No live Docker integration or base-image/apt vulnerability scanner ran; Docker's engine was unavailable. Unit tests do not prove kernel/container containment.
- GitHub code-scanning alerts returned HTTP 403 to the audit credential. The published PR's CodeQL jobs completed both language analyses but could not publish results because code scanning is disabled.
- GitHub's dependency-review action is unsupported for this private repository until the required dependency graph and Advanced Security capability is enabled or an equivalent scanner replaces it; issue [#90](https://github.com/Telepatya/Investigator/issues/90) tracks that repository-level work.
- CodeQL analysis cannot publish results until code scanning is enabled for the repository. The workflows now use supported Node 24 action majors and grant Actions metadata read access; issue [#91](https://github.com/Telepatya/Investigator/issues/91) tracks the remaining repository-level enablement.
- No live identity-provider, remote LLM, real memory-dump or production deployment validation was performed.
- Manual coverage, tests and scanners cannot establish that the entire codebase is vulnerability-free. The PR must remain draft while blocking findings or required validation are unresolved.
