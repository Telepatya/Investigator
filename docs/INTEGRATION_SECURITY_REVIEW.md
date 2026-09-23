# Integration and deployment security review — 2026-09-23

This review covers the optional OIDC integration, shared deployment controls,
provider destinations, evidence paths, current GitHub CodeQL findings, and the
repository's dependency checks. It uses synthetic tests and source inspection;
no real Okta or Entra tenant, organization proxy, production evidence, or live
Reverse container was used.

## Tracked changes

| Issue | Change |
| --- | --- |
| [#98](https://github.com/Telepatya/Investigator/issues/98) | Bound anonymous OIDC login initiation and pending transactions. |
| [#99](https://github.com/Telepatya/Investigator/issues/99) | Invalidate sessions and pending logins when identity policy changes, and enforce revocation on active WebSockets. |
| [#100](https://github.com/Telepatya/Investigator/issues/100) | Enforce the configured SSO administrator role on shared settings, rules, and destructive case/workspace operations. |
| [#101](https://github.com/Telepatya/Investigator/issues/101) | Resolve CodeQL control-flow and error-handling findings. |
| [#102](https://github.com/Telepatya/Investigator/issues/102) | Remove untrusted project identifiers from Reverse log messages. |
| [#103](https://github.com/Telepatya/Investigator/issues/103) | Protect the memory extraction manifest and review flagged artifact paths. |
| [#104](https://github.com/Telepatya/Investigator/issues/104) | Reconcile the retired OIDC cookie alert with the merged browser-binding fix; closed after documented mitigation. |

The existing [#70](https://github.com/Telepatya/Investigator/issues/70)
tracks an unpatched advisory in `diskcache`, a required transitive dependency of
pySigma. The dependency audit remains a failing gate. No scanner exception has
been added.

## Deployment boundary

The default launcher is for a single local user on loopback. A shared
deployment needs one backend process, a same-host TLS reverse proxy, an exact
configured public origin and callback URL, environment-managed OIDC credentials,
and a reachable trusted IdP. See [SSO.md](SSO.md) for Okta and Entra setup and a
deployment check. An isolated machine without a reachable IdP can use the
loopback mode but must keep it private.

OIDC permits one organization IdP and one shared pool of cases, rules, and
Reverse projects. A configured administrator claim limits organization-wide
settings and rules changes and shared case/workspace deletion. It does not
provide per-case permissions or an immutable per-user action audit. SAML, SCIM,
Graph group expansion, back-channel logout, and live membership checks are not
implemented. For separate evidence access policies, use separate deployments
and data directories. These boundaries are also recorded in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Code scanning disposition

The PR for this review fixes confirmed scanner findings in OIDC-adjacent error
handling, Reverse control flow, log output, chmod parsing, and the memory
extraction manifest. Path alerts are inspected individually against the
canonical containment checks at their file operations. Alerts that are already
mitigated or are false positives are dismissed only with per-alert evidence;
changes on the PR branch are not considered fixed on `main` until merged and
scanned there.

The rules-profile cache alert (#166) and the validated case-path alert (#176)
were dismissed as false positives after code review. The Reverse source-path
alerts (#109–#113), contained memory copy/cache alerts (#154, #155, #157), and
retired dynamic-scan flow-through alerts (#91, #92, #103–#106) were also
dismissed individually with root-containment or non-sink evidence. The former
OIDC binding-cookie alert (#108) was previously marked mitigated after the
merged callback-cookie fix. Confirmed findings such as the manifest write
(#156) remain represented by the PR changes until `main` is rescanned after a
merge. The PR scan itself is the acceptance check for any newly introduced
alerts.

## Validation limits

The pull request records the exact reviewed revision, local test results, and
hosted checks. The checks do not prove that every integration or operating
environment is secure. In particular, a deployment operator must verify the
actual IdP claims, proxy headers, TLS, filesystem permissions, outbound network
policy, and session revocation procedure before inviting users.
