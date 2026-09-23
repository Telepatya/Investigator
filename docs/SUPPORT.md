# Support and dependency matrix

This matrix describes the environments the project promises to validate for the
current `0.1.x` beta. “Unsupported” means a useful bug report is welcome, but a
release may not be delayed for that environment.

## Operating systems

| Operating system | Architecture | Level | Log/artifact analysis | Memory analysis | Distribution |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | x86-64 | Supported | CI/release validated | Supported when optional MemProcFS and YARA dependencies load | Reproducible release ZIP |
| Ubuntu 24.04 LTS | x86-64 | Core supported | CI validated from source | Best effort; depends on MemProcFS platform support | Source checkout |
| Other Windows, Linux, macOS | any | Unsupported/community | May work from source | Not release validated | None |

Investigator's default mode is a local desktop workflow and is not supported as
an Internet-exposed service. An explicitly configured OIDC deployment may be
used by one organization behind TLS and a correctly configured reverse proxy,
with one shared pool of cases/rules/Reverse projects; it is not a general
multi-tenant service and has no per-case RBAC. Windows on ARM, containers, WSL
GUI use, and network filesystems for the case directory are not release targets.

## Toolchain

| Dependency | Supported version | Required when | Notes |
| --- | --- | --- | --- |
| CPython | 3.11 or 3.12, 64-bit | Always | The release archive creates a local virtual environment. Python 3.13+ is not yet a release target. |
| Node.js | 22.x | Building from source or frontend development | Not needed by the release ZIP, which contains a prebuilt frontend. |
| npm | Version bundled with supported Node 22 | Building from source | Installs exactly from `frontend/package-lock.json` with `npm ci`. |
| Modern browser | Current Edge, Chrome, or Firefox | Always | The backend binds to loopback and opens the UI locally. |

## Optional organization SSO

OIDC SSO is supported as an environment-configured deployment option with one
IdP per backend. Okta and Microsoft Entra web-app registrations are documented
in [SSO.md](SSO.md). The SSO path is validated against the supported browser and
Python runtimes above, but an IdP tenant, reverse proxy, TLS termination, and
claim policy remain deployment-specific. SAML, SCIM, API tokens, multi-tenant
isolation, and Entra Graph group expansion are not supported. A configured admin
claim limits shared settings/rule changes and case/project deletion; it does not
isolate case evidence between permitted members.

## Required Python dependencies

The application runtime dependencies in `backend/requirements.in` and their
transitive dependencies in `backend/requirements.lock` are required. They cover
the API/server, SQLite access, evidence ingestion, credential-vault integration,
and configured LLM-provider clients. Releases install them from a hashed lock
file; floating installs are unsupported.

An AI service is not required for deterministic parsing, search, correlation, or
detections. Ollama and remote-provider accounts/keys are runtime integrations,
not installation prerequisites.

## Optional dependencies

| Dependency | Capability enabled | Behavior when absent |
| --- | --- | --- |
| `memprocfs` | Raw-memory mounting and forensic extraction | Memory images cannot be processed; log and artifact workflows remain available. |
| `yara-python` | YARA scanning of extracted memory bytes | YARA results are skipped and health/status explains the missing capability. |
| Ollama | Fully local AI reports and chat | Deterministic investigation remains available. |
| OpenAI, OpenRouter, Anthropic, or Gemini account/API key | Remote AI reports and chat | That provider cannot be selected; no effect on deterministic analysis. |
| Custom YARA rules | Organization-specific memory signatures | Only bundled rules are used. |

The source launcher currently installs `backend/requirements-memory.lock` by
default so the optional memory features are available when compatible wheels
exist. This does not make raw-memory analysis necessary to use Investigator.

## Compatibility policy

The lock files, CI versions, and this matrix are authoritative together. A pull
request that raises a minimum version, removes an operating-system target, or
changes an optional capability to required must update this document and the
versioned release notes. Security fixes may require an earlier compatibility
change, which will be called out prominently.
