# Optional organization SSO (OIDC)

Investigator remains authentication-disabled and loopback-only by default. To
enable one organization identity provider for a deployment, configure the
environment variables below before starting the backend. SSO configuration is
not written to `~/.investigator/config.json`, the browser, logs, or API
responses.

```text
INVESTIGATOR_AUTH_ENABLED=true
INVESTIGATOR_PUBLIC_ORIGIN=https://investigator.example.com
INVESTIGATOR_OIDC_ISSUER=https://issuer.example.com/oauth2/default
INVESTIGATOR_OIDC_CLIENT_ID=<web-app-client-id>
INVESTIGATOR_OIDC_CLIENT_SECRET=<web-app-client-secret>
INVESTIGATOR_OIDC_SCOPES=openid profile email
INVESTIGATOR_SSO_CLAIMS=groups,roles
INVESTIGATOR_SSO_ALLOWED_VALUES=Investigator-Analysts,00000000-0000-0000-0000-000000000001
INVESTIGATOR_SSO_ADMIN_CLAIM=roles
INVESTIGATOR_SSO_ADMIN_VALUE=Investigator-Admins
```

`INVESTIGATOR_PUBLIC_ORIGIN` is an exact origin (scheme, hostname, and optional
port only). HTTPS is required except for loopback development origins
(`localhost`, `127.0.0.1`, or `::1`). The callback URI is derived from it as
`<public-origin>/api/auth/callback`; it is never derived from `Host` or proxy
headers. Use HTTPS in a shared deployment. The client secret is required when
SSO is enabled; an incomplete configuration fails closed with no silent
fallback to anonymous access.

## Private and organization deployment

Run one backend process on a dedicated supported host under a service account
that can access only its own Investigator data directory. The built-in server
binds to `127.0.0.1` on `INVESTIGATOR_PORT` (default `8400`). Put a TLS reverse
proxy on the same host in front of it and publish only the proxy. Route the
entire site, including `/api` and WebSocket upgrades, to that loopback port
without rewriting paths. Preserve the public `Host` header. The browser URL must
exactly match `INVESTIGATOR_PUBLIC_ORIGIN`; register that origin's
`/api/auth/callback` URL at the IdP. Investigator deliberately ignores forwarded
host/protocol headers when deciding trusted origins. Do not use development
reload or multiple backend workers against the same case directory.

Provide the OIDC client secret through the service environment or a deployment
secret store, with access limited to the service operator. Keep the data
directory, backups, and proxy logs protected as forensic evidence. The backend
must be able to reach its configured issuer's discovery, token, and key
endpoints over trusted TLS. An isolated environment without an available IdP
can use the default single-user loopback mode; it must not publish that mode to
other machines.

Before sharing a deployment, test a permitted account, a denied account, a
denied cross-origin request, logout, and a fresh login after changing IdP
policy. Use synthetic evidence for this check. Restrict IdP app assignment to
the intended investigation team. Every permitted member can read and work in
the same case, rule, and Reverse project pool; there is no tenant or per-case
isolation. Keep separate deployments and data directories for teams that must
not see each other's evidence.

`INVESTIGATOR_OIDC_SCOPES` is a space-delimited list of safe OAuth scope
tokens. `openid` is always added if omitted. Keep the list limited to scopes
registered for this application; it is sent only in the authorization request.

The implementation uses Authorization Code + PKCE S256, state and nonce
transactions held server-side for one use, Authlib signature/issuer/audience/
time validation, an allowlisted asymmetric JWT algorithm set, and opaque
HttpOnly SameSite=Lax sessions. Cookie tokens are only stored as SHA-256
hashes in `~/.investigator/auth.db`, with idle and absolute expiry. Logout
invalidates the server-side session. The deployment is one IdP and one shared
pool of cases, rules, and Reverse projects; it does not provide per-case RBAC,
SAML, SCIM, directory Graph calls, or API tokens.

## Okta web application

1. In **Applications → Create App Integration**, choose **OIDC – OpenID
   Connect**, **Web Application**, and Authorization Code. Enable PKCE if the
   tenant exposes that option; keep the client secret private.
2. Add the exact sign-in redirect URI
   `https://investigator.example.com/api/auth/callback`. Investigator logout
   ends its local session; it does not perform IdP-wide logout.
3. Use the issuer for the authorization server assigned to the app (for the
   Default server this is `https://<org>.okta.com/oauth2/default`). Set the
   resulting client ID and secret as environment variables above.
4. Add a **groups** claim to the ID token (or use an existing one), with a
   filter that only emits the groups needed by this app. Set
   `INVESTIGATOR_OIDC_SCOPES=openid profile email groups` and set
   `INVESTIGATOR_SSO_CLAIMS=groups` and list the exact case-sensitive Okta group
   names in `INVESTIGATOR_SSO_ALLOWED_VALUES`. If administrators use a separate
   group, set the admin claim/value to `groups` and that exact group name.

See Okta's [web app integration](https://help.okta.com/en-us/Content/Topics/Apps/Apps_App_Integration_Wizard_OIDC.htm)
and [groups-claim](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/)
guides for the tenant-specific screens and claim filter.

## Microsoft Entra ID app registration

1. In **Microsoft Entra admin center → App registrations → New registration**,
   register a web app and add the exact redirect URI
   `https://investigator.example.com/api/auth/callback` under **Web**.
2. Create a client secret and store its value in the deployment secret store,
   never in `config.json` or source control. Set the issuer to the tenant
   authority used by the app, for example
   `https://login.microsoftonline.com/<tenant-id>/v2.0`.
3. Under **Token configuration**, add a **Groups** claim. Prefer **Groups
   assigned to the application** and assign the required users/groups under
   **Enterprise applications → Users and groups**. Keep
   `INVESTIGATOR_OIDC_SCOPES=openid profile email`; group claims are configured
   in the app registration and are not requested through an unconditional
   `groups` scope. Set `INVESTIGATOR_SSO_CLAIMS=groups` and allowlist the exact Entra group object
   IDs (case-sensitive string comparison). The "Groups assigned to the
   application" option includes direct group membership and requires the
   relevant Entra licensing; use app roles if that option is unavailable.
4. Alternatively define an **app role** such as `Investigator.Analyst` and
   assign it to users/groups. Configure `INVESTIGATOR_SSO_CLAIMS=roles` and
   allowlist the exact role value. The role claim is an array; do not use a
   display name that is not present in the token.

Entra can emit `hasgroups` or `_claim_names` when group membership exceeds the
token limit. Investigator rejects those tokens closed; it does not call Graph
and does not request directory-wide permissions. Reduce assigned groups,
prefer app roles, or use groups assigned to the application so the complete
allowlisted claim fits in the ID token.

See Microsoft's [group claims and app roles](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)
guide for assignment and overage behavior.

The optional `INVESTIGATOR_SSO_ADMIN_CLAIM` and
`INVESTIGATOR_SSO_ADMIN_VALUE` settings identify operators allowed to change
organization-wide settings and rules or delete shared cases or Reverse
projects. If these settings are omitted, every permitted SSO member retains
the shared-pool permissions of earlier releases. Configure a separate exact
admin group or app role for a shared deployment. The admin marker does not
create per-case RBAC:
permitted members can still read and work in every case and project. Admins
must also satisfy `INVESTIGATOR_SSO_ALLOWED_VALUES`; an admin claim alone does
not grant sign-in. The application does not provide an immutable, per-user
audit trail for every shared case or rule change. Deployments requiring that
attribution need an external control or a future application feature.

## Operations and troubleshooting

- Anonymous access to product APIs and all WebSockets is denied with JSON 401 or
  a pre-accept WebSocket denial. Health and the auth bootstrap/login/callback
  endpoints remain anonymous so the UI can show a login or configuration error.
- FastAPI's `/docs`, `/redoc`, and `/openapi.json` metadata endpoints are
  protected by the same session boundary when SSO is enabled; static SPA assets
  remain public so the login shell can load.
- Authenticated browser mutations require the exact configured HTTP `Origin`.
  Host, CORS, HTTP Origin, and WebSocket Origin checks all use the explicit
  public origin. Missing/bad origins are denied while SSO is enabled.
- The frontend keeps no token in localStorage. It uses same-origin credentials,
  centralizes 401 handling, validates relative return paths, and offers logout.
- Login initiation is bounded to 120 requests per minute per direct peer and
  1,024 unexpired transactions overall. Excess requests receive `429` with
  `Retry-After` before contacting the IdP. A same-host reverse proxy is the
  direct peer for all remote browsers, so its users share that limit;
  forwarded client-IP headers are deliberately ignored. Operators with larger
  login bursts should add trusted rate controls at the proxy and account for
  this application-wide limit.
- Changing environment configuration requires a process restart. Changes to
  the issuer, client, origin, or allowlisted group/role policy invalidate
  existing sessions so users must sign in again. To revoke every session
  independently of a policy change, stop the backend, back up the auth database
  if required by policy, then remove `~/.investigator/auth.db` and any
  `auth.db-wal`/`auth.db-shm` sidecars during a planned maintenance window.
- Open WebSockets recheck the current session before each new client command
  and before sending each progress or model-output event. Logout, session expiry,
  or an authentication-policy change therefore blocks the next action or output.
  An idle socket can remain connected until another action or event occurs. A
  provider call already dispatched may continue until it yields its next event;
  the backend checks the session before sending that event, but cannot undo work
  already performed by the provider or retract earlier output.
- Group or role removal at the IdP is checked at the next login, not on every
  HTTP request or active WebSocket message. A current browser session can
  remain valid until its absolute expiry or logout. Set
  `INVESTIGATOR_SSO_ABSOLUTE_SECONDS` to match the
  organization's offboarding window; use the maintenance procedure above to
  revoke all sessions sooner. There is no SCIM or back-channel logout.


## Provider destinations and request limits

With SSO enabled, Ollama and OpenRouter base URLs are restricted to their exact
built-in defaults (`http://localhost:11434` and `https://openrouter.ai/api/v1`).
To use an internal gateway, the operator must set
`INVESTIGATOR_OLLAMA_APPROVED_URLS` or `INVESTIGATOR_OPENROUTER_APPROVED_URLS`
to a comma-separated list of approved absolute HTTP(S) bases, then select that
base in Settings. Hosted non-loopback destinations must use HTTPS, even when
explicitly approved. HTTP remains available for `localhost` and literal loopback
IP addresses. Approval includes the exact path; it is not a host wildcard.
Approving a gateway authorizes it to receive that provider's key and case data.
Only approve endpoints and DNS that the operator trusts. Apply network egress
controls in hosted deployments as an additional boundary.

Both settings saves and outgoing requests check this policy, including old
`config.json` values. Invalid URLs, credentials in URLs, query strings, fragments,
and ambiguous paths are rejected. Local mode still supports analyst-selected
custom Ollama and OpenRouter endpoints, including loopback services. OpenAI,
Anthropic, and Gemini use explicit official endpoints. Provider HTTP clients do
not follow redirects or inherit proxy/base URL overrides from SDK environment
variables; configure a trusted gateway through the supported URL settings.

Responses prohibit framing and include `nosniff` and `no-referrer` headers. The
CSP limits framing only, so scripts, styles, assets, and OIDC navigation retain
their existing behavior. Non-upload request bodies are limited to 1 MiB before
JSON parsing. Upload bodies are counted as they arrive, before multipart file
spooling, and rejected with 413 when the route's configured limit is exceeded.
Case uploads use the lesser of `INVESTIGATOR_MAX_UPLOAD_BYTES` and
`INVESTIGATOR_MAX_CASE_BYTES`; Reverse uses the lesser of its configured file and
project limits. A 1 MiB multipart framing allowance applies, with a 1 TiB hard
request ceiling. Chunk upload requests allow at most 64 MiB of payload plus the
framing allowance, while the assembled file retains the configured file quota.
Declared lengths are checked early and actual streamed bytes are authoritative.
Route handlers also retain cumulative file and case/project storage quotas. Events
and memory handle queries allow 1–5000 rows, timeline queries 0–10000 rows (zero
loads facets only), and offsets are nonnegative. Chat messages allow 32000
characters and entity IDs 4096; invalid WebSocket inputs never start a model
request. The built-in server also limits incoming WebSocket messages to 128 KiB.
Operators launching Uvicorn separately should set `--ws-max-size 131072`.
