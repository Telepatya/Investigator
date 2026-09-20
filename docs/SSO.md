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
INVESTIGATOR_SSO_CLAIMS=groups,roles
INVESTIGATOR_SSO_ALLOWED_VALUES=Investigator-Analysts,00000000-0000-0000-0000-000000000001
INVESTIGATOR_SSO_ADMIN_CLAIM=roles
INVESTIGATOR_SSO_ADMIN_VALUE=Investigator-Admins
```

`INVESTIGATOR_PUBLIC_ORIGIN` is an exact `http(s)` origin (scheme, hostname,
and optional port only). The callback URI is derived from it as
`<public-origin>/api/auth/callback`; it is never derived from `Host` or proxy
headers. Use HTTPS in a shared deployment. The client secret is required when
SSO is enabled; an incomplete configuration fails closed with no silent
fallback to anonymous access.

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
   `https://investigator.example.com/api/auth/callback`. Add the exact logout
   URI/origin used by the deployment if your Okta policy requires it.
3. Use the issuer for the authorization server assigned to the app (for the
   Default server this is `https://<org>.okta.com/oauth2/default`). Set the
   resulting client ID and secret as environment variables above.
4. Add a **groups** claim to the ID token (or use an existing one), with a
   filter that only emits the groups needed by this app. Set
   `INVESTIGATOR_SSO_CLAIMS=groups` and list the exact case-sensitive Okta group
   names in `INVESTIGATOR_SSO_ALLOWED_VALUES`. If administrators use a separate
   group, set the admin claim/value to `groups` and that exact group name.

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
   **Enterprise applications → Users and groups**. Configure
   `INVESTIGATOR_SSO_CLAIMS=groups` and allowlist the exact Entra group object
   IDs (case-sensitive string comparison).
4. Alternatively define an **app role** such as `Investigator.Analyst` and
   assign it to users/groups. Configure `INVESTIGATOR_SSO_CLAIMS=roles` and
   allowlist the exact role value. The role claim is an array; do not use a
   display name that is not present in the token.

Entra can emit `hasgroups` or `_claim_names` when group membership exceeds the
token limit. Investigator rejects those tokens closed; it does not call Graph
and does not request directory-wide permissions. Reduce assigned groups,
prefer app roles, or use groups assigned to the application so the complete
allowlisted claim fits in the ID token.

## Operations and troubleshooting

- Anonymous access to product APIs and all WebSockets is denied with JSON 401 or
  a pre-accept WebSocket denial. Health and the auth bootstrap/login/callback
  endpoints remain anonymous so the UI can show a login or configuration error.
- Authenticated browser mutations require the exact configured HTTP `Origin`.
  Host, CORS, HTTP Origin, and WebSocket Origin checks all use the explicit
  public origin. Missing/bad origins are denied while SSO is enabled.
- The frontend keeps no token in localStorage. It uses same-origin credentials,
  centralizes 401 handling, validates relative return paths, and offers logout.
- Changing environment configuration requires a process restart. Existing
  server-side sessions remain bounded by their configured expiry; revoke them by
  removing `~/.investigator/auth.db` only during a planned maintenance window.
