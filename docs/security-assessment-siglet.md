# Siglet Security Assessment: Participant Context Isolation

| | |
|---|---|
| Date | 2026-09-28 |
| Scope | `siglet` (all four APIs), `dsdk-facet-core`, `dsdk-facet-postgres`, `dsdk-facet-hashicorp-vault`, `dataplane-sdk` / `-axum` / `-postgres` 0.1.2 |
| Focus | Multi-tenant isolation between participant contexts; secondary: SSRF, token lifecycle, input handling |
| Method | Manual code review of every request path from the HTTP boundary down to the SQL / Vault call, followed by fixes and a cross-tenant regression suite |

## Summary

Siglet's JWT middleware is sound. It pins the signing algorithm, requires `kid`, validates `aud`,
`exp`, `nbf` and scope, and on participant-scoped routes binds `sub` to the `{participant_context_id}`
path segment. Its defaults fail closed: auth is on, and an empty `jwks_url` fails startup.

The layers underneath did not re-check ownership. Once a caller was authenticated for its own
participant context, several paths let it reach another context's flows or tokens:

- A flow id known to the attacker was enough to read, terminate or rewrite another context's flow.
- An encoded `../` in a token id was enough to read or delete another context's Vault-stored tokens.

Two findings were critical. Both are fixed, along with every High and Medium finding. The
fixes span this repository and `dataplane-sdk-rust`.

## Threat model

- **Tenant**: a participant context. Its id is the `sub` of the JWTs it presents to Siglet.
- **Attacker A**: holds a valid, correctly scoped JWT for its own participant context and wants to
  read, change or disrupt another context's flows or tokens.
- **Attacker B**: a malicious counterparty that controls the data address (refresh endpoint,
  `expiresIn`, tokens) delivered to a consumer-side Siglet.
- **Trusted**: the IdP issuing caller JWTs, Vault, Postgres, platform operators holding the
  management API scopes.

## Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F1 | Critical | Flow operations ignored the caller's participant context | Fixed (SDK) |
| F2 | Critical | Path traversal from the token API into other contexts' Vault secrets | Fixed |
| F3 | High | SSRF / credential exfiltration via counterparty-supplied refresh endpoint | Fixed |
| F4 | Medium | Token revocation not scoped to the participant context | Fixed |
| F5 | Medium | Refresh tokens never expired | Fixed |
| F6 | Medium | `/tokens/verify` returned claims of any context's tokens | Fixed |
| F7 | Medium | Management API accepted arbitrary Vault key names | Fixed |
| F8 | Medium | Global flow-id namespace: existence oracle and unencoded callback URL | Fixed (SDK) |
| F9 | Low–Medium | Panics / overflow on counterparty-supplied `expires_in` | Fixed |
| F10 | Low–Medium | Token refresh lock gave no mutual exclusion and was not context-scoped | Fixed |
| F11 | Low | `expires_in` reported the refresh-token lifetime, not the access token's | Fixed |
| F12 | Low | `iss` never validated; tokens printable via `Debug`; remote error bodies logged | Fixed |

### F1: Flow operations ignored the caller's participant context (Critical)

**What was wrong**
- `DataPlaneSdkInternal::{terminate, started, completed, suspend, resume, status}` received the
  authenticated participant context as `_ctx` and discarded it.
- Flows were loaded with `fetch_by_id(flow_id)`. The Postgres query was `WHERE id = $1`; the memory
  store used a global map.
- So tenant A could call `/api/v1/A/dataflows/{B's flow id}/…` with its own token and:
  - read B's flow state (`status`);
  - terminate or suspend B's flow. Siglet then revoked B's tokens, because the handler rebuilds the
    participant context from the stored flow;
  - replace B's data address (`started`, `resume`).
- Flow ids are chosen by the caller and are known to the counterparty, so they are not a secret.

**Fix** (`dataplane-sdk-rust`)
- `DataFlowRepo::fetch_by_id`/`delete` take the participant context id, and `update` keys on
  `(flow.participant_context_id, flow.id)`.
- Postgres filters on both columns.
- Every flow operation, including `send_callback`, passes the caller's context. A flow of another
  context is reported as `404`, exactly like a missing one.

### F2: Path traversal into other contexts' Vault secrets (Critical)

**What was wrong**
- `GET/DELETE /tokens/{participant_context_id}/{id}` binds `sub` only to the first segment.
- Axum percent-decodes `{id}`, so `..%2FB%2Fflow` became `../B/flow`. That value was `format!`-ed
  into `/v1/secret/data/{pc}/{id}`, and URL normalisation resolved it to B's secret.
- With Kubernetes service-account auth, one Vault token serves all tenants, so Vault policy did
  not stop this. A could read B's access and refresh tokens, or delete them.
- `key_name` in `/v1/transit/sign/{key_name}` had the same problem (see F7).

**Fix**
- `dsdk_facet_core::util::path::validate_path_segment` accepts non-empty values of at most 256
  characters from `[A-Za-z0-9._:@~-]`, excluding `.` and `..`.
- It is enforced at the token and management API boundary (400).
- It is enforced again inside `HashicorpVaultClient` for the participant context id, every KV path
  segment and every transit key name, so no other entry point can traverse.

### F3: SSRF via refresh endpoint (High)

**What was wrong**
- The consumer side stored the `refreshEndpoint` from the provider's data address verbatim.
- On refresh, Siglet POSTed the refresh token plus a proof JWT (signed with the participant
  context's key and embedding the access token) to it.
- There was no scheme or host check, redirects were followed, and the error response body was
  logged at error level.

**Fix**
- New `[token.refresh_endpoint_policy]`: HTTPS-only by default, with optional `allowed_hosts`
  (exact or `*.domain`). URLs with credentials are rejected.
- The endpoint is checked in `on_started` before the token is stored, and again in
  `OAuth2TokenClient` before anything is signed.
- Redirects are disabled on Siglet's shared HTTP client and on the OAuth client's default client.
- Remote error bodies are no longer copied into errors. A 512-byte prefix is logged at debug level
  only.

### F4: Token revocation not scoped to the participant context (Medium)

**What was wrong**
- `JwtTokenManager::revoke_token` ignored its participant context argument.
- `RenewableTokenStore::remove_by_flow_id` deleted every row with that flow id, across contexts.
- The memory store's flow index kept one entry per flow id. A second token for the same flow
  overwrote it, leaving the first token unrevocable.

**Fix**
- `find_by_flow_id`/`remove_by_flow_id` take the participant context id, and Postgres filters on it
  (with a new `(participant_context_id, flow_id)` index).
- The memory store indexes `(context, flow)` to every entry issued for it.

### F5: Refresh tokens never expired (Medium)

**What was wrong:** `renew` never compared the stored entry's expiry (the refresh-token lifetime,
48 h by default) with the current time.

**Fix:** `renew` rejects an expired refresh token with `401`.

### F6: `/tokens/verify` returned any context's claims (Medium)

**What was wrong**
- The route has no participant context in its path, so the middleware authenticated the caller
  without binding `sub`.
- The audience came from the request body.
- Any token-API caller could therefore validate a token minted for another context and read its
  claims. The practical effect is that tenant B's data plane would accept tenant A's tokens.

**Fix**
- The middleware now injects an `AuthenticatedCaller { subject, is_admin }` extension.
- `TokenManager::validate_token` takes an optional participant context id, and the verify handler
  passes the caller's `sub` unless the caller holds the admin scope.
- A token of another context gets the same `401` as an unknown token.

### F7: Management API accepted arbitrary key names (Medium)

**What was wrong:** signing-key mappings were stored verbatim. A `keyName` of `../keys/x` escaped
the transit sign endpoint.

**Fix:** participant context ids and key names are validated as path segments (400), and `kid`
must be non-empty.

Pointing one context at another context's transit key is still possible for holders of
`siglet-mgmt-api:write`. The management API is an operator API by design; see residual risks.

### F8: Global flow-id namespace (Medium)

**What was wrong**
- `data_flows.id` was the table's primary key, so all tenants shared one flow-id space.
- A `start` with another tenant's id returned `409`, which told the caller that id existed and let
  it squat ids.
- The flow id went into the control-plane callback URL without encoding.

**Fix** (`dataplane-sdk-rust`)
- A migration changes the primary key to `(participant_context_id, id)`.
- Callback URLs are built with `Url::path_segments_mut`, so the flow id is always a single encoded
  segment.

### F9 – F12 (Low / Low–Medium)

- **F9: counterparty `expires_in` could panic or overflow.**
  - `OAuth2TokenClient` clamps it to `[0, 30 days]`.
  - The signaling handler rejects out-of-range `expiresIn`.
  - `TokenClientApi` treats an unrepresentable refresh time as expired instead of panicking.
- **F10: the refresh lock gave no mutual exclusion.** The lock owner was the flow id, and the lock
  managers are reentrant per owner, so concurrent refreshes were not excluded. Each request now uses
  a fresh UUID owner, and the lock key is `{participant_context_id}/{flow_id}`.
- **F11: wrong `expires_in`.** `RenewableTokenPair::expires_at` now reports the access token's
  `exp`, as the data address documentation already stated. Previously it reported the
  refresh-token expiry, so consumers cached expired access tokens.
- **F12: issuer, `Debug` output and logs.**
  - Optional `issuer` on `[signaling_auth]`, `[token_api_auth]` and `[management_api_auth]`
    enforces `iss`.
  - `RenewableTokenPair`, `RenewableTokenEntry`, `TokenData` and `RefreshedTokenData` redact tokens
    in `Debug`.

## Residual risks and design decisions

- **One signing key and issuer for all tenants.** Access tokens are signed with `signing-siglet` and
  carry the same `iss`. Tenant separation of issued tokens rests on `aud` (the participant's DID)
  and on the stored `participant_context_id` (checked by `/tokens/verify`). Consumers that verify
  locally via JWKS must check `aud`. Per-tenant signing keys would be a larger design change.
- **Body-supplied flow identities.** `participantId` and `counterPartyId` in `start`/`prepare` come
  from the control plane's request body and are not tied to the caller's `sub`. Siglet trusts the
  control plane for them. Signaling tokens must therefore only be issued to control planes.
- **Management API is platform-admin.** `siglet-mgmt-api:write` holders can re-point any context's
  signing key or transfer-type mappings. Grant it only to operators.
- **Shared Vault token.** With Kubernetes service-account auth, one Vault token serves every tenant,
  so Siglet's own checks are the only isolation for KV secrets. Prefer Vault `TokenExchange` auth,
  where each participant context gets a policy-scoped Vault token.
- **Refresh-endpoint allowlist.** The default policy only enforces HTTPS. It does not block internal
  HTTPS hosts. Set `allowed_hosts` in production.
- **Refresh API is unauthenticated by design.** It is protected by the refresh token and the proof
  JWT. Expose it only over TLS.

## Production hardening checklist

- [ ] `[signaling_auth]`, `[token_api_auth]` and `[management_api_auth]` are all `mode = "enabled"`.
- [ ] `token_api_auth.admin_scope` is **not** set.
- [ ] `audience` is unique per Siglet instance (not the default `"siglet"`).
- [ ] `issuer` is set on all three auth blocks when the IdP's JWKS is shared.
- [ ] The IdP guarantees that `sub` equals the participant context id and cannot be chosen by clients.
- [ ] Management API scopes are granted to platform operators only.
- [ ] `[token.refresh_endpoint_policy]` keeps `allow_http = false` and lists `allowed_hosts`.
- [ ] Vault uses `TokenExchange` auth, or its policy is reviewed for a shared token.
- [ ] `vault.use_http_resolution = false`.
- [ ] The refresh API (port 8082) is served over TLS.
- [ ] `dataplane-sdk*` is at a version that includes the tenant-scoped flow repository (0.1.3+).

## Verification

- `siglet/tests/tenant_isolation.rs` drives the production routers behind the enabled auth layer
  and asserts that tenant A cannot:
  - see, terminate, suspend, complete or re-address tenant B's flow;
  - revoke B's tokens by reusing a flow id;
  - traverse into B's tokens;
  - validate B's tokens through `/tokens/verify`.
- Unit tests cover each fix:
  - SDK repository isolation (memory and Postgres test suite);
  - SDK operation isolation and callback URL encoding;
  - path validation and Vault URL checks;
  - scoped revocation (memory and Postgres);
  - refresh-token expiry and the refresh-endpoint policy, redirects and `expires_in` clamping;
  - issuer enforcement and caller injection.
