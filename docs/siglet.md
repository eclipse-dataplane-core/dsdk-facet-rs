# Siglet Runtime

## Overview

Siglet is a **Security Token Service (STS)** for data plane infrastructure
in [Eclipse Dataspace](https://eclipse-dataspace.org) ecosystems. It has two complementary roles depending on which side
of a data transfer it serves:

- **Provider side**: Issues short-lived, signed JWT access tokens to data consumers so they can access a data endpoint.
  Applications and data infrastructure verify these tokens to authorize requests.
- **Consumer side**: Acts as a token cache and handles automated token renewal from the upstream provider's Siglet,
  including distributed locking to prevent concurrent refresh storms.

Siglet integrates with the control plane via
the [Data Plane Signaling (DPS) protocol](https://github.com/eclipse-dataplane-signaling/dataplane-signaling), which
drives the token lifecycle through flow events (`on_start`, `on_prepare`, `on_started`, `on_terminate`).

Siglet exposes four HTTP servers:

| Server         | Default Port | Purpose                                                          |
|----------------|--------------|------------------------------------------------------------------|
| Siglet API     | 8080         | Token retrieval, verification, JWKS endpoint                     |
| Signaling API  | 8081         | DPS protocol endpoint (control plane integration)                |
| Refresh API    | 8082         | OAuth2-compatible token refresh endpoint                         |
| Management API | 8083         | Runtime configuration: transfer-type & signing-key mappings CRUD |

---

## Architecture

```
                        ┌─────────────────────────────────────┐
                        │             Siglet Runtime           │
                        │                                      │
 Control Plane ─── DPS ──▶  Signaling API (:8081)             │
                        │         │                            │
                        │    Flow lifecycle events             │
                        │         │                            │
                        │   ┌─────▼──────────┐                │
                        │   │ Token Manager  │  ← Vault (sign) │
                        │   │ (JWT issuance) │                 │
                        │   └─────┬──────────┘                │
                        │         │                            │
 Application  ◀── JWT ──   Siglet API (:8080)                 │
                        │   /tokens/{ctx}/{id}  GET            │
                        │   /tokens/{ctx}/{id}  DELETE         │
                        │   /tokens/verify      POST           │
                        │   /keys               GET            │
                        │                                      │
 Provider Siglet ◀──────   Refresh API (:8082)                │
                        │   /token      POST           │
                        │                                      │
 Operator      ────────▶   Management API (:8083)              │
                        │   /transfer-type-mappings  CRUD      │
                        │   /key-mappings            CRUD      │
                        └─────────────────────────────────────┘
                                      │
                              PostgreSQL + Vault
```

---

## Token Shape

Siglet issues JWTs signed with an Ed25519 or RSA key managed in Vault (via the transit secrets engine). The token is a
standard JWT with the following claims:

### Standard Claims

| Claim | Description                                                                   |
|-------|-------------------------------------------------------------------------------|
| `iss` | Issuer. Defaults to `"siglet"`, configurable via `token.issuer`.              |
| `sub` | Subject. The counter-party DID (the consumer's identity).                     |
| `aud` | Audience. The participant's DID — used to scope token acceptance.             |
| `iat` | Issued-at timestamp (Unix seconds). Set by the token generator.               |
| `exp` | Expiration timestamp (Unix seconds). Default: `iat + 3600` (1 hour).          |
| `nbf` | Not-before timestamp. Optional.                                               |
| `jti` | JWT ID. A UUID. Required for revocation checks via the verification endpoint. |

### Custom Claims (Data Flow Context)

When a token is issued for a provider-initiated flow, additional claims are flattened into the JWT:

| Claim            | Description                              |
|------------------|------------------------------------------|
| `agreementId`    | The contract agreement ID from the flow. |
| `participantId`  | The participant context ID.              |
| `counterPartyId` | The counter-party's ID.                  |
| `datasetId`      | The dataset being transferred.           |

Custom claims **cannot** override reserved claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`).

### Mapped Claims

On top of the above, a transfer type may declare **claim mappings** that compute claims from the data flow — see
[Claim Mapping](#claim-mapping). Claims are assembled in two layers, the second able to override the first:

1. the four flow-level claims in the table above (provider-initiated flows only)
2. the configured claim mappings

Because mappings are applied last, an operator can deliberately reshape or replace a built-in claim. Reserved claim
names remain off limits and are rejected when the configuration is written, not at flow time.

`DataFlow.metadata` is **not** copied into the token. Metadata is control-plane-to-data-plane state and may carry
information that has no business reaching the counter-party, so a metadata entry is exposed only when an operator
asks for it by name:

```toml
[[transfer_types.claim_mappings]]
from = "flow.metadata.region"
to = "region"
```

Metadata still drives endpoint resolution (`endpoint_mappings`), which stays internal to the data plane.

> **Migrating.** Metadata used to be copied into every token verbatim. If a deployment relied on that, add one
> `claimMappings` entry per key you actually need — there is no wildcard, and mapping `flow.metadata` as a whole
> would nest the entire map under a single claim rather than flatten it. One value can also differ: the old copy
> preserved a double-JSON-encoded string as `"\"x\""`, whereas `flow.metadata.k` unwraps it to `x`.

Claim values keep their JSON type end to end: a mapping that yields a list or an object lands in the JWT as a real
JSON array or object, not as a string.

### Example Decoded Payload

```json
{
  "iss": "siglet",
  "sub": "did:web:consumer.example.com",
  "aud": "did:web:provider.example.com",
  "iat": 1713436800,
  "exp": 1713440400,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "agreementId": "contract-abc-123",
  "participantId": "participant-uuid",
  "counterPartyId": "did:web:consumer.example.com",
  "datasetId": "dataset-xyz",
  "holderIdentifier": "BPNL0001"
}
```

(`holderIdentifier` here is a mapped claim, extracted from a verifiable credential on the flow.)

The token is signed and the `kid` header identifies the Vault key version used, enabling key rotation without
invalidating in-flight tokens.

---

## Token Verification

Siglet supports two complementary verification approaches.

### Local Verification via JWKS (Preferred)

Applications should verify tokens locally using the public keys from the JWKS endpoint. This avoids network calls on the
hot path and scales without adding load to Siglet.

```
GET http://siglet:8080/keys
```

Response (JSON Web Key Set):

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "signing-siglet-1",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

The `/keys` endpoint is **public** — it publishes only public keys and is the discovery mechanism consumers use to
verify Siglet-issued tokens, so it requires no authentication even when token-API auth is enabled.

Use a standard JWT library to verify the signature, expiration, `aud`, and `iss` claims. Cache the JWKS response and
refresh it on key rotation (when verification fails with the cached key).

**Limitation**: A token that has been explicitly revoked (e.g., flow terminated early) may still pass local verification
until it expires. If revocation must be detected immediately, use the verification endpoint below.

### Server-Side Verification Endpoint (Revocation-Aware)

```
POST http://siglet:8080/tokens/verify
Authorization: Bearer <siglet-token-api JWT>
Content-Type: application/json

{
  "token": "eyJhbGc...",
  "audience": "did:web:your-component.example.com"
}
```

When token-API auth is enabled, this endpoint requires a caller JWT granting the `siglet-token-api` scope (see
[Token API Authentication](#token-api-authentication)); it is distinct from the `token` being verified in the body.

Siglet checks the JWT signature **and** looks up the token's `jti` in the renewable token store. If the token has been
revoked (flow terminated), this returns `401` even if the JWT is cryptographically valid.

**Response (200 OK)** — all token claims as JSON:

```json
{
  "iss": "siglet",
  "sub": "did:web:consumer.example.com",
  "aud": "did:web:provider.example.com",
  "iat": 1713436800,
  "exp": 1713440400,
  "jti": "a1b2c3d4-...",
  "agreementId": "contract-abc-123"
}
```

**Error responses**: `401 Unauthorized` for invalid, expired, or revoked tokens. `500` for internal errors.

> Prefer local verification to avoid putting excessive load on the Siglet runtime. Use the verification endpoint only
> when revocation must be detected before a token expires naturally.

---

## Signaling API Authentication

The Signaling API (port 8081) authenticates incoming DPS requests with a JWT supplied
in the `Authorization` header. The JWT is verified against a JWKS published by the
trusted control-plane identity provider (IdP).

The verifier is interoperable with providers that expose keys via JWKS sets.

### Expected JWT Shape

```json
// Header
{
  "alg": "EdDSA",
  // accepted: EdDSA, RS256, ES256
  "typ": "JWT",
  // tolerated, not enforced
  "kid": "<key id present in the JWKS>"
  // required
}

// Payload
{
  "sub": "<participant_context_id>",
  // MUST equal the URL path parameter
  "scope": "dplane-signaling",
  // required — space-delimited; MUST contain "dplane-signaling"
  "exp": 1713440400,
  // required — Unix seconds
  "iat": 1713436800,
  // optional
  "nbf": 1713436800
  // optional — enforced when present
}
```

Required:

- `alg` must be one of `EdDSA`, `RS256`, or `ES256` (allowlist is fixed in code
  to prevent algorithm-confusion attacks).
- If the matched JWK advertises an `alg`, it must agree with the JWT header's
  `alg` — a mismatch is rejected before the signature is even checked.
- `kid` must resolve to a key in the JWKS; without it the request is rejected.
- `sub` must be byte-equal to the `{participant_context_id}` path segment on the
  requested URL. A mismatch returns `403 Forbidden` (the caller authenticated, but
  is not authorized for the targeted context).
- `scope` must grant `dplane-signaling`. The claim follows the OAuth2 convention
  (RFC 6749 §3.3) of a single space-delimited string, so a token may carry other
  scopes alongside it (e.g. `"read:data dplane-signaling"`). A missing `scope`, or
  one that doesn't include `dplane-signaling` as a whole entry, returns `403 Forbidden`.
- `aud` must contain the value configured in `signaling_auth.audience`
  (default `"siglet"`). String- and array-valued `aud` claims are both accepted.
  A missing or non-matching `aud` returns `401`.
- `exp` must be in the future (with a small leeway for clock skew); `nbf`, when
  present, must be in the past.

`iss` and other claims are tolerated and ignored at this layer. Add downstream
validation if your deployment requires `iss` pinning.

### Expected JWKS Shape

The JWKS is fetched verbatim from the configured `jwks_url`. Each key must conform
to RFC 7517; for Ed25519 that looks like:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "signing_pc-1",
      "crv": "Ed25519",
      "x": "<base64url-encoded 32-byte public key>"
    }
  ]
}
```

RSA and EC keys (RS256/ES256 algorithms) are also supported via standard JWK
parameters (`n`/`e` for RSA; `crv`/`x`/`y` for EC).

### Rejection Responses

| Condition                                          | Status |
|----------------------------------------------------|--------|
| Missing or malformed `Authorization: Bearer <jwt>` | 401    |
| Token signature invalid / expired / unknown `kid`  | 401    |
| `sub` claim does not match the URL path id         | 403    |
| `scope` claim missing or lacks `dplane-signaling`  | 403    |
| JWKS endpoint unreachable                          | 503    |

### Configuration

Auth is **on by default**. Operators must either supply a JWKS URL or explicitly opt
out — there is no silent default. The config is a tagged union, so the JWKS URL is
inexpressible when auth is off:

```toml
# Production
[signaling_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "https://siglet.example.com"   # optional, defaults to "siglet"
cache_ttl_seconds = 300                    # optional, defaults to 300
required_scope = "dplane-signaling"        # optional, defaults to "dplane-signaling"
```

`audience` is the value the verifier requires in the JWT's `aud` claim. Pick an
identifier that's unique to this siglet instance (e.g. its public URL or DID).
The upstream IdP / token-exchange service must mint tokens with `aud` set to
the same string — that binding is what prevents a JWT minted for some *other*
recipient (off the same JWKS) from being replayed against this siglet. The
default `"siglet"` is suitable for single-instance dev deployments only.

`required_scope` is the scope the JWT's `scope` claim must grant (matched as a
whole entry within the OAuth2 space-delimited string). It defaults to
`"dplane-signaling"`, so it doesn't need to be set explicitly; override it only if
your IdP issues signaling access under a different scope name. An empty value is
rejected at startup — it could never be satisfied and would lock out every caller.

```toml
# Development — skip JWT verification entirely.
# The middleware still extracts participant_context_id from the URL, but does not
# require an Authorization header. Logs a loud warning at startup.
[signaling_auth]
mode = "disabled"
```

Environment-variable overrides follow the standard `SIGLET__` convention:

```bash
SIGLET__SIGNALING_AUTH__MODE=enabled
SIGLET__SIGNALING_AUTH__JWKS_URL=https://idp.example.com/.well-known/jwks.json
SIGLET__SIGNALING_AUTH__AUDIENCE=https://siglet.example.com
SIGLET__SIGNALING_AUTH__REQUIRED_SCOPE=dplane-signaling
```

The JWKS is fetched lazily and cached in-process for `cache_ttl_seconds`. A request
arriving after the TTL pays the round-trip cost of refreshing the cache.

---

## Token API Authentication

The token-management API (port 8080) has its own auth configuration block,
`[token_api_auth]`, separate from `[signaling_auth]`. It can therefore be pointed at a
different IdP, audience or scope than the DPS signaling protocol, and enabled or disabled
on its own. The verification mechanics are otherwise identical to the signaling API; what
differs is the default scope and which routes are protected.

### Protected vs. public routes

| Route                                     | Auth required | Notes                                              |
|-------------------------------------------|---------------|----------------------------------------------------|
| `GET`/`DELETE /tokens/{participant_context_id}/{id}` | yes | `sub` must equal the `{participant_context_id}` path segment, unless the caller holds the [admin scope](#admin-scope) |
| `POST /tokens/verify`                     | yes           | No participant context, so `sub` is not bound      |
| `GET /keys` (JWKS)                        | no            | Public discovery endpoint                          |
| `GET /` , `GET /health`                   | no            | Liveness/readiness                                 |

### Required scope

Protected routes require a JWT whose space-delimited `scope` claim contains
`token_api_auth.required_scope` — `siglet-token-api` by default, rather than the signaling
API's `dplane-signaling`. The matching and rejection semantics are identical to the
signaling API: a missing or non-matching scope returns `403`, a missing/invalid/expired
token or wrong `aud` returns `401`, and a `sub` that doesn't match the path participant
context returns `403`. Unlike the signaling API — whose only pathless routes are
intentionally open — every protected token-API route requires a valid token, including
`POST /tokens/verify`.

### Admin scope

`token_api_auth.admin_scope` names an optional second scope that **waives subject binding**:
a caller holding it may read and delete tokens for any participant context, not just its
own. It exists for demos and debugging, where one client needs to pull tokens on behalf of
several participants.

The grant is *additive* — it relaxes the `sub` check only, and does not stand in for
`required_scope`:

| `scope` claim                               | Result                                    |
|---------------------------------------------|-------------------------------------------|
| `siglet-token-api siglet-token-api:admin`   | `200` — any participant context reachable |
| `siglet-token-api`                          | `200` — `sub` must match the path segment |
| `siglet-token-api:admin`                    | `403` — missing the required scope        |

Everything else is unchanged: signature, `aud`, `exp`/`nbf` and the required-scope check all
still apply, and `POST /tokens/verify` (which never bound `sub`) behaves as before.

The feature is **off unless configured** — with the key absent, `siglet-token-api:admin` is
just an unrecognised scope string and `sub` stays bound. When it *is* configured, siglet
logs a warning at startup naming the scope, and a further warning on every request that
uses the bypass, carrying the token's `sub` and the participant context it reached.

Two values are rejected at startup: a blank scope (omit the key instead to disable the
bypass) and a value equal to `required_scope` (which would silently turn every valid token
into an admin token).

> **Do not enable this in production.** Tokens are credentials for the underlying data
> transfers; a caller with the admin scope can retrieve every participant's.

### Configuration

Like the signaling API, auth is **on by default**: operators must either supply a
`jwks_url` or explicitly opt out with `mode = "disabled"`. A siglet that omits
`[token_api_auth]` entirely fails to start.

```toml
# Production
[token_api_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "https://siglet.example.com"   # optional, defaults to "siglet"
cache_ttl_seconds = 300                    # optional, defaults to 300
required_scope = "siglet-token-api"        # optional, defaults to "siglet-token-api"

# Demo/debug only — waives the sub == participant_context_id check for callers holding this
# scope. Absent by default; must differ from required_scope. Logs a warning at startup.
# admin_scope = "siglet-token-api:admin"

# Development — skip JWT verification on the token API. Logs a loud warning at startup.
# [token_api_auth]
# mode = "disabled"
```

Pointing this block at the same `jwks_url` and `audience` as `[signaling_auth]` reproduces
the behaviour of siglet versions that had no separate token-API auth config.

Environment-variable overrides follow the standard `SIGLET__` convention, e.g.
`SIGLET__TOKEN_API_AUTH__MODE=disabled`.

---

## Management API Authentication

The Management API (port 8083) — which hosts the transfer-type and signing-key mapping CRUD — has its own
auth configuration block, `[management_api_auth]`, separate from `[signaling_auth]`. This lets the admin
endpoints be secured against a different IdP or audience than the DPS signaling protocol.

Like the signaling API, auth is **on by default**: operators must either supply a `jwks_url` or explicitly
opt out with `mode = "disabled"`. It is an admin API that spans many participant contexts, so — unlike the
token API — the JWT `sub` is **not** bound to the path; any valid token with the right scope may manage any
participant context.

Scopes are fixed per HTTP method (not configurable): reads (`GET`) require `siglet-mgmt-api:read` and writes
(`POST`/`PUT`/`DELETE`) require `siglet-mgmt-api:write`. A missing or non-matching scope returns `403`; a
missing/invalid/expired token or wrong `aud` returns `401`.

```toml
# Production
[management_api_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "siglet"          # optional, defaults to "siglet"
cache_ttl_seconds = 300       # optional, defaults to 300

# Development — skip JWT verification on the management API.
# [management_api_auth]
# mode = "disabled"
```

Environment-variable overrides follow the standard `SIGLET__` convention, e.g.
`SIGLET__MANAGEMENT_API_AUTH__MODE=enabled`.

---

## Consumer-Side Token Caching

On the consumer side, applications should retrieve tokens through Siglet's token cache API rather than calling the
provider's Siglet directly on every request. Siglet handles expiry detection, renewal, and distributed locking
automatically.

### Token Retrieval

```
GET http://siglet:8080/tokens/{participant_context_id}/{flow_id}
```

Returns:

```json
{
  "token": "eyJhbGc..."
}
```

Siglet inspects the cached token's expiry. If it is within 5 seconds of expiring, Siglet:

1. Acquires a cluster-wide lock on the `flow_id` (via the lock manager).
2. Re-checks the token after acquiring the lock — if another instance already refreshed it, the fresh token is returned
   without a second refresh call.
3. If still expired, calls the provider's refresh endpoint using OAuth2 refresh token grant.
4. Stores the new token and returns it.

**Applications should reuse the cached token** across requests rather than calling this endpoint on every request. Only
fetch a new token when the current one is rejected (HTTP 401) by the data endpoint.

### Token Deletion

```
DELETE http://siglet:8080/tokens/{participant_context_id}/{flow_id}
```

Returns `204 No Content`. Removes the cached token from the store.

### Refresh Flow Detail

When Siglet refreshes a token, it sends a signed proof JWT as the bearer credential:

```
POST {refresh_endpoint}
Authorization: Bearer <proof-jwt>
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>
```

The proof JWT contains:

- `iss` / `sub`: The consumer's DID
- `aud`: The token's `identifier` (flow ID)
- `exp`: Short-lived (default 5 minutes)
- `token` claim: The current access token (for provider-side validation)

The provider Siglet's refresh endpoint validates the proof JWT, verifies the refresh token, issues a new access/refresh
token pair, and returns:

```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "<new-refresh-token>",
  "expires_in": 3600
}
```

---

## Data Plane Signaling Integration

Siglet implements the DPS `DataFlowHandler` trait to participate in flow lifecycle events sent by the control plane.

| Event          | Provider Behaviour                                                              | Consumer Behaviour                                                        |
|----------------|---------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `on_start`     | Generates JWT + refresh token pair; returns `DataAddress` with token properties | —                                                                         |
| `on_prepare`   | —                                                                               | Generates token pair for client-initiated transfers                       |
| `on_started`   | —                                                                               | Receives `DataAddress` from provider; caches access token + refresh token |
| `on_terminate` | Revokes token (removes from renewable store)                                    | Removes cached token                                                      |
| `on_suspend`   | Revokes token                                                                   | Removes cached token                                                      |

The `DataAddress` returned on `on_start` / `on_prepare` contains the following properties:

| Property          | Description                                         |
|-------------------|-----------------------------------------------------|
| `authorization`   | The JWT access token                                |
| `authType`        | Always `"bearer"`                                   |
| `refreshToken`    | The opaque refresh token                            |
| `expiresIn`       | Seconds until the access token expires              |
| `refreshEndpoint` | URL of Siglet's refresh API (`:8082/token`) |

### Transfer Type Resolution

Each DPS flow carries a `transferType` (the flow `profile`) that Siglet maps to a data endpoint and a token source
(whether the **provider** or the **client** generates the token). Siglet resolves this mapping from two sources, in
priority order:

1. **Dynamic, per-participant-context mappings** stored in the database and configured at runtime through the
   [Management API](#transfer-type-management-api). These are keyed by `participantContextId`, so each participant
   context can point the same transfer type at a different backend and auth configuration.
2. **Static, global mappings** from the `[[transfer_types]]` blocks in the configuration file (see
   [Transfer Types](#complete-configuration-reference) below). These apply to every participant context.

On each flow event Siglet looks up the flow's `participantContextId` in the store:

- If that participant context has **any** stored mappings, they are **authoritative** — Siglet resolves the flow's
  transfer type from that set only. If the set does not contain the flow's transfer type, the flow is rejected as
  unsupported; the static configuration is **not** consulted (all-or-nothing per participant context).
- If that participant context has **no** stored mappings, Siglet falls back to the static `[[transfer_types]]`
  configuration.

This lets a single-participant or dev deployment rely entirely on the config file, while a multi-participant deployment
overrides individual participant contexts at runtime without a restart.

#### Transfer Type Management API

The Management API (port 8083) exposes CRUD over per-participant-context transfer-type mappings. A mapping associates a
`participantContextId` with the **complete** map of transfer types for that context — configuring a context replaces its
whole map (there is no per-entry patch).

| Method   | Route                                        | Purpose                                                  |
|----------|----------------------------------------------|----------------------------------------------------------|
| `POST`   | `/transfer-type-mappings`                    | Create the mapping for a participant context → `201`     |
| `GET`    | `/transfer-type-mappings/{participant_context_id}` | Fetch the mapping for a participant context        |
| `PUT`    | `/transfer-type-mappings/{participant_context_id}` | Replace the whole map for a participant context → `204` |
| `DELETE` | `/transfer-type-mappings/{participant_context_id}` | Delete the mapping (reverts to static config) → `204` |

Reads require the `siglet-mgmt-api:read` scope and writes the `siglet-mgmt-api:write` scope; see
[Management API Authentication](#management-api-authentication). `POST` on an existing participant context returns
`409 Conflict`; `GET`/`PUT`/`DELETE` on an unknown one return `404 Not Found`. `POST` and `PUT` bodies whose
`claimMappings` are invalid — an unparseable expression, an empty or duplicate `to`, or a reserved claim name — return
`400 Bad Request` with the offending entries named in the response body.

The JSON payload is camelCase throughout — both the wrapper (`participantContextId`, `mappings`) and each `TransferType`
value (`transferType`, `endpointType`, `tokenSource`, `endpointMappings`, `claimMappings`, `txRenewalSupport`). For convenience the
snake_case field names used in the config file are also accepted on input (via serde aliases), but responses are always
serialized in camelCase:

```json
POST http://siglet:8083/transfer-type-mappings
Authorization: Bearer <siglet-mgmt-api:write JWT>
Content-Type: application/json

{
  "participantContextId": "participant-uuid",
  "mappings": {
    "HttpData-PULL": {
      "transferType": "HttpData-PULL",
      "endpointType": "HTTP",
      "tokenSource": "provider",
      "endpoint": "https://data.provider.example.com/assets"
    },
    "HttpData-PUSH": {
      "transferType": "HttpData-PUSH",
      "endpointType": "HTTP",
      "tokenSource": "client",
      "endpoint": "https://data.consumer.example.com/inbox",
      "claimMappings": [
        { "from": "flow.metadata.region", "to": "region" },
        { "from": "flow.metadata.tier", "to": "tier", "optional": true }
      ]
    }
  }
}
```

Each entry accepts the same fields as a static `[[transfer_types]]` block, including `endpointMappings` for
metadata-driven endpoint resolution and `claimMappings` for computed JWT claims.

---

## Claim Mapping

A transfer type can compute JWT claims from the data flow. Each mapping binds the result of an expression to a claim
key:

| Field      | Description                                                                                      |
|------------|--------------------------------------------------------------------------------------------------|
| `from`     | A [CEL](https://github.com/google/cel-spec) expression, evaluated against the `flow` root variable. |
| `to`       | The JWT claim key to bind the result to. Cannot be a reserved claim.                              |
| `optional` | When `true`, the mapping is skipped if the expression fails or yields null. Defaults to `false`.   |

Mappings apply after the built-in claims, so they can override them, and they are the only way a `flow.metadata` entry
reaches a token — see [Mapped Claims](#mapped-claims).

### Where mappings live

Mappings may be declared at the root of a transfer type and on an individual endpoint mapping. Root mappings are the
base and apply to every flow using the transfer type. When an endpoint mapping matches, its own mappings are layered on
top and **win on a shared `to` key**; a key it does not mention keeps the root's value. A transfer type with a static
endpoint (no `endpointMappings`) only ever uses its root mappings.

### Failure handling

A mapping whose expression fails to compile or evaluate **fails the whole flow**, so a typo surfaces immediately rather
than silently issuing a token with claims missing. Mark a mapping `optional = true` when absence is legitimate — an
optional credential, say — and it will be skipped instead.

A mapping that evaluates cleanly to `null` is *not* a failure: a required mapping binds JSON `null`, while an optional
one is skipped.

### The `flow` variable

Expressions see a single root variable, `flow`, whose field names match the camelCase wire form of the signaling model:

| Path                                                     | Type   | Notes                                            |
|----------------------------------------------------------|--------|--------------------------------------------------|
| `flow.id`, `flow.profile`                                 | string | Flow ID and transfer type                        |
| `flow.agreementId`, `flow.datasetId`                      | string |                                                  |
| `flow.participantId`, `flow.counterPartyId`               | string |                                                  |
| `flow.participantContextId`, `flow.controlPlaneId`        | string |                                                  |
| `flow.dataspaceContext`                                   | string |                                                  |
| `flow.state`                                              | string | `INITIATING`, `STARTED`, … (SCREAMING_SNAKE_CASE) |
| `flow.kind`                                               | string | `PROVIDER` or `CONSUMER`                          |
| `flow.suspensionReason`, `flow.terminationReason`         | string \| null | Explicit `null` when unset               |
| `flow.labels`                                             | list   | Empty list, never null                            |
| `flow.metadata`, `flow.claims`                            | map    | Always present, possibly empty                    |
| `flow.dataAddress`                                        | map \| null | Normally `null` during `on_start`/`on_prepare` |
| `flow.createdAt`, `flow.updatedAt`                        | string | RFC3339; wrap in `timestamp(...)` for arithmetic  |

Two behaviours worth knowing:

- **JSON-encoded strings are unwrapped.** Control planes differ in whether they send structured metadata as real JSON
  or as a string containing JSON. Values in `flow.metadata` and `flow.claims` that parse as JSON are exposed to
  expressions as the parsed structure, so one expression works against both. Only the top level is unwrapped.
- **`flow.dataAddress["@type"]`** needs index syntax, since `@type` is not an identifier.

### Cookbook

```python
# expose a metadata entry as a claim (metadata is never copied in on its own)
flow.metadata.region

# metadata keys that are not identifiers need index syntax
flow.metadata["https://w3id.org/edc/v0.0.1/ns/region"]

# derive a value
"urn:asset:" + flow.datasetId

# default when a key may be absent
has(flow.metadata.tier) ? flow.metadata.tier : "basic"

# has() only accepts field selection; for a namespaced key use membership instead
"https://w3id.org/edc/v0.0.1/ns/tier" in flow.metadata

# sizes, membership, regex
size(flow.labels)
"gold" in flow.labels
flow.participantId.matches("^did:web:.*")
```

### Credential helpers

Verifiable credentials are awkward to navigate in raw CEL because the W3C VC data model makes several fields
**array-or-scalar**: `type` and `@context` may be a string or a list, and `credentialSubject` may be a single object or
an array of subjects. To hide that, siglet registers a set of credential-aware functions whose names and semantics match
the [Eclipse EDC `decentralized-claims-cel`
extension](https://eclipse-edc.github.io/documentation/for-adopters/control-plane/policy-engine/cel/), so expressions are
portable between the EDC control plane and siglet.

| Function | Target | Returns | Description |
|---|---|---|---|
| `withType(t)` | credential list | list | the credentials whose `type` set contains `t` |
| `hasType(t)` | single credential | bool | whether the credential has type `t` (for use inside `exists(c, c.hasType(...))`) |
| `hasCredential(t)` | credential list | bool | whether any credential in the list has type `t` |
| `hasClaim(name)` / `hasClaim(name, value)` | credential list | bool | whether any subject has claim `name` (equal to `value`, when given) |
| `claim(name)` | credential list | dynamic | the first non-null value of subject claim `name`, else `null`; `name` may be a dotted path (`degree.type`) |
| `claims(name)` | credential list | list | all non-null values of subject claim `name` across every credential and subject |

They normalize `type` (scalar or list), `@type` (JSON-LD), and `credentialSubject` (object or array) internally, and are
**lenient**: a target that is not credential-shaped yields an empty list / `null` / `false` rather than an error. Given a
list of verifiable credentials on the flow — whether sent as real JSON or as a JSON-encoded string, and whether
`credentialSubject` is an object or an array:

```json
[ { "type": ["VerifiableCredential", "MembershipCredential"],
    "credentialSubject": [ { "holderIdentifier": "BPNL0001", "status": "active" } ] },
  { "type": ["VerifiableCredential", "DismantlerCredential"],
    "credentialSubject": [ { "allowedBrands": ["BMW", "Audi"] } ] } ]
```

```python
# pluck one property out of the matching credential
flow.claims.vc.withType("MembershipCredential").claim("holderIdentifier")
# -> "BPNL0001"

# a list of every matching value
flow.claims.vc.withType("MembershipCredential").claims("holderIdentifier")
# -> ["BPNL0001"]

# a boolean gate
flow.claims.vc.hasClaim("status", "active")
# -> true

# compose with the standard macros for the single-credential form
flow.claims.vc.exists(c, c.hasType("DismantlerCredential"))
# -> true
```

Because the helpers never index by position, they do not hit the empty-filter and array-shape pitfalls described below;
`claim(...)` simply returns `null` when nothing matches (mark the mapping `optional` if a null claim should be dropped).

#### Without the helpers (equivalent raw CEL)

The same results in plain CEL are more verbose and must account for the array shapes by hand — both `type` and
`credentialSubject` are arrays, so accessing them requires membership (`in`) and indexing (`[...]`) rather than plain
field access:

```python
# equivalent to withType(...).claim(...)
flow.claims.vc.filter(c, "MembershipCredential" in c.type)[0].credentialSubject[0].holderIdentifier
# -> "BPNL0001"

# filter and project in one pass; yields a list
flow.claims.vc.map(c, "MembershipCredential" in c.type, c.credentialSubject[0].holderIdentifier)
# -> ["BPNL0001"]

# guard so a missing credential does not fail the flow
flow.claims.vc.exists(c, "DismantlerCredential" in c.type)
  ? flow.claims.vc.filter(c, "DismantlerCredential" in c.type)[0].credentialSubject[0].allowedBrands
  : null
```

Indexing an empty filter result (`[0]` when nothing matched) is an evaluation error, so either guard it with
`exists(...)`/`size(...)` as above or mark the mapping `optional`.

If evaluation fails with `Unexpected type: got 'string', want 'int|uint'`, a `.field` access landed on an **array**
instead of an object — CEL reads `someArray.field` as "index the array by the string `field`". Index the element you
want first (`credentialSubject[0].holderIdentifier`), `map`/`filter` over the array, or use the credential helpers above.
This is the most common mistake when treating an array-valued `credentialSubject` as if it were a single object.

Available macros are `has`, `all`, `exists`, `exists_one`, `map` (two- and three-argument forms) and `filter`. CEL is
non-Turing-complete and always terminates, so an expression cannot hang the signaling path.

---

## Configuration

Configuration is loaded from a file (TOML, YAML, or JSON) specified via the first CLI argument or the
`SIGLET_CONFIG_FILE` environment variable. Environment variables with the prefix `SIGLET__` override file values (double
underscore as separator for nesting).

### Complete Configuration Reference

```toml
# Network binding
bind = "0.0.0.0"              # Default: 0.0.0.0
siglet_api_port = 8080       # Default: 8080 — token API + JWKS + verify
signaling_port = 8081        # Default: 8081 — DPS signaling
refresh_api_port = 8082      # Default: 8082 — OAuth2 token refresh
management_api_port = 8083   # Default: 8083 — transfer-type & signing-key mapping CRUD

# Storage backend: "memory" (default, single-node dev) or "postgres-vault" (production)
[storage_backend]
type = "postgres-vault"
url = "postgresql://siglet:password@postgres:5432/siglet"

# HashiCorp Vault
[vault]
url = "https://vault.vault.svc.cluster.local:8200"
# Authenticate with a static token (dev only):
token = "hvs.xxxxxxxxxxxx"
# Or read token from a file (Kubernetes ServiceAccount — recommended):
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
# Transit key name used to sign access tokens. Default: "signing-siglet"
signing_key_name = "signing-siglet"
# Allow HTTP for DID Web resolution. Default: false. Never enable in production.
use_http_resolution = false

# Signaling API JWT authentication
# REQUIRED: either set mode = "enabled" with a jwks_url, or mode = "disabled".
# There is no silent default — see the "Signaling API Authentication" section above.
[signaling_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "https://siglet.example.com"  # Default: "siglet". Must agree with the IdP's stamped aud claim.
cache_ttl_seconds = 300

# Token API JWT authentication (token retrieval/deletion and /tokens/verify, port 8080).
# Separate from [signaling_auth]. Same on-by-default rule: set mode = "enabled" with a jwks_url,
# or mode = "disabled". Point it at the same jwks_url/audience as [signaling_auth] to reproduce
# the pre-split behaviour.
[token_api_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "siglet"                     # Default: "siglet"
cache_ttl_seconds = 300                 # Default: 300
required_scope = "siglet-token-api"     # Default: "siglet-token-api"
# Waives sub == participant_context_id for holders of this scope. Absent by default; must
# differ from required_scope. Demo/debug only — holders can read ANY participant's tokens.
# admin_scope = "siglet-token-api:admin"

# Management API JWT authentication (transfer-type & signing-key mapping CRUD, port 8083).
# Separate from [signaling_auth]. Same on-by-default rule: set mode = "enabled" with a jwks_url,
# or mode = "disabled". Scopes are fixed (siglet-mgmt-api:read / :write) — not configurable here.
[management_api_auth]
mode = "enabled"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "siglet"          # Default: "siglet"
cache_ttl_seconds = 300

# Shared outbound HTTP client (JWKS fetch, OAuth2 token refresh, etc.). Optional —
# omit to use the built-in defaults shown below. Both values must be > 0.
[http_client]
connect_timeout_seconds = 10   # Default: 10. TCP connect-phase timeout.
request_timeout_seconds = 30   # Default: 30. Total per-request timeout (connect + send + read).

# Token settings
[token]
issuer = "siglet"          # JWT `iss` claim. Default: "siglet"
# Override the refresh endpoint advertised to consumers.
# Default: http://{bind}:{refresh_api_port}/token
refresh_endpoint = "https://siglet.example.com/token"
# Hex-encoded secret used to derive symmetric keys (HMAC, etc.).
# Must be at least 16 bytes (32 hex chars). Generate with: openssl rand -hex 32
server_secret = "0102030405060708090a0b0c0d0e0f10..."

# Transfer types — one block per supported transfer type.
# These are the STATIC, GLOBAL mappings applied to every participant context. They act as the
# fallback for any participant context that has no dynamic mappings configured via the Management
# API (see the "Transfer Type Resolution" section). A participant context with dynamic mappings
# ignores these blocks entirely.
[[transfer_types]]
transfer_type = "HttpData-PULL"
endpoint_type = "HTTP"
token_source = "provider"           # "provider" or "client"
# Static endpoint (use this OR endpoint_mappings, not both):
endpoint = "https://data.provider.example.com/assets"

[[transfer_types]]
transfer_type = "HttpData-PUSH"
endpoint_type = "HTTP"
token_source = "client"
endpoint = "https://data.consumer.example.com/inbox"

# Dynamic endpoint resolution based on flow metadata:
[[transfer_types]]
transfer_type = "HttpData-PULL"
endpoint_type = "HTTP"
token_source = "provider"

[[transfer_types.endpoint_mappings]]
key = "region"
value = "eu-west-1"
endpoint = "https://eu-west-1.data.example.com"

[[transfer_types.endpoint_mappings]]
key = "region"
value = "us-east-1"
endpoint = "https://us-east-1.data.example.com"

# Claim mappings — compute JWT claims from the flow (see the "Claim Mapping" section).
# `from` is a CEL expression evaluated against the `flow` root variable; `to` is the claim key.
# Set `optional = true` to skip a mapping whose expression fails or yields null instead of
# failing the flow.
[[transfer_types]]
transfer_type = "HttpData-PULL"
endpoint_type = "HTTP"
token_source = "provider"

# Root-level mappings apply to every flow using this transfer type.
[[transfer_types.claim_mappings]]
from = "flow.metadata.region"
to = "region"

[[transfer_types.claim_mappings]]
from = '"urn:asset:" + flow.datasetId'
to = "assetUrn"

[[transfer_types.claim_mappings]]
from = 'flow.claims.vc.withType("MembershipCredential").claim("holderIdentifier")'
to = "holderIdentifier"
optional = true

[[transfer_types.endpoint_mappings]]
key = "region"
value = "us-east-1"
endpoint = "https://us-east-1.data.example.com"

# Mappings on a matched endpoint are layered over the root ones and win on a shared `to`.
[[transfer_types.endpoint_mappings.claim_mappings]]
from = '"us-east-1"'
to = "region"
```

### Environment Variable Overrides

Any config field can be overridden at runtime via environment variables using `SIGLET__` prefix and `__` as the nesting
separator:

```bash
SIGLET__VAULT__URL=https://vault:8200
SIGLET__VAULT__TOKEN_FILE=/var/run/secrets/vault/token
SIGLET__TOKEN__ISSUER=my-siglet
SIGLET__STORAGE_BACKEND__TYPE=postgres-vault
SIGLET__STORAGE_BACKEND__URL=postgresql://...
```

---

## PostgreSQL Setup

When using `storage_backend.type = "postgres-vault"`, Siglet uses PostgreSQL for:

- The **renewable token store**: tracks issued token metadata and hashed refresh tokens, scoped by participant context.
- The **lock manager**: cluster-wide distributed locks for safe concurrent token refresh.

Database schema migrations are applied automatically on startup. The database user needs `CREATE TABLE`, `SELECT`,
`INSERT`, `UPDATE`, and `DELETE` privileges.

**Connection URL format:**

```
postgresql://{user}:{password}@{host}:{port}/{database}
```

Siglet uses a connection pool (via `sqlx`). The pool size is tuned automatically based on available resources.

---

## Vault Setup

### Transit Key

Siglet signs JWTs using a Vault [transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
key. The key must be created before starting Siglet.

```bash
# Enable the transit engine (if not already enabled)
vault secrets enable transit

# Create the signing key (Ed25519 recommended)
vault write -f transit/keys/signing-siglet type=ed25519
```

The key name must match `vault.signing_key_name` in the configuration (default: `signing-siglet`).

### KV Store (Consumer Token Cache)

For the consumer-side `VaultTokenStore`, Siglet also requires KV v2:

```bash
vault secrets enable -path=secret kv-v2
```

### Vault Policy

```hcl
# Allow signing via transit
path "transit/sign/signing-siglet" {
  capabilities = ["create", "update"]
}
path "transit/keys/signing-siglet" {
  capabilities = ["read"]
}

# Allow token caching in KV (consumer side)
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/*" {
  capabilities = ["list", "delete"]
}
```

### Authentication Methods

**Static token** (development only):

```toml
[vault]
token = "hvs.xxxxxxxxxxxx"
```

**Token file** (Kubernetes — recommended):

```toml
[vault]
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

---

## Kubernetes Deployment

### Service Account JWT Authentication

In Kubernetes, Siglet authenticates to Vault using a projected ServiceAccount token.
Vault's [Kubernetes auth method](https://developer.hashicorp.com/vault/docs/auth/kubernetes) validates the token against
the Kubernetes API server.

**Step 1 — Enable and configure Vault Kubernetes auth:**

```bash
vault auth enable kubernetes

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443"
```

**Step 2 — Create a Vault role bound to the Siglet ServiceAccount:**

```bash
vault write auth/kubernetes/role/siglet \
  bound_service_account_names=siglet \
  bound_service_account_namespaces=siglet \
  policies=siglet-policy \
  ttl=1h
```

**Step 3 — Kubernetes manifests:**

```yaml
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: siglet
  namespace: siglet
---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siglet
  namespace: siglet
spec:
  replicas: 2
  selector:
    matchLabels:
      app: siglet
  template:
    metadata:
      labels:
        app: siglet
    spec:
      serviceAccountName: siglet
      volumes:
        - name: config
          configMap:
            name: siglet-config
        - name: vault-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 7200
                  audience: vault
      containers:
        - name: siglet
          image: siglet:latest
          args: [ "/etc/siglet/config.toml" ]
          ports:
            - containerPort: 8080   # Siglet API
            - containerPort: 8081   # Signaling API
            - containerPort: 8082   # Refresh API
            - containerPort: 8083   # Management API
          volumeMounts:
            - name: config
              mountPath: /etc/siglet
            - name: vault-token
              mountPath: /var/run/secrets/vault
          env:
            - name: SIGLET__VAULT__URL
              value: "https://vault.vault.svc.cluster.local:8200"
            - name: SIGLET__VAULT__TOKEN_FILE
              value: "/var/run/secrets/vault/token"
            - name: SIGLET__STORAGE_BACKEND__URL
              valueFrom:
                secretKeyRef:
                  name: siglet-db-credentials
                  key: url
---
# Service
apiVersion: v1
kind: Service
metadata:
  name: siglet
  namespace: siglet
spec:
  selector:
    app: siglet
  ports:
    - name: api
      port: 8080
      targetPort: 8080
    - name: signaling
      port: 8081
      targetPort: 8081
    - name: refresh
      port: 8082
      targetPort: 8082
    - name: management
      port: 8083
      targetPort: 8083
```

### How Kubernetes JWT SA Auth Works

1. Kubernetes mounts a short-lived, audience-scoped ServiceAccount token into the pod at the projected volume path (
   `/var/run/secrets/vault/token`).
2. On startup, Siglet reads this token from disk (controlled by `vault.token_file`).
3. Siglet presents the token to Vault's Kubernetes auth endpoint (`auth/kubernetes/login`).
4. Vault calls the Kubernetes `TokenReview` API to validate that the token is genuine, unexpired, and bound to the
   configured ServiceAccount and namespace.
5. If valid, Vault issues a Vault token scoped to the `siglet-policy` with the configured TTL.
6. Siglet uses this Vault token for all subsequent Vault operations (transit signing, KV reads/writes).

The projected token is automatically rotated by Kubernetes before expiry (`expirationSeconds: 7200`). Siglet re-reads
the file on each Vault authentication renewal, so no restart is required.

> Set `audience: vault` on the projected token to ensure it cannot be replayed against other services.

### ConfigMap Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: siglet-config
  namespace: siglet
data:
  config.toml: |
    siglet_api_port  = 8080
    signaling_port   = 8081
    refresh_api_port = 8082
    bind = "0.0.0.0"

    [storage_backend]
    type = "postgres-vault"
    # url injected via SIGLET__STORAGE_BACKEND__URL env var

    [vault]
    signing_key_name = "signing-siglet"
    # url and token_file injected via env vars

    [token]
    issuer = "siglet"
    refresh_endpoint = "https://siglet.example.com/token"

    [[transfer_types]]
    transfer_type = "HttpData-PULL"
    endpoint_type = "HTTP"
    token_source  = "provider"
    endpoint      = "https://data.provider.example.com/assets"
```

---

## Operational Notes

**Scale-out**: Multiple Siglet replicas are safe with `postgres-vault` storage. The PostgreSQL lock manager ensures only
one replica performs a token refresh at a time per flow ID.

**Token revocation**: Tokens are revoked when a flow terminates (`on_terminate`) or is suspended (`on_suspend`). The
JWKS-based local verifier will not detect revocation until the token's `exp` is reached. Use the `/tokens/verify`
endpoint for revocation-aware checks.

**Key rotation**: The Vault transit engine supports key rotation. Existing tokens signed with previous key versions
remain verifiable because the JWKS endpoint includes all active key versions. Rotate keys with:

```bash
vault write -f transit/keys/signing-siglet/rotate
```

**Health check**: The Siglet API and Signaling API expose standard HTTP health endpoints on their respective ports.
Return HTTP 200 from `/` for liveness probes.

**Minimum secret length**: `token.server_secret` must be at least 16 bytes (32 hex characters). Generate a suitable
value with:

```bash
openssl rand -hex 32
```
