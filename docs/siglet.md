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

Siglet exposes three HTTP servers:

| Server        | Default Port | Purpose                                           |
|---------------|--------------|---------------------------------------------------|
| Siglet API    | 8080         | Token retrieval, verification, JWKS endpoint      |
| Signaling API | 8081         | DPS protocol endpoint (control plane integration) |
| Refresh API   | 8082         | OAuth2-compatible token refresh endpoint          |

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
                        │   /token/refresh      POST           │
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
  "datasetId": "dataset-xyz"
}
```

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

The token-management API (port 8080) authenticates the same way as the signaling API,
against the **same** JWKS and audience configured under `[signaling_auth]` — there is no
separate auth config block. The only differences are the required scope and which routes
are protected.

### Protected vs. public routes

| Route                                     | Auth required | Notes                                              |
|-------------------------------------------|---------------|----------------------------------------------------|
| `GET`/`DELETE /tokens/{participant_context_id}/{id}` | yes | `sub` must equal the `{participant_context_id}` path segment |
| `POST /tokens/verify`                     | yes           | No participant context, so `sub` is not bound      |
| `GET /keys` (JWKS)                        | no            | Public discovery endpoint                          |
| `GET /` , `GET /health`                   | no            | Liveness/readiness                                 |

### Required scope

Protected routes require a JWT whose space-delimited `scope` claim contains
`siglet-token-api` (rather than the signaling API's `dplane-signaling`). The matching
and rejection semantics are identical to the signaling API: a missing or non-matching
scope returns `403`, a missing/invalid/expired token or wrong `aud` returns `401`, and a
`sub` that doesn't match the path participant context returns `403`. Unlike the signaling
API — whose only pathless routes are intentionally open — every protected token-API route
requires a valid token, including `POST /tokens/verify`.

Unlike `signaling_auth.required_scope`, the token-API scope is a fixed value, not a config
knob; enabling/disabling token-API auth follows `signaling_auth.mode` together with the
signaling API.

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
| `refreshEndpoint` | URL of Siglet's refresh API (`:8082/token/refresh`) |

### Transfer Type Configuration

Siglet is configured with one or more transfer types that map DPS `transferType` values to data endpoints. Each transfer
type specifies whether the **provider** or the **client** generates the token (`token_source`).

---

## Configuration

Configuration is loaded from a file (TOML, YAML, or JSON) specified via the first CLI argument or the
`SIGLET_CONFIG_FILE` environment variable. Environment variables with the prefix `SIGLET__` override file values (double
underscore as separator for nesting).

### Complete Configuration Reference

```toml
# Network binding
bind = "0.0.0.0"           # Default: 0.0.0.0
siglet_api_port = 8080    # Default: 8080 — token API + JWKS + verify
signaling_port = 8081    # Default: 8081 — DPS signaling
refresh_api_port = 8082    # Default: 8082 — OAuth2 token refresh

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

# Shared outbound HTTP client (JWKS fetch, OAuth2 token refresh, etc.). Optional —
# omit to use the built-in defaults shown below. Both values must be > 0.
[http_client]
connect_timeout_seconds = 10   # Default: 10. TCP connect-phase timeout.
request_timeout_seconds = 30   # Default: 30. Total per-request timeout (connect + send + read).

# Token settings
[token]
issuer = "siglet"          # JWT `iss` claim. Default: "siglet"
# Override the refresh endpoint advertised to consumers.
# Default: http://{bind}:{refresh_api_port}/token/refresh
refresh_endpoint = "https://siglet.example.com/token/refresh"
# Hex-encoded secret used to derive symmetric keys (HMAC, etc.).
# Must be at least 16 bytes (32 hex chars). Generate with: openssl rand -hex 32
server_secret = "0102030405060708090a0b0c0d0e0f10..."

# Transfer types — one block per supported transfer type
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
    refresh_endpoint = "https://siglet.example.com/token/refresh"

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
