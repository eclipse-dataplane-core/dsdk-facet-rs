//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

//! JWT authentication middleware shared by the signaling API and the token-management API.
//!
//! Two modes:
//! - [`AuthLayer::Disabled`] — extracts `participant_context_id` from the URL path (when
//!   present) and injects it into the request extensions without verifying any bearer
//!   token. Intended for development and existing tests; not safe for production.
//! - [`AuthLayer::Enabled`] — additionally requires an `Authorization: Bearer <jwt>` header,
//!   verifies the JWT signature against a JWKS fetched from a configurable URL, requires the
//!   `scope` claim to grant a configured scope, and — when the route carries a
//!   `participant_context_id` — asserts that the `sub` claim matches it.
//!
//! ## Subject binding and pathless routes
//!
//! Routes are keyed on `participant_context_id` on the signaling API and on the
//! per-participant token routes; there the `sub` claim must equal that path segment. Some
//! protected routes have no participant context (e.g. the token API's `/tokens/verify`).
//! [`NoParticipantContext`] selects what happens then: the signaling API passes such
//! requests through unauthenticated (its only pathless routes are intentionally open),
//! while the token API still requires a valid scoped token but skips subject binding.
//!
//! Subject binding can additionally be waived per-caller by an optional *admin scope*
//! (`token_api_auth.admin_scope`, absent by default). A token whose `scope` claim carries
//! that value may act on any participant context. The grant is additive: the required
//! scope is still enforced, so an admin token that lacks it is rejected like any other.
//!
//! ## Expected JWT shape (enabled mode)
//!
//! ```json
//! {
//!   "kid": "<key id present in JWKS>",   // header
//!   "alg": "EdDSA" | "RS256" | "ES256",  // header
//!   "sub": "<participant_context_id>",   // payload — MUST equal URL param when present
//!   "scope": "dplane-signaling",          // payload — space-delimited; MUST contain the required scope
//!   "exp": <unix-seconds>,                // payload
//!   "iat": <unix-seconds>                 // payload, optional
//! }
//! ```
//!
//! The `kid` header is required so the middleware can pick the right key from the JWKS.
//! The `scope` claim follows the OAuth2 convention (RFC 6749 §3.3): a single string of
//! space-delimited scope tokens. A token may carry other scopes alongside the required
//! one (e.g. `"read:data dplane-signaling"`). `aud` and `iss` are not validated here —
//! add a separate check downstream if needed.

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    Json, RequestPartsExt,
    body::Body,
    extract::{Path, Request},
    response::{IntoResponse, Response},
};
use dataplane_sdk::core::model::{control_plane::ControlPlane, participant::ParticipantContext};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
};
use reqwest::StatusCode;
use serde_json::json;
use tokio::sync::RwLock;
use tower::{Layer, Service};

/// The path parameter that carries the participant-context identifier on
/// participant-scoped routes (signaling routes and the per-participant token routes).
/// Kept here (rather than inline) so any future renaming stays at one location.
const PATH_PARAM_PC_ID: &str = "participant_context_id";

/// Allowlist of signing algorithms accepted on incoming JWTs.
///
/// Constraining this list (rather than trusting `header.alg`) defeats the classic
/// alg-confusion attack where a forged token claims a weaker algorithm than the
/// JWK supports. EdDSA the default; RS256 and ES256 are included, so deployments fronted by Keycloak, Auth0,
/// or other OIDC IdPs work out of the box.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::EdDSA, Algorithm::RS256, Algorithm::ES256];

/// What the middleware does with an enabled-mode request whose path carries no
/// `participant_context_id`.
///
/// Subject binding requires a participant-context id to bind against; this enum
/// covers the routes that don't have one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoParticipantContext {
    /// Pass the request through without authenticating it. The signaling router only
    /// mounts participant-scoped routes plus intentionally-open ones (e.g. health), so
    /// a missing id means an open route. (Signaling API.)
    PassThrough,
    /// Still require a valid, correctly-scoped JWT, but skip subject binding. Used by
    /// the token API, whose `/tokens/verify` route is protected yet has no participant
    /// context to bind `sub` against.
    RequireToken,
}

/// JWT-auth middleware shared by the signaling and token-management APIs.
#[derive(Clone)]
pub enum AuthLayer {
    Disabled,
    Enabled(Arc<AuthState>),
}

impl AuthLayer {
    /// Builds an enabled `AuthLayer` that fetches JWKS over HTTP from `jwks_url`.
    ///
    /// `client` is the shared process-wide `reqwest::Client` — callers should
    /// pass the same instance used elsewhere in the runtime so the connection
    /// pool, timeouts, and TLS config are unified.
    ///
    /// `expected_audience` is the string the verifier requires in the JWT's
    /// `aud` claim. This binds a token to *this* siglet instance and blocks
    /// cross-service replay of JWTs issued by the same IdP for other recipients.
    ///
    /// `required_scope` is the scope the JWT's `scope` claim must grant. Comes from
    /// `signaling_auth.required_scope` in config (default `"dplane-signaling"`).
    ///
    /// Built for the signaling API: pathless requests pass through unauthenticated
    /// ([`NoParticipantContext::PassThrough`]) and there is no admin-scope bypass. Use
    /// [`AuthLayer::enabled_http_require_token`] for the token API.
    pub fn enabled_http(
        jwks_url: impl Into<String>,
        cache_ttl: Duration,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
        client: reqwest::Client,
    ) -> Self {
        let provider = HttpKeyProvider::new(jwks_url.into(), cache_ttl, client);
        Self::enabled(
            Box::new(provider),
            expected_audience,
            required_scope,
            None,
            NoParticipantContext::PassThrough,
        )
    }

    /// Like [`AuthLayer::enabled_http`] but authenticates *every* request even when the
    /// path carries no participant context ([`NoParticipantContext::RequireToken`]).
    /// Built for the token-management API, whose `/tokens/verify` route is protected but
    /// has no participant context to bind `sub` against.
    ///
    /// `admin_scope` is the optional scope that waives subject binding on participant-scoped
    /// routes (`token_api_auth.admin_scope`). Pass `None` — the default — to keep `sub`
    /// bound for every caller.
    pub fn enabled_http_require_token(
        jwks_url: impl Into<String>,
        cache_ttl: Duration,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
        admin_scope: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        let provider = HttpKeyProvider::new(jwks_url.into(), cache_ttl, client);
        Self::enabled(
            Box::new(provider),
            expected_audience,
            required_scope,
            admin_scope,
            NoParticipantContext::RequireToken,
        )
    }

    /// Builds an enabled `AuthLayer` backed by a caller-supplied key provider, using the
    /// signaling pass-through policy. Tests use this with an in-memory provider to avoid
    /// hitting the network.
    pub fn enabled_with_provider(
        provider: Box<dyn KeyProvider>,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
    ) -> Self {
        Self::enabled(
            provider,
            expected_audience,
            required_scope,
            None,
            NoParticipantContext::PassThrough,
        )
    }

    /// Builds an enabled `AuthLayer` backed by a caller-supplied key provider, with an
    /// explicit [`NoParticipantContext`] policy and optional admin scope. Lets token-API
    /// tests exercise the require-token and admin-bypass behavior with an in-memory provider.
    pub fn enabled_with_provider_and_policy(
        provider: Box<dyn KeyProvider>,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
        admin_scope: Option<String>,
        no_participant_context: NoParticipantContext,
    ) -> Self {
        Self::enabled(
            provider,
            expected_audience,
            required_scope,
            admin_scope,
            no_participant_context,
        )
    }

    fn enabled(
        provider: Box<dyn KeyProvider>,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
        admin_scope: Option<String>,
        no_participant_context: NoParticipantContext,
    ) -> Self {
        Self::Enabled(Arc::new(AuthState {
            key_provider: provider,
            expected_audience: expected_audience.into(),
            required_scope: required_scope.into(),
            admin_scope,
            no_participant_context,
        }))
    }
}

/// Per-request state shared by every clone of the middleware service.
pub struct AuthState {
    key_provider: Box<dyn KeyProvider>,
    /// The string the JWT's `aud` claim must contain for the request to be
    /// accepted. Comes from `signaling_auth.audience` in config (default `"siglet"`).
    expected_audience: String,
    /// The scope the JWT's `scope` claim must grant. For the signaling API this comes
    /// from `signaling_auth.required_scope` (default `"dplane-signaling"`); for the token
    /// API from `token_api_auth.required_scope` (default `"siglet-token-api"`). Validated
    /// non-empty at config load, so an empty value never reaches here.
    required_scope: String,
    /// Optional scope that waives subject binding on participant-scoped routes. Comes from
    /// `token_api_auth.admin_scope` and is `None` — the bypass off — unless an operator
    /// names one. The signaling and management APIs always leave it `None`.
    ///
    /// Additive, not a substitute: a token carrying only this scope still fails the
    /// [`AuthState::required_scope`] check below.
    admin_scope: Option<String>,
    /// How to handle an enabled-mode request whose path carries no participant context.
    no_participant_context: NoParticipantContext,
}

/// Resolves the verifying key for a given JWT `kid`.
///
/// Implementations are responsible for any caching/refresh behavior.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn jwks(&self) -> Result<JwkSet, AuthError>;

    /// Returns the JWKS.
    async fn fetch_jwks(&self, kid: &str) -> Result<JwkSet, AuthError> {
        let _ = kid;
        self.jwks().await
    }
}

/// HTTP-backed JWKS provider with simple TTL caching.
///
/// The cache is refreshed lazily: a request that arrives after the TTL expires
/// pays the round-trip cost.
pub struct HttpKeyProvider {
    url: String,
    client: reqwest::Client,
    cache_ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
}

struct CachedJwks {
    fetched_at: Instant,
    jwk_set: JwkSet,
}

impl HttpKeyProvider {
    /// Builds an HTTP-backed JWKS provider. `client` is owned by the caller and
    /// expected to be the shared process-wide `reqwest::Client` so timeouts and
    /// connection pooling are unified across the runtime.
    pub fn new(url: String, cache_ttl: Duration, client: reqwest::Client) -> Self {
        Self {
            url,
            client,
            cache_ttl,
            cache: RwLock::new(None),
        }
    }

    async fn force_refresh(&self) -> Result<JwkSet, AuthError> {
        let fresh = self.fetch().await?;
        let mut guard = self.cache.write().await;
        *guard = Some(CachedJwks {
            fetched_at: Instant::now(),
            jwk_set: fresh.clone(),
        });
        Ok(fresh)
    }

    async fn fetch(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;
        if !response.status().is_success() {
            return Err(AuthError::JwksFetch(format!(
                "JWKS endpoint returned status {}",
                response.status()
            )));
        }
        response
            .json::<JwkSet>()
            .await
            .map_err(|e| AuthError::JwksFetch(format!("Failed to parse JWKS: {}", e)))
    }
}

#[async_trait]
impl KeyProvider for HttpKeyProvider {
    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        {
            let guard = self.cache.read().await;
            if let Some(cached) = guard.as_ref()
                && cached.fetched_at.elapsed() < self.cache_ttl
            {
                return Ok(cached.jwk_set.clone());
            }
        }
        self.force_refresh().await
    }

    async fn fetch_jwks(&self, kid: &str) -> Result<JwkSet, AuthError> {
        let jwks = self.jwks().await?;
        if jwks.find(kid).is_some() {
            return Ok(jwks);
        }
        // kid absent from cached set — key may have been rotated; one forced refresh
        self.force_refresh().await
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingAuthHeader,
    MalformedAuthHeader(String),
    JwksFetch(String),
    KidNotInJwks(String),
    UnsupportedKey(String),
    InvalidSignature(String),
    SubjectMismatch { expected: String, got: String },
    InsufficientScope { required: String },
}

impl AuthError {
    fn status(&self) -> StatusCode {
        match self {
            AuthError::SubjectMismatch { .. } | AuthError::InsufficientScope { .. } => StatusCode::FORBIDDEN,
            AuthError::JwksFetch(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    fn client_message(&self) -> String {
        match self {
            AuthError::MissingAuthHeader => "Missing Authorization header".to_string(),
            AuthError::MalformedAuthHeader(reason) => format!("Malformed Authorization header: {}", reason),
            AuthError::JwksFetch(_) => "Unable to verify token (JWKS unavailable)".to_string(),
            AuthError::KidNotInJwks(kid) => format!("Token kid '{}' is not in the JWKS", kid),
            AuthError::UnsupportedKey(reason) => format!("Unsupported verification key: {}", reason),
            AuthError::InvalidSignature(reason) => format!("Invalid token: {}", reason),
            AuthError::SubjectMismatch { expected, got } => format!(
                "Token subject '{}' does not match participant context '{}'",
                got, expected
            ),
            AuthError::InsufficientScope { required } => {
                format!("Token is missing required scope '{}'", required)
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Log details server-side; return only safe-to-disclose info to the client.
        if matches!(self, AuthError::JwksFetch(_)) {
            tracing::error!("JWKS fetch failed: {:?}", self);
        } else {
            tracing::debug!("Auth rejected: {:?}", self);
        }
        let body = Json(json!({
            "message": self.client_message()
        }));
        (self.status(), body).into_response()
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    layer: AuthLayer,
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let layer = self.layer.clone();

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            // Participant-scoped routes carry participant_context_id in the path; pull it
            // out (if any) to drive subject binding below.
            let path: Path<HashMap<String, String>> = match parts.extract().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Failed to extract path parameters: {}", e);
                    return Ok((StatusCode::BAD_REQUEST, "missing path parameters").into_response());
                }
            };

            let pc_id = path.get(PATH_PARAM_PC_ID).cloned();

            match (&layer, pc_id) {
                // Disabled mode never verifies a token. When the route carries a
                // participant context we still inject it (legacy behavior); otherwise we
                // pass through untouched.
                (AuthLayer::Disabled, pc_id) => {
                    let mut req = Request::from_parts(parts, body);
                    if let Some(pc_id) = pc_id {
                        req.extensions_mut()
                            .insert(ParticipantContext::builder().id(&pc_id).build());
                        req.extensions_mut()
                            .insert(ControlPlane::builder().id(pc_id).url("http://example.org").build());
                    }
                    inner.call(req).await
                }

                // Enabled mode, participant-scoped route: verify the token and bind
                // `sub` to the path id, then inject the participant context.
                (AuthLayer::Enabled(state), Some(pc_id)) => {
                    if let Err(err) = verify_jwt(state.as_ref(), &parts.headers, Some(&pc_id)).await {
                        return Ok(err.into_response());
                    }
                    let mut req = Request::from_parts(parts, body);
                    req.extensions_mut()
                        .insert(ParticipantContext::builder().id(&pc_id).build());
                    req.extensions_mut()
                        .insert(ControlPlane::builder().id(pc_id).url("http://example.org").build());
                    inner.call(req).await
                }

                // Enabled mode, pathless route: behavior depends on the configured policy.
                (AuthLayer::Enabled(state), None) => match state.no_participant_context {
                    NoParticipantContext::PassThrough => {
                        let req = Request::from_parts(parts, body);
                        inner.call(req).await
                    }
                    NoParticipantContext::RequireToken => {
                        // Require a valid, correctly-scoped token, but with no subject to
                        // bind against.
                        if let Err(err) = verify_jwt(state.as_ref(), &parts.headers, None).await {
                            return Ok(err.into_response());
                        }
                        let req = Request::from_parts(parts, body);
                        inner.call(req).await
                    }
                },
            }
        })
    }
}

/// Verifies the bearer token in the request headers against the JWKS, enforcing the
/// audience and required scope. When `expected_pc_id` is `Some`, additionally asserts
/// that the token's `sub` claim equals that participant-context id; when `None`
/// (pathless routes) the subject is not bound. A token carrying the configured
/// [`AuthState::admin_scope`], if any, also skips that assertion.
async fn verify_jwt(
    state: &AuthState,
    headers: &axum::http::HeaderMap,
    expected_pc_id: Option<&str>,
) -> Result<(), AuthError> {
    let token = extract_bearer(headers)?;

    let header = decode_header(token).map_err(|e| AuthError::InvalidSignature(format!("bad JWT header: {}", e)))?;
    let kid = header
        .kid
        .ok_or_else(|| AuthError::InvalidSignature("JWT header missing kid".to_string()))?;

    // Pin the algorithm to our allowlist *before* touching the key. This prevents
    // an attacker from inducing alg-confusion by signing a token with HS256 using
    // the public RSA modulus published in the JWKS as a shared secret.
    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(AuthError::InvalidSignature(format!(
            "algorithm '{:?}' not in allowlist",
            header.alg
        )));
    }

    let jwk_set = state.key_provider.fetch_jwks(&kid).await?;
    let jwk = jwk_set.find(&kid).ok_or_else(|| AuthError::KidNotInJwks(kid.clone()))?;

    // If the JWK advertises an `alg`, cross-check that the JWT's header alg matches.
    // an attacker swapping algs gets rejected here before we even build a DecodingKey.
    if let Some(jwk_alg) = jwk.common.key_algorithm
        && !key_alg_matches(jwk_alg, header.alg)
    {
        return Err(AuthError::InvalidSignature(format!(
            "JWT alg '{:?}' does not match JWK alg '{:?}'",
            header.alg, jwk_alg
        )));
    }

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| AuthError::UnsupportedKey(format!("DecodingKey from JWK failed: {}", e)))?;

    let mut validation = Validation::new(header.alg);
    // Restrict the accepted algorithm set so the underlying decoder doesn't fall
    // back to anything else even if the call site is changed later.
    validation.algorithms = vec![header.alg];
    // Audience binding: only accept tokens whose `aud` matches the configured
    // value. This is what stops a JWT minted for some other recipient (off the
    // same JWKS) from being replayed against this siglet. Issuer/`iss` is still
    // unchecked at this layer — downstream code can enforce it if needed.
    validation.aud = Some(std::collections::HashSet::from([state.expected_audience.clone()]));
    validation.validate_aud = true;
    validation.validate_nbf = true;
    validation.required_spec_claims = std::collections::HashSet::from(["exp".to_string(), "aud".to_string()]);

    let token_data =
        decode::<Claims>(token, &decoding_key, &validation).map_err(|e| AuthError::InvalidSignature(e.to_string()))?;

    // Authorization check: the caller proved their identity (signature, and `sub` when
    // bound), but must additionally hold the required scope. `required_spec_claims` only
    // covers registered claims, so a missing `scope` isn't caught by `decode` — handle it
    // here. Both "no scope claim" and "scope present but lacking the value" are the
    // same authorization failure → 403.
    if !scope_grants(token_data.claims.scope.as_deref(), &state.required_scope) {
        return Err(AuthError::InsufficientScope {
            required: state.required_scope.clone(),
        });
    }

    // An admin-scoped caller may act on any participant context, so subject binding is
    // waived for it. This does not relax the required-scope gate below: the admin scope is
    // additive, so a token holding it alone is still rejected as insufficiently scoped.
    let is_admin = state
        .admin_scope
        .as_deref()
        .is_some_and(|admin| scope_grants(token_data.claims.scope.as_deref(), admin));

    // Subject binding only applies on participant-scoped routes. Pathless routes
    // (token API's `/tokens/verify`) pass `None` and skip this check.
    if let Some(expected_pc_id) = expected_pc_id {
        if is_admin {
            // Cross-participant access to token material: log every use so it is auditable.
            tracing::warn!(
                subject = %token_data.claims.sub,
                participant_context = %expected_pc_id,
                "Admin scope granted — skipping subject binding on a participant-scoped route"
            );
        } else if token_data.claims.sub != expected_pc_id {
            return Err(AuthError::SubjectMismatch {
                expected: expected_pc_id.to_string(),
                got: token_data.claims.sub,
            });
        }
    }

    Ok(())
}

/// Returns true if `scope` (an OAuth2 space-delimited scope string) contains
/// `required` as one of its whitespace-separated entries. A `None` scope claim
/// never grants anything.
fn scope_grants(scope: Option<&str>, required: &str) -> bool {
    scope.is_some_and(|s| s.split_whitespace().any(|entry| entry == required))
}

/// Pairs a JWK-advertised `alg` (`KeyAlgorithm`) with the `Algorithm` parsed from
/// the JWT header. The two enums are not unified upstream, so we map by name.
fn key_alg_matches(jwk_alg: KeyAlgorithm, header_alg: Algorithm) -> bool {
    matches!(
        (jwk_alg, header_alg),
        (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
            | (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::HS256, Algorithm::HS256)
            | (KeyAlgorithm::HS384, Algorithm::HS384)
            | (KeyAlgorithm::HS512, Algorithm::HS512)
    )
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, AuthError> {
    let value = headers.get("authorization").ok_or(AuthError::MissingAuthHeader)?;
    let s = value
        .to_str()
        .map_err(|_| AuthError::MalformedAuthHeader("non-ASCII bytes in header".to_string()))?;
    s.strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::MalformedAuthHeader("expected 'Bearer <token>' scheme".to_string()))
}

/// Minimal claim shape required for participant-context binding and scope
/// authorization. `aud`/`exp`/`nbf` are validated by `decode` via the `Validation`
/// struct rather than deserialized here; other claims (iss, custom) are tolerated
/// and ignored at this layer.
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    /// OAuth2 `scope` claim (RFC 6749 §3.3): a single space-delimited string.
    /// Optional in the wire format — absence is treated as granting no scopes,
    /// and rejected by the scope check in `verify_jwt`.
    #[serde(default)]
    scope: Option<String>,
}
