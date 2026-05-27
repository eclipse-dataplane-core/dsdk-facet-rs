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

//! Signaling-API authentication middleware.
//!
//! Two modes:
//! - [`AuthLayer::Disabled`] — extracts `participant_context_id` from the URL path and
//!   injects it into the request extensions without verifying any bearer token. Intended
//!   for development and existing tests; not safe for production.
//! - [`AuthLayer::Enabled`] — additionally requires an `Authorization: Bearer <jwt>` header,
//!   verifies the JWT signature against a JWKS fetched from a configurable URL, asserts
//!   that the `sub` claim matches the `participant_context_id` from the URL path, and
//!   requires the `scope` claim to grant the configured required scope
//!   (`signaling_auth.required_scope`, default `dplane-signaling`).
//!
//! ## Expected JWT shape (enabled mode)
//!
//! ```json
//! {
//!   "kid": "<key id present in JWKS>",   // header
//!   "alg": "EdDSA" | "RS256" | "ES256",  // header
//!   "sub": "<participant_context_id>",   // payload — MUST equal URL param
//!   "scope": "dplane-signaling",          // payload — space-delimited; MUST contain "dplane-signaling"
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

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    RequestPartsExt,
    body::Body,
    extract::{Path, Request},
    response::{IntoResponse, Response},
};
use dataplane_sdk::core::model::participant::ParticipantContext;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
};
use reqwest::StatusCode;
use tokio::sync::RwLock;
use tower::{Layer, Service};

/// The path parameter that carries the participant-context identifier on the
/// signaling routes. Kept here (rather than inline) so any future renaming
/// stays at one location.
const PATH_PARAM_PC_ID: &str = "participant_context_id";

/// Allowlist of signing algorithms accepted on incoming signaling-API JWTs.
///
/// Constraining this list (rather than trusting `header.alg`) defeats the classic
/// alg-confusion attack where a forged token claims a weaker algorithm than the
/// JWK supports. EdDSA the default; RS256 and ES256 are included, so deployments fronted by Keycloak, Auth0,
/// or other OIDC IdPs work out of the box.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::EdDSA, Algorithm::RS256, Algorithm::ES256];

/// JWT-auth middleware for the signaling API.
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
    pub fn enabled_http(
        jwks_url: impl Into<String>,
        cache_ttl: Duration,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
        client: reqwest::Client,
    ) -> Self {
        let provider = HttpKeyProvider::new(jwks_url.into(), cache_ttl, client);
        Self::Enabled(Arc::new(AuthState {
            key_provider: Box::new(provider),
            expected_audience: expected_audience.into(),
            required_scope: required_scope.into(),
        }))
    }

    /// Builds an enabled `AuthLayer` backed by a caller-supplied key provider.
    /// Tests use this with an in-memory provider to avoid hitting the network.
    pub fn enabled_with_provider(
        provider: Box<dyn KeyProvider>,
        expected_audience: impl Into<String>,
        required_scope: impl Into<String>,
    ) -> Self {
        Self::Enabled(Arc::new(AuthState {
            key_provider: provider,
            expected_audience: expected_audience.into(),
            required_scope: required_scope.into(),
        }))
    }
}

/// Per-request state shared by every clone of the middleware service.
pub struct AuthState {
    key_provider: Box<dyn KeyProvider>,
    /// The string the JWT's `aud` claim must contain for the request to be
    /// accepted. Comes from `signaling_auth.audience` in config (default `"siglet"`).
    expected_audience: String,
    /// The scope the JWT's `scope` claim must grant. Comes from
    /// `signaling_auth.required_scope` in config (default `"dplane-signaling"`).
    /// Validated non-empty at config load, so an empty value never reaches here.
    required_scope: String,
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
        (self.status(), self.client_message()).into_response()
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

            // Every signaling route is keyed on participant_context_id. If the path
            // doesn't have it, we have nothing to authenticate against.
            let path: Path<HashMap<String, String>> = match parts.extract().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Failed to extract path parameters: {}", e);
                    return Ok((StatusCode::BAD_REQUEST, "missing path parameters").into_response());
                }
            };

            let pc_id = match path.get(PATH_PARAM_PC_ID) {
                Some(id) => id.clone(),
                None => {
                    // Backward-compat: previously this middleware passed through requests
                    // without a participant_context_id silently. Maintain that for routes
                    // that don't carry the parameter rather than breaking them.
                    let req = Request::from_parts(parts, body);
                    return inner.call(req).await;
                }
            };

            // Enabled mode does JWT verification; disabled mode trusts the path
            // identifier directly (legacy behavior).
            if let AuthLayer::Enabled(state) = &layer
                && let Err(err) = verify_jwt(state.as_ref(), &parts.headers, &pc_id).await
            {
                return Ok(err.into_response());
            }

            let mut req = Request::from_parts(parts, body);
            req.extensions_mut()
                .insert(ParticipantContext::builder().id(&pc_id).build());
            inner.call(req).await
        })
    }
}

/// Verifies the bearer token in the request headers against the JWKS and asserts
/// that the token's `sub` claim equals the expected participant-context id.
async fn verify_jwt(state: &AuthState, headers: &axum::http::HeaderMap, expected_pc_id: &str) -> Result<(), AuthError> {
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

    if token_data.claims.sub != expected_pc_id {
        return Err(AuthError::SubjectMismatch {
            expected: expected_pc_id.to_string(),
            got: token_data.claims.sub,
        });
    }

    // Authorization check: the caller proved their identity (signature + sub), but
    // must additionally hold the signaling scope. `required_spec_claims` only covers
    // registered claims, so a missing `scope` isn't caught by `decode` — handle it
    // here. Both "no scope claim" and "scope present but lacking the value" are the
    // same authorization failure → 403.
    if !scope_grants(token_data.claims.scope.as_deref(), &state.required_scope) {
        return Err(AuthError::InsufficientScope {
            required: state.required_scope.clone(),
        });
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
