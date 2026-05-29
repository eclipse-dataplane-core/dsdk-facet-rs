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

#![allow(clippy::unwrap_used)]

//! Unit tests for the shared JWT auth middleware.
//!
//! These tests drive `AuthLayer` directly through a minimal axum router so we
//! never need to spin up a real server or a real JWKS endpoint. The shared
//! key provider is an in-memory `StaticKeyProvider` that returns a fixed
//! `JwkSet` derived from a freshly generated Ed25519 keypair.

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Path},
    http::{Request, StatusCode},
    routing::get,
};
use dataplane_sdk::core::model::participant::ParticipantContext;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters, OctetKeyPairType,
        PublicKeyUse,
    },
};
use rand::RngCore;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::server::auth::{AuthError, AuthLayer, KeyProvider, NoParticipantContext};

// ============================================================================
// Test Fixtures
// ============================================================================

/// Test key bundle: holds the Ed25519 signing key plus a JwkSet exposing the
/// corresponding public key under a fixed `kid`.
struct TestKey {
    signing_key: SigningKey,
    kid: String,
    jwk_set: JwkSet,
}

impl TestKey {
    fn new(kid: &str) -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let x_b64 = base64_url(public_key_bytes.as_slice());

        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: Some(kid.to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: jsonwebtoken::jwk::EllipticCurve::Ed25519,
                x: x_b64,
            }),
        };

        Self {
            signing_key,
            kid: kid.to_string(),
            jwk_set: JwkSet { keys: vec![jwk] },
        }
    }

    fn issue(&self, claims: Value) -> String {
        let pkcs8_bytes = self.signing_key.to_keypair_bytes();
        // jsonwebtoken's EncodingKey for Ed25519 wants either PEM or DER PKCS8.
        // The DER path is simpler since we already have raw bytes — but we have
        // a 64-byte keypair (seed || public), not a PKCS8 DER blob, so we route
        // through the seed-only constructor by base64'ing as a PEM.
        let pem = ed25519_seed_to_pkcs8_pem(&pkcs8_bytes[..32]);
        let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes()).expect("encoding key from PEM");

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());

        encode(&header, &claims, &encoding_key).expect("JWT encode")
    }
}

/// Encodes raw bytes using URL-safe base64 with no padding (RFC 7515 §3).
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Wraps a 32-byte Ed25519 seed in a PKCS8 PEM envelope that `EncodingKey::from_ed_pem`
/// will accept. The DER prefix is the constant PKCS8 v1 header for Ed25519 (RFC 8410).
fn ed25519_seed_to_pkcs8_pem(seed: &[u8]) -> String {
    use base64::Engine;
    assert_eq!(seed.len(), 32, "Ed25519 seed must be 32 bytes");
    // PKCS8 v1 prefix for Ed25519 private key, followed by OCTET STRING wrapping the seed.
    let prefix: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    let mut der = Vec::with_capacity(prefix.len() + seed.len());
    der.extend_from_slice(&prefix);
    der.extend_from_slice(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64)
}

/// Minimal `KeyProvider` that returns a fixed `JwkSet`. Records call count so
/// tests can verify caching/forwarding behavior.
struct StaticKeyProvider {
    jwk_set: JwkSet,
}

impl StaticKeyProvider {
    fn new(jwk_set: JwkSet) -> Self {
        Self { jwk_set }
    }
}

#[async_trait]
impl KeyProvider for StaticKeyProvider {
    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        Ok(self.jwk_set.clone())
    }
}

/// Builds a minimal router that pulls the participant context out of request
/// extensions and echoes its id. Used to assert what the middleware injected.
fn echo_router(layer: AuthLayer) -> Router {
    async fn handler(Path(_pc_id): Path<String>, Extension(pc): Extension<ParticipantContext>) -> String {
        pc.id.clone()
    }
    Router::new()
        .route("/dataflows/{participant_context_id}/start", get(handler))
        .layer(layer)
}

/// Builds a router that does NOT require the ParticipantContext extension —
/// for testing the early-return-path-without-pc-id behavior.
fn router_without_pc_id(layer: AuthLayer) -> Router {
    async fn handler() -> &'static str {
        "ok"
    }
    Router::new().route("/health", get(handler)).layer(layer)
}

const TEST_AUDIENCE: &str = "siglet";

/// The signaling scope these tests configure the layer with (the default value of
/// `signaling_auth.required_scope`).
const REQUIRED_SCOPE: &str = "dplane-signaling";

/// The scope the token-management API requires (the fixed `TOKEN_API_REQUIRED_SCOPE`).
const TOKEN_API_SCOPE: &str = "siglet-token-api";

fn standard_claims(sub: &str) -> Value {
    let exp = chrono::Utc::now().timestamp() + 3600;
    json!({
        "sub": sub,
        "aud": TEST_AUDIENCE,
        "scope": REQUIRED_SCOPE,
        "iat": chrono::Utc::now().timestamp(),
        "exp": exp,
    })
}

// ============================================================================
// Disabled Mode
// ============================================================================

#[tokio::test]
async fn disabled_mode_extracts_pc_id_without_token() {
    let app = echo_router(AuthLayer::Disabled);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "ctx-abc");
}

#[tokio::test]
async fn disabled_mode_passes_through_routes_without_pc_id() {
    let app = router_without_pc_id(AuthLayer::Disabled);

    let response = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Enabled Mode — Happy Path
// ============================================================================

#[tokio::test]
async fn enabled_mode_accepts_valid_jwt_with_matching_sub() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let token = key.issue(standard_claims("ctx-abc"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "ctx-abc");
}

// ============================================================================
// Enabled Mode — Rejection Paths
// ============================================================================

#[tokio::test]
async fn enabled_mode_rejects_missing_authorization_header() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(response).await;
    assert!(body.contains("Missing Authorization header"));
}

#[tokio::test]
async fn enabled_mode_rejects_non_bearer_scheme() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", "Basic dXNlcjpwYXNz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_mode_rejects_malformed_jwt() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", "Bearer not.a.jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_mode_rejects_unknown_kid() {
    let signing_key = TestKey::new("kid-signing");
    // The JWKS only contains a *different* kid than the one stamped on the token.
    let advertised_key = TestKey::new("kid-advertised");
    let provider = Box::new(StaticKeyProvider::new(advertised_key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let token = signing_key.issue(standard_claims("ctx-abc"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(response).await;
    assert!(body.contains("kid-signing"));
}

#[tokio::test]
async fn enabled_mode_rejects_subject_mismatch_with_403() {
    // Authentication succeeds (signature is valid) but the JWT was issued for a
    // different participant context than the one in the URL — that's an
    // authorization failure, not an authentication failure, so 403 is correct.
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let token = key.issue(standard_claims("ctx-other"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("ctx-other"));
    assert!(body.contains("ctx-abc"));
}

#[tokio::test]
async fn enabled_mode_rejects_expired_token() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    // Far enough in the past that the default 60s leeway in jsonwebtoken's
    // Validation can't rescue it.
    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "iat": now - 7200,
        "exp": now - 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_mode_rejects_wrong_signature() {
    // The token is signed by a different keypair than the one advertised in the JWKS,
    // even though both use the same `kid` — so the JWKS lookup succeeds but the
    // crypto verification fails.
    let advertised = TestKey::new("kid-1");
    let attacker = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(advertised.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let token = attacker.issue(standard_claims("ctx-abc"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_mode_rejects_token_without_kid() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    // Manually build a token with no kid in the header so the middleware
    // can't pick a key from the JWKS.
    let pem = ed25519_seed_to_pkcs8_pem(&key.signing_key.to_keypair_bytes()[..32]);
    let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
    let header = Header::new(Algorithm::EdDSA); // no kid
    let token = encode(&header, &standard_claims("ctx-abc"), &encoding_key).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Audience Binding
// ============================================================================

/// A signature-valid JWT whose `aud` claim doesn't match the configured audience
/// is rejected. This is the core defense against cross-service replay: even if
/// the token is cryptographically valid against the JWKS, it must have been
/// issued for *this* siglet specifically.
#[tokio::test]
async fn enabled_mode_rejects_wrong_audience() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    // Same signature, same sub, same exp — but the token was minted for a
    // different recipient.
    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": "other-service",
        "iat": now,
        "exp": now + 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A JWT with no `aud` claim at all is rejected — audience is required, not
/// optional, when the layer is configured.
#[tokio::test]
async fn enabled_mode_rejects_missing_audience() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "iat": now,
        "exp": now + 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// When the JWT's `aud` is an array (which is RFC-legal and emitted by some
/// IdPs), the verifier accepts it as long as the configured audience is one of
/// the entries.
#[tokio::test]
async fn enabled_mode_accepts_audience_array_containing_expected() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": ["other-service", TEST_AUDIENCE, "yet-another"],
        "scope": REQUIRED_SCOPE,
        "iat": now,
        "exp": now + 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Scope Authorization
// ============================================================================

/// A signature-valid JWT with a matching `sub` and correct `aud` is still
/// rejected if it carries no `scope` claim at all. Holding a valid identity
/// isn't sufficient — the token must be explicitly authorized for signaling.
/// This is an authorization failure, so 403 (not 401).
#[tokio::test]
async fn enabled_mode_rejects_missing_scope() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": TEST_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        // no "scope" claim
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(REQUIRED_SCOPE));
}

/// A `scope` claim that is present but doesn't include the required signaling
/// scope is rejected with 403. Substring matches don't count — the value must
/// appear as a whole space-delimited entry.
#[tokio::test]
async fn enabled_mode_rejects_insufficient_scope() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    // `dplane-signaling-extra` shares a prefix with the required scope but is a
    // distinct entry — it must not satisfy the requirement.
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": TEST_AUDIENCE,
        "scope": "read:data dplane-signaling-extra",
        "iat": now,
        "exp": now + 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(REQUIRED_SCOPE));
}

/// A `scope` claim carrying several space-delimited entries is accepted as long
/// as one of them is the required signaling scope. This is the common real-world
/// shape — an IdP grants signaling alongside other scopes.
#[tokio::test]
async fn enabled_mode_accepts_multi_scope_token() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": TEST_AUDIENCE,
        "scope": format!("read:data {} write:data", REQUIRED_SCOPE),
        "iat": now,
        "exp": now + 3600,
    }));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "ctx-abc");
}

/// The required scope is configurable per instance, not hardcoded. A layer built
/// with a custom required scope accepts a token granting *that* scope, and rejects
/// one that only carries the default `dplane-signaling`. Proves `required_scope`
/// is threaded from config through to the verifier.
#[tokio::test]
async fn enabled_mode_honors_custom_required_scope() {
    let custom_scope = "custom:signaling";
    let key = TestKey::new("kid-1");

    // A token granting the custom scope is accepted.
    let app = echo_router(AuthLayer::enabled_with_provider(
        Box::new(StaticKeyProvider::new(key.jwk_set.clone())),
        TEST_AUDIENCE,
        custom_scope,
    ));
    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "ctx-abc",
        "aud": TEST_AUDIENCE,
        "scope": custom_scope,
        "iat": now,
        "exp": now + 3600,
    }));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The default scope no longer satisfies a layer configured for the custom one.
    let app = echo_router(AuthLayer::enabled_with_provider(
        Box::new(StaticKeyProvider::new(key.jwk_set.clone())),
        TEST_AUDIENCE,
        custom_scope,
    ));
    let token = key.issue(standard_claims("ctx-abc")); // scope = "dplane-signaling"
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ============================================================================
// JWT Compatibility
// ============================================================================
//
// Reference shapes:
//   JWT header  : {"alg":"EdDSA","typ":"JWT","kid":"<key>-<version>"}
//   JWT payload : {sub, aud, iat, nbf, exp, ...custom incl. act}
//   JWK         : {"kty":"OKP","use":"sig","alg":"EdDSA","kid":"<key>-<version>",
//                  "crv":"Ed25519","x":"<base64url(32-byte pubkey)>"}

/// Deserializing a JWKS document
/// `/.well-known/jwks.json` returns must yield something our verifier can
/// look up by `kid` and feed to `DecodingKey::from_jwk`.
#[tokio::test]
async fn jwt_jwks_shape_deserializes_and_resolves_kid() {
    // Generate a real public key so we have valid base64url bytes for `x`,
    // then inline it into a literal JSON document
    let key = TestKey::new("signing-jwt_pc-1");
    let x = match &key.jwk_set.keys[0].algorithm {
        AlgorithmParameters::OctetKeyPair(p) => p.x.clone(),
        _ => unreachable!("TestKey emits OKP"),
    };
    let jwks_json = format!(
        r#"{{
            "keys": [
                {{
                    "kty": "OKP",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "signing-jwt_pc-1",
                    "crv": "Ed25519",
                    "x": "{x}"
                }}
            ]
        }}"#
    );

    let parsed: JwkSet = serde_json::from_str(&jwks_json).expect("JWKS must deserialize");
    let jwk = parsed
        .find("signing-jwt_pc-1")
        .expect("kid must be findable via JwkSet::find");

    // The decoding-key construction is where most shape mismatches would surface
    // (e.g. a 'kty' rename, an alg the lib doesn't recognize).
    let _ = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("DecodingKey::from_jwk on JWK must succeed");
}

/// End-to-end: build a JWT with the exact header + claim shape
/// `VaultJwtGenerator` produces (alg=EdDSA, typ=JWT, kid=`signing-<pc>-<n>`,
/// payload with sub/aud/iat/nbf/exp/custom including `act`) and confirm it
/// passes our middleware when `sub` equals the URL participant context.
#[tokio::test]
async fn enabled_mode_accepts_shaped_jwt() {
    let kid = "signing-jwt_pc-1";
    let key = TestKey::new(kid);
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    // In a real jwtlet → siglet handshake, jwtlet's `token.audience` config and
    // siglet's `signaling_auth.audience` config must agree. Pin a non-default
    // value here to prove the layer respects whatever audience was configured,
    // not just the "siglet" baseline.
    let expected_audience = "https://siglet.example.com";
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        expected_audience,
        REQUIRED_SCOPE,
    ));

    let now = chrono::Utc::now().timestamp();
    // `sub` is whatever participant_context value was requested at the
    // token-exchange endpoint. Use a Siglet-style local context id — that's what
    // shows up on the URL path of the signaling API.
    let pc_id = "ctx-jwt-participant-1";
    let claims = json!({
        "sub": pc_id,
        "aud": expected_audience,
        "scope": format!("{} resource:read", REQUIRED_SCOPE),
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "scope_resource_read": true,
    });

    let pem = ed25519_seed_to_pkcs8_pem(&key.signing_key.to_keypair_bytes()[..32]);
    let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());
    header.kid = Some(kid.to_string());
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/dataflows/{}/start", pc_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, pc_id);
}

// ============================================================================
// Algorithm-Pinning Hardening
// ============================================================================

/// `alg = "none"` must be rejected even if no signature is provided. This is the
/// canonical JWT confusion attack — `Validation` falls back to whatever the token
/// header claims unless explicitly constrained.
#[tokio::test]
async fn enabled_mode_rejects_alg_none() {
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    // Hand-craft an alg=none token: base64url("{\"alg\":\"none\",\"kid\":\"kid-1\"}") + payload + empty signature.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(br#"{"alg":"none","kid":"kid-1","typ":"JWT"}"#);
    let now = chrono::Utc::now().timestamp();
    let payload = b64.encode(format!(r#"{{"sub":"ctx-abc","exp":{}}}"#, now + 3600).as_bytes());
    let token = format!("{}.{}.", header, payload);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// If the JWK in the JWKS advertises one algorithm and the JWT header claims a
/// different one, reject — even if both are individually in the allowlist.
#[tokio::test]
async fn enabled_mode_rejects_jwk_alg_mismatch() {
    let key = TestKey::new("kid-1");
    // Replace the JWK's advertised alg with RS256 even though the key is EdDSA.
    let mut jwk_set = key.jwk_set.clone();
    jwk_set.keys[0].common.key_algorithm = Some(KeyAlgorithm::RS256);
    let provider = Box::new(StaticKeyProvider::new(jwk_set));
    let app = echo_router(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    // Token still uses EdDSA — JWK says RS256 — so cross-check fails.
    let token = key.issue(standard_claims("ctx-abc"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Token-API policy (NoParticipantContext::RequireToken)
// ============================================================================
//
// The token API reuses this middleware with the RequireToken policy and the
// siglet-token-api scope. Unlike the signaling API, a protected route with no
// participant_context_id (e.g. /tokens/verify) must still present a valid scoped
// token rather than passing through.

/// Builds a token-API-style layer: RequireToken policy + the siglet-token-api scope.
fn token_api_layer(jwk_set: JwkSet) -> AuthLayer {
    AuthLayer::enabled_with_provider_and_policy(
        Box::new(StaticKeyProvider::new(jwk_set)),
        TEST_AUDIENCE,
        TOKEN_API_SCOPE,
        NoParticipantContext::RequireToken,
    )
}

/// Router with a pathless protected route, mirroring `/tokens/verify`.
fn pathless_router(layer: AuthLayer) -> Router {
    async fn handler() -> &'static str {
        "ok"
    }
    Router::new().route("/tokens/verify", get(handler)).layer(layer)
}

/// Claims carrying the token-API scope. `sub` is irrelevant on pathless routes but
/// matters on participant-scoped ones.
fn token_api_claims(sub: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "sub": sub,
        "aud": TEST_AUDIENCE,
        "scope": TOKEN_API_SCOPE,
        "iat": now,
        "exp": now + 3600,
    })
}

#[tokio::test]
async fn require_token_mode_accepts_pathless_scoped_token() {
    let key = TestKey::new("kid-1");
    let app = pathless_router(token_api_layer(key.jwk_set.clone()));

    // No participant context on the path, but a valid siglet-token-api token → 200.
    let token = key.issue(token_api_claims("any-subject"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/tokens/verify")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn require_token_mode_rejects_pathless_without_token() {
    // The key difference from the signaling API: a pathless protected route is NOT
    // passed through. With no Authorization header it's rejected.
    let key = TestKey::new("kid-1");
    let app = pathless_router(token_api_layer(key.jwk_set.clone()));

    let response = app
        .oneshot(Request::builder().uri("/tokens/verify").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_token_mode_rejects_pathless_wrong_scope() {
    let key = TestKey::new("kid-1");
    let app = pathless_router(token_api_layer(key.jwk_set.clone()));

    // A token scoped for the signaling API must not satisfy the token API.
    let now = chrono::Utc::now().timestamp();
    let token = key.issue(json!({
        "sub": "any-subject",
        "aud": TEST_AUDIENCE,
        "scope": REQUIRED_SCOPE, // dplane-signaling, not siglet-token-api
        "iat": now,
        "exp": now + 3600,
    }));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/tokens/verify")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains(TOKEN_API_SCOPE));
}

#[tokio::test]
async fn require_token_mode_still_binds_subject_on_participant_route() {
    // When a participant context IS present (the per-participant token routes), the
    // RequireToken policy still binds `sub` to it — exactly like the signaling API.
    let key = TestKey::new("kid-1");

    // Matching sub → 200.
    let app = echo_router(token_api_layer(key.jwk_set.clone()));
    let token = key.issue(token_api_claims("ctx-abc"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Mismatched sub → 403, even with the correct scope.
    let app = echo_router(token_api_layer(key.jwk_set.clone()));
    let token = key.issue(token_api_claims("ctx-other"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dataflows/ctx-abc/start")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pass_through_mode_allows_pathless_route_without_token() {
    // Contrast with RequireToken: the signaling (PassThrough) policy lets a pathless
    // route through unauthenticated even when auth is enabled.
    let key = TestKey::new("kid-1");
    let provider = Box::new(StaticKeyProvider::new(key.jwk_set.clone()));
    let app = router_without_pc_id(AuthLayer::enabled_with_provider(
        provider,
        TEST_AUDIENCE,
        REQUIRED_SCOPE,
    ));

    let response = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Helpers
// ============================================================================

async fn response_text(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}
