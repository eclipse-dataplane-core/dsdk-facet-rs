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

use std::time::Duration;

use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters, OctetKeyPairType,
    PublicKeyUse,
};
use rand::RngCore;
use siglet::server::auth::{AuthError, HttpKeyProvider, KeyProvider};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const JWKS_PATH: &str = "/.well-known/jwks.json";

// ============================================================================
// HttpKeyProvider — TTL caching
// ============================================================================

/// A second `jwks()` call within the TTL must not trigger a second HTTP request —
/// the response is served from the in-memory cache.
#[tokio::test]
async fn cache_hit_within_ttl_avoids_second_fetch() {
    let server = MockServer::start().await;
    let key = TestKey::new("kid-1");

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(jwks_response(&key))
        .expect(1)
        .mount(&server)
        .await;

    let p = provider(&server, Duration::from_secs(300));
    p.jwks().await.unwrap();
    p.jwks().await.unwrap(); // served from cache — MockServer verifies expect(1) on drop
}

/// Once the TTL elapses, the next `jwks()` call must re-fetch from the endpoint.
#[tokio::test]
async fn cache_miss_after_ttl_triggers_refetch() {
    let server = MockServer::start().await;
    let key = TestKey::new("kid-1");

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(jwks_response(&key))
        .expect(2)
        .mount(&server)
        .await;

    let p = provider(&server, Duration::from_millis(10));
    p.jwks().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // outlast TTL
    p.jwks().await.unwrap();
}

// ============================================================================
// HttpKeyProvider — key rotation via fetch_jwks
// ============================================================================

/// When a `kid` is absent from the cached JWKS, `fetch_jwks` must force one
/// refresh and return the updated set that contains the rotated key.
#[tokio::test]
async fn kid_miss_triggers_force_refresh_and_finds_rotated_key() {
    let server = MockServer::start().await;
    let key_a = TestKey::new("kid-a");
    let key_b = TestKey::new("kid-b");

    let p = provider(&server, Duration::from_secs(300));

    // Seed the cache with JWKS containing kid-a only.
    {
        let _guard = Mock::given(method("GET"))
            .and(path(JWKS_PATH))
            .respond_with(jwks_response(&key_a))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        p.jwks().await.unwrap();
    }

    // Cache is warm (TTL far off) but kid-b is absent. fetch_jwks must force a
    // refresh; the rotated endpoint response contains kid-b.
    {
        let _guard = Mock::given(method("GET"))
            .and(path(JWKS_PATH))
            .respond_with(jwks_response(&key_b))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let jwks = p.fetch_jwks("kid-b").await.unwrap();
        assert!(jwks.find("kid-b").is_some(), "refreshed JWKS should contain kid-b");
    }
}

/// When the kid is absent even after the forced refresh, `fetch_jwks` returns
/// the refreshed set unchanged — `verify_jwt` is responsible for converting the
/// absence into a `KidNotInJwks` error.
#[tokio::test]
async fn kid_miss_force_refresh_still_absent_returns_refreshed_set() {
    let server = MockServer::start().await;
    let key = TestKey::new("kid-known");

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(jwks_response(&key))
        .expect(2) // initial seed + forced refresh
        .mount(&server)
        .await;

    let p = provider(&server, Duration::from_secs(300));
    p.jwks().await.unwrap(); // seed cache
    let jwks = p.fetch_jwks("kid-unknown").await.unwrap();
    assert!(jwks.find("kid-unknown").is_none());
}

// ============================================================================
// HttpKeyProvider — error paths
// ============================================================================

/// A non-2xx response from the JWKS endpoint must surface as `AuthError::JwksFetch`.
#[tokio::test]
async fn fetch_returns_error_on_non_200_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let p = provider(&server, Duration::from_secs(300));
    assert!(matches!(p.jwks().await, Err(AuthError::JwksFetch(_))));
}

/// A malformed (non-JSON) response body must surface as `AuthError::JwksFetch`.
#[tokio::test]
async fn fetch_returns_error_on_invalid_json() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .mount(&server)
        .await;

    let p = provider(&server, Duration::from_secs(300));
    assert!(matches!(p.jwks().await, Err(AuthError::JwksFetch(_))));
}

// ============================================================================
// Helpers
// ============================================================================

fn provider(server: &MockServer, ttl: Duration) -> HttpKeyProvider {
    HttpKeyProvider::new(format!("{}{}", server.uri(), JWKS_PATH), ttl, reqwest::Client::new())
}

fn jwks_response(key: &TestKey) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(&key.jwk_set)
}

struct TestKey {
    jwk_set: JwkSet,
}

impl TestKey {
    fn new(kid: &str) -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let x_b64 = base64_url(signing_key.verifying_key().to_bytes().as_slice());

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
            jwk_set: JwkSet { keys: vec![jwk] },
        }
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
