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

use crate::jwt::{DidWebVerificationKeyResolver, JwtVerificationError, KeyFormat, VerificationKeyResolver};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// did_web_to_url — share one resolver per group to avoid repeated reqwest::Client init
// ============================================================================

#[test]
fn test_did_web_to_url_variants() {
    let resolver = DidWebVerificationKeyResolver::builder().build();

    assert_eq!(
        resolver.did_web_to_url("did:web:example.com").unwrap(),
        "https://example.com/.well-known/did.json"
    );
    assert_eq!(
        resolver.did_web_to_url("did:web:example.com:user:alice").unwrap(),
        "https://example.com/user/alice/did.json"
    );
    assert_eq!(
        resolver.did_web_to_url("did:web:example.com%3A3000").unwrap(),
        "https://example.com:3000/.well-known/did.json"
    );
    assert_eq!(
        resolver.did_web_to_url("did:web:example.com%3a8080").unwrap(),
        "https://example.com:8080/.well-known/did.json"
    );
    assert_eq!(
        resolver.did_web_to_url("did:web:example.com%3A3000:user:bob").unwrap(),
        "https://example.com:3000/user/bob/did.json"
    );
    assert_eq!(
        resolver.did_web_to_url("did:web:example.com::user").unwrap(),
        "https://example.com//user/did.json"
    );
}

#[test]
fn test_did_web_to_url_edge_cases() {
    // Invalid format: no did:web prefix
    let resolver = DidWebVerificationKeyResolver::builder().build();
    assert!(matches!(
        resolver.did_web_to_url("example.com"),
        Err(JwtVerificationError::VerificationFailed(_))
    ));

    // HTTP protocol (use_https = false)
    let http_resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();
    assert_eq!(
        http_resolver.did_web_to_url("did:web:localhost%3A3000").unwrap(),
        "http://localhost:3000/.well-known/did.json"
    );
}

// ============================================================================
// find_verification_method — pure data, no resolver or HTTP
// ============================================================================

#[test]
fn test_find_verification_method_scenarios() {
    let did_doc = serde_json::from_value::<crate::jwt::DidDocument>(create_did_document(
        "did:web:example.com",
        "did:web:example.com#key-1",
        &valid_ed25519_multibase(),
    ))
    .unwrap();

    // Fragment suffix match
    assert!(DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-1").is_ok());

    // Exact match on bare id
    let did_doc_bare = serde_json::from_value::<crate::jwt::DidDocument>(json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:web:example.com",
        "verificationMethod": [{
            "id": "key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:example.com",
            "publicKeyMultibase": valid_ed25519_multibase()
        }]
    }))
    .unwrap();
    assert!(DidWebVerificationKeyResolver::find_verification_method(&did_doc_bare, "key-1").is_ok());

    // Not found
    assert!(matches!(
        DidWebVerificationKeyResolver::find_verification_method(&did_doc, "key-2"),
        Err(JwtVerificationError::VerificationFailed(msg)) if msg.contains("not found")
    ));

    // No verification methods in document
    let did_doc_empty = serde_json::from_value::<crate::jwt::DidDocument>(json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:web:example.com"
    }))
    .unwrap();
    assert!(matches!(
        DidWebVerificationKeyResolver::find_verification_method(&did_doc_empty, "key-1"),
        Err(JwtVerificationError::VerificationFailed(msg)) if msg.contains("no verification methods")
    ));
}

// ============================================================================
// verification_method_to_key_material — pure data, no resolver or HTTP
// ============================================================================

#[test]
fn test_verification_method_to_key_material_scenarios() {
    // Valid multibase Ed25519 key
    let vm = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
        "publicKeyMultibase": valid_ed25519_multibase()
    }))
    .unwrap();
    let km = DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "key-1").unwrap();
    assert_eq!(km.kid, "key-1");
    assert_eq!(km.key.len(), 32); // raw 32-byte Ed25519 public key

    // Invalid multibase encoding
    let vm_bad = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
        "publicKeyMultibase": "invalid-multibase-key"
    }))
    .unwrap();
    assert!(DidWebVerificationKeyResolver::verification_method_to_key_material(&vm_bad, "key-1").is_err());

    // JWK format — stored as serialized JSON bytes tagged with KeyFormat::Jwk
    let jwk_value = json!({ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" });
    let vm_jwk = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:example.com",
        "publicKeyJwk": jwk_value,
    }))
    .unwrap();
    let km_jwk = DidWebVerificationKeyResolver::verification_method_to_key_material(&vm_jwk, "key-1").unwrap();
    assert_eq!(km_jwk.kid, "key-1");
    assert_eq!(km_jwk.key_format, KeyFormat::Jwk);
    let roundtrip: serde_json::Value = serde_json::from_slice(&km_jwk.key).unwrap();
    assert_eq!(roundtrip, jwk_value);

    // No key present
    let vm_none = serde_json::from_value::<crate::jwt::VerificationMethod>(json!({
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com"
    }))
    .unwrap();
    assert!(matches!(
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm_none, "key-1"),
        Err(JwtVerificationError::VerificationFailed(msg)) if msg.contains("No supported public key format")
    ));
}

// ============================================================================
// fetch_did_document — one MockServer for all HTTP response scenarios.
// Scoped mounts prevent overlapping matchers on the same path across scenarios.
// ============================================================================

#[tokio::test]
async fn test_fetch_did_document_scenarios() {
    let mock_server = MockServer::start().await;
    let resolver = DidWebVerificationKeyResolver::builder().build();
    let url = format!("{}/.well-known/did.json", mock_server.uri());

    // Scenario: 200 with valid DID document
    {
        let did_doc = create_did_document(
            "did:web:example.com",
            "did:web:example.com#key-1",
            &valid_ed25519_multibase(),
        );
        let _guard = Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
            .expect(1)
            .mount_as_scoped(&mock_server)
            .await;
        let result = resolver.fetch_did_document(&url).await;
        assert!(result.is_ok());
        assert!(result.unwrap().verification_method.is_some());
    }

    // Scenario: 404 not found
    {
        let _guard = Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount_as_scoped(&mock_server)
            .await;
        assert!(matches!(
            resolver.fetch_did_document(&url).await,
            Err(JwtVerificationError::VerificationFailed(msg)) if msg.contains("404")
        ));
    }

    // Scenario: 200 with invalid JSON body
    {
        let _guard = Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .expect(1)
            .mount_as_scoped(&mock_server)
            .await;
        assert!(resolver.fetch_did_document(&url).await.is_err());
    }
}

// ============================================================================
// resolve_key — one MockServer for all scenarios.
// Permanent mounts are used for paths that don't conflict; scoped mounts for
// scenarios that share the same path but need different responses.
// ============================================================================

#[tokio::test]
async fn test_resolve_key_scenarios() {
    let mock_server = MockServer::start().await;
    let resolver = DidWebVerificationKeyResolver::builder().use_https(false).build();

    let host = mock_server.address().to_string().replace(":", "%3A");
    let did = format!("did:web:{}", host);
    let key_id = format!("{}#key-1", did);
    let did_doc = create_did_document(&did, &key_id, &valid_ed25519_multibase());

    // Mount /.well-known/did.json once — serves all well-known scenarios below.
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    // Mount /users/alice/did.json for the with-path scenario (non-conflicting path).
    let did_alice = format!("did:web:{}:users:alice", host);
    let kid_alice = format!("{}#signing-key", did_alice);
    Mock::given(method("GET"))
        .and(path("/users/alice/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&create_did_document(
            &did_alice,
            &kid_alice,
            &valid_ed25519_multibase(),
        )))
        .mount(&mock_server)
        .await;

    // Scenario: full DID URL as kid
    assert!(resolver.resolve_key(&did, &key_id).await.is_ok());

    // Scenario: kid with leading # prefix
    assert!(resolver.resolve_key(&did, "#key-1").await.is_ok());

    // Scenario: bare fragment (no # prefix)
    assert!(resolver.resolve_key(&did, "key-1").await.is_ok());

    // Scenario: DID with path component → /users/alice/did.json
    assert!(resolver.resolve_key(&did_alice, "signing-key").await.is_ok());

    // Scenario: HTTPS resolver fails against HTTP mock server
    let https_resolver = DidWebVerificationKeyResolver::builder().use_https(true).build();
    assert!(https_resolver.resolve_key(&did, "key-1").await.is_err());

    // Scenario: kid with no fragment → error before HTTP call
    assert!(matches!(
        resolver.resolve_key(&did, &did).await,
        Err(JwtVerificationError::VerificationFailed(msg)) if msg.contains("must include fragment")
    ));

    // Scenario: non-existent host → network error
    assert!(
        resolver
            .resolve_key("did:web:nonexistent.invalid.domain.test", "key-1")
            .await
            .is_err()
    );
}

/// Verifies the full Ed25519 sign→DID-document-roundtrip→verify path used by the e2e test.
///
/// Specifically:
///   1. Generate a keypair from a fixed seed (same as `CONSUMER_DID_SEED` in the e2e test).
///   2. Encode the public key as multibase (same as `create_consumer_did_document`).
///   3. Sign a JWT with the PKCS#8 DER private key via `LocalJwtGenerator`.
///   4. Decode the multibase key → `DidWebVerificationKeyResolver::verification_method_to_key_material`.
///   5. Verify the JWT using `LocalJwtVerifier` with the resolved `KeyMaterial`.
///
/// This confirms that `DecodingKey::from_ed_der` accepts the bytes returned by
/// `verification_method_to_key_material` and that the sign/verify roundtrip is valid.
#[tokio::test]
async fn test_did_web_sign_verify_roundtrip_via_multibase() {
    use crate::context::ParticipantContext;
    use crate::jwt::test_fixtures::{StaticSigningKeyResolver, generate_ed25519_keypair_der};
    use crate::jwt::{
        DidWebVerificationKeyResolver, JwtGenerator, JwtVerifier, KeyFormat, LocalJwtGenerator, LocalJwtVerifier,
        SigningAlgorithm, TokenClaims, VerificationMethod,
    };
    use crate::util::crypto::convert_to_multibase;
    use base64::Engine as _;
    use std::sync::Arc;

    // Step 1: generate a random Ed25519 keypair
    let keypair = generate_ed25519_keypair_der().expect("keypair generation");

    // Step 2: encode public key as multibase (mirrors create_consumer_did_document)
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&keypair.public_key);
    let public_key_multibase = convert_to_multibase(&public_key_b64).expect("multibase conversion");

    // Step 3: sign a JWT using the PKCS#8 DER private key
    let resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(keypair.private_key)
            .key_format(KeyFormat::DER)
            .kid("did:web:consumer#key-1")
            .build(),
    );
    let generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );
    let now = chrono::Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .iss("did:web:consumer")
        .sub("did:web:consumer")
        .aud("did:web:provider")
        .exp(now + 300)
        .build();
    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:consumer")
        .audience("did:web:provider")
        .build();
    let token = generator.generate_token(&pc, claims).await.expect("token generation");

    // Step 4: decode multibase → KeyMaterial (same path as DidWebVerificationKeyResolver)
    let vm = serde_json::from_value::<VerificationMethod>(serde_json::json!({
        "id": "did:web:consumer#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:consumer",
        "publicKeyMultibase": public_key_multibase,
    }))
    .expect("VerificationMethod deserialization");

    let key_material =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:consumer#key-1")
            .expect("key material extraction");

    // Step 5: verify the JWT
    let static_resolver = Arc::new(
        crate::jwt::test_fixtures::StaticVerificationKeyResolver::builder()
            .key(key_material.key)
            .key_format(key_material.key_format)
            .build(),
    );
    let verifier = LocalJwtVerifier::builder()
        .verification_key_resolver(static_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let result = verifier.verify_token("did:web:provider", &token).await;
    assert!(
        result.is_ok(),
        "JWT verification should succeed: {:?}",
        result.unwrap_err()
    );
    assert_eq!(result.unwrap().sub, "did:web:consumer");
}

/// Mirror of `test_did_web_sign_verify_roundtrip_via_multibase` for the JWK path:
/// confirms that a `publicKeyJwk` (OKP/Ed25519) carried through
/// `verification_method_to_key_material` can be fed to `LocalJwtVerifier` via
/// `DecodingKey::from_jwk` and successfully verifies a JWT signed with the
/// matching private key.
#[tokio::test]
async fn test_did_web_sign_verify_roundtrip_via_jwk() {
    use crate::context::ParticipantContext;
    use crate::jwt::test_fixtures::{StaticSigningKeyResolver, generate_ed25519_keypair_der};
    use crate::jwt::{
        DidWebVerificationKeyResolver, JwtGenerator, JwtVerifier, KeyFormat, LocalJwtGenerator, LocalJwtVerifier,
        SigningAlgorithm, TokenClaims, VerificationMethod,
    };
    use base64::Engine as _;
    use std::sync::Arc;

    // Step 1: generate a random Ed25519 keypair
    let keypair = generate_ed25519_keypair_der().expect("keypair generation");

    // Step 2: base64url-encode the raw 32-byte public key as the JWK `x` parameter
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&keypair.public_key);

    // Step 3: sign a JWT using the PKCS#8 DER private key
    let resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(keypair.private_key)
            .key_format(KeyFormat::DER)
            .kid("did:web:consumer#key-1")
            .build(),
    );
    let generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );
    let now = chrono::Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .iss("did:web:consumer")
        .sub("did:web:consumer")
        .aud("did:web:provider")
        .exp(now + 300)
        .build();
    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:consumer")
        .audience("did:web:provider")
        .build();
    let token = generator.generate_token(&pc, claims).await.expect("token generation");

    // Step 4: build a VerificationMethod containing the JWK and extract KeyMaterial
    let vm = serde_json::from_value::<VerificationMethod>(json!({
        "id": "did:web:consumer#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:web:consumer",
        "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
    }))
    .expect("VerificationMethod deserialization");

    let key_material =
        DidWebVerificationKeyResolver::verification_method_to_key_material(&vm, "did:web:consumer#key-1")
            .expect("key material extraction");
    assert_eq!(key_material.key_format, KeyFormat::Jwk);

    // Step 5: verify the JWT — DecodingKey::from_jwk is exercised inside the verifier
    let static_resolver = Arc::new(
        crate::jwt::test_fixtures::StaticVerificationKeyResolver::builder()
            .key(key_material.key)
            .key_format(key_material.key_format)
            .build(),
    );
    let verifier = LocalJwtVerifier::builder()
        .verification_key_resolver(static_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let result = verifier.verify_token("did:web:provider", &token).await;
    assert!(
        result.is_ok(),
        "JWT verification should succeed: {:?}",
        result.unwrap_err()
    );
    assert_eq!(result.unwrap().sub, "did:web:consumer");
}

// ============================================================================
// Test helpers
// ============================================================================

fn valid_ed25519_multibase() -> String {
    // z prefix indicates base58btc encoding of Ed25519 public key
    // This is a valid 32-byte Ed25519 public key
    "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()
}

fn create_did_document(did: &str, key_id: &str, multibase_key: &str) -> serde_json::Value {
    json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": multibase_key
        }]
    })
}
