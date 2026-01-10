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

use crate::token::jwt::{KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm, VerificationKeyResolver};
use crate::token::tests::jwt_fixtures::{
    generate_ed25519_keypair_der, generate_ed25519_keypair_pem, generate_rsa_keypair_pem,
};
use crate::token::{JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use chrono::Utc;
use rstest::rstest;
use std::sync::Arc;

#[rstest]
#[case(KeyFormat::PEM)]
#[case(KeyFormat::DER)]
fn test_token_generation_validation(#[case] key_format: KeyFormat) {
    let keypair = match key_format {
        KeyFormat::PEM => generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair"),
        KeyFormat::DER => generate_ed25519_keypair_der().expect("Failed to generate DER keypair"),
    };

    let private_key = keypair.private_key.clone();
    let public_key = keypair.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(key_format)
        .signing_key_resolver(Arc::new(move |_| private_key.clone()))
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(now)
        .exp(now + 10000)
        .custom({
            let mut custom = serde_json::Map::new();
            custom.insert(
                "access_token".to_string(),
                serde_json::Value::String("token-value".to_string()),
            );
            custom
        })
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    let verifier = LocalJwtVerifier::builder()
        .key_format(key_format)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let verified_claims = verifier
        .verify_token("participant1", token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-123");
    assert_eq!(verified_claims.iss, "user-id-123");
    assert_eq!(verified_claims.iat, now);
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(
        verified_claims.custom.get("access_token").unwrap(),
        &serde_json::Value::String("token-value".to_string())
    );
}

#[test]
fn test_expired_token_validation_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let private_key = keypair.private_key.clone();
    let public_key = keypair.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key.clone()))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(now - 20000)
        .exp(now - 10000) // Expired 10,000 seconds ago
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let result = verifier.verify_token("participant1", token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[test]
fn test_leeway_allows_recently_expired_token_pem() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let private_key = keypair.private_key.clone();
    let public_key = keypair.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key.clone()))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-789")
        .iss("issuer-leeway")
        .aud("audience-123")
        .iat(now - 100)
        .exp(now - 20) // Expired 20 seconds ago
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway (default) should accept token expired 20 seconds ago
    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .leeway_seconds(30)
        .build();

    let verified_claims = verifier
        .verify_token("participant1", token.as_str())
        .expect("Token should be valid with leeway");

    assert_eq!(verified_claims.sub, "user-id-789");
    assert_eq!(verified_claims.iss, "issuer-leeway");
}

#[test]
fn test_leeway_rejects_token_expired_beyond_leeway_pem() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let private_key = keypair.private_key.clone();
    let public_key = keypair.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key.clone()))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-999")
        .iss("issuer-expired")
        .aud("audience-123")
        .iat(now - 200)
        .exp(now - 100) // Expired 100 seconds ago
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway should reject token expired 100 seconds ago
    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .leeway_seconds(30)
        .build();

    let result = verifier.verify_token("participant1", token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[test]
fn test_invalid_signature_pem_eddsa() {
    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");

    let private_key1 = keypair1.private_key.clone();
    let public_key2 = keypair2.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key1.clone()))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(now)
        .exp(now + 10000)
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    // Try to verify with a different public key
    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key2)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let result = verifier.verify_token("participant1", token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidSignature));
}

#[test]
fn test_malformed_token_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let public_key = keypair.public_key.clone();

    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let malformed_tokens = vec![
        "not.a.token",
        "invalid-token",
        "",
        "header.payload", // Missing signature
    ];

    for malformed_token in malformed_tokens {
        let result = verifier.verify_token("participant1", malformed_token);
        assert!(result.is_err(), "Token '{}' should fail validation", malformed_token);
        // Malformed tokens can return either InvalidFormat or VerificationFailed
        match result.unwrap_err() {
            JwtVerificationError::InvalidFormat | JwtVerificationError::VerificationFailed(_) => {}
            other => panic!("Expected InvalidFormat or VerificationFailed, got {:?}", other),
        }
    }
}

#[test]
fn test_mismatched_key_format_pem_eddsa() {
    let keypair_pem = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");
    let private_key_pem = keypair_pem.private_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key_pem.clone()))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(now)
        .exp(now + 10000)
        .build();

    let token = generator
        .generate_token("participant-1", claims)
        .expect("Token generation should succeed");

    let keypair_der = generate_ed25519_keypair_der().expect("Failed to generate DER keypair");
    let public_key_der = keypair_der.public_key.clone();

    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::DER)
        .verification_key_resolver(Arc::new(StaticResolver(public_key_der)))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let result = verifier.verify_token("participant1", token.as_str());

    // This should fail because we're using a different keypair
    assert!(result.is_err());
}

#[test]
fn test_rsa_token_generation_validation_pem() {
    let keypair = generate_rsa_keypair_pem().expect("Failed to generate RSA PEM keypair");
    let private_key = keypair.private_key.clone();
    let public_key = keypair.public_key.clone();

    let generator = LocalJwtGenerator::builder()
        .key_format(KeyFormat::PEM)
        .signing_key_resolver(Arc::new(move |_| private_key.clone()))
        .signing_algorithm(SigningAlgorithm::RS256)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-456")
        .iss("issuer-rsa")
        .aud("audience-123")
        .iat(now)
        .exp(now + 10000)
        .custom({
            let mut custom = serde_json::Map::new();
            custom.insert("scope".to_string(), serde_json::Value::String("read:data".to_string()));
            custom
        })
        .build();

    let token = generator
        .generate_token("participant-rsa", claims)
        .expect("Token generation should succeed");

    let verifier = LocalJwtVerifier::builder()
        .key_format(KeyFormat::PEM)
        .verification_key_resolver(Arc::new(StaticResolver(public_key)))
        .signing_algorithm(SigningAlgorithm::RS256)
        .build();

    let verified_claims = verifier
        .verify_token("participant1", token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-456");
    assert_eq!(verified_claims.iss, "issuer-rsa");
    assert_eq!(verified_claims.iat, now);
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(
        verified_claims.custom.get("scope").unwrap(),
        &serde_json::Value::String("read:data".to_string())
    );
}

struct StaticResolver(Vec<u8>);

impl VerificationKeyResolver for StaticResolver {
    fn resolve_verification_key(&self, _: &str, _: &str) -> Result<Vec<u8>, JwtVerificationError> {
        Ok(self.0.clone())
    }
}
