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

//! Tests for VaultSigningKeyResolver

use super::common::*;
use crate::context::ParticipantContext;
use crate::jwt::jwtutils::{generate_ed25519_keypair_pem, SigningKeyRecord, VaultSigningKeyResolver};
use crate::jwt::{JwtGenerator, JwtVerifier, KeyFormat, LocalJwtGenerator, SigningAlgorithm, TokenClaims};
use crate::vault::{MemoryVaultClient, VaultClient};
use chrono::Utc;
use std::sync::Arc;

#[tokio::test]
async fn test_vault_signing_key_resolver_successful_resolution() {
    // Setup vault client with a stored key
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    // Create and store a SigningKeyRecord as JSON in the vault
    let key_record = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record_json = serde_json::to_string(&key_record).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc, "signing-key", &key_record_json)
        .await
        .expect("Failed to store secret");

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );

    // Create generator with vault resolver
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    // Generate token
    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verify the token with the public key
    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let verified_claims = verifier
        .verify_token(&pc, token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-123");
    assert_eq!(verified_claims.iss, "did:web:example.com");
}

#[tokio::test]
async fn test_vault_signing_key_resolver_missing_key() {
    // Setup vault client without storing a key
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("missing-key")
            .build(),
    );

    // Create generator with vault resolver
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    // Attempt to generate token should fail
    let result = generator.generate_token(&pc, claims).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Failed to resolve signing key from vault"),
        "Error message should mention vault resolution failure"
    );
}

#[tokio::test]
async fn test_vault_signing_key_resolver_different_participants() {
    // Setup vault client with keys for different participants
    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");

    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc1 = ParticipantContext::builder()
        .id("participant-1")
        .identifier("did:web:example.com")
        .audience("audience-1")
        .build();

    let pc2 = ParticipantContext::builder()
        .id("participant-2")
        .identifier("did:web:example.com")
        .audience("audience-2")
        .build();

    // Create and store SigningKeyRecords as JSON for each participant
    let key_record1 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair1.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record1_json = serde_json::to_string(&key_record1).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc1, "signing-key", &key_record1_json)
        .await
        .expect("Failed to store secret for participant 1");

    let key_record2 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair2.private_key).unwrap())
        .kid("did:web:example.com#key-2")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record2_json = serde_json::to_string(&key_record2).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc2, "signing-key", &key_record2_json)
        .await
        .expect("Failed to store secret for participant 2");

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );

    // Create generator
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();

    // Generate token for participant 1
    let claims1 = TokenClaims::builder()
        .sub("user-123")
        .aud("audience-1")
        .exp(now + 10000)
        .build();

    let token1 = generator
        .generate_token(&pc1, claims1)
        .await
        .expect("Token generation for participant 1 should succeed");

    // Generate token for participant 2
    let claims2 = TokenClaims::builder()
        .sub("user-456")
        .aud("audience-2")
        .exp(now + 10000)
        .build();

    let token2 = generator
        .generate_token(&pc2, claims2)
        .await
        .expect("Token generation for participant 2 should succeed");

    // Verify token 1 with keypair 1
    let verifier1 = create_test_verifier(keypair1.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified_claims1 = verifier1
        .verify_token(&pc1, token1.as_str())
        .expect("Token 1 verification should succeed");
    assert_eq!(verified_claims1.sub, "user-123");

    // Verify token 2 with keypair 2
    let verifier2 = create_test_verifier(keypair2.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified_claims2 = verifier2
        .verify_token(&pc2, token2.as_str())
        .expect("Token 2 verification should succeed");
    assert_eq!(verified_claims2.sub, "user-456");

    // Verify token 1 with keypair 2 should fail
    let result = verifier2.verify_token(&pc1, token1.as_str());
    assert!(result.is_err());
}
