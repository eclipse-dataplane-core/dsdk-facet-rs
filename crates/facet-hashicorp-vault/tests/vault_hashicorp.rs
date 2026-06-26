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
use base64::Engine;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerator, PrefixTransitKeyResolver, TokenClaims, VaultJwtGenerator};
use dsdk_facet_core::vault::{PublicKeyFormat, VaultClient, VaultSigningClient};
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, JwtKidTransformer, VaultAuthConfig};
use dsdk_facet_testcontainers::{
    keycloak::setup_keycloak_container, utils::create_network, vault::setup_vault_container,
};
use serde_json::json;
use std::sync::Arc;

// Signing-specific constants
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MULTIBASE_KEY_MIN_LENGTH: usize = 40;
const MULTIBASE_KEY_MAX_LENGTH: usize = 60;
const TEST_TIMESTAMP_EXP: i64 = 1234571490;
const KEY_NAME_TRANSFORMER_PREFIX: &str = "transformed-";
const TEST_SIGNING_KEY_NAME: &str = "test-signing-key";
const INITIAL_KEY_VERSION: usize = 1;

fn create_test_context() -> ParticipantContext {
    ParticipantContext {
        id: "test-id".to_string(),
        identifier: "test-identifier".to_string(),
        audience: "test-audience".to_string(),
    }
}

fn create_signing_test_context() -> ParticipantContext {
    // id = "signing-key" so VaultJwtGenerator derives key "test-signing-key"
    // (prefix "test" + "-" + id "signing-key")
    ParticipantContext {
        id: "signing-key".to_string(),
        identifier: "test-identifier".to_string(),
        audience: "test-audience".to_string(),
    }
}

/// Integration tests for HashicorpVaultClient
///
/// All scenarios are combined in a single test to amortize the expensive container
/// startup time (Vault + Keycloak).
///
/// Scenarios covered:
/// 1. CRUD operations with soft delete (default)
/// 2. Secret not found error handling
/// 3. CRUD operations with hard delete
/// 4. Health check functionality
/// 5. Initialization failure with invalid credentials
#[tokio::test]
async fn test_vault_client_integration() {
    // ============================================================================
    // SETUP: Start containers once for all scenarios
    // ============================================================================
    let network = create_network().await;

    let (keycloak_setup, _keycloak_container) = setup_keycloak_container(&network).await;

    let jwks_url = format!(
        "{}/realms/master/protocol/openid-connect/certs",
        keycloak_setup.keycloak_internal_url
    );
    let (vault_url, _root_token, _vault_container) =
        setup_vault_container(&network, &jwks_url, &keycloak_setup.keycloak_container_id).await;

    // ============================================================================
    // SCENARIO 1: CRUD Operations with Soft Delete (Default)
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Test: Store a secret
        client
            .store_secret(&ctx, "test/path", "my-secret-value")
            .await
            .expect("Failed to store secret");

        // Test: Resolve the secret
        let retrieved = client
            .resolve_secret(&ctx, "test/path")
            .await
            .expect("Failed to resolve secret");
        assert_eq!(retrieved, "my-secret-value");

        // Test: Update the secret
        client
            .store_secret(&ctx, "test/path", "updated-secret-value")
            .await
            .expect("Failed to update secret");

        let updated = client
            .resolve_secret(&ctx, "test/path")
            .await
            .expect("Failed to resolve updated secret");
        assert_eq!(updated, "updated-secret-value");

        // Test: Store another secret at a different path
        client
            .store_secret(&ctx, "test/another", "another-value")
            .await
            .expect("Failed to store another secret");

        let another = client
            .resolve_secret(&ctx, "test/another")
            .await
            .expect("Failed to resolve another secret");
        assert_eq!(another, "another-value");

        // Test: Remove a secret (soft delete)
        client
            .remove_secret(&ctx, "test/path")
            .await
            .expect("Failed to remove secret");

        // Test: Verify secret is gone
        let result = client.resolve_secret(&ctx, "test/path").await;
        assert!(result.is_err(), "Expected error when reading deleted secret");

        // Test: The other secret should still be accessible
        let still_there = client
            .resolve_secret(&ctx, "test/another")
            .await
            .expect("Other secret should still be accessible");
        assert_eq!(still_there, "another-value");
    }

    // ============================================================================
    // SCENARIO 2: Secret Not Found Error Handling
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Try to read a non-existent secret
        let result = client.resolve_secret(&ctx, "nonexistent/path").await;
        assert!(result.is_err(), "Expected error for non-existent secret");

        match result {
            Err(dsdk_facet_core::vault::VaultError::SecretNotFound(identifier)) => {
                assert_eq!(identifier, "nonexistent/path");
            }
            _ => panic!("Expected SecretNotFound error"),
        }
    }

    // ============================================================================
    // SCENARIO 3: CRUD Operations with Hard Delete
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .soft_delete(false)
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Store a secret
        client
            .store_secret(&ctx, "test/hard-delete", "value")
            .await
            .expect("Failed to store secret");

        // Verify it exists
        let value = client.resolve_secret(&ctx, "test/hard-delete").await.unwrap();
        assert_eq!(value, "value");

        // Hard delete the secret
        client
            .remove_secret(&ctx, "test/hard-delete")
            .await
            .expect("Failed to remove secret");

        // Verify it is removed
        let result = client.resolve_secret(&ctx, "test/hard-delete").await;
        assert!(result.is_err(), "Expected error after hard delete");
    }

    // ============================================================================
    // SCENARIO 4: Health Check Functionality
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Client should be healthy immediately after initialization
        assert!(
            client.is_healthy().await,
            "Client should be healthy after initialization"
        );

        // Last error should be None
        let last_error = client.last_error().await.expect("Should get last error");
        assert!(
            last_error.is_none(),
            "Last error should be None after successful initialization"
        );

        // Consecutive failures should be 0
        let failures = client
            .consecutive_failures()
            .await
            .expect("Should get consecutive failures");
        assert_eq!(
            failures, 0,
            "Consecutive failures should be 0 after successful initialization"
        );

        // Verify client can perform operations while healthy
        client
            .store_secret(&ctx, "test/health", "healthy-value")
            .await
            .expect("Healthy client should be able to store secrets");

        let value = client
            .resolve_secret(&ctx, "test/health")
            .await
            .expect("Should resolve secret");
        assert_eq!(value, "healthy-value");
    }

    // ============================================================================
    // SCENARIO 5: Initialization Failure with Invalid Credentials
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: "invalid-client-id".to_string(),
                client_secret: "invalid-secret".to_string(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");

        // Initialization should fail due to invalid credentials
        let init_result = client.initialize().await;
        assert!(
            init_result.is_err(),
            "Initialization should fail with invalid credentials"
        );

        // Client should not be usable after failed initialization
        let resolve_result = client.resolve_secret(&ctx, "test/any").await;
        assert!(
            resolve_result.is_err(),
            "Operations should fail on uninitialized client"
        );
    }

    // ============================================================================
    // SCENARIO 6: Participant Context Isolation
    // ============================================================================
    {
        let ctx1 = ParticipantContext {
            id: "participant-1".to_string(),
            identifier: "participant-1-identifier".to_string(),
            audience: "participant-1-audience".to_string(),
        };

        let ctx2 = ParticipantContext {
            id: "participant-2".to_string(),
            identifier: "participant-2-identifier".to_string(),
            audience: "participant-2-audience".to_string(),
        };

        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .build();

        let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Store secrets for both participants at the same path
        client
            .store_secret(&ctx1, "shared/path", "secret-for-participant-1")
            .await
            .expect("Failed to store secret for participant 1");

        client
            .store_secret(&ctx2, "shared/path", "secret-for-participant-2")
            .await
            .expect("Failed to store secret for participant 2");

        // Each participant should retrieve only their own secret
        let secret1 = client
            .resolve_secret(&ctx1, "shared/path")
            .await
            .expect("Failed to resolve secret for participant 1");
        assert_eq!(secret1, "secret-for-participant-1");

        let secret2 = client
            .resolve_secret(&ctx2, "shared/path")
            .await
            .expect("Failed to resolve secret for participant 2");
        assert_eq!(secret2, "secret-for-participant-2");

        // Remove secret for participant 1
        client
            .remove_secret(&ctx1, "shared/path")
            .await
            .expect("Failed to remove secret for participant 1");

        // Participant 1's secret should be gone
        let result = client.resolve_secret(&ctx1, "shared/path").await;
        assert!(
            result.is_err(),
            "Expected error when reading deleted secret for participant 1"
        );

        // Participant 2's secret should still be accessible
        let secret2_after = client
            .resolve_secret(&ctx2, "shared/path")
            .await
            .expect("Participant 2's secret should still be accessible");
        assert_eq!(secret2_after, "secret-for-participant-2");
    }

    // ============================================================================
    // SCENARIO 7: Transit Signing
    // Reuses the already-running Vault + Keycloak containers from above.
    // (Previously a separate test_vault_signing_with_transit test.)
    // ============================================================================
    {
        let ctx = create_signing_test_context();
        let transformer: JwtKidTransformer = Arc::new(|name| format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, name));

        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .signing_key_name(TEST_SIGNING_KEY_NAME.to_string())
            .jwt_kid_transformer(transformer)
            .build();

        let mut signing_client = HashicorpVaultClient::new(config).expect("Failed to create signing Vault client");
        signing_client
            .initialize()
            .await
            .expect("Failed to initialize signing Vault client");
        let signing_client = Arc::new(signing_client);

        test_key_metadata_multibase(&signing_client).await;
        test_key_metadata_base64url(&signing_client).await;
        test_content_signing_determinism(&signing_client).await;
        test_jwt_generation(&signing_client, &ctx).await;
    }
}

async fn test_key_metadata_multibase(client: &Arc<HashicorpVaultClient>) {
    let metadata = client
        .get_key_metadata(TEST_SIGNING_KEY_NAME, PublicKeyFormat::Multibase)
        .await
        .expect("Failed to get key metadata");

    let expected_name = format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME);
    assert_eq!(metadata.key_name, expected_name, "Key name should be transformed");
    assert!(!metadata.keys.is_empty());
    assert_eq!(metadata.current_version, INITIAL_KEY_VERSION);

    let first_key = &metadata.keys[0];
    assert!(first_key.starts_with('z'), "Multibase key should start with 'z'");
    assert!(
        first_key.len() > MULTIBASE_KEY_MIN_LENGTH && first_key.len() < MULTIBASE_KEY_MAX_LENGTH,
        "Unexpected multibase key length: {}",
        first_key.len()
    );
}

async fn test_key_metadata_base64url(client: &Arc<HashicorpVaultClient>) {
    let metadata = client
        .get_key_metadata(TEST_SIGNING_KEY_NAME, PublicKeyFormat::Base64Url)
        .await
        .expect("Failed to get key metadata in Base64Url format");

    let expected_name = format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME);
    assert_eq!(metadata.key_name, expected_name);
    assert!(!metadata.keys.is_empty());
    assert_eq!(metadata.current_version, INITIAL_KEY_VERSION);

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.keys[0])
        .expect("Key should be valid base64url");
    assert_eq!(
        decoded.len(),
        ED25519_PUBLIC_KEY_BYTES,
        "Ed25519 public key must be 32 bytes"
    );
}

async fn test_content_signing_determinism(client: &Arc<HashicorpVaultClient>) {
    let payload = serde_json::to_vec(&json!({
        "sub": "test-subject", "aud": "test-audience", "iss": "test-issuer",
        "iat": 1234567890i64, "exp": TEST_TIMESTAMP_EXP
    }))
    .expect("Failed to serialize payload");

    let sig1 = client
        .sign_content(TEST_SIGNING_KEY_NAME, &payload)
        .await
        .expect("Failed to sign");
    assert_eq!(sig1.len(), ED25519_SIGNATURE_BYTES);

    let sig2 = client
        .sign_content(TEST_SIGNING_KEY_NAME, &payload)
        .await
        .expect("Failed to sign second time");
    assert_eq!(sig1, sig2, "Same content should produce the same signature");

    let different = serde_json::to_vec(&json!({
        "sub": "different-subject", "aud": "test-audience", "iss": "test-issuer",
        "iat": 1234567890i64, "exp": TEST_TIMESTAMP_EXP
    }))
    .expect("Failed to serialize");
    let sig3 = client
        .sign_content(TEST_SIGNING_KEY_NAME, &different)
        .await
        .expect("Failed to sign different content");
    assert_ne!(sig1, sig3, "Different content should produce different signatures");
}

async fn test_jwt_generation(client: &Arc<HashicorpVaultClient>, ctx: &ParticipantContext) {
    let generator = VaultJwtGenerator::builder()
        .signing_client(Arc::clone(client) as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("test").build()))
        .build();

    let claims = TokenClaims::builder()
        .sub("test-subject")
        .aud("test-audience")
        .iss("test-issuer")
        .exp(TEST_TIMESTAMP_EXP)
        .build();

    let jwt = generator
        .generate_token(ctx, claims.clone())
        .await
        .expect("Failed to generate JWT");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");

    let expected_kid = format!(
        "{}{}-{}",
        KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME, INITIAL_KEY_VERSION
    );

    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("Failed to decode header"),
    )
    .expect("Failed to parse header");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], expected_kid);

    let payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("Failed to decode payload"),
    )
    .expect("Failed to parse payload");
    assert_eq!(payload["sub"], "test-subject");
    assert_eq!(payload["aud"], "test-audience");
    assert_eq!(payload["iss"], "test-issuer");
    assert_eq!(payload["exp"], TEST_TIMESTAMP_EXP);
    assert!(payload["iat"].is_i64());

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("Signature must be valid base64url");
    assert_eq!(sig_bytes.len(), ED25519_SIGNATURE_BYTES);

    // Different claims → different JWT
    let other = TokenClaims::builder()
        .sub("different-subject")
        .aud("test-audience")
        .iss("test-issuer")
        .exp(TEST_TIMESTAMP_EXP)
        .build();
    let other_jwt = generator
        .generate_token(ctx, other)
        .await
        .expect("Failed to generate second JWT");
    assert_ne!(jwt, other_jwt);
}
