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

use base64::Engine;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerator, TokenClaims, VaultJwtGenerator};
use dsdk_facet_core::vault::{PublicKeyFormat, VaultSigningClient};
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, JwtKidTransformer, VaultAuthConfig};
use dsdk_facet_testcontainers::{
    keycloak::setup_keycloak_container, utils::create_network, vault::setup_vault_container,
};
use serde_json::json;
use std::sync::Arc;

// Test constants
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MULTIBASE_KEY_MIN_LENGTH: usize = 40;
const MULTIBASE_KEY_MAX_LENGTH: usize = 60;
const TEST_TIMESTAMP_IAT: i64 = 1234567890;
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

/// Integration test for HashicorpVaultClient signing functionality using Transit engine
///
/// This test verifies that:
/// 1. The signing key is automatically created during initialization if it doesn't exist
/// 2. Content can be signed using the Transit engine
/// 3. A valid signature is returned
/// 4. Key name transformer correctly transforms the key name in metadata and JWT kid
#[tokio::test]
async fn test_vault_signing_with_transit() {
    // ============================================================================
    // SETUP: Start containers (expensive operation - only done once)
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
    // Initialize Vault client with key name transformer
    // ============================================================================
    let ctx = create_test_context();

    // Create transformer that adds prefix to JWT kid
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

    let mut client = HashicorpVaultClient::new(config).expect("Failed to create Vault client");

    // Initialize should create the signing key automatically
    client.initialize().await.expect("Failed to initialize Vault client");

    // Wrap client in Arc for use throughout the test
    let client = Arc::new(client);

    // ============================================================================
    // Run all test scenarios with the initialized client
    // ============================================================================
    test_key_metadata_multibase(&client, &ctx).await;
    test_key_metadata_base64url(&client, &ctx).await;
    test_content_signing_determinism(&client, &ctx).await;
    test_jwt_generation(&client, &ctx).await;
}

/// Test key metadata retrieval in Multibase format
async fn test_key_metadata_multibase(client: &Arc<HashicorpVaultClient>, ctx: &ParticipantContext) {
    let metadata = client
        .get_key_metadata(ctx, PublicKeyFormat::Multibase)
        .await
        .expect("Failed to get key metadata");

    let expected_transformed_name = format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME);

    assert_eq!(
        metadata.key_name, expected_transformed_name,
        "Key name should be transformed with prefix"
    );
    assert!(!metadata.keys.is_empty(), "Should have at least one key");
    assert_eq!(
        metadata.current_version, INITIAL_KEY_VERSION,
        "Current version should be {} for a newly created key", INITIAL_KEY_VERSION
    );

    // Verify the key is in multibase format (should start with 'z' for base58btc encoding)
    let first_key = &metadata.keys[0];
    assert!(
        first_key.starts_with('z'),
        "Public key should be in multibase format starting with 'z', got: {}",
        first_key
    );

    // Verify the key has a reasonable length
    // Ed25519 public key is 32 bytes + multicodec prefix 2 bytes = 34 bytes
    // Base58btc encoding of 34 bytes should be around 46-48 characters plus the 'z' prefix
    assert!(
        first_key.len() > MULTIBASE_KEY_MIN_LENGTH && first_key.len() < MULTIBASE_KEY_MAX_LENGTH,
        "Public key length seems incorrect: {}",
        first_key.len()
    );
}

/// Test key metadata retrieval in Base64Url format
async fn test_key_metadata_base64url(client: &Arc<HashicorpVaultClient>, ctx: &ParticipantContext) {
    let metadata = client
        .get_key_metadata(ctx, PublicKeyFormat::Base64Url)
        .await
        .expect("Failed to get key metadata in Base64Url format");

    let expected_transformed_name = format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME);

    assert_eq!(
        metadata.key_name, expected_transformed_name,
        "Key name should be transformed with prefix for Base64Url format"
    );
    assert!(!metadata.keys.is_empty(), "Should have at least one key in Base64Url format");
    assert_eq!(
        metadata.current_version, INITIAL_KEY_VERSION,
        "Current version should be {} for Base64Url format", INITIAL_KEY_VERSION
    );

    // Verify the key is in base64url format (should NOT start with 'z')
    let first_key = &metadata.keys[0];
    assert!(
        !first_key.starts_with('z'),
        "Public key in Base64Url format should NOT start with 'z', got: {}",
        first_key
    );

    // Verify it's valid base64url by attempting to decode
    let decoded_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(first_key)
        .expect("Public key should be valid base64url");

    // Verify the decoded key has the right length for Ed25519
    assert_eq!(
        decoded_key.len(),
        ED25519_PUBLIC_KEY_BYTES,
        "Ed25519 public key should be {} bytes, got: {}",
        ED25519_PUBLIC_KEY_BYTES,
        decoded_key.len()
    );
}

/// Test content signing for determinism and uniqueness
async fn test_content_signing_determinism(client: &Arc<HashicorpVaultClient>, ctx: &ParticipantContext) {
    // Create a test payload
    let jwt_payload = json!({
        "sub": "test-subject",
        "iat": TEST_TIMESTAMP_IAT,
        "exp": TEST_TIMESTAMP_EXP,
        "aud": "test-audience",
        "iss": "test-issuer"
    });

    let payload_bytes = serde_json::to_vec(&jwt_payload).expect("Failed to serialize payload");

    // Sign the content
    let signature = client
        .sign_content(ctx, &payload_bytes)
        .await
        .expect("Failed to sign content");

    // Verify we got a signature back
    assert!(!signature.is_empty(), "Signature should not be empty");

    // Ed25519 signatures are 64 bytes
    assert_eq!(
        signature.len(),
        ED25519_SIGNATURE_BYTES,
        "Ed25519 signature should be {} bytes, got: {}",
        ED25519_SIGNATURE_BYTES,
        signature.len()
    );

    // Sign the same content again and verify we get a consistent signature
    // Note: Vault's Ed25519 implementation appears to be deterministic in practice
    let signature2 = client
        .sign_content(ctx, &payload_bytes)
        .await
        .expect("Failed to sign content second time");

    assert_eq!(
        signature, signature2,
        "Same content should produce the same signature with Vault's signing"
    );

    // Sign different content and verify we get a different signature
    let different_payload = json!({
        "sub": "different-subject",
        "iat": TEST_TIMESTAMP_IAT,
        "exp": TEST_TIMESTAMP_EXP,
        "aud": "test-audience",
        "iss": "test-issuer"
    });

    let different_payload_bytes =
        serde_json::to_vec(&different_payload).expect("Failed to serialize different payload");

    let different_signature = client
        .sign_content(ctx, &different_payload_bytes)
        .await
        .expect("Failed to sign different content");

    assert_ne!(
        signature, different_signature,
        "Different content should produce different signatures"
    );
}

/// Test JWT generation and structure validation
async fn test_jwt_generation(client: &Arc<HashicorpVaultClient>, ctx: &ParticipantContext) {
    // Create a VaultJwtGenerator with the vault client
    let jwt_generator = VaultJwtGenerator::builder()
        .signing_client(Arc::clone(client) as Arc<dyn VaultSigningClient>)
        .build();

    // Create token claims
    let claims = TokenClaims::builder()
        .sub("test-subject")
        .aud("test-audience")
        .iss("test-issuer")
        .exp(TEST_TIMESTAMP_EXP)
        .build();

    // Generate the JWT
    let jwt = jwt_generator
        .generate_token(ctx, claims.clone())
        .await
        .expect("Failed to generate JWT");

    // Verify the JWT format (should have 3 parts separated by dots)
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(jwt_parts.len(), 3, "JWT should have 3 parts (header.payload.signature)");

    // Calculate expected kid
    let expected_transformed_name = format!("{}{}", KEY_NAME_TRANSFORMER_PREFIX, TEST_SIGNING_KEY_NAME);
    let expected_kid = format!("{}-{}", expected_transformed_name, INITIAL_KEY_VERSION);

    // Decode and verify the header
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_parts[0])
        .expect("Failed to decode JWT header");
    let header: serde_json::Value = serde_json::from_slice(&header_json)
        .expect("Failed to parse JWT header");

    assert_eq!(header["alg"], "EdDSA", "Algorithm should be EdDSA");
    assert_eq!(header["typ"], "JWT", "Type should be JWT");
    assert_eq!(header["kid"], expected_kid, "Kid should match the calculated kid");

    // Decode and verify the payload
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .expect("Failed to decode JWT payload");
    let decoded_payload: serde_json::Value = serde_json::from_slice(&payload_json)
        .expect("Failed to parse JWT payload");

    assert_eq!(decoded_payload["sub"], "test-subject", "Subject should match");
    assert_eq!(decoded_payload["aud"], "test-audience", "Audience should match");
    assert_eq!(decoded_payload["iss"], "test-issuer", "Issuer should match");
    assert_eq!(decoded_payload["exp"], TEST_TIMESTAMP_EXP, "Expiry should match");
    assert!(decoded_payload["iat"].is_i64(), "IAT should be set by the generator");

    // Verify signature is not empty and is valid base64url
    assert!(!jwt_parts[2].is_empty(), "Signature should not be empty");
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_parts[2])
        .expect("Signature should be valid base64url");

    // Ed25519 signatures are 64 bytes
    assert_eq!(
        signature_bytes.len(), ED25519_SIGNATURE_BYTES,
        "Ed25519 signature should be {} bytes", ED25519_SIGNATURE_BYTES
    );

    // Generate a token with different claims and verify we get a different JWT
    let different_claims = TokenClaims::builder()
        .sub("different-subject")
        .aud("test-audience")
        .iss("test-issuer")
        .exp(TEST_TIMESTAMP_EXP)
        .build();

    let different_jwt = jwt_generator
        .generate_token(ctx, different_claims)
        .await
        .expect("Failed to generate different JWT");

    assert_ne!(jwt, different_jwt, "Different claims should produce different JWTs");
}

