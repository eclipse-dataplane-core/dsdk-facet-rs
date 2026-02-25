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

//! Tests for VaultJwtGenerator

use super::common::*;
use crate::context::ParticipantContext;
use crate::jwt::{JwtGenerator, TokenClaims, VaultJwtGenerator};
use crate::vault::VaultSigningClient;
use base64::Engine;
use chrono::Utc;
use std::sync::Arc;

#[tokio::test]
async fn test_vault_jwt_generator_generates_valid_jwt_structure() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    // Verify JWT has 3 parts
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts: header.payload.signature");

    // Verify header
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");

    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "test-key-1");

    // Verify payload
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");

    assert_eq!(payload["sub"], "user-123");
    assert_eq!(payload["aud"], "test-audience");
    assert_eq!(payload["exp"], now + 3600);
    assert!(payload["iat"].is_i64(), "iat should be set");

    // Verify signature is not empty
    assert!(!parts[2].is_empty(), "Signature should not be empty");
}

#[tokio::test]
async fn test_vault_jwt_generator_uses_transformed_key_name_in_kid() {
    // Mock vault with a specific key name
    let mock_vault = Arc::new(MockVaultSigningClient {
        key_name: "transformed-signing-key".to_string(),
        current_version: 1,
        signature_bytes: vec![0u8; 64], // Mock Ed25519 signature
    });

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    // Decode header and verify kid
    let parts: Vec<&str> = jwt.split('.').collect();
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");

    assert_eq!(
        header["kid"], "transformed-signing-key-1",
        "Kid should use transformed key name"
    );
}

#[tokio::test]
async fn test_vault_jwt_generator_sets_iat_automatically() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let before_generation = Utc::now().timestamp();

    // Set iat to an old value that should be overwritten
    let old_iat = 1609459200; // 2021-01-01
    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .iat(old_iat)
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let after_generation = Utc::now().timestamp();

    // Decode payload and verify iat was set to current time
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");

    let actual_iat = payload["iat"].as_i64().expect("iat should be present");
    assert_ne!(actual_iat, old_iat, "iat should be overwritten");
    assert!(
        actual_iat >= before_generation && actual_iat <= after_generation,
        "iat should be current timestamp, got {}",
        actual_iat
    );
}

#[tokio::test]
async fn test_vault_jwt_generator_with_different_key_versions() {
    // Mock vault with version 3
    let mock_vault = Arc::new(MockVaultSigningClient {
        key_name: "versioned-key".to_string(),
        current_version: 3,
        signature_bytes: vec![0u8; 64], // Mock Ed25519 signature
    });

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    // Verify kid includes version 3
    let parts: Vec<&str> = jwt.split('.').collect();
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");

    assert_eq!(header["kid"], "versioned-key-3", "Kid should include version number");
}

#[tokio::test]
async fn test_vault_jwt_generator_preserves_custom_claims() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();

    let mut custom = serde_json::Map::new();
    custom.insert(
        "scope".to_string(),
        serde_json::Value::String("read:data write:data".to_string()),
    );
    custom.insert("role".to_string(), serde_json::Value::String("admin".to_string()));

    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .custom(custom)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    // Decode payload and verify custom claims are preserved
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");

    assert_eq!(payload["scope"], "read:data write:data");
    assert_eq!(payload["role"], "admin");
}
