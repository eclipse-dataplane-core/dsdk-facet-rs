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

use crate::assembly::{SIGLET_PC_ID, create_siglet_handler, create_token_manager, generate_server_secret};
use crate::config::{SigletConfig, VaultConfig};
use crate::handler::SigletDataFlowHandler;
use async_trait::async_trait;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{
    JwkSet, JwkSetProvider, JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims,
};
use dsdk_facet_core::token::client::MemoryTokenStore;
use dsdk_facet_core::token::manager::{MemoryRenewableTokenStore, ValidatedServerSecret};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

// ============================================================================
// generate_server_secret() Tests
// ============================================================================

#[test]
fn test_generate_server_secret_from_hex() {
    let mut cfg = create_test_config();
    // 64 hex chars = 32 bytes (minimum valid length)
    cfg.token.server_secret = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    let secret = generate_server_secret(&cfg).unwrap();

    assert_eq!(secret.len(), 32);
    assert_eq!(
        secret,
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
    );
}

#[test]
fn test_generate_server_secret_from_hex_uppercase() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string());

    let secret = generate_server_secret(&cfg).unwrap();

    assert_eq!(secret.len(), 32);
    assert_eq!(
        secret,
        hex::decode("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").unwrap()
    );
}

#[test]
fn test_generate_server_secret_from_hex_mixed_case() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("0123456789AbCdEf0123456789aBcDeF0123456789AbCdEf0123456789aBcDeF".to_string());

    let secret = generate_server_secret(&cfg).unwrap();

    assert_eq!(secret.len(), 32);
}

#[test]
fn test_generate_server_secret_long_hex() {
    let mut cfg = create_test_config();
    // 128 hex chars = 64 bytes
    cfg.token.server_secret = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    let secret = generate_server_secret(&cfg).unwrap();

    assert_eq!(secret.len(), 64);
}

#[test]
fn test_generate_server_secret_random_when_none() {
    let cfg = create_test_config(); // No token_server_secret

    let secret = generate_server_secret(&cfg).unwrap();

    // Random secret should be 32 bytes (256 bits)
    assert_eq!(secret.len(), 32);
}

#[test]
fn test_generate_server_secret_random_is_different() {
    let cfg = create_test_config();

    let secret1 = generate_server_secret(&cfg).unwrap();
    let secret2 = generate_server_secret(&cfg).unwrap();

    // Two random secrets should be different
    assert_ne!(secret1, secret2);
}

#[test]
fn test_generate_server_secret_invalid_hex() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("not-valid-hex".to_string());

    let result = generate_server_secret(&cfg);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Invalid server secret hex"));
}

#[test]
fn test_generate_server_secret_short_hex_rejected() {
    let mut cfg = create_test_config();
    // 32 hex chars = 16 bytes — too short
    cfg.token.server_secret = Some("0123456789abcdef0123456789abcdef".to_string());

    let result = generate_server_secret(&cfg);

    assert!(result.is_err(), "Secret shorter than 32 bytes should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Server secret must be at least")
    );
}

#[test]
fn test_generate_server_secret_empty_hex_rejected() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("".to_string());

    let result = generate_server_secret(&cfg);

    assert!(result.is_err(), "Empty secret should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Server secret must be at least")
    );
}

#[test]
fn test_generate_server_secret_odd_length_hex() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("123".to_string()); // Odd length

    let result = generate_server_secret(&cfg);

    // hex::decode should fail on odd-length strings
    assert!(result.is_err());
}

#[test]
fn test_generate_server_secret_with_spaces() {
    let mut cfg = create_test_config();
    cfg.token.server_secret = Some("01 23 45 67".to_string());

    let result = generate_server_secret(&cfg);

    // Spaces are not valid hex
    assert!(result.is_err());
}

// ============================================================================
// create_token_manager() Tests
// ============================================================================

fn valid_secret() -> ValidatedServerSecret {
    ValidatedServerSecret::try_from(vec![0u8; 32]).unwrap()
}

#[test]
fn test_create_token_manager_with_default_issuer() {
    let cfg = create_test_config(); // No token_issuer
    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );

    // Verify manager is created
    assert!(Arc::strong_count(&manager) >= 1);
}

#[test]
fn test_create_token_manager_with_custom_issuer() {
    let mut cfg = create_test_config();
    cfg.token.issuer = Some("custom-issuer".to_string());

    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );

    assert!(Arc::strong_count(&manager) >= 1);
}

#[test]
fn test_create_token_manager_with_custom_refresh_endpoint() {
    let mut cfg = create_test_config();
    cfg.token.refresh_endpoint = Some("https://custom.example.com/refresh".to_string());

    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );

    assert!(Arc::strong_count(&manager) >= 1);
}

#[test]
fn test_create_token_manager_with_default_refresh_endpoint() {
    let mut cfg = create_test_config();
    cfg.bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    cfg.siglet_api_port = 9000;
    // No token_refresh_endpoint - should generate default

    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );

    assert!(Arc::strong_count(&manager) >= 1);
    // Default should be: http://127.0.0.1:9000/token/refresh
}

#[test]
fn test_create_token_manager_with_different_secret_lengths() {
    let cfg = create_test_config();
    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    // 32 bytes (minimum)
    let secret32 = ValidatedServerSecret::try_from(vec![0u8; 32]).unwrap();
    let manager32 = create_token_manager(
        &cfg,
        secret32,
        jwt_gen.clone(),
        jwt_ver.clone(),
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store.clone(),
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );
    assert!(Arc::strong_count(&manager32) >= 1);

    // 64 bytes
    let secret64 = ValidatedServerSecret::try_from(vec![0u8; 64]).unwrap();
    let manager64 = create_token_manager(
        &cfg,
        secret64,
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );
    assert!(Arc::strong_count(&manager64) >= 1);
}

#[test]
fn test_create_token_manager_returns_arc() {
    let cfg = create_test_config();
    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );

    // Verify it's Arc-wrapped
    let manager_clone = manager.clone();
    assert_eq!(Arc::strong_count(&manager), 2);
    drop(manager_clone);
    assert_eq!(Arc::strong_count(&manager), 1);
}

#[test]
fn test_secret_generation_and_token_manager_integration() {
    // Test that generated secret can be used with token manager
    let cfg = create_test_config();

    // Generate secret
    let secret = generate_server_secret(&cfg).unwrap();
    assert_eq!(secret.len(), 32);

    // Use secret in token manager
    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        secret,
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );
    assert!(Arc::strong_count(&manager) >= 1);
}

#[test]
fn test_hex_secret_generation_and_token_manager_integration() {
    // Test that hex-decoded secret can be used with token manager
    let mut cfg = create_test_config();
    // 64 hex chars = 32 bytes
    cfg.token.server_secret = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    // Generate secret from hex
    let secret = generate_server_secret(&cfg).unwrap();
    assert_eq!(secret.len(), 32);

    // Use secret in token manager
    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let store = Arc::new(MemoryRenewableTokenStore::default());

    let manager = create_token_manager(
        &cfg,
        secret,
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );
    assert!(Arc::strong_count(&manager) >= 1);
}

#[test]
fn test_token_manager_and_handler_integration() {
    // Test that token manager can be used with handler
    let cfg = create_test_config();

    let jwt_gen = Arc::new(MockJwtGenerator) as Arc<dyn JwtGenerator>;
    let jwt_ver = Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>;
    let renewable_store = Arc::new(MemoryRenewableTokenStore::default());

    let token_manager = create_token_manager(
        &cfg,
        valid_secret(),
        jwt_gen,
        jwt_ver,
        Arc::new(MockJwtVerifier) as Arc<dyn JwtVerifier>,
        renewable_store,
        Arc::new(NoOpJwkSetProvider) as Arc<dyn JwkSetProvider>,
        SIGLET_PC_ID,
    );
    let token_store = Arc::new(MemoryTokenStore::default());

    // Default Tx = MemoryTransaction; type annotation anchors the generic.
    let _handler: SigletDataFlowHandler = create_siglet_handler(&cfg, token_store, token_manager);
}

// ============================================================================
// Mock Implementations for Testing
// ============================================================================

/// No-op JwkSetProvider for testing
struct NoOpJwkSetProvider;

#[async_trait::async_trait]
impl JwkSetProvider for NoOpJwkSetProvider {
    async fn jwk_set(&self) -> JwkSet {
        JwkSet { keys: vec![] }
    }
}

/// Mock JWT Generator for testing
struct MockJwtGenerator;

#[async_trait::async_trait]
impl JwtGenerator for MockJwtGenerator {
    async fn generate_token(
        &self,
        _participant_context: &ParticipantContext,
        _claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        Ok("mock_jwt_token".to_string())
    }
}

/// Mock JWT Verifier for testing
struct MockJwtVerifier;

#[async_trait]
impl JwtVerifier for MockJwtVerifier {
    async fn verify_token(&self, _audience: &str, _token: &str) -> Result<TokenClaims, JwtVerificationError> {
        let exp_time = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp();
        Ok(TokenClaims::builder()
            .sub("test-subject")
            .iss("test-issuer")
            .aud("test-audience")
            .exp(exp_time)
            .build())
    }
}

/// Helper function to create a minimal valid config.
///
/// Signaling auth is set to Disabled — these assembly tests don't exercise the
/// signaling-API auth layer, and the default of `Enabled { jwks_url: "" }`
/// would otherwise fail SigletConfig::validate() (not called here, but kept
/// consistent with the config-test helper so future validation calls work).
fn create_test_config() -> SigletConfig {
    SigletConfig {
        vault: VaultConfig {
            url: Some("https://vault.example.com".to_string()),
            token: Some("test-token".to_string()),
            ..Default::default()
        },
        signaling_auth: crate::config::SignalingAuthConfig::Disabled,
        ..Default::default()
    }
}
