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
#[cfg(test)]
mod mem;

#[cfg(test)]
mod token_manager;

use super::{JwtTokenManager, TokenManager, ValidatedServerSecret};
use crate::jwt::{JwkSet, JwkSetProvider, JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier};
use crate::token::manager::MemoryRenewableTokenStore;
use crate::util::clock::{Clock, MockClock};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use std::sync::Arc;

// Mock JWT generator for testing
struct MockJwtGenerator;

#[async_trait]
impl JwtGenerator for MockJwtGenerator {
    async fn generate_token(
        &self,
        _participant_context: &crate::context::ParticipantContext,
        _claims: crate::jwt::TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        Ok("mock_jwt_token".to_string())
    }
}

// JWT generator that records the id of each participant context it signs for and returns a fixed
// token. Used to assert which participant context each signing path uses.
struct RecordingJwtGenerator {
    signed_ids: std::sync::Mutex<Vec<String>>,
    token: String,
}

impl RecordingJwtGenerator {
    fn new(token: &str) -> Self {
        Self {
            signed_ids: std::sync::Mutex::new(Vec::new()),
            token: token.to_string(),
        }
    }
}

#[async_trait]
impl JwtGenerator for RecordingJwtGenerator {
    async fn generate_token(
        &self,
        participant_context: &crate::context::ParticipantContext,
        _claims: crate::jwt::TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        self.signed_ids.lock().unwrap().push(participant_context.id.clone());
        Ok(self.token.clone())
    }
}

// Verifier that returns the subject and embedded token expected by `renew`.
struct RenewMockVerifier {
    subject: String,
    embedded_token: String,
}

#[async_trait]
impl JwtVerifier for RenewMockVerifier {
    async fn verify_token(&self, _aud: &str, _token: &str) -> Result<crate::jwt::TokenClaims, JwtVerificationError> {
        let mut custom = serde_json::Map::new();
        custom.insert("token".to_string(), Value::String(self.embedded_token.clone()));
        Ok(crate::jwt::TokenClaims::builder()
            .iss("test")
            .sub(&self.subject)
            .aud("test_audience")
            .exp(9999999999)
            .custom(custom)
            .build())
    }
}

// Mock JWK set provider for testing
pub(super) struct MockJwkSetProvider;

#[async_trait]
impl JwkSetProvider for MockJwkSetProvider {
    async fn jwk_set(&self) -> JwkSet {
        JwkSet { keys: vec![] }
    }
}

// Mock JWT verifier for testing
struct MockJwtVerifier;

#[async_trait]
impl JwtVerifier for MockJwtVerifier {
    async fn verify_token(&self, _aud: &str, _token: &str) -> Result<crate::jwt::TokenClaims, JwtVerificationError> {
        Ok(crate::jwt::TokenClaims::builder()
            .iss("test")
            .sub("test_subject")
            .aud("test_audience")
            .exp(9999999999)
            .build())
    }
}

fn create_test_manager() -> JwtTokenManager {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let secret = ValidatedServerSecret::try_from(b"test_secret_key_32bytes_long!!!!".to_vec()).unwrap();
    JwtTokenManager::builder()
        .issuer("test_issuer")
        .refresh_endpoint("http://localhost/refresh")
        .server_secret(secret)
        .token_duration(3600)
        .renewal_token_duration(86400)
        .clock(Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>)
        .token_store(Arc::new(MemoryRenewableTokenStore::new()))
        .token_generator(Arc::new(MockJwtGenerator))
        .client_verifier(Arc::new(MockJwtVerifier))
        .provider_verifier(Arc::new(MockJwtVerifier))
        .jwk_set_provider(Arc::new(MockJwkSetProvider))
        .build()
}

#[tokio::test]
async fn test_generate_pair_and_renew_both_sign_with_issuer_context() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let generator = Arc::new(RecordingJwtGenerator::new("signed-token"));
    let manager = JwtTokenManager::builder()
        .issuer("test_issuer")
        .refresh_endpoint("http://localhost/refresh")
        .server_secret(ValidatedServerSecret::try_from(b"test_secret_key_32bytes_long!!!!".to_vec()).unwrap())
        .token_duration(3600)
        .renewal_token_duration(86400)
        .clock(Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>)
        .token_store(Arc::new(MemoryRenewableTokenStore::new()))
        .token_generator(generator.clone())
        .client_verifier(Arc::new(RenewMockVerifier {
            subject: "did:web:consumer.com".to_string(),
            embedded_token: "signed-token".to_string(),
        }))
        .provider_verifier(Arc::new(MockJwtVerifier))
        .jwk_set_provider(Arc::new(MockJwkSetProvider))
        .build();

    // Signaling mint: a dynamic participant context is passed in, but server-side signing uses the
    // issuer context.
    let pc = ParticipantContext::builder()
        .id("participant-A")
        .identifier("did:web:provider.com")
        .audience("did:web:provider.com")
        .build();
    let pair = manager
        .generate_pair(&pc, "did:web:consumer.com", HashMap::new(), "flow-1".to_string())
        .await
        .expect("generate_pair should succeed");

    // Renewal (server side): also signs with the issuer context, not the participant context. The
    // participant-context binding is used only on the client side (`OAuth2TokenClient`).
    manager
        .renew("bound-token", &pair.refresh_token)
        .await
        .expect("renew should succeed");

    let ids = generator.signed_ids.lock().unwrap().clone();
    assert_eq!(
        ids,
        vec!["test_issuer".to_string(), "test_issuer".to_string()],
        "both generate_pair and renew sign with the issuer context on the server side"
    );
}

#[test]
fn test_create_renewal_token_generates_valid_hex() {
    let manager = create_test_manager();

    let result = manager.create_renewal_token();
    assert!(result.is_ok(), "create_renewal_token should succeed");

    let (token, hash) = result.unwrap();

    // Token should be 64 hex characters (32 bytes * 2)
    assert_eq!(token.len(), 64, "Token should be 64 hex characters");
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "Token should only contain hex digits"
    );

    // Hash should be 64 hex characters (SHA256 output)
    assert_eq!(hash.len(), 64, "Hash should be 64 hex characters");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash should only contain hex digits"
    );
}

#[test]
fn test_create_renewal_token_generates_unique_tokens() {
    let manager = create_test_manager();

    let (token1, hash1) = manager.create_renewal_token().unwrap();
    let (token2, hash2) = manager.create_renewal_token().unwrap();
    let (token3, hash3) = manager.create_renewal_token().unwrap();

    // Tokens should be unique
    assert_ne!(token1, token2, "Tokens should be unique");
    assert_ne!(token2, token3, "Tokens should be unique");
    assert_ne!(token1, token3, "Tokens should be unique");

    // Hashes should be unique
    assert_ne!(hash1, hash2, "Hashes should be unique");
    assert_ne!(hash2, hash3, "Hashes should be unique");
    assert_ne!(hash1, hash3, "Hashes should be unique");
}

#[test]
fn test_create_renewal_token_hash_matches() {
    let manager = create_test_manager();

    let (token, hash_from_create) = manager.create_renewal_token().unwrap();

    // Manually hash the token and verify it matches
    let hash_manual = manager.hash(&token).unwrap();

    assert_eq!(
        hash_from_create, hash_manual,
        "Hash from create_renewal_token should match manual hash"
    );
}

#[test]
fn test_hash_deterministic() {
    let manager = create_test_manager();

    let input = "test_token_12345";

    let hash1 = manager.hash(input).unwrap();
    let hash2 = manager.hash(input).unwrap();
    let hash3 = manager.hash(input).unwrap();

    assert_eq!(hash1, hash2, "Hash should be deterministic");
    assert_eq!(hash2, hash3, "Hash should be deterministic");
}

#[test]
fn test_hash_different_inputs_different_outputs() {
    let manager = create_test_manager();

    let hash1 = manager.hash("token1").unwrap();
    let hash2 = manager.hash("token2").unwrap();
    let hash3 = manager.hash("completely_different_token").unwrap();

    assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    assert_ne!(hash2, hash3, "Different inputs should produce different hashes");
    assert_ne!(hash1, hash3, "Different inputs should produce different hashes");
}

#[test]
fn test_hash_empty_string() {
    let manager = create_test_manager();

    let result = manager.hash("");
    assert!(result.is_ok(), "Hash should handle empty string");

    let hash = result.unwrap();
    assert_eq!(hash.len(), 64, "Hash should be 64 hex characters even for empty string");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash should only contain hex digits"
    );
}

#[test]
fn test_hash_output_format() {
    let manager = create_test_manager();

    let hash = manager.hash("test").unwrap();

    // Verify it's a valid hex string
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Verify it's lowercase (hex::encode produces lowercase)
    assert_eq!(hash, hash.to_lowercase());
}

#[test]
fn test_weak_server_secret_rejected() {
    let result = ValidatedServerSecret::try_from(b"short_secret".to_vec()); // Only 12 bytes
    assert!(result.is_err(), "Should reject weak server secret");
    match result.err().unwrap() {
        crate::token::TokenError::GeneralError(msg) => {
            assert!(msg.contains("Server secret must be at least 32 bytes"));
            assert!(msg.contains("got 12"));
        }
        _ => panic!("Expected GeneralError with server secret message"),
    }
}

#[test]
fn test_empty_server_secret_rejected() {
    let result = ValidatedServerSecret::try_from(Vec::new());
    assert!(result.is_err(), "Should reject empty server secret");
    match result.err().unwrap() {
        crate::token::TokenError::GeneralError(msg) => {
            assert!(msg.contains("Server secret must be at least 32 bytes"));
            assert!(msg.contains("got 0"));
        }
        _ => panic!("Expected GeneralError with server secret message"),
    }
}

#[tokio::test]
async fn test_valid_server_secret_accepted() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let secret = ValidatedServerSecret::try_from(b"this_is_exactly_32bytes_long!!!!".to_vec())
        .expect("Exactly 32 bytes should be valid");
    let manager = JwtTokenManager::builder()
        .issuer("test_issuer")
        .refresh_endpoint("http://localhost/refresh")
        .server_secret(secret)
        .token_duration(3600)
        .renewal_token_duration(86400)
        .clock(Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>)
        .token_store(Arc::new(MemoryRenewableTokenStore::new()))
        .token_generator(Arc::new(MockJwtGenerator))
        .client_verifier(Arc::new(MockJwtVerifier))
        .provider_verifier(Arc::new(MockJwtVerifier))
        .jwk_set_provider(Arc::new(MockJwkSetProvider))
        .build();

    let pc = ParticipantContext::builder().id("test_participant").build();
    let result = manager
        .generate_pair(&pc, "test_subject", HashMap::new(), "test_flow".to_string())
        .await;

    assert!(result.is_ok(), "Should accept valid 32-byte server secret");
}

#[tokio::test]
async fn test_reserved_claim_iss_rejected() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let manager = create_test_manager();
    let pc = ParticipantContext::builder().id("test_participant").build();

    let mut claims = HashMap::new();
    claims.insert("iss".to_string(), Value::String("custom_issuer".to_string()));

    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;

    assert!(result.is_err(), "Should reject custom claim 'iss'");
    match result.unwrap_err() {
        crate::token::TokenError::GeneralError(msg) => {
            assert!(
                msg.contains("Custom claims cannot contain reserved claim: iss"),
                "Actual error: {}",
                msg
            );
        }
        other => panic!("Expected GeneralError with reserved claim message, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_reserved_claim_sub_rejected() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let manager = create_test_manager();
    let pc = ParticipantContext::builder().id("test_participant").build();

    let mut claims = HashMap::new();
    claims.insert("sub".to_string(), Value::String("custom_subject".to_string()));

    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;

    assert!(result.is_err(), "Should reject custom claim 'sub'");
    match result.unwrap_err() {
        crate::token::TokenError::GeneralError(msg) => {
            assert!(msg.contains("Custom claims cannot contain reserved claim: sub"));
        }
        _ => panic!("Expected GeneralError with reserved claim message"),
    }
}

#[tokio::test]
async fn test_reserved_claim_jti_rejected() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let manager = create_test_manager();
    let pc = ParticipantContext::builder().id("test_participant").build();

    let mut claims = HashMap::new();
    claims.insert("jti".to_string(), Value::String("custom_jti".to_string()));

    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;

    assert!(result.is_err(), "Should reject custom claim 'jti'");
    match result.unwrap_err() {
        crate::token::TokenError::GeneralError(msg) => {
            assert!(msg.contains("Custom claims cannot contain reserved claim: jti"));
        }
        _ => panic!("Expected GeneralError with reserved claim message"),
    }
}

#[tokio::test]
async fn test_reserved_claims_exp_iat_nbf_rejected() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let manager = create_test_manager();
    let pc = ParticipantContext::builder().id("test_participant").build();

    // Test exp
    let mut claims = HashMap::new();
    claims.insert("exp".to_string(), Value::String("123456789".to_string()));
    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;
    assert!(result.is_err(), "Should reject custom claim 'exp'");

    // Test iat
    let mut claims = HashMap::new();
    claims.insert("iat".to_string(), Value::String("123456789".to_string()));
    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;
    assert!(result.is_err(), "Should reject custom claim 'iat'");

    // Test nbf
    let mut claims = HashMap::new();
    claims.insert("nbf".to_string(), Value::String("123456789".to_string()));
    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;
    assert!(result.is_err(), "Should reject custom claim 'nbf'");
}

#[tokio::test]
async fn test_non_reserved_custom_claims_accepted() {
    use crate::context::ParticipantContext;
    use std::collections::HashMap;

    let manager = create_test_manager();
    let pc = ParticipantContext::builder().id("test_participant").build();

    let mut claims = HashMap::new();
    claims.insert("custom_field1".to_string(), Value::String("value1".to_string()));
    claims.insert("custom_field2".to_string(), Value::String("value2".to_string()));
    claims.insert("role".to_string(), Value::String("admin".to_string()));

    let result = manager
        .generate_pair(&pc, "test_subject", claims, "test_flow".to_string())
        .await;

    assert!(result.is_ok(), "Should accept non-reserved custom claims");
}

#[test]
fn test_custom_refresh_token_size() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();

    // Create manager with custom 16-byte refresh token size
    let secret = ValidatedServerSecret::try_from(b"test_secret_key_32bytes_long!!!!".to_vec()).unwrap();
    let manager = JwtTokenManager::builder()
        .issuer("test_issuer")
        .refresh_endpoint("http://localhost/refresh")
        .server_secret(secret)
        .token_duration(3600)
        .renewal_token_duration(86400)
        .refresh_token_bytes(16) // Custom size
        .clock(Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>)
        .token_store(Arc::new(MemoryRenewableTokenStore::new()))
        .token_generator(Arc::new(MockJwtGenerator))
        .client_verifier(Arc::new(MockJwtVerifier))
        .provider_verifier(Arc::new(MockJwtVerifier))
        .jwk_set_provider(Arc::new(MockJwkSetProvider))
        .build();

    let (token, hash) = manager.create_renewal_token().unwrap();

    // Token should be 32 hex characters (16 bytes * 2)
    assert_eq!(token.len(), 32, "Token should be 32 hex characters for 16-byte config");
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "Token should only contain hex digits"
    );

    // Hash should still be 64 hex characters (SHA256 output)
    assert_eq!(hash.len(), 64, "Hash should always be 64 hex characters");
}

#[test]
fn test_default_refresh_token_size() {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();

    // Create manager without specifying refresh_token_bytes (should default to 32)
    let secret = ValidatedServerSecret::try_from(b"test_secret_key_32bytes_long!!!!".to_vec()).unwrap();
    let manager = JwtTokenManager::builder()
        .issuer("test_issuer")
        .refresh_endpoint("http://localhost/refresh")
        .server_secret(secret)
        .token_duration(3600)
        .renewal_token_duration(86400)
        // Note: refresh_token_bytes NOT specified, should default to 32
        .clock(Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>)
        .token_store(Arc::new(MemoryRenewableTokenStore::new()))
        .token_generator(Arc::new(MockJwtGenerator))
        .client_verifier(Arc::new(MockJwtVerifier))
        .provider_verifier(Arc::new(MockJwtVerifier))
        .jwk_set_provider(Arc::new(MockJwkSetProvider))
        .build();

    let (token, _hash) = manager.create_renewal_token().unwrap();

    // Token should be 64 hex characters (32 bytes * 2) by default
    assert_eq!(
        token.len(),
        64,
        "Token should be 64 hex characters with default 32-byte config"
    );
}

#[tokio::test]
async fn test_jwk_set_delegates_to_provider() {
    let manager = create_test_manager();
    let jwk_set = manager.jwk_set().await.expect("jwk_set() should succeed");
    assert!(jwk_set.keys.is_empty(), "MockJwkSetProvider returns an empty JWK set");
}
