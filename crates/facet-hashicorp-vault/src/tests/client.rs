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

use crate::auth::VaultAuthClient;
use crate::client::HashicorpVaultClient;
use crate::config::{ErrorCallback, HashicorpVaultConfig, VaultAuthConfig};
use crate::renewal::TokenRenewer;
use crate::state::VaultClientState;
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use dsdk_facet_core::util::clock::{Clock, MockClock};
use dsdk_facet_core::vault::VaultError;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// Mock auth provider for testing
struct MockAuthProvider;

#[test]
fn test_calculate_renewal_interval_no_failures() {
    let lease_duration = 100; // 100 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 0, 0.8, 0.0);

    // Should be 80% of 100 = 80 seconds with no backoff
    assert_eq!(interval, Duration::from_secs(80));
}

#[test]
fn test_calculate_renewal_interval_with_backoff() {
    let lease_duration = 100; // 100 seconds

    // Base: 80 seconds (80% of 100)
    // 1 failure: 80 * 2^1 = 160 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 1, 0.8, 0.0);
    assert_eq!(interval, Duration::from_secs(160));

    // 2 failures: 80 * 2^2 = 320 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 2, 0.8, 0.0);
    assert_eq!(interval, Duration::from_secs(320));

    // 3 failures: 80 * 2^3 = 640 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 3, 0.8, 0.0);
    assert_eq!(interval, Duration::from_secs(640));
}

#[test]
fn test_calculate_renewal_interval_max_backoff() {
    let lease_duration = 100; // 100 seconds

    // 5 failures: 80 * 2^5 = 2560 seconds (at max exponent)
    let interval_5 = TokenRenewer::calculate_renewal_interval(lease_duration, 5, 0.8, 0.0);
    assert_eq!(interval_5, Duration::from_secs(2560));

    // 10 failures: should still be 80 * 2^5 = 2560 (capped at max exponent 5)
    let interval_10 = TokenRenewer::calculate_renewal_interval(lease_duration, 10, 0.8, 0.0);
    assert_eq!(interval_10, Duration::from_secs(2560));
}

#[test]
fn test_calculate_renewal_interval_with_jitter() {
    let lease_duration = 100; // 100 seconds
    let jitter = 0.1; // 10% jitter

    // Base interval without jitter: 80 seconds
    let base_interval = TokenRenewer::calculate_renewal_interval(lease_duration, 0, 0.8, 0.0);
    assert_eq!(base_interval, Duration::from_secs(80));

    // With 10% jitter, should be within [72, 88] seconds (80 * 0.9 to 80 * 1.1)
    let min_expected = 72;
    let max_expected = 88;

    // Run multiple times to ensure jitter is working
    for _ in 0..10 {
        let interval_with_jitter = TokenRenewer::calculate_renewal_interval(lease_duration, 0, 0.8, jitter);
        let secs = interval_with_jitter.as_secs();
        assert!(
            secs >= min_expected && secs <= max_expected,
            "Jittered interval {} should be between {} and {} seconds",
            secs,
            min_expected,
            max_expected
        );
    }
}

#[tokio::test]
async fn test_record_renewal_error_updates_state() {
    let state = renewed_state();
    let renewer = create_test_renewer(Arc::clone(&state), None);

    let error = VaultError::NetworkError("Network error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(state_guard.consecutive_failures(), 1);
    assert!(state_guard.last_error().is_some());
    assert!(state_guard.last_error().as_ref().unwrap().contains("Network error"));
}

#[tokio::test]
async fn test_record_renewal_error_increments_failures() {
    let state = failing_state(3);
    let renewer = create_test_renewer(Arc::clone(&state), None);

    let error = VaultError::NetworkError("Another error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(state_guard.consecutive_failures(), 4);
}

#[tokio::test]
async fn test_record_renewal_error_invokes_callback() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let state = renewed_state();
    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_clone = Arc::clone(&callback_count);
    let callback: ErrorCallback = Arc::new(move |_| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let renewer = create_test_renewer(Arc::clone(&state), Some(callback));

    let error = VaultError::NetworkError("Test error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(callback_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_update_state_on_success_resets_state() {
    let mock_clock = Arc::new(MockClock::new(Utc::now()));
    let now = mock_clock.now();

    let state = Arc::new(RwLock::new(
        VaultClientState::builder()
            .token("test-token")
            .last_created(Utc::now())
            .lease_duration(3600)
            .last_error("Previous error")
            .consecutive_failures(5)
            .health_threshold(3)
            .build(),
    ));

    let auth_client = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let renewal_trigger_config = crate::renewal::RenewalTriggerConfig::TimeBased {
        renewal_percentage: 0.8,
        renewal_jitter: 0.1,
    };
    let renewer = Arc::new(
        TokenRenewer::builder()
            .auth_client(auth_client)
            .http_client(http_client)
            .vault_url("http://vault:8200")
            .state(Arc::clone(&state))
            .renewal_trigger_config(renewal_trigger_config)
            .clock(mock_clock)
            .build(),
    );

    let mut state_guard = state.write().await;
    renewer.update_state_on_success(&mut state_guard);

    assert_eq!(state_guard.consecutive_failures(), 0);
    assert!(state_guard.last_error().is_none());
    assert_eq!(state_guard.last_renewed(), Some(now));
}

#[tokio::test]
async fn test_update_state_on_success_preserves_other_fields() {
    let token = "my-token".to_string();
    let created = Utc::now();
    let lease = 7200;
    let new_time = created + TimeDelta::try_hours(1).unwrap();

    let state = Arc::new(RwLock::new(
        VaultClientState::builder()
            .token(token.clone())
            .last_created(created)
            .lease_duration(lease)
            .last_error("Error")
            .consecutive_failures(3)
            .health_threshold(3)
            .build(),
    ));

    let mock_clock = Arc::new(MockClock::new(new_time));
    let auth_client = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let renewal_trigger_config = crate::renewal::RenewalTriggerConfig::TimeBased {
        renewal_percentage: 0.8,
        renewal_jitter: 0.1,
    };
    let renewer = Arc::new(
        TokenRenewer::builder()
            .auth_client(auth_client)
            .http_client(http_client)
            .vault_url("http://vault:8200")
            .state(Arc::clone(&state))
            .renewal_trigger_config(renewal_trigger_config)
            .clock(mock_clock)
            .build(),
    );

    let mut state_guard = state.write().await;
    renewer.update_state_on_success(&mut state_guard);

    // These should be unchanged
    assert_eq!(state_guard.token(), token);
    assert_eq!(state_guard.last_created(), created);
    assert_eq!(state_guard.lease_duration(), lease);
}

#[async_trait]
impl VaultAuthClient for MockAuthProvider {
    async fn authenticate(&self) -> Result<(String, u64), VaultError> {
        Ok(("mock-token".to_string(), 3600))
    }
}

fn create_test_renewer(
    state: Arc<RwLock<VaultClientState>>,
    on_renewal_error: Option<ErrorCallback>,
) -> Arc<TokenRenewer> {
    let auth_client = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let renewal_trigger_config = crate::renewal::RenewalTriggerConfig::TimeBased {
        renewal_percentage: 0.8,
        renewal_jitter: 0.1,
    };

    Arc::new(
        TokenRenewer::builder()
            .auth_client(auth_client)
            .http_client(http_client)
            .vault_url("http://vault:8200")
            .state(state)
            .renewal_trigger_config(renewal_trigger_config)
            .maybe_on_renewal_error(on_renewal_error)
            .clock(clock)
            .build(),
    )
}

// Test fixture helpers
fn renewed_state() -> Arc<RwLock<VaultClientState>> {
    Arc::new(RwLock::new(
        VaultClientState::builder()
            .token("test-token")
            .last_created(Utc::now())
            .last_renewed(Utc::now())
            .lease_duration(3600)
            .health_threshold(3)
            .build(),
    ))
}

fn failing_state(failures: u32) -> Arc<RwLock<VaultClientState>> {
    Arc::new(RwLock::new(
        VaultClientState::builder()
            .token("test-token")
            .last_created(Utc::now())
            .lease_duration(3600)
            .consecutive_failures(failures)
            .last_error("Test error")
            .health_threshold(3)
            .build(),
    ))
}

// Tests for multibase encoding
#[test]
fn test_convert_to_multibase_valid_key() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Ed25519 public key example (32 bytes) encoded in base64
    // This is a valid Ed25519 public key
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    let result = client.convert_to_multibase(public_key_base64);
    assert!(result.is_ok(), "Should successfully convert valid key");

    let multibase_key = result.unwrap();
    // Should start with 'z' for base58btc encoding
    assert!(multibase_key.starts_with('z'), "Multibase key should start with 'z'");

    // Should have reasonable length (32 bytes key + 2 bytes multicodec prefix = 34 bytes)
    // Base58btc encoding should result in ~46-48 characters plus 'z' prefix
    assert!(
        multibase_key.len() > 40 && multibase_key.len() < 60,
        "Multibase key length {} seems incorrect",
        multibase_key.len()
    );
}

#[test]
fn test_convert_to_multibase_deterministic() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    // Convert the same key twice
    let result1 = client.convert_to_multibase(public_key_base64).unwrap();
    let result2 = client.convert_to_multibase(public_key_base64).unwrap();

    // Should produce identical results
    assert_eq!(result1, result2, "Same key should produce same multibase encoding");
}

#[test]
fn test_convert_to_multibase_different_keys() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    let key1_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    // Another valid Ed25519 public key (32 bytes)
    let key2_base64 = "mcDE6jR9BjH3kojBtfm0wJrrm43rE9f+rVMKIaqIJQk=";

    let result1 = client.convert_to_multibase(key1_base64).unwrap();
    let result2 = client.convert_to_multibase(key2_base64).unwrap();

    // Different keys should produce different multibase encodings
    assert_ne!(result1, result2, "Different keys should produce different multibase encodings");
}

#[test]
fn test_convert_to_multibase_invalid_base64() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Invalid base64 string
    let invalid_base64 = "not-valid-base64!@#$%";

    let result = client.convert_to_multibase(invalid_base64);
    assert!(result.is_err(), "Should fail with invalid base64");

    match result {
        Err(VaultError::InvalidData(msg)) => {
            assert!(msg.contains("Invalid key format"), "Error message should be generic");
        }
        _ => panic!("Expected InvalidData error"),
    }
}

#[test]
fn test_convert_to_multibase_has_correct_multicodec_prefix() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let multibase_key = client.convert_to_multibase(public_key_base64).unwrap();

    // Decode the multibase key to verify the multicodec prefix
    // Remove 'z' prefix
    let encoded = &multibase_key[1..];
    let decoded = bs58::decode(encoded).into_vec().unwrap();

    // First two bytes should be 0xed, 0x01 (Ed25519 public key multicodec)
    assert_eq!(decoded[0], 0xed, "First byte should be 0xed");
    assert_eq!(decoded[1], 0x01, "Second byte should be 0x01");

    // Remaining bytes should be the public key (32 bytes for Ed25519)
    assert_eq!(decoded.len(), 34, "Decoded length should be 34 bytes (2 multicodec + 32 key)");
}

// Tests for multibase validation
#[test]
fn test_validate_multibase_ed25519_valid_key() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Generate a valid multibase key
    let public_key_base64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let multibase_key = client.convert_to_multibase(public_key_base64).unwrap();

    // Validate it
    let result = client.validate_multibase_ed25519(&multibase_key);
    assert!(result.is_ok(), "Should validate correct multibase key");

    let key_bytes = result.unwrap();
    assert_eq!(key_bytes.len(), 32, "Should extract 32-byte Ed25519 key");
}

#[test]
fn test_validate_multibase_ed25519_invalid_prefix() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Key with wrong prefix (not 'z')
    let invalid_key = "f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    let result = client.validate_multibase_ed25519(invalid_key);
    assert!(result.is_err(), "Should reject key without 'z' prefix");

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("expected 'z' prefix"), "Error should mention missing 'z' prefix");
}

#[test]
fn test_validate_multibase_ed25519_wrong_multicodec() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Create a key with wrong multicodec prefix (e.g., 0xec01 instead of 0xed01)
    let mut wrong_prefix = vec![0xec, 0x01]; // Wrong prefix
    wrong_prefix.extend_from_slice(&[0u8; 32]); // Add 32 bytes

    let encoded = format!("z{}", bs58::encode(&wrong_prefix).into_string());

    let result = client.validate_multibase_ed25519(&encoded);
    assert!(result.is_err(), "Should reject key with wrong multicodec prefix");

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid multicodec prefix"), "Error should mention invalid prefix");
}

#[test]
fn test_validate_multibase_ed25519_wrong_key_size() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Create a key with correct prefix but wrong size (16 bytes instead of 32)
    let mut wrong_size = vec![0xed, 0x01];
    wrong_size.extend_from_slice(&[0u8; 16]); // Only 16 bytes

    let encoded = format!("z{}", bs58::encode(&wrong_size).into_string());

    let result = client.validate_multibase_ed25519(&encoded);
    assert!(result.is_err(), "Should reject key with wrong size");

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid Ed25519 key size"), "Error should mention wrong key size");
}

#[test]
fn test_validate_multibase_ed25519_invalid_base58() {
    let config = HashicorpVaultConfig::builder()
        .vault_url("http://localhost:8200")
        .auth_config(VaultAuthConfig::OAuth2 {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            token_url: "http://localhost:8080/token".to_string(),
            role: None,
        })
        .build();

    let client = HashicorpVaultClient::new(config).expect("Failed to create client");

    // Invalid base58 characters
    let invalid_key = "z0OIl"; // Contains invalid base58 characters (0, O, I, l)

    let result = client.validate_multibase_ed25519(invalid_key);
    assert!(result.is_err(), "Should reject invalid base58 encoding");
}
