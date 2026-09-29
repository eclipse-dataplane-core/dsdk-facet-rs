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
use crate::config::ErrorCallback;
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

#[test]
fn kv_path_rejects_cross_context_traversal() {
    use crate::client::checked_kv_path;
    use dsdk_facet_core::context::ParticipantContext;

    let pc = ParticipantContext::builder().id("tenant-a").build();
    assert!(checked_kv_path(&pc, "flow-1").is_ok());
    assert!(checked_kv_path(&pc, "tokens/flow-1").is_ok());

    for path in [
        "../tenant-b/flow-1",
        "tokens/../../tenant-b/flow-1",
        "..%2Ftenant-b",
        "flow?x",
        "",
    ] {
        assert!(
            matches!(checked_kv_path(&pc, path), Err(VaultError::InvalidData(_))),
            "{path:?}"
        );
    }

    let bad_pc = ParticipantContext::builder().id("tenant-a/../tenant-b").build();
    assert!(checked_kv_path(&bad_pc, "flow-1").is_err());
}

#[test]
fn transit_key_name_must_be_single_segment() {
    use crate::client::checked_key_name;

    assert!(checked_key_name("signing-tenant-a").is_ok());
    assert!(checked_key_name("../keys/signing-tenant-b").is_err());
    assert!(checked_key_name("signing/tenant-b").is_err());
}
