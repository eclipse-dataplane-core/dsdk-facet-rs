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

use std::sync::Arc;
use std::time::Duration;
use crate::util::clock::{Clock, MockClock};
use chrono::{TimeDelta, Utc};
use crate::vault::hashicorp::{ErrorCallback, TokenRenewer, VaultClientState, VaultAuthProvider};
use crate::vault::VaultError;
use tokio::sync::RwLock;
use reqwest::Client;
use async_trait::async_trait;

// Mock auth provider for testing
struct MockAuthProvider;

#[async_trait]
impl VaultAuthProvider for MockAuthProvider {
    async fn get_vault_access_token(&self) -> Result<String, VaultError> {
        Ok("mock-jwt".to_string())
    }

    async fn create_vault_token(&self, _jwt: &str) -> Result<(String, u64), VaultError> {
        Ok(("mock-token".to_string(), 3600))
    }
}

fn create_test_renewer(state: Arc<RwLock<VaultClientState>>, on_renewal_error: Option<ErrorCallback>) -> Arc<TokenRenewer> {
    let auth_provider = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let clock = Arc::new(MockClock::new(Utc::now()));

    Arc::new(TokenRenewer::new(
        auth_provider,
        http_client,
        "http://vault:8200".to_string(),
        state,
        on_renewal_error,
        clock,
    ))
}

#[test]
fn test_calculate_renewal_interval_no_failures() {
    let lease_duration = 100; // 100 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 0);

    // Should be 80% of 100 = 80 seconds with no backoff
    assert_eq!(interval, Duration::from_secs(80));
}

#[test]
fn test_calculate_renewal_interval_with_backoff() {
    let lease_duration = 100; // 100 seconds

    // Base: 80 seconds (80% of 100)
    // 1 failure: 80 * 2^1 = 160 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 1);
    assert_eq!(interval, Duration::from_secs(160));

    // 2 failures: 80 * 2^2 = 320 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 2);
    assert_eq!(interval, Duration::from_secs(320));

    // 3 failures: 80 * 2^3 = 640 seconds
    let interval = TokenRenewer::calculate_renewal_interval(lease_duration, 3);
    assert_eq!(interval, Duration::from_secs(640));
}

#[test]
fn test_calculate_renewal_interval_max_backoff() {
    let lease_duration = 100; // 100 seconds

    // 5 failures: 80 * 2^5 = 2560 seconds (at max exponent)
    let interval_5 = TokenRenewer::calculate_renewal_interval(lease_duration, 5);
    assert_eq!(interval_5, Duration::from_secs(2560));

    // 10 failures: should still be 80 * 2^5 = 2560 (capped at max exponent 5)
    let interval_10 = TokenRenewer::calculate_renewal_interval(lease_duration, 10);
    assert_eq!(interval_10, Duration::from_secs(2560));
}

#[tokio::test]
async fn test_record_renewal_error_updates_state() {
    let state = Arc::new(RwLock::new(VaultClientState {
        token: "test-token".to_string(),
        last_created: Utc::now(),
        last_renewed: Some(Utc::now()),
        lease_duration: 3600,
        last_error: None,
        consecutive_failures: 0,
    }));

    let renewer = create_test_renewer(Arc::clone(&state), None);

    let error = VaultError::GeneralError("Network error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(state_guard.consecutive_failures, 1);
    assert!(state_guard.last_error.is_some());
    assert!(state_guard.last_error.as_ref().unwrap().contains("Network error"));
}

#[tokio::test]
async fn test_record_renewal_error_increments_failures() {
    let state = Arc::new(RwLock::new(VaultClientState {
        token: "test-token".to_string(),
        last_created: Utc::now(),
        last_renewed: Some(Utc::now()),
        lease_duration: 3600,
        last_error: None,
        consecutive_failures: 3,
    }));

    let renewer = create_test_renewer(Arc::clone(&state), None);

    let error = VaultError::GeneralError("Another error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(state_guard.consecutive_failures, 4);
}

#[tokio::test]
async fn test_record_renewal_error_invokes_callback() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let state = Arc::new(RwLock::new(VaultClientState {
        token: "test-token".to_string(),
        last_created: Utc::now(),
        last_renewed: Some(Utc::now()),
        lease_duration: 3600,
        last_error: None,
        consecutive_failures: 0,
    }));

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_clone = Arc::clone(&callback_count);
    let callback: ErrorCallback = Arc::new(move |_| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let renewer = create_test_renewer(Arc::clone(&state), Some(callback));

    let error = VaultError::GeneralError("Test error".to_string());
    let mut state_guard = state.write().await;
    renewer.record_renewal_error(&mut state_guard, &error);

    assert_eq!(callback_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_update_state_on_success_resets_state() {
    let mock_clock = Arc::new(MockClock::new(Utc::now()));
    let now = mock_clock.now();

    let state = Arc::new(RwLock::new(VaultClientState {
        token: "test-token".to_string(),
        last_created: Utc::now(),
        last_renewed: None,
        lease_duration: 3600,
        last_error: Some("Previous error".to_string()),
        consecutive_failures: 5,
    }));

    let auth_provider = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let renewer = Arc::new(TokenRenewer::new(
        auth_provider,
        http_client,
        "http://vault:8200".to_string(),
        Arc::clone(&state),
        None,
        mock_clock,
    ));

    let mut state_guard = state.write().await;
    renewer.update_state_on_success(&mut state_guard);

    assert_eq!(state_guard.consecutive_failures, 0);
    assert!(state_guard.last_error.is_none());
    assert_eq!(state_guard.last_renewed, Some(now));
}

#[tokio::test]
async fn test_update_state_on_success_preserves_other_fields() {
    let token = "my-token".to_string();
    let created = Utc::now();
    let lease = 7200;
    let new_time = created + TimeDelta::try_hours(1).unwrap();

    let state = Arc::new(RwLock::new(VaultClientState {
        token: token.clone(),
        last_created: created,
        last_renewed: None,
        lease_duration: lease,
        last_error: Some("Error".to_string()),
        consecutive_failures: 3,
    }));

    let mock_clock = Arc::new(MockClock::new(new_time));
    let auth_provider = Arc::new(MockAuthProvider);
    let http_client = Client::new();
    let renewer = Arc::new(TokenRenewer::new(
        auth_provider,
        http_client,
        "http://vault:8200".to_string(),
        Arc::clone(&state),
        None,
        mock_clock,
    ));

    let mut state_guard = state.write().await;
    renewer.update_state_on_success(&mut state_guard);

    // These should be unchanged
    assert_eq!(state_guard.token, token);
    assert_eq!(state_guard.last_created, created);
    assert_eq!(state_guard.lease_duration, lease);
}