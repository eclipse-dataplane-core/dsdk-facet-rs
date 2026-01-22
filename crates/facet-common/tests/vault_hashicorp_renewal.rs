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

//! These tests verify the renewal loop behavior without requiring full container setup,
//! using WireMock to simulate Vault and OAuth2 endpoints.

mod common;

use chrono::Utc;
use facet_common::vault::hashicorp::{ErrorCallback, HashicorpVaultClient, HashicorpVaultConfig, VaultClientState};
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};
use tokio::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use crate::common::wait_for_condition;

// Helper to create test state
fn create_test_state(token: &str, lease_duration: u64, consecutive_failures: u32) -> Arc<RwLock<VaultClientState>> {
    Arc::new(RwLock::new(VaultClientState {
        token: token.to_string(),
        last_created: Utc::now(),
        last_renewed: None,
        lease_duration,
        last_error: None,
        consecutive_failures,
    }))
}

#[tokio::test(start_paused = true)]
async fn test_renewal_loop_successful_renewal_cycle() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "test-token",
                "lease_duration": 3600
            }
        })))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let config = HashicorpVaultConfig::builder()
        .vault_url(mock_server.uri())
        .client_id("test-client")
        .client_secret("test-secret")
        .token_url("http://localhost/token")
        .build();

    let http_client = Client::new();
    let state = create_test_state("test-token", 10, 0);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state_clone = Arc::clone(&state);
    let loop_handle = tokio::spawn(async move {
        HashicorpVaultClient::renewal_loop(config, http_client, state_clone, shutdown_rx).await;
    });

    // Wait for renewal to happen (last_renewed is set)
    let renewed = wait_for_condition(
        &state,
        |s| s.last_renewed.is_some(),
        Duration::from_secs(20),
    )
    .await;

    assert!(renewed, "Renewal should have occurred");

    let state_guard = state.read().await;
    assert_eq!(state_guard.consecutive_failures, 0);
    assert!(state_guard.last_renewed.is_some());
    drop(state_guard);

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), loop_handle)
        .await
        .expect("Loop should exit")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn test_renewal_loop_max_consecutive_failures() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
        .expect(10..)
        .mount(&mock_server)
        .await;

    let error_count = Arc::new(AtomicUsize::new(0));
    let error_count_clone = Arc::clone(&error_count);
    let callback: ErrorCallback = Arc::new(move |_| {
        error_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let config = HashicorpVaultConfig::builder()
        .vault_url(mock_server.uri())
        .client_id("test-client")
        .client_secret("test-secret")
        .token_url("http://localhost/token")
        .on_renewal_error(callback)
        .build();

    let http_client = Client::new();
    let state = create_test_state("test-token", 2, 0);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let state_clone = Arc::clone(&state);
    let loop_handle = tokio::spawn(async move {
        HashicorpVaultClient::renewal_loop(config, http_client, state_clone, shutdown_rx).await;
    });

    // Wait for failures to reach 10
    let max_failures = wait_for_condition(
        &state,
        |s| s.consecutive_failures >= 10,
        Duration::from_secs(600),
    )
    .await;

    assert!(max_failures, "Should reach max consecutive failures");

    // Loop should exit after MAX_CONSECUTIVE_FAILURES
    tokio::time::timeout(Duration::from_secs(60), loop_handle)
        .await
        .expect("Loop should exit after max failures")
        .unwrap();

    let state_guard = state.read().await;
    assert_eq!(state_guard.consecutive_failures, 10);
    assert!(state_guard.last_error.is_some());
    assert_eq!(error_count.load(Ordering::SeqCst), 10);
}

#[tokio::test(start_paused = true)]
async fn test_renewal_loop_token_expiration_recovery() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(403).set_body_string("invalid token"))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-jwt-token",
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "new-vault-token",
                "lease_duration": 3600
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = HashicorpVaultConfig::builder()
        .vault_url(&mock_server.uri())
        .client_id("test-client")
        .client_secret("test-secret")
        .token_url(&format!("{}/token", mock_server.uri()))
        .build();

    let http_client = Client::new();
    let state = create_test_state("old-expired-token", 5, 0);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state_clone = Arc::clone(&state);
    let loop_handle = tokio::spawn(async move {
        HashicorpVaultClient::renewal_loop(config, http_client, state_clone, shutdown_rx).await;
    });

    // Wait for token to be replaced
    let token_replaced = wait_for_condition(
        &state,
        |s| s.token == "new-vault-token",
        Duration::from_secs(20),
    )
    .await;

    assert!(token_replaced, "Token should have been replaced");

    let state_guard = state.read().await;
    assert_eq!(state_guard.token, "new-vault-token");
    assert_eq!(state_guard.lease_duration, 3600);
    assert_eq!(state_guard.consecutive_failures, 0);
    drop(state_guard);

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), loop_handle)
        .await
        .expect("Loop should exit")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn test_renewal_loop_shutdown_signal() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "test-token",
                "lease_duration": 3600
            }
        })))
        .mount(&mock_server)
        .await;

    let config = HashicorpVaultConfig::builder()
        .vault_url(mock_server.uri())
        .client_id("test-client")
        .client_secret("test-secret")
        .token_url("http://localhost/token")
        .build();

    let http_client = Client::new();
    let state = create_test_state("test-token", 100, 0);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state_clone = Arc::clone(&state);
    let loop_handle = tokio::spawn(async move {
        HashicorpVaultClient::renewal_loop(config, http_client, state_clone, shutdown_rx).await;
    });

    // Send shutdown immediately
    shutdown_tx.send(true).unwrap();

    tokio::time::timeout(Duration::from_secs(1), loop_handle)
        .await
        .expect("Loop should exit immediately")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn test_renewal_loop_error_callback_not_invoked_on_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "test-token",
                "lease_duration": 3600
            }
        })))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let error_count = Arc::new(AtomicUsize::new(0));
    let error_count_clone = Arc::clone(&error_count);
    let callback: ErrorCallback = Arc::new(move |_| {
        error_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let config = HashicorpVaultConfig::builder()
        .vault_url(mock_server.uri())
        .client_id("test-client")
        .client_secret("test-secret")
        .token_url("http://localhost/token")
        .on_renewal_error(callback)
        .build();

    let http_client = Client::new();
    let state = create_test_state("test-token", 5, 0);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state_clone = Arc::clone(&state);
    let loop_handle = tokio::spawn(async move {
        HashicorpVaultClient::renewal_loop(config, http_client, state_clone, shutdown_rx).await;
    });

    // Wait for renewal to complete
    let renewed = wait_for_condition(
        &state,
        |s| s.last_renewed.is_some(),
        Duration::from_secs(20),
    )
    .await;

    assert!(renewed, "Renewal should have occurred");

    // Callback should NOT have been invoked
    assert_eq!(error_count.load(Ordering::SeqCst), 0);

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), loop_handle)
        .await
        .expect("Loop should exit")
        .unwrap();
}
