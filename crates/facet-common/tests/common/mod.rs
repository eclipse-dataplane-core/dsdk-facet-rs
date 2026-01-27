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

// Allow dead code in this module since test utilities are shared across multiple test files
// and each test binary is compiled separately
#![allow(dead_code)]

mod mocks;
mod proxy_s3;
mod minio;
mod postgres;
mod vault;
mod keycloak;

use std::net::TcpListener;
use std::sync::{Arc};
use std::time::Duration;
use testcontainers::bollard::Docker;
use testcontainers::bollard::models::NetworkCreateRequest;
use tokio::sync::RwLock;
use chrono::{TimeDelta, Utc};
use facet_common::vault::hashicorp::state::VaultClientState;
#[allow(unused_imports)] // Mocks are used in some test files but not others
pub use mocks::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use proxy_s3::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use minio::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use postgres::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use vault::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use keycloak::*;

// ============================================================================
// VaultClientState Test Fixtures
// ============================================================================
//
// These factory functions provide convenient ways to create VaultClientState
// instances for testing. Use semantic helpers for common scenarios, or the
// base factory for custom configurations.
//
// Examples:
//
//   // Healthy state with defaults
//   let state = healthy_vault_state();
//   assert!(state.is_healthy());
//
//   // State with failures
//   let state = failing_vault_state(5);
//   assert!(!state.is_healthy());
//
//   // Custom configuration
//   let state = create_test_state("my-token", 7200, 0);
//
//   // For use with TokenRenewer (wrapped in Arc<RwLock>)
//   let state = wrapped_test_state("token", 3600, 0);
//
//   // Full builder control for unique cases
//   let state = VaultClientState::builder()
//       .token("special-token")
//       .last_created(specific_time)
//       .lease_duration(100)
//       .health_threshold(5)
//       .build();
//
// ============================================================================

/// Creates a VaultClientState for testing with configurable parameters.
/// This is the base factory function - use the semantic helpers below for common scenarios.
pub fn create_test_state(token: &str, lease_duration: u64, consecutive_failures: u32) -> VaultClientState {
    VaultClientState::builder()
        .token(token)
        .last_created(Utc::now())
        .lease_duration(lease_duration)
        .consecutive_failures(consecutive_failures)
        .health_threshold(3)
        .build()
}

/// Creates a healthy VaultClientState with default test values.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - No failures
/// - Healthy status
pub fn healthy_vault_state() -> VaultClientState {
    create_test_state("test-token", 3600, 0)
}

/// Creates a VaultClientState that has been successfully renewed.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - Recently renewed
/// - No failures
pub fn renewed_vault_state() -> VaultClientState {
    VaultClientState::builder()
        .token("test-token")
        .last_created(Utc::now())
        .last_renewed(Utc::now())
        .lease_duration(3600)
        .health_threshold(3)
        .build()
}

/// Creates a VaultClientState with the specified number of consecutive failures.
/// - Token: "test-token"
/// - Lease: 3600 seconds
/// - Last error set
/// - Unhealthy if failures >= 3
pub fn failing_vault_state(failures: u32) -> VaultClientState {
    VaultClientState::builder()
        .token("test-token")
        .last_created(Utc::now())
        .lease_duration(3600)
        .consecutive_failures(failures)
        .last_error("Test error")
        .health_threshold(3)
        .build()
}

/// Creates a VaultClientState with a nearly expired token for testing recovery scenarios.
/// - Token: "old-token"
/// - Created 1 hour ago
/// - Very short lease (10 seconds)
/// - Simulates expiration
pub fn expiring_vault_state() -> VaultClientState {
    let past = Utc::now() - TimeDelta::try_hours(1).unwrap();
    VaultClientState::builder()
        .token("old-token")
        .last_created(past)
        .lease_duration(10)
        .health_threshold(3)
        .build()
}

/// Creates a wrapped VaultClientState ready for use with TokenRenewer.
/// Returns Arc<RwLock<VaultClientState>> which is the standard pattern.
pub fn wrapped_test_state(token: &str, lease_duration: u64, consecutive_failures: u32) -> Arc<RwLock<VaultClientState>> {
    Arc::new(RwLock::new(create_test_state(token, lease_duration, consecutive_failures)))
}

/// Creates a Docker network and returns its name.
///
/// Automatically cleans up old test networks matching the pattern "test-network-*"
/// to prevent Docker address pool exhaustion. Networks are not automatically cleaned
/// up by testcontainers when containers drop, so we must manually remove them.
///
/// Note: Rust Testcontainers lacks network creation functionality (which is available in Go and Java).
pub async fn create_network() -> String {
    // Try to connect to Docker using the socket path from DOCKER_HOST env var,
    // or fall back to platform-specific defaults
    let docker = if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        Docker::connect_with_unix(&docker_host, 120, testcontainers::bollard::API_DEFAULT_VERSION)
            .expect("Failed to connect to Docker via DOCKER_HOST")
    } else if cfg!(target_os = "macos") {
        // On macOS with Docker Desktop, socket is typically at ~/.docker/run/docker.sock
        let home = std::env::var("HOME").expect("HOME env var not set");
        let socket_path = format!("{}/.docker/run/docker.sock", home);
        Docker::connect_with_unix(&socket_path, 120, testcontainers::bollard::API_DEFAULT_VERSION)
            .unwrap_or_else(|_| {
                // Fall back to default if custom path doesn't work
                Docker::connect_with_local_defaults().expect("Failed to connect to Docker")
            })
    } else {
        Docker::connect_with_local_defaults().expect("Failed to connect to Docker")
    };

    // Clean up old test networks before creating a new one
    cleanup_old_test_networks(&docker).await;

    let network_name = format!("test-network-{}", uuid::Uuid::new_v4());

    let config = NetworkCreateRequest {
        name: network_name.clone(),
        ..Default::default()
    };

    docker
        .create_network(config)
        .await
        .expect("Failed to create Docker network");

    network_name
}

/// Cleans up old test networks to prevent address pool exhaustion
async fn cleanup_old_test_networks(docker: &Docker) {
    use testcontainers::bollard::query_parameters::ListNetworksOptions;

    // List all networks (best effort - ignore errors)
    let networks = match docker.list_networks(Option::<ListNetworksOptions>::None).await {
        Ok(networks) => networks,
        Err(_) => return,
    };

    for network in networks {
        if let Some(name) = &network.name {
            // Clean up networks matching our test pattern
            if name.starts_with("test-network-") {
                // Best effort cleanup - ignore errors
                let _ = docker.remove_network(name).await;
            }
        }
    }
}


/// Get an available port by binding to port 0 and retrieving the assigned port
pub fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    let port = listener.local_addr().expect("Failed to get local address").port();
    drop(listener);
    port
}

/// Poll state until a condition is met or timeout expires
pub async fn wait_for_condition<F>(
    state: &Arc<RwLock<VaultClientState>>,
    condition: F,
    timeout: Duration,
) -> bool
where
    F: Fn(&VaultClientState) -> bool,
{
    let start = tokio::time::Instant::now();
    let poll_interval = Duration::from_millis(10);

    loop {
        {
            let guard = state.read().await;
            if condition(&guard) {
                return true;
            }
        }

        if tokio::time::Instant::now().duration_since(start) >= timeout {
            return false;
        }

        // Use sleep instead of yield_now to allow time to advance with paused time
        tokio::time::sleep(poll_interval).await;
    }
}
