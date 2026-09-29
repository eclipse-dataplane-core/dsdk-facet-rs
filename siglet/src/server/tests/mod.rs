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

use crate::error::SigletError;
use crate::handler::refresh::TokenRefreshHandler;
use crate::server::handle_task_result;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::JwkSet;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use dsdk_facet_testcontainers::utils::{get_available_port, wait_for_port_ready};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

struct NoOpTokenManager;

#[async_trait::async_trait]
impl TokenManager for NoOpTokenManager {
    async fn generate_pair(
        &self,
        _ctx: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, Value>,
        _flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!("not used in server tests")
    }

    async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!("not used in server tests")
    }

    async fn revoke_token(&self, _ctx: &ParticipantContext, _flow_id: &str) -> Result<(), TokenError> {
        unimplemented!("not used in server tests")
    }

    async fn validate_token(
        &self,
        _participant_context_id: Option<&str>,
        _audience: &str,
        _token: &str,
    ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
        unimplemented!("not used in server tests")
    }

    async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
        unimplemented!("not used in server tests")
    }
}

fn no_op_refresh_handler() -> TokenRefreshHandler {
    TokenRefreshHandler::builder()
        .token_manager(Arc::new(NoOpTokenManager))
        .build()
}

// ============================================================================
// handle_task_result() Tests
// ============================================================================

#[test]
fn test_handle_task_result_success() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    let result: Result<Result<(), SigletError>, JoinError> = Ok(Ok(()));

    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_ok());
    assert!(!cancel_token.is_cancelled());
}

#[test]
fn test_handle_task_result_task_error() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    let error = SigletError::InvalidConfiguration("test error".to_string());
    let result: Result<Result<(), SigletError>, JoinError> = Ok(Err(error));

    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_err());
    assert!(cancel_token.is_cancelled());
    let err_msg = outcome.unwrap_err().to_string();
    assert!(err_msg.contains("test error"));
}

#[tokio::test]
async fn test_handle_task_result_task_panic() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    // Spawn a task that panics
    let handle = tokio::spawn(async {
        panic!("intentional panic");
        #[allow(unreachable_code)]
        Ok::<(), SigletError>(())
    });

    let result = handle.await;

    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_err());
    assert!(cancel_token.is_cancelled());

    // Verify it's a TaskPanic error with proper message
    let err = outcome.unwrap_err();
    assert!(matches!(err, SigletError::TaskPanic(_)));
    assert!(err.to_string().contains("Server task panicked"));
}

#[tokio::test]
async fn test_handle_task_result_cancels_remaining_tasks() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    // Add some tasks to the join set
    for _ in 0..3 {
        join_set.spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            Ok(())
        });
    }

    assert_eq!(join_set.len(), 3);

    // Simulate a task error
    let error = SigletError::InvalidConfiguration("test error".to_string());
    let result: Result<Result<(), SigletError>, JoinError> = Ok(Err(error));

    let _ = handle_task_result(result, &cancel_token, &mut join_set);

    // Tasks are marked for cancellation but remain in set until polled
    // Verify cancellation token was triggered
    assert!(cancel_token.is_cancelled());

    // Drain the join set to verify all tasks were aborted
    let mut aborted_count = 0;
    while let Some(result) = join_set.join_next().await {
        assert!(result.is_err()); // Should be JoinError from cancellation
        aborted_count += 1;
    }
    assert_eq!(aborted_count, 3);
    assert_eq!(join_set.len(), 0);
}

#[tokio::test]
async fn test_port_conflict_propagates() {
    use std::net::{IpAddr, Ipv4Addr};

    let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    // Bind to a port first
    let listener = tokio::net::TcpListener::bind((bind, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Keep listener alive to hold the port
    let cancel_token = CancellationToken::new();

    // Try to bind to the same port - should fail
    let result = crate::server::run_refresh_api(bind, port, no_op_refresh_handler(), cancel_token).await;

    assert!(result.is_err());
    drop(listener);
}

#[tokio::test]
async fn test_cancellation_token_stops_server() {
    use std::net::{IpAddr, Ipv4Addr};

    let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = get_available_port();
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    // Spawn refresh API server on specific port
    let handle = tokio::spawn(async move {
        crate::server::run_refresh_api(bind, port, no_op_refresh_handler(), cancel_token_clone).await
    });

    // Wait for server to be ready (port accepting connections)
    let addr = SocketAddr::new(bind, port);
    wait_for_port_ready(addr, Duration::from_secs(2))
        .await
        .expect("Server should start within timeout");

    // Cancel the server
    cancel_token.cancel();

    // Server should exit cleanly
    let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await;

    assert!(result.is_ok());
    let server_result = result.unwrap().unwrap();
    assert!(server_result.is_ok());
}

#[tokio::test]
async fn test_server_graceful_shutdown_with_cancellation() {
    use std::net::{IpAddr, Ipv4Addr};

    let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = get_available_port();
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    let handle = tokio::spawn(async move {
        crate::server::run_refresh_api(bind, port, no_op_refresh_handler(), cancel_token_clone).await
    });

    // Wait for server to be ready (port accepting connections)
    let addr = SocketAddr::new(bind, port);
    wait_for_port_ready(addr, Duration::from_secs(2))
        .await
        .expect("Server should start within timeout");

    // Trigger shutdown
    cancel_token.cancel();

    // Server should exit within reasonable time
    let result = tokio::time::timeout(tokio::time::Duration::from_secs(2), handle).await;

    assert!(result.is_ok(), "Server should shutdown within timeout");
    let server_result = result.unwrap().unwrap();
    assert!(server_result.is_ok(), "Server should shutdown without error");
}

#[tokio::test]
async fn test_multiple_tasks_one_fails_others_cancelled() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    // Spawn successful tasks
    for _ in 0..3 {
        let token = cancel_token.clone();
        join_set.spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => Ok(()),
                _ = token.cancelled() => Ok(()),
            }
        });
    }

    // Spawn a failing task
    join_set.spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        Err(SigletError::InvalidConfiguration("test failure".to_string()))
    });

    // Wait for first task to complete
    let result = join_set.join_next().await.unwrap();

    // Handle the result (should be the failing task)
    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_err());
    assert!(cancel_token.is_cancelled());

    // Drain remaining tasks - they will complete via cancellation token or be aborted
    let mut remaining_count = 0;
    while join_set.join_next().await.is_some() {
        remaining_count += 1;
    }

    assert_eq!(remaining_count, 3); // The 3 tasks that were running
    assert_eq!(join_set.len(), 0);
}

#[tokio::test]
async fn test_task_completes_before_cancellation() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    // Task that completes quickly
    join_set.spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        Ok(())
    });

    // Wait for task to complete
    let result = join_set.join_next().await.unwrap();

    // Task should complete successfully before we even try to cancel
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());

    // Now cancel (even though task already completed)
    cancel_token.cancel();
    assert!(cancel_token.is_cancelled());
}

#[tokio::test]
async fn test_handle_task_result_with_io_error() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    let io_error = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port in use");
    let siglet_error = SigletError::Io(io_error);
    let result: Result<Result<(), SigletError>, JoinError> = Ok(Err(siglet_error));

    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_err());
    assert!(cancel_token.is_cancelled());
}

#[tokio::test]
async fn test_handle_task_result_with_network_error() {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), SigletError>> = JoinSet::new();

    let parse_error = "invalid".parse::<std::net::SocketAddr>().unwrap_err();
    let siglet_error = SigletError::Network(Box::new(parse_error));
    let result: Result<Result<(), SigletError>, JoinError> = Ok(Err(siglet_error));

    let outcome = handle_task_result(result, &cancel_token, &mut join_set);

    assert!(outcome.is_err());
    assert!(cancel_token.is_cancelled());
}
