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

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use auth::AuthLayer;
use axum::{
    Router,
    response::{IntoResponse, Json},
    routing::get,
};
use dataplane_sdk::{core::db::tx::TransactionalContext, sdk::DataPlaneSdk};
use dataplane_sdk_axum::router::participants_router as signaling_router;
use serde_json::json;
use tokio::{signal, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::config::SignalingAuthConfig;
use crate::error::SigletError;
use crate::handler::TokenApiHandler;
use crate::handler::refresh::TokenRefreshHandler;

/// Builds the `AuthLayer` for the signaling API from configuration.
///
/// `http_client` is the shared process-wide `reqwest::Client`. Pass the same
/// instance used elsewhere in the runtime so JWKS fetching shares the connection
/// pool and timeout settings of every other outbound call.
///
/// Disabled mode logs a loud warning at startup so it's never accidentally
/// shipped to production by anyone skimming logs.
pub fn build_signaling_auth_layer(cfg: &SignalingAuthConfig, http_client: reqwest::Client) -> AuthLayer {
    match cfg {
        SignalingAuthConfig::Disabled => {
            warn!(
                "Signaling API authentication is DISABLED — \
                 Do not use in production."
            );
            AuthLayer::Disabled
        }
        SignalingAuthConfig::Enabled {
            jwks_url,
            cache_ttl_seconds,
            audience,
            required_scope,
        } => AuthLayer::enabled_http(
            jwks_url,
            Duration::from_secs(*cache_ttl_seconds),
            audience,
            required_scope,
            http_client,
        ),
    }
}

/// Scope required on token-management-API JWTs.
///
/// The token API reuses the signaling JWKS and audience (see [`build_token_api_auth_layer`])
/// but requires this scope in place of the signaling one. Kept as a fixed value rather
/// than a config knob to keep the shared `signaling_auth` block small.
const TOKEN_API_REQUIRED_SCOPE: &str = "siglet-token-api";

/// Builds the `AuthLayer` for the token-management API from the (shared) signaling auth
/// configuration.
///
/// Reuses `jwks_url`, `cache_ttl_seconds`, and `audience` from `signaling_auth`, but
/// requires the `siglet-token-api` scope and authenticates pathless protected routes
/// (`/tokens/verify`) rather than passing them through. `build_signaling_auth_layer`
/// already logs the "auth disabled" warning, so the disabled branch here stays quiet.
pub fn build_token_api_auth_layer(cfg: &SignalingAuthConfig, http_client: reqwest::Client) -> AuthLayer {
    match cfg {
        SignalingAuthConfig::Disabled => AuthLayer::Disabled,
        SignalingAuthConfig::Enabled {
            jwks_url,
            cache_ttl_seconds,
            audience,
            ..
        } => AuthLayer::enabled_http_require_token(
            jwks_url,
            Duration::from_secs(*cache_ttl_seconds),
            audience,
            TOKEN_API_REQUIRED_SCOPE,
            http_client,
        ),
    }
}

// ============================================================================
// Visibility note: run_siglet_api and run_refresh_api are pub(crate) so that
// server tests can exercise them directly.
// ============================================================================

pub mod auth;
#[cfg(test)]
mod tests;

// ============================================================================
// API Endpoint Constants
// ============================================================================

/// Root API endpoint path
const ENDPOINT_ROOT: &str = "/";

/// Health check endpoint path
const ENDPOINT_HEALTH: &str = "/health";

/// Application name for API responses
const APP_NAME: &str = "Siglet";

/// Status value for running state
const STATUS_RUNNING: &str = "running";

/// Status value for healthy state
const STATUS_HEALTHY: &str = "healthy";

// ============================================================================
// Server Functions
// ============================================================================

/// Run all three APIs with structured concurrency:
/// - Signaling API (dataplane SDK)
/// - Siglet API (token management + health)
/// - Refresh API (token refresh endpoint)
///
/// This function uses JoinSet to manage multiple server tasks and provides:
/// - Proper error propagation from spawned tasks
/// - Graceful shutdown coordination via CancellationToken
/// - Fail-fast behavior: if one server fails, all are cancelled
#[allow(clippy::too_many_arguments)]
pub async fn run_server<C>(
    bind: IpAddr,
    signaling_port: u16,
    siglet_api_port: u16,
    refresh_api_port: u16,
    sdk: DataPlaneSdk<C>,
    token_api_handler: TokenApiHandler,
    refresh_handler: TokenRefreshHandler,
    signaling_auth: AuthLayer,
    token_api_auth: AuthLayer,
) -> Result<(), SigletError>
where
    C: TransactionalContext + 'static,
    C::Transaction: Send,
{
    let mut join_set = JoinSet::new();
    let cancel_token = CancellationToken::new();

    // Spawn all three server tasks
    join_set.spawn(run_signaling_api(
        bind,
        signaling_port,
        sdk.clone(),
        signaling_auth,
        cancel_token.clone(),
    ));

    join_set.spawn(run_siglet_api(
        bind,
        siglet_api_port,
        token_api_handler,
        token_api_auth,
        cancel_token.clone(),
    ));

    join_set.spawn(run_refresh_api(
        bind,
        refresh_api_port,
        refresh_handler,
        cancel_token.clone(),
    ));

    info!("Ready");

    // Wait for shutdown signal OR first task to complete/fail
    tokio::select! {
        // Shutdown signal received (Ctrl+C or SIGTERM)
        _ = wait_for_shutdown() => {
            cancel_token.cancel();
        }

        // A server task completed (either successfully or with error)
        Some(result) = join_set.join_next() => {
            handle_task_result(result, &cancel_token, &mut join_set)?
        }
    }

    // Wait for all remaining tasks to complete
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(())) => {
                // Task completed successfully during cleanup
            }
            Ok(Err(e)) => {
                error!("Server task failed during cleanup: {}", e);
            }
            Err(e) => {
                error!("Server task panicked during cleanup: {}", e);
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}

/// Handles the result of a completed task
///
/// Returns Err if the task failed or panicked, which will cause
/// immediate shutdown of all other tasks.
fn handle_task_result(
    result: Result<Result<(), SigletError>, tokio::task::JoinError>,
    cancel_token: &CancellationToken,
    join_set: &mut JoinSet<Result<(), SigletError>>,
) -> Result<(), SigletError> {
    match result {
        // Task completed successfully
        Ok(Ok(())) => Ok(()),

        // Task returned an error
        Ok(Err(e)) => {
            error!("Server task failed: {}", e);
            cancel_token.cancel();
            join_set.abort_all();
            Err(e)
        }

        // Task panicked
        Err(e) => {
            error!("Server task panicked: {}", e);
            cancel_token.cancel();
            join_set.abort_all();
            Err(SigletError::TaskPanic(Box::new(e)))
        }
    }
}

/// Run the DataPlane SDK signaling API
///
/// This function binds to the specified address and runs until either:
/// - The cancellation token is triggered
/// - An error occurs
async fn run_signaling_api<C>(
    bind: IpAddr,
    port: u16,
    sdk: DataPlaneSdk<C>,
    auth_layer: AuthLayer,
    cancel_token: CancellationToken,
) -> Result<(), SigletError>
where
    C: TransactionalContext + 'static,
    C::Transaction: Send,
{
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| SigletError::Network(Box::new(e)))?;

    let router = signaling_router();
    let app = router
        .layer(TraceLayer::new_for_http())
        .layer(auth_layer)
        .with_state(sdk);

    info!("Signaling API listening on {}", addr);

    // Bind to address - returns error if fails (e.g., port already in use)
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await
        .map_err(|e| SigletError::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Run the Siglet management API (token CRUD + health)
///
/// This function binds to the specified address and runs until either:
/// - The cancellation token is triggered
/// - An error occurs
pub(crate) async fn run_siglet_api(
    bind: IpAddr,
    port: u16,
    token_api_handler: TokenApiHandler,
    token_api_auth: AuthLayer,
    cancel_token: CancellationToken,
) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| SigletError::Network(Box::new(e)))?;

    let app = create_router().merge(token_api_handler.router(token_api_auth));

    info!("Siglet API listening on {}", addr);

    // Bind to address - returns error if fails (e.g., port already in use)
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await
        .map_err(|e| SigletError::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Run the token refresh API
///
/// This function binds to the specified address and runs until either:
/// - The cancellation token is triggered
/// - An error occurs
pub(crate) async fn run_refresh_api(
    bind: IpAddr,
    port: u16,
    refresh_handler: TokenRefreshHandler,
    cancel_token: CancellationToken,
) -> Result<(), SigletError> {
    let addr: SocketAddr = format!("{}:{}", bind, port)
        .parse()
        .map_err(|e: std::net::AddrParseError| SigletError::Network(Box::new(e)))?;

    let app = refresh_handler.router().layer(TraceLayer::new_for_http());

    info!("Refresh API listening on {}", addr);

    // Bind to address - returns error if fails (e.g., port already in use)
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await
        .map_err(|e| SigletError::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Create the Siglet management API router
fn create_router() -> Router {
    Router::new()
        .route(ENDPOINT_ROOT, get(root))
        .route(ENDPOINT_HEALTH, get(health))
        .layer(TraceLayer::new_for_http())
}

/// Root endpoint handler
async fn root() -> impl IntoResponse {
    Json(json!({
        "name": APP_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "status": STATUS_RUNNING
    }))
}

/// Health check endpoint handler
async fn health() -> impl IntoResponse {
    Json(json!({
        "status": STATUS_HEALTHY
    }))
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
