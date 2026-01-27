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

use crate::util::backoff::{BackoffConfig, calculate_backoff_interval};
use crate::util::clock::Clock;
use crate::vault::VaultError;
use super::auth::VaultAuthClient;
use super::config::{ErrorCallback, DEFAULT_TOKEN_RENEWAL_PERCENTAGE, DEFAULT_MAX_CONSECUTIVE_FAILURES, DEFAULT_RENEWAL_JITTER};
use super::state::VaultClientState;
use bon::Builder;
use log::{debug, error};
use rand::Rng;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use serde::Serialize;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

/// Handle for managing the token renewal task lifecycle.
///
/// Dropping this handle will signal the renewal task to stop and abort it.
pub(crate) struct RenewalHandle {
    shutdown_tx: watch::Sender<bool>,
    task_handle: JoinHandle<()>,
}

impl RenewalHandle {
    pub(crate) fn new(shutdown_tx: watch::Sender<bool>, task_handle: JoinHandle<()>) -> Self {
        Self {
            shutdown_tx,
            task_handle,
        }
    }

    /// Signals the renewal task to stop and aborts it.
    #[allow(dead_code)]
    pub(crate) fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.task_handle.abort();
    }
}

impl Drop for RenewalHandle {
    fn drop(&mut self) {
        // Signal the renewal task to stop
        let _ = self.shutdown_tx.send(true);
        // Abort the task as backup
        self.task_handle.abort();
    }
}

/// Manages automatic renewal of Vault tokens in a background task.
///
/// **Note**: This struct is exposed for testing but should not be used directly in production.
#[derive(Builder)]
#[builder(on(String, into))]
pub struct TokenRenewer {
    auth_client: Arc<dyn VaultAuthClient>,
    http_client: Client,
    vault_url: String,
    state: Arc<RwLock<VaultClientState>>,
    on_renewal_error: Option<ErrorCallback>,
    clock: Arc<dyn Clock>,
    /// Percentage of lease duration at which to renew token (0.0-1.0, defaults to 0.8)
    #[builder(default = DEFAULT_TOKEN_RENEWAL_PERCENTAGE)]
    token_renewal_percentage: f64,
    /// Maximum consecutive renewal failures before stopping renewal loop (defaults to 10)
    #[builder(default = DEFAULT_MAX_CONSECUTIVE_FAILURES)]
    max_consecutive_failures: u32,
    /// Jitter percentage applied to renewal interval (0.0-1.0, defaults to 0.1 = ±10%)
    #[builder(default = DEFAULT_RENEWAL_JITTER)]
    renewal_jitter: f64,
}

impl TokenRenewer {

    /// Starts the renewal loop in a background task.
    pub(crate) fn start(self: Arc<Self>) -> RenewalHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task_handle = tokio::spawn(self.renewal_loop(shutdown_rx));
        RenewalHandle::new(shutdown_tx, task_handle)
    }

    /// Main renewal loop that periodically renews the Vault token.
    #[doc(hidden)]
    pub async fn renewal_loop(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        loop {
            let (lease_duration, consecutive_failures) = {
                let state = self.state.read().await;
                (state.lease_duration(), state.consecutive_failures())
            };

            // Check if we've exceeded the maximum number of failures
            if consecutive_failures >= self.max_consecutive_failures {
                error!(
                    "Token renewal failed {} times consecutively. Stopping renewal task.",
                    self.max_consecutive_failures
                );
                break;
            }

            // Calculate renewal interval with exponential backoff and jitter
            let renewal_interval = Self::calculate_renewal_interval(lease_duration, consecutive_failures, self.token_renewal_percentage, self.renewal_jitter);

            // Wait for either the renewal interval or shutdown signal
            tokio::select! {
                _ = tokio::time::sleep(renewal_interval) => {
                    // Attempt to renew the token
                    let current_token = {
                        let state = self.state.read().await;
                        state.token()
                    };

                    match self.renew_token(&current_token, lease_duration).await {
                        Ok(_) => {
                            let mut state = self.state.write().await;
                            self.update_state_on_success(&mut state);
                        }
                        Err(e) => {
                            if matches!(e, VaultError::TokenExpired) {
                                self.handle_token_expiration().await;
                            } else {
                                let mut state = self.state.write().await;
                                self.record_renewal_error(&mut state, &e);
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }

    /// Renews the current Vault token.
    async fn renew_token(&self, token: &str, lease_duration: u64) -> Result<(), VaultError> {
        let url = format!("{}/v1/auth/token/renew-self", self.vault_url);
        let request = TokenRenewRequest {
            increment: format!("{}s", lease_duration),
        };

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&request)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to renew token: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check if the token is invalid (expired)
            if body.contains("invalid token") || body.contains("permission denied") {
                return Err(VaultError::TokenExpired);
            }

            return Err(VaultError::GeneralError(format!(
                "Token renewal failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Records a renewal error in the state and invokes the error callback if configured.
    #[doc(hidden)]
    pub fn record_renewal_error(&self, state: &mut VaultClientState, error: &VaultError) {
        error!("Error renewing token: {}. Will attempt renewal at next interval", error);
        if let Some(callback) = &self.on_renewal_error {
            callback(error);
        }
        state.consecutive_failures += 1;
        state.last_error = Some(error.to_string());
    }

    /// Updates the state after successful token renewal.
    #[doc(hidden)]
    pub fn update_state_on_success(&self, state: &mut VaultClientState) {
        state.last_renewed = Some(self.clock.now());
        state.consecutive_failures = 0;
        state.last_error = None;
    }

    /// Handles token expiration by obtaining a new JWT and creating a new Vault token.
    async fn handle_token_expiration(&self) {
        debug!("Token expired, getting a new access token");

        let result = self.auth_client.authenticate().await;

        match result {
            Ok((new_token, new_lease_duration)) => {
                let mut state = self.state.write().await;
                state.token = new_token;
                state.lease_duration = new_lease_duration;
                state.last_created = self.clock.now();
                state.last_renewed = None;
                state.consecutive_failures = 0;
                state.last_error = None;
            }
            Err(e) => {
                let mut state = self.state.write().await;
                self.record_renewal_error(&mut state, &e);
            }
        }
    }

    /// Calculates the renewal interval with exponential backoff and jitter based on consecutive failures.
    #[doc(hidden)]
    pub fn calculate_renewal_interval(lease_duration: u64, consecutive_failures: u32, renewal_percentage: f64, jitter: f64) -> Duration {
        // Calculate base renewal interval (e.g., 80% of lease duration)
        let base_renewal_interval = Duration::from_secs((lease_duration as f64 * renewal_percentage) as u64);

        // Apply exponential backoff using the default configuration (2x multiplier, max 5 exponent)
        let interval_with_backoff = calculate_backoff_interval(base_renewal_interval, consecutive_failures, &BackoffConfig::default());

        // Apply jitter to prevent thundering herd (e.g., ±10% randomization)
        if jitter > 0.0 {
            let jitter_factor = 1.0 + rand::rng().random_range(-jitter..jitter);
            let jittered_secs = interval_with_backoff.as_secs_f64() * jitter_factor;
            Duration::from_secs_f64(jittered_secs.max(0.0))
        } else {
            interval_with_backoff
        }
    }
}

/// Vault token renewal request
#[derive(Debug, Serialize)]
struct TokenRenewRequest {
    pub(crate) increment: String,
}

