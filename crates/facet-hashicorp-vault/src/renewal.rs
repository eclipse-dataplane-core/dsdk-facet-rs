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

use super::auth::VaultAuthClient;
use super::config::{DEFAULT_MAX_CONSECUTIVE_FAILURES, ErrorCallback};
use super::state::VaultClientState;
use async_trait::async_trait;
use bon::Builder;
use dsdk_facet_core::util::backoff::{BackoffConfig, calculate_backoff_interval};
use dsdk_facet_core::util::clock::Clock;
use dsdk_facet_core::vault::VaultError;
use log::error;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::Rng;
use reqwest::Client;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc, watch};
use tokio::task::JoinHandle;

/// Trait for abstracting token renewal trigger mechanisms.
///
/// Implementations can be time-based (wait for a percentage of TTL) or event-based (wait for file system events).
#[async_trait]
pub trait RenewalTrigger: Send + Sync {
    /// Wait until the next renewal should occur.
    ///
    /// # Arguments
    /// * `last_ttl` - The TTL from the last authentication, used for calculating time-based triggers
    /// * `consecutive_failures` - Number of consecutive failures, used for backoff calculation
    ///
    /// # Returns
    /// * `Ok(())` - When renewal should happen
    /// * `Err(VaultError)` - If the trigger mechanism fails
    async fn wait_for_trigger(&mut self, last_ttl: u64, consecutive_failures: u32) -> Result<(), VaultError>;
}

/// Configuration for creating a renewal trigger.
///
/// This enum specifies which type of trigger to create and its parameters.
/// The actual trigger instance is created lazily when the renewal loop starts.
#[derive(Clone)]
pub enum RenewalTriggerConfig {
    /// Time-based trigger that renews at a percentage of the token TTL
    TimeBased {
        /// Percentage of lease duration at which to renew token (0.0-1.0, defaults to 0.8)
        renewal_percentage: f64,
        /// Jitter percentage applied to renewal interval (0.0-1.0, defaults to 0.1 = ±10%)
        renewal_jitter: f64,
    },
    /// File-based trigger that watches for file system changes
    FileBased {
        /// Path to the token file to watch for changes
        token_file_path: PathBuf,
    },
}

impl RenewalTriggerConfig {
    /// Creates a trigger instance from this configuration.
    pub fn build(self) -> Result<Box<dyn RenewalTrigger>, VaultError> {
        match self {
            Self::TimeBased {
                renewal_percentage,
                renewal_jitter,
            } => Ok(Box::new(TimeBasedRenewalTrigger::new(
                renewal_percentage,
                renewal_jitter,
            ))),
            Self::FileBased { token_file_path } => Ok(Box::new(FileBasedRenewalTrigger::new(token_file_path)?)),
        }
    }
}

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
    renewal_trigger_config: RenewalTriggerConfig,
    on_renewal_error: Option<ErrorCallback>,
    clock: Arc<dyn Clock>,
    /// Maximum consecutive renewal failures before stopping renewal loop (defaults to 10)
    #[builder(default = DEFAULT_MAX_CONSECUTIVE_FAILURES)]
    max_consecutive_failures: u32,
}

impl TokenRenewer {
    /// Starts the renewal loop in a background task.
    ///
    /// Creates the renewal trigger from the configured trigger config and spawns the renewal loop.
    pub(crate) fn start(self: Arc<Self>) -> Result<RenewalHandle, VaultError> {
        // Create the trigger from config
        let trigger = self.renewal_trigger_config.clone().build()?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task_handle = tokio::spawn(self.renewal_loop(shutdown_rx, trigger));
        Ok(RenewalHandle::new(shutdown_tx, task_handle))
    }

    /// Main renewal loop that periodically renews the Vault token.
    #[doc(hidden)]
    pub async fn renewal_loop(
        self: Arc<Self>,
        mut shutdown_rx: watch::Receiver<bool>,
        mut trigger: Box<dyn RenewalTrigger>,
    ) {
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

            // Wait for either the renewal trigger or shutdown signal
            tokio::select! {
                trigger_result = trigger.wait_for_trigger(lease_duration, consecutive_failures) => {
                    match trigger_result {
                        Ok(()) => {
                            // Trigger fired - attempt renewal
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
                                    if matches!(e, VaultError::AuthenticationError(_)) {
                                        self.handle_token_expiration().await;
                                    } else {
                                        let mut state = self.state.write().await;
                                        self.record_renewal_error(&mut state, &e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Trigger mechanism failed
                            error!("Renewal trigger failed: {}. Stopping renewal task.", e);
                            let mut state = self.state.write().await;
                            self.record_renewal_error(&mut state, &e);
                            break;
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
            .map_err(|e| VaultError::NetworkError(format!("Failed to renew token: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let message = format!("Token renewal failed with status {}: {}", status, body);

            // Check if the token is invalid (expired)
            if body.contains("invalid token") || body.contains("permission denied") {
                return Err(VaultError::AuthenticationError(message));
            }

            return Err(match status.as_u16() {
                403 => VaultError::PermissionDenied(message),
                429 | 500..=599 => VaultError::NetworkError(message.clone()),
                _ => VaultError::NetworkError(message),
            });
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
    pub fn calculate_renewal_interval(
        lease_duration: u64,
        consecutive_failures: u32,
        renewal_percentage: f64,
        jitter: f64,
    ) -> Duration {
        // Calculate base renewal interval (e.g., 80% of lease duration)
        let base_renewal_interval = Duration::from_secs((lease_duration as f64 * renewal_percentage) as u64);

        // Apply exponential backoff using the default configuration (2x multiplier, max 5 exponent)
        let interval_with_backoff =
            calculate_backoff_interval(base_renewal_interval, consecutive_failures, &BackoffConfig::default());

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

/// Time-based renewal trigger that waits for a percentage of the token TTL.
///
/// This is used for OAuth2/OIDC authentication where tokens have a known TTL
/// and should be renewed proactively before expiration.
pub struct TimeBasedRenewalTrigger {
    /// Percentage of lease duration at which to renew token (0.0-1.0, defaults to 0.8)
    renewal_percentage: f64,
    /// Jitter percentage applied to renewal interval (0.0-1.0, defaults to 0.1 = ±10%)
    renewal_jitter: f64,
}

impl TimeBasedRenewalTrigger {
    pub fn new(renewal_percentage: f64, renewal_jitter: f64) -> Self {
        Self {
            renewal_percentage,
            renewal_jitter,
        }
    }
}

#[async_trait]
impl RenewalTrigger for TimeBasedRenewalTrigger {
    async fn wait_for_trigger(&mut self, last_ttl: u64, consecutive_failures: u32) -> Result<(), VaultError> {
        let renewal_interval = TokenRenewer::calculate_renewal_interval(
            last_ttl,
            consecutive_failures,
            self.renewal_percentage,
            self.renewal_jitter,
        );

        tokio::time::sleep(renewal_interval).await;
        Ok(())
    }
}

/// File-based renewal trigger that waits for file system events.
///
/// This is used for Kubernetes service account authentication where a Vault agent sidecar
/// writes tokens to a file. The trigger fires when the file is modified.
pub struct FileBasedRenewalTrigger {
    /// Watcher must be kept alive for the duration of the trigger.
    /// It is not directly accessed, but dropping it would stop file watching.
    _watcher: Option<RecommendedWatcher>,
    event_rx: mpsc::Receiver<notify::Result<Event>>,
}

impl FileBasedRenewalTrigger {
    pub fn new(token_file_path: PathBuf) -> Result<Self, VaultError> {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Create a watcher that sends events to our channel
        let mut watcher = notify::recommended_watcher(move |res| {
            // Use try_send to avoid blocking. If the channel is full, we'll miss this event
            // but another event will come soon.
            let _ = event_tx.try_send(res);
        })
        .map_err(|e| VaultError::TokenFileReadError(format!("Failed to create file watcher: {}", e)))?;

        // Watch the token file for changes
        watcher
            .watch(&token_file_path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                VaultError::TokenFileReadError(format!(
                    "Failed to watch token file {}: {}",
                    token_file_path.display(),
                    e
                ))
            })?;

        Ok(Self {
            _watcher: Some(watcher),
            event_rx,
        })
    }
}

#[async_trait]
impl RenewalTrigger for FileBasedRenewalTrigger {
    async fn wait_for_trigger(&mut self, _last_ttl: u64, _consecutive_failures: u32) -> Result<(), VaultError> {
        loop {
            match self.event_rx.recv().await {
                Some(Ok(event)) => {
                    // Check if this is a modify, create, or remove event
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        return Ok(());
                    }
                    // Other events (access, etc.) - ignore and continue waiting
                }
                Some(Err(e)) => {
                    return Err(VaultError::TokenFileReadError(format!("File watch error: {}", e)));
                }
                None => {
                    // Channel closed - watcher dropped
                    return Err(VaultError::TokenFileReadError(
                        "File watcher channel closed".to_string(),
                    ));
                }
            }
        }
    }
}
