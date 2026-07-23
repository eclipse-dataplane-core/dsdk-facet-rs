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

//! Token providers abstract *how* a valid Vault token is obtained for a given participant context,
//! decoupling that concern from the Vault operations in [`crate::client`].
//!
//! Two strategies are supported:
//! - [`RenewingTokenProvider`] wraps the single-token, background-renewed model used by the
//!   `OAuth2` and `KubernetesServiceAccount` auth mechanisms. It returns the same global token
//!   regardless of participant context.
//! - [`ExchangingTokenProvider`] implements the OAuth2 Token Exchange (RFC 8693) flow, minting a
//!   participant-context-bound token on demand and caching it per participant context.

use super::auth::{FileBasedVaultAuthClient, JwtVaultAuthClient, VaultAuthClient, exchange_subject_token, jwt_login};
use super::config::{DEFAULT_ROLE, HashicorpVaultConfig, VaultAuthConfig};
use super::renewal::{RenewalTriggerConfig, TokenRenewer};
use super::state::VaultClientState;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::util::clock::Clock;
use dsdk_facet_core::util::task::TaskHandle;
use dsdk_facet_core::vault::VaultError;
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Abstraction over how a valid Vault token is obtained for a given participant context.
#[async_trait]
pub(crate) trait VaultTokenProvider: Send + Sync {
    /// Returns a valid Vault token for operations bound to the given participant context.
    ///
    /// Implementations that use a single global token (e.g. [`RenewingTokenProvider`]) ignore the
    /// participant context.
    async fn token(&self, ctx: &ParticipantContext) -> Result<String, VaultError>;

    /// Returns true if the provider is healthy (no recent failures beyond the threshold).
    async fn is_healthy(&self) -> bool;

    /// Returns the last error encountered while obtaining a token, if any.
    async fn last_error(&self) -> Option<String>;

    /// Returns the number of consecutive failures obtaining a token.
    async fn consecutive_failures(&self) -> u32;

    /// Signals any background task owned by the provider to stop. No-op if the provider has none.
    fn shutdown(&self);
}

/// Provider that wraps the single-token, background-renewed model.
///
/// Used for the `OAuth2` and `KubernetesServiceAccount` auth mechanisms. A single Vault token is
/// obtained at construction and kept fresh by a background [`TokenRenewer`]; the same token is
/// returned regardless of participant context.
pub(crate) struct RenewingTokenProvider {
    state: Arc<RwLock<VaultClientState>>,
    renewal_handle: Mutex<Option<TaskHandle>>,
}

impl RenewingTokenProvider {
    /// Authenticates once, seeds the client state, and starts the background renewer.
    ///
    /// Returns the provider together with the initial Vault token, so the caller can perform any
    /// one-time setup that needs a token (e.g. ensuring the transit signing key exists).
    ///
    /// Returns an error if `config.auth_config` is not a renewal-based mechanism.
    pub(crate) async fn new(
        config: &HashicorpVaultConfig,
        http_client: Client,
        clock: Arc<dyn Clock>,
    ) -> Result<(Arc<Self>, String), VaultError> {
        let (auth_client, renewal_trigger_config): (Arc<dyn VaultAuthClient>, RenewalTriggerConfig) =
            match &config.auth_config {
                VaultAuthConfig::OAuth2 {
                    client_id,
                    client_secret,
                    token_url,
                    role,
                } => {
                    let auth = Arc::new(
                        JwtVaultAuthClient::builder()
                            .http_client(http_client.clone())
                            .vault_url(&config.vault_url)
                            .client_id(client_id)
                            .client_secret(client_secret)
                            .token_url(token_url)
                            .role(role.as_deref().unwrap_or(DEFAULT_ROLE))
                            .build(),
                    );
                    let trigger_config = RenewalTriggerConfig::TimeBased {
                        renewal_percentage: config.token_renewal_percentage,
                        renewal_jitter: config.renewal_jitter,
                    };
                    (auth, trigger_config)
                }
                VaultAuthConfig::KubernetesServiceAccount { token_file_path } => {
                    let auth = Arc::new(
                        FileBasedVaultAuthClient::builder()
                            .token_file_path(token_file_path.clone())
                            .build(),
                    );
                    let trigger_config = RenewalTriggerConfig::FileBased {
                        token_file_path: token_file_path.clone(),
                    };
                    (auth, trigger_config)
                }
                VaultAuthConfig::TokenExchange { .. } => {
                    return Err(VaultError::InvalidData(
                        "RenewingTokenProvider does not support TokenExchange auth".to_string(),
                    ));
                }
            };

        // Obtain the initial token.
        let (token, lease_duration) = auth_client.authenticate().await?;

        // Create internal state.
        let state = Arc::new(RwLock::new(
            VaultClientState::builder()
                .token(token.clone())
                .last_created(clock.now())
                .lease_duration(lease_duration)
                .health_threshold(config.health_threshold)
                .build(),
        ));

        // Create and start the renewer.
        let renewer = Arc::new(
            TokenRenewer::builder()
                .auth_client(auth_client)
                .http_client(http_client)
                .vault_url(&config.vault_url)
                .state(Arc::clone(&state))
                .renewal_trigger_config(renewal_trigger_config)
                .maybe_on_renewal_error(config.on_renewal_error.clone())
                .clock(clock)
                .max_consecutive_failures(config.max_consecutive_failures)
                .build(),
        );

        let handle = renewer.start()?;

        Ok((
            Arc::new(Self {
                state,
                renewal_handle: Mutex::new(Some(handle)),
            }),
            token,
        ))
    }
}

#[async_trait]
impl VaultTokenProvider for RenewingTokenProvider {
    async fn token(&self, _ctx: &ParticipantContext) -> Result<String, VaultError> {
        Ok(self.state.read().await.token())
    }

    async fn is_healthy(&self) -> bool {
        self.state.read().await.is_healthy()
    }

    async fn last_error(&self) -> Option<String> {
        self.state.read().await.last_error()
    }

    async fn consecutive_failures(&self) -> u32 {
        self.state.read().await.consecutive_failures()
    }

    fn shutdown(&self) {
        if let Ok(mut guard) = self.renewal_handle.lock()
            && let Some(handle) = guard.take()
        {
            handle.shutdown();
        }
    }
}

/// A cached Vault token for a single participant context.
struct CachedToken {
    token: String,
    /// Instant after which the cached token is considered stale and is re-acquired.
    expires_at: DateTime<Utc>,
}

/// Health/observability counters for [`ExchangingTokenProvider`].
struct ProviderHealth {
    consecutive_failures: u32,
    last_error: Option<String>,
    health_threshold: u32,
}

/// Provider implementing OAuth2 Token Exchange (RFC 8693).
///
/// For each participant context, the Kubernetes service-account token (the *subject token*) is
/// exchanged at an STS/OAuth2 endpoint for a participant-context-bound JWT, which is then used with
/// Vault's `auth/jwt/login` to obtain the Vault client token. Tokens are cached per participant
/// context and refreshed lazily on access once they approach expiry — there is no background task.
pub(crate) struct ExchangingTokenProvider {
    http_client: Client,
    vault_url: String,
    exchange_url: String,
    audience: String,
    scope: String,
    subject_token_file_path: PathBuf,
    role: String,
    /// Fraction of the Vault lease after which a cached token is refreshed (e.g. 0.8 = 80%).
    renewal_percentage: f64,
    clock: Arc<dyn Clock>,
    cache: RwLock<HashMap<String, CachedToken>>,
    health: RwLock<ProviderHealth>,
}

impl ExchangingTokenProvider {
    /// Builds a token-exchange provider from a `TokenExchange` auth configuration.
    ///
    /// Returns an error if `config.auth_config` is not [`VaultAuthConfig::TokenExchange`].
    pub(crate) fn new(
        config: &HashicorpVaultConfig,
        http_client: Client,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, VaultError> {
        let VaultAuthConfig::TokenExchange {
            subject_token_file_path,
            exchange_url,
            audience,
            scope,
            role,
        } = &config.auth_config
        else {
            return Err(VaultError::InvalidData(
                "ExchangingTokenProvider requires TokenExchange auth".to_string(),
            ));
        };

        Ok(Arc::new(Self {
            http_client,
            vault_url: config.vault_url.clone(),
            exchange_url: exchange_url.clone(),
            audience: audience.clone(),
            scope: scope.clone(),
            subject_token_file_path: subject_token_file_path.clone(),
            role: role.clone().unwrap_or_else(|| DEFAULT_ROLE.to_string()),
            renewal_percentage: config.token_renewal_percentage,
            clock,
            cache: RwLock::new(HashMap::new()),
            health: RwLock::new(ProviderHealth {
                consecutive_failures: 0,
                last_error: None,
                health_threshold: config.health_threshold,
            }),
        }))
    }

    /// Reads the subject token, performs the RFC 8693 exchange bound to `resource`, and logs into
    /// Vault.
    async fn acquire_token(&self, resource: &str) -> Result<(String, u64), VaultError> {
        if !self.subject_token_file_path.exists() {
            return Err(VaultError::TokenFileNotFound(format!(
                "Subject token file not found at path: {}",
                self.subject_token_file_path.display()
            )));
        }

        let subject_token = tokio::fs::read_to_string(&self.subject_token_file_path)
            .await
            .map_err(|e| {
                VaultError::TokenFileReadError(format!(
                    "Failed to read subject token file {}: {}",
                    self.subject_token_file_path.display(),
                    e
                ))
            })?;
        let subject_token = subject_token.trim();
        if subject_token.is_empty() {
            return Err(VaultError::InvalidTokenFormat(
                "Subject token file is empty".to_string(),
            ));
        }

        // Bind the exchanged token via the `resource` parameter.
        let participant_jwt = exchange_subject_token(
            &self.http_client,
            &format!("{}/token", self.exchange_url),
            subject_token,
            resource,
            &self.audience,
            &self.scope,
        )
        .await?;

        jwt_login(&self.http_client, &self.vault_url, &participant_jwt, &self.role).await
    }

    /// Returns a cached token for `cache_key`, acquiring a fresh one (bound to `resource`) on miss or
    /// expiry. Concurrent acquisitions for the same key are coalesced under the write lock.
    async fn token_for(&self, cache_key: &str, resource: &str) -> Result<String, VaultError> {
        // Fast path: return a still-valid cached token without acquiring the write lock.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(cache_key)
                && self.clock.now() < cached.expires_at
            {
                return Ok(cached.token.clone());
            }
        }

        // Slow path: acquire a fresh token under the write lock. Holding the lock across the
        // exchange serializes concurrent first-time acquisitions, which prevents a thundering herd
        // of duplicate exchanges. A per-key lock would improve throughput but is left as a future
        // optimization — token acquisition is infrequent relative to cached reads.
        let mut cache = self.cache.write().await;

        // Double-check: another task may have populated the cache while we waited for the lock.
        if let Some(cached) = cache.get(cache_key)
            && self.clock.now() < cached.expires_at
        {
            return Ok(cached.token.clone());
        }

        match self.acquire_token(resource).await {
            Ok((token, lease_duration)) => {
                let expires_at = self.compute_expiry(lease_duration);
                cache.insert(
                    cache_key.to_string(),
                    CachedToken {
                        token: token.clone(),
                        expires_at,
                    },
                );
                drop(cache);
                self.record_success().await;
                Ok(token)
            }
            Err(e) => {
                drop(cache);
                self.record_error(&e).await;
                Err(e)
            }
        }
    }

    /// Computes the cache expiry instant from a Vault lease duration.
    fn compute_expiry(&self, lease_duration: u64) -> DateTime<Utc> {
        let valid_secs = (lease_duration as f64 * self.renewal_percentage) as i64;
        self.clock.now() + chrono::Duration::seconds(valid_secs.max(1))
    }

    async fn record_success(&self) {
        let mut health = self.health.write().await;
        health.consecutive_failures = 0;
        health.last_error = None;
    }

    async fn record_error(&self, error: &VaultError) {
        let mut health = self.health.write().await;
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_error = Some(error.to_string());
    }
}

#[async_trait]
impl VaultTokenProvider for ExchangingTokenProvider {
    async fn token(&self, ctx: &ParticipantContext) -> Result<String, VaultError> {
        // Cache key and exchange `resource` are both the participant context id.
        self.token_for(&ctx.id, &ctx.id).await
    }

    async fn is_healthy(&self) -> bool {
        let health = self.health.read().await;
        health.consecutive_failures < health.health_threshold
    }

    async fn last_error(&self) -> Option<String> {
        self.health.read().await.last_error.clone()
    }

    async fn consecutive_failures(&self) -> u32 {
        self.health.read().await.consecutive_failures
    }

    fn shutdown(&self) {
        // Lazy refresh model: no background task to stop.
    }
}
