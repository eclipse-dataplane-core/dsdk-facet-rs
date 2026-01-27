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

use super::auth::{JwtVaultAuthClient, VaultAuthClient, handle_error_response};
use super::config::{CONTENT_KEY, DEFAULT_ROLE, HashicorpVaultConfig};
use super::renewal::{RenewalHandle, TokenRenewer};
use super::state::VaultClientState;
use crate::context::ParticipantContext;
use crate::util::clock::Clock;
use crate::vault::{VaultClient, VaultError};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Hashicorp Vault client implementation with JWT authentication and automatic token renewal.
pub struct HashicorpVaultClient {
    config: HashicorpVaultConfig,
    http_client: Client,
    clock: Arc<dyn Clock>,
    state: Option<Arc<RwLock<VaultClientState>>>,
    renewal_handle: Option<RenewalHandle>,
}

impl HashicorpVaultClient {
    /// Creates a new uninitialized Hashicorp Vault client.
    ///
    /// The client must be initialized by calling [`initialize()`](Self::initialize) before use.
    pub fn new(config: HashicorpVaultConfig) -> Result<Self, VaultError> {
        let http_client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| VaultError::GeneralError(format!("Failed to create HTTP client: {}", e)))?;

        let clock = config.clock.clone();

        Ok(Self {
            config,
            http_client,
            clock,
            state: None,
            renewal_handle: None,
        })
    }

    /// Initializes the client by obtaining a vault access token and starting the renewal task.
    ///
    /// This method must be called before using any vault operations.
    pub async fn initialize(&mut self) -> Result<(), VaultError> {
        if self.state.is_some() {
            return Err(VaultError::GeneralError("Client is already initialized".to_string()));
        }

        // Create auth client
        let auth_client = Arc::new(
            JwtVaultAuthClient::builder()
                .http_client(self.http_client.clone())
                .vault_url(&self.config.vault_url)
                .client_id(&self.config.client_id)
                .client_secret(&self.config.client_secret)
                .token_url(&self.config.token_url)
                .role(self.config.role.as_deref().unwrap_or(DEFAULT_ROLE))
                .build(),
        );

        // Obtain initial token
        let (token, lease_duration) = auth_client.authenticate().await?;

        // Create internal state
        let state = Arc::new(RwLock::new(
            VaultClientState::builder()
                .token(token)
                .last_created(self.clock.now())
                .lease_duration(lease_duration)
                .health_threshold(self.config.health_threshold)
                .build(),
        ));

        // Create and start the renewer
        let renewer = Arc::new(
            TokenRenewer::builder()
                .auth_client(auth_client)
                .http_client(self.http_client.clone())
                .vault_url(&self.config.vault_url)
                .state(Arc::clone(&state))
                .maybe_on_renewal_error(self.config.on_renewal_error.clone())
                .clock(self.clock.clone())
                .token_renewal_percentage(self.config.token_renewal_percentage)
                .max_consecutive_failures(self.config.max_consecutive_failures)
                .build(),
        );

        let handle = renewer.start();

        self.state = Some(state);
        self.renewal_handle = Some(handle);

        Ok(())
    }

    /// Returns the last error encountered during token renewal, if any.
    pub async fn last_error(&self) -> Result<Option<String>, VaultError> {
        let state = self.ensure_initialized()?;
        Ok(state.read().await.last_error())
    }

    /// Returns true if the client is healthy (no recent failures).
    ///
    /// A client is considered healthy if there are no consecutive failures or fewer than 3 consecutive failures.
    pub async fn is_healthy(&self) -> bool {
        if let Ok(state) = self.ensure_initialized() {
            state.read().await.is_healthy()
        } else {
            false
        }
    }

    /// Returns the number of consecutive renewal failures.
    pub async fn consecutive_failures(&self) -> Result<u32, VaultError> {
        let state = self.ensure_initialized()?;
        Ok(state.read().await.consecutive_failures())
    }

    /// Constructs the URL for KV v2 operations.
    fn kv_url(&self, participant_context: &ParticipantContext, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}/{}",
            self.config.vault_url,
            self.config.mount_path.as_deref().unwrap_or("secret"),
            participant_context.id,
            path
        )
    }

    /// Constructs the URL for KV v2 metadata operations.
    fn kv_metadata_url(&self, participant_context: &ParticipantContext, path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}/{}",
            self.config.vault_url,
            self.config.mount_path.as_deref().unwrap_or("secret"),
            participant_context.id,
            path
        )
    }

    /// Ensures the client is initialized, returning an error if not.
    fn ensure_initialized(&self) -> Result<&Arc<RwLock<VaultClientState>>, VaultError> {
        self.state
            .as_ref()
            .ok_or_else(|| VaultError::GeneralError("Client not initialized. Call initialize() first.".to_string()))
    }
}

#[async_trait]
impl VaultClient for HashicorpVaultClient {
    async fn resolve_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<String, VaultError> {
        let state = self.ensure_initialized()?;
        let url = self.kv_url(participant_context, path);
        let token = {
            let state = state.read().await;
            state.token()
        };

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to read secret: {}", e)))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(VaultError::SecretNotFound {
                identifier: path.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to read secret").await);
        }

        let read_response: KvV2ReadResponse = response
            .json()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to parse secret response: {}", e)))?;

        read_response
            .data
            .data
            .get(CONTENT_KEY)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::GeneralError("Content field not found or not a string".to_string()))
    }

    async fn store_secret(
        &self,
        participant_context: &ParticipantContext,
        path: &str,
        secret: &str,
    ) -> Result<(), VaultError> {
        let state = self.ensure_initialized()?;
        let url = self.kv_url(participant_context, path);
        let token = {
            let state = state.read().await;
            state.token()
        };

        let mut data = serde_json::Map::new();
        data.insert(CONTENT_KEY.to_string(), serde_json::Value::String(secret.to_string()));

        let request = KvV2WriteRequest {
            data: serde_json::Value::Object(data),
        };

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", &token)
            .json(&request)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to write secret: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, &format!("Failed to write secret to path {}", path)).await);
        }

        Ok(())
    }

    async fn remove_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<(), VaultError> {
        let state = self.ensure_initialized()?;
        let token = {
            let state = state.read().await;
            state.token()
        };

        let url = if self.config.soft_delete {
            // Soft delete - delete the latest version
            self.kv_url(participant_context, path)
        } else {
            // Hard delete - remove all versions and metadata
            self.kv_metadata_url(participant_context, path)
        };

        let response = self
            .http_client
            .delete(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to delete secret: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, &format!("Failed to delete secret at path {}", path)).await);
        }

        Ok(())
    }
}

impl Drop for HashicorpVaultClient {
    fn drop(&mut self) {
        // Signal the renewal task to stop and abort it
        if let Some(handle) = self.renewal_handle.take() {
            handle.shutdown();
        }
    }
}

/// Vault KV v2 write request
#[derive(Debug, Serialize)]
struct KvV2WriteRequest {
    data: serde_json::Value,
}

/// Vault KV v2 read response
#[derive(Debug, Deserialize)]
struct KvV2ReadResponse {
    data: KvV2Data,
}

#[derive(Debug, Deserialize)]
struct KvV2Data {
    data: serde_json::Value,
}
