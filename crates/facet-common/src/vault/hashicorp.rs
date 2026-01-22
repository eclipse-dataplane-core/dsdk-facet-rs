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
use crate::util::clock::{Clock, default_clock};
use crate::vault::{VaultClient, VaultError};
use async_trait::async_trait;
use bon::Builder;
use chrono::{DateTime, Utc};
use log::{debug, error};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

const CONTENT_KEY: &str = "content";
const DEFAULT_ROLE: &str = "provisioner";
const TOKEN_RENEWAL_PERCENTAGE: f64 = 0.8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONSECUTIVE_FAILURES: u32 = 10;

/// Type alias for the error callback function
pub type ErrorCallback = Arc<dyn Fn(&VaultError) + Send + Sync>;

/// Configuration for the Hashicorp Vault client using JWT authentication.
#[derive(Builder, Clone)]
pub struct HashicorpVaultConfig {
    /// The Vault server URL (e.g., "https://vault.example.com:8200")
    #[builder(into)]
    pub vault_url: String,
    /// OAuth2 client ID for obtaining the JWT token
    #[builder(into)]
    pub client_id: String,
    /// OAuth2 client secret for obtaining the JWT token
    #[builder(into)]
    pub client_secret: String,
    /// OAuth2 token endpoint URL
    #[builder(into)]
    pub token_url: String,
    /// Optional mount path for the KV v2 secrets engine (defaults to "secret")
    pub mount_path: Option<String>,
    /// Whether to use soft delete (true) or hard delete with metadata removal (false)
    #[builder(default)]
    pub soft_delete: bool,
    /// The role to use for JWT authentication (defaults to "provisioner")
    pub role: Option<String>,
    /// Optional callback function invoked when token renewal errors occur
    pub on_renewal_error: Option<ErrorCallback>,
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for HashicorpVaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashicorpVaultConfig")
            .field("vault_url", &self.vault_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("token_url", &self.token_url)
            .field("mount_path", &self.mount_path)
            .field("soft_delete", &self.soft_delete)
            .field("role", &self.role)
            .field(
                "on_renewal_error",
                &self.on_renewal_error.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

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
            .timeout(REQUEST_TIMEOUT)
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

    /// Initializes the client by obtaining a JWT token and starting the renewal task.
    ///
    /// This method must be called before using any vault operations.
    pub async fn initialize(&mut self) -> Result<(), VaultError> {
        if self.state.is_some() {
            return Err(VaultError::GeneralError("Client is already initialized".to_string()));
        }

        // Obtain initial token
        let jwt = Self::get_vault_access_token(
            &self.http_client,
            &self.config.client_id,
            &self.config.client_secret,
            &self.config.token_url,
        )
        .await?;

        let (token, lease_duration) = Self::jwt_login(
            &self.http_client,
            &self.config.vault_url,
            &jwt,
            self.config.role.as_deref().unwrap_or(DEFAULT_ROLE),
        )
        .await?;

        let state = Arc::new(RwLock::new(VaultClientState {
            token,
            last_created: self.clock.now(),
            last_renewed: None,
            lease_duration,
            last_error: None,
            consecutive_failures: 0,
        }));

        // Create auth provider
        let auth_provider = Arc::new(HashicorpAuthProvider {
            http_client: self.http_client.clone(),
            vault_url: self.config.vault_url.clone(),
            client_id: self.config.client_id.clone(),
            client_secret: self.config.client_secret.clone(),
            token_url: self.config.token_url.clone(),
            role: self.config.role.clone().unwrap_or_else(|| DEFAULT_ROLE.to_string()),
        });

        // Create and start renewer
        let renewer = Arc::new(TokenRenewer::new(
            auth_provider,
            self.http_client.clone(),
            self.config.vault_url.clone(),
            Arc::clone(&state),
            self.config.on_renewal_error.clone(),
            self.clock.clone(),
        ));

        let handle = renewer.start();

        self.state = Some(state);
        self.renewal_handle = Some(handle);

        Ok(())
    }

    /// Returns the last error encountered during token renewal, if any.
    pub async fn last_error(&self) -> Result<Option<String>, VaultError> {
        let state = self.ensure_initialized()?;
        Ok(state.read().await.last_error.clone())
    }

    /// Returns true if the client is healthy (no recent failures).
    ///
    /// A client is considered healthy if there are no consecutive failures or fewer than 3 consecutive failures.
    pub async fn is_healthy(&self) -> bool {
        if let Ok(state) = self.ensure_initialized() {
            let s = state.read().await;
            s.consecutive_failures == 0 || s.consecutive_failures < 3
        } else {
            false
        }
    }

    /// Returns the number of consecutive renewal failures.
    pub async fn consecutive_failures(&self) -> Result<u32, VaultError> {
        let state = self.ensure_initialized()?;
        Ok(state.read().await.consecutive_failures)
    }

    /// Constructs the URL for KV v2 operations.
    fn kv_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.config.vault_url,
            self.config.mount_path.as_deref().unwrap_or("secret"),
            path
        )
    }

    /// Constructs the URL for KV v2 metadata operations.
    fn kv_metadata_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.config.vault_url,
            self.config.mount_path.as_deref().unwrap_or("secret"),
            path
        )
    }

    /// Ensures the client is initialized, returning an error if not.
    fn ensure_initialized(&self) -> Result<&Arc<RwLock<VaultClientState>>, VaultError> {
        self.state
            .as_ref()
            .ok_or_else(|| VaultError::GeneralError("Client not initialized. Call initialize() first.".to_string()))
    }

    /// Helper to extract error details from an HTTP response.
    async fn handle_error_response(response: reqwest::Response, context: &str) -> VaultError {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        VaultError::GeneralError(format!("{} with status {}: {}", context, status, body))
    }

    /// Obtains a JWT access token from the OAuth2 token endpoint using client credentials flow.
    async fn get_vault_access_token(
        client: &Client,
        client_id: &str,
        client_secret: &str,
        token_url: &str,
    ) -> Result<String, VaultError> {
        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "client_credentials"),
        ];

        let response = client
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to request access token: {}", e)))?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response, "Token request failed").await);
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to parse token response: {}", e)))?;

        if token_response.access_token.is_empty() {
            return Err(VaultError::GeneralError(
                "Access token not found in response".to_string(),
            ));
        }

        Ok(token_response.access_token)
    }

    /// Authenticates with Vault using JWT and returns the client token and lease duration.
    async fn jwt_login(client: &Client, vault_url: &str, jwt: &str, role: &str) -> Result<(String, u64), VaultError> {
        let url = format!("{}/v1/auth/jwt/login", vault_url);
        let request = JwtLoginRequest {
            jwt: jwt.to_string(),
            role: role.to_string(),
        };

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to authenticate with JWT: {}", e)))?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response, "JWT login failed").await);
        }

        let login_response: JwtLoginResponse = response
            .json()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to parse JWT login response: {}", e)))?;

        Ok((login_response.auth.client_token, login_response.auth.lease_duration))
    }

    /// Main renewal loop that periodically renews the Vault token.
    ///
    /// **Note**: This method is public to allow testing but should not be called directly in production code.
    /// Use the `HashicorpVaultClient` initialization which automatically spawns this loop internally.
    ///
    /// This method now delegates to TokenRenewer for the actual implementation.
    #[doc(hidden)]
    pub async fn renewal_loop(
        config: HashicorpVaultConfig,
        http_client: Client,
        state: Arc<RwLock<VaultClientState>>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // Create auth provider
        let auth_provider = Arc::new(HashicorpAuthProvider {
            http_client: http_client.clone(),
            vault_url: config.vault_url.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            token_url: config.token_url.clone(),
            role: config.role.clone().unwrap_or_else(|| DEFAULT_ROLE.to_string()),
        });

        // Create renewer and delegate
        let renewer = Arc::new(TokenRenewer::new(
            auth_provider,
            http_client,
            config.vault_url.clone(),
            state,
            config.on_renewal_error.clone(),
            config.clock.clone(),
        ));

        renewer.renewal_loop(shutdown_rx).await;
    }
}

#[async_trait]
impl VaultClient for HashicorpVaultClient {
    async fn resolve_secret(&self, path: &str) -> Result<String, VaultError> {
        let state = self.ensure_initialized()?;
        let url = self.kv_url(path);
        let token = {
            let state = state.read().await;
            state.token.clone()
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
            return Err(Self::handle_error_response(response, "Failed to read secret").await);
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

    async fn store_secret(&self, path: &str, secret: &str) -> Result<(), VaultError> {
        let state = self.ensure_initialized()?;
        let url = self.kv_url(path);
        let token = {
            let state = state.read().await;
            state.token.clone()
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
            return Err(Self::handle_error_response(response, &format!("Failed to write secret to path {}", path)).await);
        }

        Ok(())
    }

    async fn remove_secret(&self, path: &str) -> Result<(), VaultError> {
        let state = self.ensure_initialized()?;
        let token = {
            let state = state.read().await;
            state.token.clone()
        };

        let url = if self.config.soft_delete {
            // Soft delete - delete the latest version
            self.kv_url(path)
        } else {
            // Hard delete - remove all versions and metadata
            self.kv_metadata_url(path)
        };

        let response = self
            .http_client
            .delete(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::GeneralError(format!("Failed to delete secret: {}", e)))?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response, &format!("Failed to delete secret at path {}", path)).await);
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

/// OAuth2 token response structure
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Vault JWT login request
#[derive(Debug, Serialize)]
struct JwtLoginRequest {
    jwt: String,
    role: String,
}

/// Vault JWT login response
#[derive(Debug, Deserialize)]
struct JwtLoginResponse {
    auth: AuthInfo,
}

#[derive(Debug, Deserialize)]
struct AuthInfo {
    client_token: String,
    lease_duration: u64,
}

/// Vault token renewal request
#[derive(Debug, Serialize)]
struct TokenRenewRequest {
    increment: String,
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

/// Provides authentication operations for Vault token management.
///
/// This trait enables the token renewal logic to obtain new tokens when the current token expires.
#[async_trait]
pub(crate) trait VaultAuthProvider: Send + Sync {
    /// Obtains a JWT access token from the OAuth2 token endpoint.
    async fn get_vault_access_token(&self) -> Result<String, VaultError>;

    /// Authenticates with Vault using a JWT and returns the client token and lease duration.
    async fn create_vault_token(&self, jwt: &str) -> Result<(String, u64), VaultError>;
}

/// Implementation of VaultAuthProvider for HashiCorp Vault with OAuth2 authentication.
struct HashicorpAuthProvider {
    http_client: Client,
    vault_url: String,
    client_id: String,
    client_secret: String,
    token_url: String,
    role: String,
}

#[async_trait]
impl VaultAuthProvider for HashicorpAuthProvider {
    async fn get_vault_access_token(&self) -> Result<String, VaultError> {
        HashicorpVaultClient::get_vault_access_token(
            &self.http_client,
            &self.client_id,
            &self.client_secret,
            &self.token_url,
        )
        .await
    }

    async fn create_vault_token(&self, jwt: &str) -> Result<(String, u64), VaultError> {
        HashicorpVaultClient::jwt_login(&self.http_client, &self.vault_url, jwt, &self.role).await
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

/// Internal state for the Vault client.
///
/// **Note**: This struct is public to allow testing but should not be used directly in production code.
#[doc(hidden)]
#[cfg_attr(test, derive(Debug))]
pub struct VaultClientState {
    /// The current Vault token
    pub token: String,
    /// When the token was last created
    pub last_created: DateTime<Utc>,
    /// When the token was last renewed
    pub last_renewed: Option<DateTime<Utc>>,
    /// The lease duration in seconds
    pub lease_duration: u64,
    /// The last error encountered during token renewal, if any
    pub last_error: Option<String>,
    /// Number of consecutive renewal failures
    pub consecutive_failures: u32,
}

/// Manages automatic renewal of Vault tokens in a background task.
///
/// **Note**: This struct is module-private and should not be used directly.
pub(crate) struct TokenRenewer {
    auth_provider: Arc<dyn VaultAuthProvider>,
    http_client: Client,
    vault_url: String,
    state: Arc<RwLock<VaultClientState>>,
    on_renewal_error: Option<ErrorCallback>,
    clock: Arc<dyn Clock>,
}

impl TokenRenewer {
    /// Creates a new TokenRenewer.
    pub(crate) fn new(
        auth_provider: Arc<dyn VaultAuthProvider>,
        http_client: Client,
        vault_url: String,
        state: Arc<RwLock<VaultClientState>>,
        on_renewal_error: Option<ErrorCallback>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            auth_provider,
            http_client,
            vault_url,
            state,
            on_renewal_error,
            clock,
        }
    }

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
                (state.lease_duration, state.consecutive_failures)
            };

            // Check if we've exceeded the maximum number of failures
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                error!(
                    "Token renewal failed {} times consecutively. Stopping renewal task.",
                    MAX_CONSECUTIVE_FAILURES
                );
                break;
            }

            // Calculate renewal interval with exponential backoff
            let renewal_interval = Self::calculate_renewal_interval(lease_duration, consecutive_failures);

            // Wait for either the renewal interval or shutdown signal
            tokio::select! {
                _ = tokio::time::sleep(renewal_interval) => {
                    // Attempt to renew the token
                    let current_token = {
                        let state = self.state.read().await;
                        state.token.clone()
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
    pub(crate) fn record_renewal_error(&self, state: &mut VaultClientState, error: &VaultError) {
        error!("Error renewing token: {}. Will attempt renewal at next interval", error);
        if let Some(callback) = &self.on_renewal_error {
            callback(error);
        }
        state.consecutive_failures += 1;
        state.last_error = Some(error.to_string());
    }

    /// Updates the state after successful token renewal.
    pub(crate) fn update_state_on_success(&self, state: &mut VaultClientState) {
        state.last_renewed = Some(self.clock.now());
        state.consecutive_failures = 0;
        state.last_error = None;
    }

    /// Handles token expiration by obtaining a new JWT and creating a new Vault token.
    async fn handle_token_expiration(&self) {
        debug!("Token expired, getting a new access token");

        let result = async {
            let jwt = self.auth_provider.get_vault_access_token().await?;
            let (new_token, new_lease_duration) = self.auth_provider.create_vault_token(&jwt).await?;
            Ok::<_, VaultError>((new_token, new_lease_duration))
        }
        .await;

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

    /// Calculates the renewal interval with exponential backoff based on consecutive failures.
    pub(crate) fn calculate_renewal_interval(lease_duration: u64, consecutive_failures: u32) -> Duration {
        // Calculate base renewal interval (80% of lease duration)
        let base_renewal_interval = Duration::from_secs((lease_duration as f64 * TOKEN_RENEWAL_PERCENTAGE) as u64);

        // Apply exponential backoff using the default configuration (2x multiplier, max 5 exponent)
        calculate_backoff_interval(base_renewal_interval, consecutive_failures, &BackoffConfig::default())
    }
}
