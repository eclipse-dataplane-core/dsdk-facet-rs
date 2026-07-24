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

use super::auth::handle_error_response;
use super::config::{CONTENT_KEY, HashicorpVaultConfig, VaultAuthConfig};
use super::provider::{ExchangingTokenProvider, RenewingTokenProvider, VaultTokenProvider};
use async_trait::async_trait;
use base64::Engine;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::util::clock::Clock;
use dsdk_facet_core::util::crypto;
use dsdk_facet_core::vault::{KeyMetadata, PublicKeyFormat, VaultClient, VaultError, VaultSigningClient};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Default mount path for the Vault Transit secrets engine
const DEFAULT_TRANSIT_MOUNT_PATH: &str = "transit";

/// Hashicorp Vault client implementation with JWT authentication and automatic token renewal.
pub struct HashicorpVaultClient {
    config: HashicorpVaultConfig,
    http_client: Client,
    clock: Arc<dyn Clock>,
    token_provider: Option<Arc<dyn VaultTokenProvider>>,
}

impl HashicorpVaultClient {
    /// Creates a new uninitialized Hashicorp Vault client.
    ///
    /// The client must be initialized by calling [`initialize()`](Self::initialize) before use.
    pub fn new(config: HashicorpVaultConfig) -> Result<Self, VaultError> {
        let http_client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| VaultError::InvalidData(format!("Failed to create HTTP client: {}", e)))?;

        let clock = config.clock.clone();

        Ok(Self {
            config,
            http_client,
            clock,
            token_provider: None,
        })
    }

    /// Initializes the client by obtaining a vault access token and starting the renewal task.
    ///
    /// This method must be called before using any vault operations.
    pub async fn initialize(&mut self) -> Result<(), VaultError> {
        if self.token_provider.is_some() {
            return Err(VaultError::NotInitializedError("Already initialized".to_string()));
        }

        // Select the token provider strategy based on the configured auth mechanism.
        let provider: Arc<dyn VaultTokenProvider> = match &self.config.auth_config {
            VaultAuthConfig::OAuth2 { .. } | VaultAuthConfig::KubernetesServiceAccount { .. } => {
                // Single global token, renewed in the background.
                let (provider, initial_token) =
                    RenewingTokenProvider::new(&self.config, self.http_client.clone(), self.clock.clone()).await?;
                // Ensure the transit signing key exists if configured (uses the global token).
                self.init_signing_key(&initial_token).await?;
                provider
            }
            VaultAuthConfig::TokenExchange { .. } => {
                // Per-participant-context tokens minted on demand via RFC 8693 token exchange.
                // Signing/transit is out of scope for this mode, so `init_signing_key` is skipped.
                ExchangingTokenProvider::new(&self.config, self.http_client.clone(), self.clock.clone())?
            }
        };

        self.token_provider = Some(provider);

        Ok(())
    }

    /// Returns the last error encountered while obtaining a token, if any.
    pub async fn last_error(&self) -> Result<Option<String>, VaultError> {
        Ok(self.token_provider()?.last_error().await)
    }

    /// Returns true if the client is healthy (no recent failures).
    ///
    /// A client is considered healthy if there are no consecutive failures or fewer than 3 consecutive failures.
    pub async fn is_healthy(&self) -> bool {
        if let Ok(provider) = self.token_provider() {
            provider.is_healthy().await
        } else {
            false
        }
    }

    /// Returns the number of consecutive failures obtaining a token.
    pub async fn consecutive_failures(&self) -> Result<u32, VaultError> {
        Ok(self.token_provider()?.consecutive_failures().await)
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

    /// Constructs the URL for Transit sign operations using an explicit key name.
    fn transit_sign_url_for_key(&self, key_name: &str) -> String {
        format!(
            "{}/v1/{}/sign/{}",
            self.config.vault_url,
            self.config
                .transit_mount_path
                .as_deref()
                .unwrap_or(DEFAULT_TRANSIT_MOUNT_PATH),
            key_name
        )
    }

    /// Constructs the URL for Transit key operations.
    fn transit_key_url(&self, key_name: &str) -> String {
        format!(
            "{}/v1/{}/keys/{}",
            self.config.vault_url,
            self.config
                .transit_mount_path
                .as_deref()
                .unwrap_or(DEFAULT_TRANSIT_MOUNT_PATH),
            key_name
        )
    }

    /// Checks if a transit signing key exists and creates it if it doesn't.
    async fn init_signing_key(&self, token: &str) -> Result<(), VaultError> {
        let key_name = match &self.config.signing_key_name {
            Some(name) => name,
            None => return Ok(()),
        };

        let url = self.transit_key_url(key_name);

        // Try to read the key
        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| VaultError::NetworkError(format!("Failed to check signing key: {}", e)))?;

        if response.status() == StatusCode::NOT_FOUND {
            // Key doesn't exist, create it
            self.create_signing_key(token, key_name).await?;
        } else if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to check signing key").await);
        }

        Ok(())
    }

    /// Creates a new transit signing key.
    async fn create_signing_key(&self, token: &str, key_name: &str) -> Result<(), VaultError> {
        let url = self.transit_key_url(key_name);

        let request = TransitCreateKeyRequest {
            r#type: "ed25519".to_string(),
        };

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&request)
            .send()
            .await
            .map_err(|e| VaultError::NetworkError(format!("Failed to create signing key: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, &format!("Failed to create signing key {}", key_name)).await);
        }

        Ok(())
    }

    /// Returns the token provider, or an error if the client is not initialized.
    fn token_provider(&self) -> Result<&Arc<dyn VaultTokenProvider>, VaultError> {
        self.token_provider
            .as_ref()
            .ok_or_else(|| VaultError::NotInitializedError("Call initialize() first.".to_string()))
    }
}

#[async_trait]
impl VaultClient for HashicorpVaultClient {
    async fn resolve_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<String, VaultError> {
        let token = self.token_provider()?.token(participant_context).await?;
        let url = self.kv_url(participant_context, path);

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::NetworkError(format!("Failed to read secret: {}", e)))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(VaultError::SecretNotFound(path.to_string()));
        }

        if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to read secret").await);
        }

        let read_response: KvV2ReadResponse = response
            .json()
            .await
            .map_err(|e| VaultError::InvalidData(format!("Failed to parse secret response: {}", e)))?;

        read_response
            .data
            .data
            .get(CONTENT_KEY)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::InvalidData("Content field not found or not a string".to_string()))
    }

    async fn store_secret(
        &self,
        participant_context: &ParticipantContext,
        path: &str,
        secret: &str,
    ) -> Result<(), VaultError> {
        let token = self.token_provider()?.token(participant_context).await?;
        let url = self.kv_url(participant_context, path);

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
            .map_err(|e| VaultError::NetworkError(format!("Failed to write secret: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, &format!("Failed to write secret to path {}", path)).await);
        }

        Ok(())
    }

    async fn remove_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<(), VaultError> {
        let token = self.token_provider()?.token(participant_context).await?;

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
            .map_err(|e| VaultError::NetworkError(format!("Failed to delete secret: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, &format!("Failed to delete secret at path {}", path)).await);
        }

        Ok(())
    }
}

impl Drop for HashicorpVaultClient {
    fn drop(&mut self) {
        // Signal any background renewal task owned by the provider to stop.
        if let Some(provider) = &self.token_provider {
            provider.shutdown();
        }
    }
}

#[async_trait]
impl VaultSigningClient for HashicorpVaultClient {
    fn signing_key_name(&self) -> Option<&str> {
        self.config.signing_key_name.as_deref()
    }

    async fn get_key_metadata(
        &self,
        participant_context: &ParticipantContext,
        key_name: &str,
        format: PublicKeyFormat,
    ) -> Result<KeyMetadata, VaultError> {
        let token = self.token_provider()?.token(participant_context).await?;
        let url = self.transit_key_url(key_name);

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::NetworkError(format!("Failed to read key metadata: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to read key metadata").await);
        }

        let key_response: TransitKeyResponse = response
            .json()
            .await
            .map_err(|e| VaultError::InvalidData(format!("Failed to parse key metadata response: {}", e)))?;

        let mut version_numbers: Vec<usize> = key_response.data.keys.keys().filter_map(|v| v.parse().ok()).collect();
        version_numbers.sort_unstable();

        let mut keys = Vec::new();
        for version in version_numbers {
            if let Some(key_info) = key_response.data.keys.get(&version.to_string()) {
                let key = match format {
                    PublicKeyFormat::Multibase => crypto::convert_to_multibase(&key_info.public_key)?,
                    PublicKeyFormat::Base64Url => {
                        let key_bytes = base64::engine::general_purpose::STANDARD
                            .decode(&key_info.public_key)
                            .map_err(|_| VaultError::InvalidData("Invalid key format".to_string()))?;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&key_bytes)
                    }
                };
                keys.push(key);
            }
        }

        // Apply transformer to key name for the returned metadata (only for the configured default key)
        let returned_key_name = if let Some(transformer) = &self.config.jwt_kid_transformer {
            transformer(key_name)
        } else {
            key_name.to_string()
        };

        Ok(KeyMetadata {
            key_name: returned_key_name,
            keys,
            current_version: key_response.data.latest_version,
        })
    }

    async fn sign_content(
        &self,
        participant_context: &ParticipantContext,
        key_name: &str,
        content: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let url = self.transit_sign_url_for_key(key_name);
        let token = self.token_provider()?.token(participant_context).await?;

        let encoded_content = base64::engine::general_purpose::STANDARD.encode(content);
        let request = TransitSignRequest { input: encoded_content };

        let response = self
            .http_client
            .post(url)
            .header("X-Vault-Token", &token)
            .json(&request)
            .send()
            .await
            .map_err(|e| VaultError::NetworkError(format!("Failed to sign content: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to sign content").await);
        }

        let sign_response: TransitSignResponse = response
            .json()
            .await
            .map_err(|e| VaultError::InvalidData(format!("Failed to parse sign response: {}", e)))?;

        let signature_b64 = sign_response
            .data
            .signature
            .rsplit_once(':')
            .map(|(_, sig)| sig)
            .ok_or_else(|| VaultError::InvalidData("Invalid signature format".to_string()))?;

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|_| VaultError::InvalidData("Signature validation failed".to_string()))?;

        Ok(signature_bytes)
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

/// Vault Transit create key request
#[derive(Debug, Serialize)]
struct TransitCreateKeyRequest {
    r#type: String,
}

/// Vault Transit sign request
#[derive(Debug, Serialize)]
struct TransitSignRequest {
    input: String,
}

/// Vault Transit sign response
#[derive(Debug, Deserialize)]
struct TransitSignResponse {
    data: TransitSignData,
}

#[derive(Debug, Deserialize)]
struct TransitSignData {
    signature: String,
}

/// Vault Transit read key response
#[derive(Debug, Deserialize)]
struct TransitKeyResponse {
    data: TransitKeyData,
}

#[derive(Debug, Deserialize)]
struct TransitKeyData {
    latest_version: usize,
    keys: HashMap<String, TransitKeyVersionInfo>,
}

#[derive(Debug, Deserialize)]
struct TransitKeyVersionInfo {
    public_key: String,
}
