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
use async_trait::async_trait;
use base64::Engine;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::util::clock::Clock;
use dsdk_facet_core::vault::{KeyMetadata, PublicKeyFormat, VaultSigningClient, VaultClient, VaultError};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default mount path for the Vault Transit secrets engine
const DEFAULT_TRANSIT_MOUNT_PATH: &str = "transit";

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
            .map_err(|e| VaultError::InvalidData(format!("Failed to create HTTP client: {}", e)))?;

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
            return Err(VaultError::NotInitializedError("Already initialized".to_string()));
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

        // Ensure signing key exists if configured
        self.init_signing_key(&token).await?;

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

    /// Constructs the URL for Transit sign operations.
    fn transit_sign_url(&self) -> Result<String, VaultError> {
        let key_name = self.config.signing_key_name.as_ref()
            .ok_or_else(|| VaultError::InvalidData("signing_key_name not configured".to_string()))?;

        Ok(format!(
            "{}/v1/{}/sign/{}",
            self.config.vault_url,
            self.config.transit_mount_path.as_deref().unwrap_or(DEFAULT_TRANSIT_MOUNT_PATH),
            key_name
        ))
    }

    /// Constructs the URL for Transit key operations.
    fn transit_key_url(&self, key_name: &str) -> String {
        format!(
            "{}/v1/{}/keys/{}",
            self.config.vault_url,
            self.config.transit_mount_path.as_deref().unwrap_or(DEFAULT_TRANSIT_MOUNT_PATH),
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

    /// Converts an Ed25519 public key to multibase format (base58btc with 'z' prefix).
    pub(crate) fn convert_to_multibase(&self, public_key_base64: &str) -> Result<String, VaultError> {
        // Decode the base64 public key
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64)
            .map_err(|_| VaultError::InvalidData("Invalid key format".to_string()))?;

        // Validate Ed25519 key size (32 bytes)
        if key_bytes.len() != 32 {
            return Err(VaultError::InvalidData(format!(
                "Invalid Ed25519 key size: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        // Add multicodec prefix for Ed25519 public key (0xed01)
        let mut prefixed_key = vec![0xed, 0x01];
        prefixed_key.extend_from_slice(&key_bytes);

        // Encode with base58btc and prepend 'z' prefix
        let encoded = bs58::encode(&prefixed_key).into_string();
        Ok(format!("z{}", encoded))
    }

    /// Validates and decodes a multibase-encoded Ed25519 public key.
    /// Returns the raw 32-byte Ed25519 public key if valid.
    #[allow(dead_code)]
    pub(crate) fn validate_multibase_ed25519(&self, multibase_key: &str) -> Result<Vec<u8>, VaultError> {
        // Check for 'z' prefix (base58btc)
        if !multibase_key.starts_with('z') {
            return Err(VaultError::InvalidData(
                "Invalid multibase format: expected 'z' prefix for base58btc".to_string()
            ));
        }

        // Decode base58btc (skip 'z' prefix)
        let decoded = bs58::decode(&multibase_key[1..])
            .into_vec()
            .map_err(|e| VaultError::InvalidData(format!("Failed to decode base58: {}", e)))?;

        // Validate minimum length (multicodec prefix + key)
        if decoded.len() < 3 {
            return Err(VaultError::InvalidData(
                "Invalid key: too short to contain multicodec prefix".to_string()
            ));
        }

        // Validate Ed25519 multicodec prefix (0xed01)
        if decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err(VaultError::InvalidData(format!(
                "Invalid multicodec prefix: expected [0xed, 0x01] for Ed25519, got [{:#x}, {:#x}]",
                decoded[0], decoded[1]
            )));
        }

        // Extract and validate key bytes
        let key_bytes = &decoded[2..];
        if key_bytes.len() != 32 {
            return Err(VaultError::InvalidData(format!(
                "Invalid Ed25519 key size: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        Ok(key_bytes.to_vec())
    }

    /// Ensures the client is initialized, returning an error if not.
    fn ensure_initialized(&self) -> Result<&Arc<RwLock<VaultClientState>>, VaultError> {
        self.state
            .as_ref()
            .ok_or_else(|| VaultError::NotInitializedError("Call initialize() first.".to_string()))
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
            .map_err(|e| VaultError::NetworkError(format!("Failed to write secret: {}", e)))?;

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
            .map_err(|e| VaultError::NetworkError(format!("Failed to delete secret: {}", e)))?;

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

#[async_trait]
impl VaultSigningClient for HashicorpVaultClient {
    async fn get_key_metadata(
        &self,
        _participant_context: &ParticipantContext,
        format: PublicKeyFormat,
    ) -> Result<KeyMetadata, VaultError> {
        let state = self.ensure_initialized()?;

        let original_key_name = self.config.signing_key_name.as_ref()
            .ok_or_else(|| VaultError::InvalidData("signing_key_name not configured".to_string()))?;

        let url = self.transit_key_url(original_key_name);
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
            .map_err(|e| VaultError::NetworkError(format!("Failed to read key metadata: {}", e)))?;

        if !response.status().is_success() {
            return Err(handle_error_response(response, "Failed to read key metadata").await);
        }

        let key_response: TransitKeyResponse = response
            .json()
            .await
            .map_err(|e| VaultError::InvalidData(format!("Failed to parse key metadata response: {}", e)))?;

        // Convert all key versions to the requested format
        // Collect and sort version numbers to maintain ordering
        let mut version_numbers: Vec<usize> = key_response.data.keys.keys()
            .filter_map(|v| v.parse().ok())
            .collect();
        version_numbers.sort_unstable();

        let mut keys = Vec::new();
        for version in version_numbers {
            if let Some(key_info) = key_response.data.keys.get(&version.to_string()) {
                let key = match format {
                    PublicKeyFormat::Multibase => self.convert_to_multibase(&key_info.public_key)?,
                    PublicKeyFormat::Base64Url => {
                        // Decode base64 and re-encode as base64url
                        let key_bytes = base64::engine::general_purpose::STANDARD
                            .decode(&key_info.public_key)
                            .map_err(|_| VaultError::InvalidData("Invalid key format".to_string()))?;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&key_bytes)
                    }
                };
                keys.push(key);
            }
        }

        // Apply transformer to key name for the returned metadata 
        let key_name = if let Some(transformer) = &self.config.jwt_kid_transformer {
            transformer(original_key_name)
        } else {
            original_key_name.clone()
        };

        Ok(KeyMetadata {
            key_name,
            keys,
            current_version: key_response.data.latest_version,
        })
    }

    async fn sign_content(&self, _participant_context: &ParticipantContext, content: &[u8]) -> Result<Vec<u8>, VaultError> {
        let state = self.ensure_initialized()?;
        let url = self.transit_sign_url()?;
        let token = {
            let state = state.read().await;
            state.token()
        };

        // Encode content as base64
        let encoded_content = base64::engine::general_purpose::STANDARD.encode(content);

        let request = TransitSignRequest {
            input: encoded_content,
        };

        let response = self
            .http_client
            .post(&url)
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

        // Parse vault signature format: "vault:v<version>:<base64_signature>"
        // Extract the raw signature bytes for use by callers
        let signature_b64 = sign_response.data.signature
            .rsplit_once(':')
            .map(|(_, sig)| sig)
            .ok_or_else(|| VaultError::InvalidData("Invalid signature format".to_string()))?;

        // Decode the vault's base64 signature to get raw bytes
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
