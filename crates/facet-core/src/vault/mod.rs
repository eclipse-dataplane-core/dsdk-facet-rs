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

#[cfg(test)]
mod tests;

use crate::context::ParticipantContext;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

/// A client for interacting with a secure secrets vault.
#[async_trait]
pub trait VaultClient: Send + Sync {
    async fn resolve_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<String, VaultError>;
    async fn store_secret(
        &self,
        participant_context: &ParticipantContext,
        path: &str,
        secret: &str,
    ) -> Result<(), VaultError>;
    async fn remove_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<(), VaultError>;
}

/// Format for public keys returned by get_key_metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyFormat {
    /// Multibase format (base58btc with 'z' prefix and Ed25519 multicodec prefix 0xed01).
    /// Example: `z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`
    ///
    /// Used for DID (Decentralized Identifier) compatibility.
    Multibase,
    /// Base64url format (raw Ed25519 key bytes, no prefix or padding).
    /// Example: `HbfGpLrYUjBN9dRhWxN3Pw5WhN1bBLRvL8VQZGkJCzE`
    ///
    /// The raw 32-byte Ed25519 public key encoded as base64url without padding.
    Base64Url,
}

/// Metadata about signing keys stored in a vault.
///
/// Contains information about available public keys and which version is currently active.
pub struct KeyMetadata {
    /// The name of the signing key, potentially transformed by a configured transformer.
    ///
    /// This name is used as the base for constructing JWT `kid` values.
    /// For example, with key_name "my-key" and version 2, the JWT kid would be "my-key-2".
    pub key_name: String,

    /// Public keys for all versions, ordered by version number (ascending).
    ///
    /// The vector is indexed by (version - 1), so:
    /// - `keys[0]` contains the public key for version 1
    /// - `keys[1]` contains the public key for version 2
    /// - etc.
    ///
    /// The format of each key string is determined by the `PublicKeyFormat` parameter
    /// passed to `get_key_metadata`.
    pub keys: Vec<String>,

    /// The current (latest) key version, 1-indexed.
    ///
    /// This indicates which key version is actively used for signing.
    /// For example, if `current_version` is 3, the active key is at `keys[2]`.
    pub current_version: usize,
}

/// A client for signing content using a vault. Only Ed25519 signatures are supported.
#[async_trait]
pub trait VaultSigningClient: Send + Sync {
    /// Returns Ed25519 signing keys and associated metadata.
    ///
    /// # Arguments
    /// * `participant_context` - The participant context.
    /// * `format` - The desired format for the public keys (Multibase or Base64Url)
    async fn get_key_metadata(
        &self,
        participant_context: &ParticipantContext,
        format: PublicKeyFormat,
    ) -> Result<KeyMetadata, VaultError>;

    /// Signs content using the current signing key.
    async fn sign_content(
        &self,
        participant_context: &ParticipantContext,
        content: &[u8],
    ) -> Result<Vec<u8>, VaultError>;
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Client not initialized: {0}")]
    NotInitializedError(String),

    #[error("Token file not found: {0}")]
    TokenFileNotFound(String),

    #[error("Token file read error: {0}")]
    TokenFileReadError(String),

    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),
}

impl VaultError {
    pub fn is_retriable(&self) -> bool {
        matches!(self, VaultError::NetworkError(_) | VaultError::AuthenticationError(_))
    }
}

/// In-memory vault client for testing.
pub struct MemoryVaultClient {
    pub secrets: RwLock<HashMap<String, String>>,
}

impl MemoryVaultClient {
    /// Creates a new empty in-memory vault client.
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryVaultClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VaultClient for MemoryVaultClient {
    async fn resolve_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<String, VaultError> {
        self.secrets
            .read()
            .unwrap()
            .get(get_path(participant_context, path).as_str())
            .cloned()
            .ok_or(VaultError::SecretNotFound(path.to_string()))
    }

    async fn store_secret(
        &self,
        participant_context: &ParticipantContext,
        path: &str,
        secret: &str,
    ) -> Result<(), VaultError> {
        self.secrets
            .write()
            .unwrap()
            .insert(get_path(participant_context, path), secret.to_string());
        Ok(())
    }

    async fn remove_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<(), VaultError> {
        self.secrets
            .write()
            .unwrap()
            .remove(get_path(participant_context, path).as_str());
        Ok(())
    }
}

fn get_path(participant_context: &ParticipantContext, path: &str) -> String {
    format!("{}/{}", participant_context.id, path)
}
