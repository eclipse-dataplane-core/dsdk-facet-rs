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

//! Per-participant-context signing-key mappings.
//!
//! Associates a participant context with the Vault transit key name and the `kid` to use
//! when signing proof JWTs in the consumer-side token renewal flow. Operators configure
//! these mappings at runtime via the management API; the [`MappingTransitKeyResolver`]
//! (see [`crate::jwt::transit_key`]) reads them to drive [`VaultJwtGenerator`].
//!
//! [`VaultJwtGenerator`]: crate::jwt::VaultJwtGenerator

use async_trait::async_trait;
use bon::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors produced by a [`SigningKeyMappingRepository`].
#[derive(Debug, Error)]
pub enum SigningKeyMappingError {
    #[error("No signing key mapping for participant context: {participant_context_id}")]
    NotFound { participant_context_id: String },

    #[error("Signing key mapping already exists for participant context: {participant_context_id}")]
    AlreadyExists { participant_context_id: String },

    #[error("Storage error: {0}")]
    Storage(String),
}

impl SigningKeyMappingError {
    pub fn not_found(participant_context_id: impl Into<String>) -> Self {
        Self::NotFound {
            participant_context_id: participant_context_id.into(),
        }
    }

    pub fn already_exists(participant_context_id: impl Into<String>) -> Self {
        Self::AlreadyExists {
            participant_context_id: participant_context_id.into(),
        }
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }
}

/// A single participant-context → signing-key association.
///
/// `participant_context_id` is the lookup key (the `id` of the participant context, matching
/// the value [`VaultJwtGenerator`] keys on). `key_name` is the Vault transit key used to sign,
/// and `kid` is the value written verbatim into the JWT header so verifiers can locate the key.
///
/// [`VaultJwtGenerator`]: crate::jwt::VaultJwtGenerator
#[derive(Debug, Clone, PartialEq, Eq, Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyMapping {
    pub participant_context_id: String,
    pub key_name: String,
    pub kid: String,
}

/// Persists and retrieves [`SigningKeyMapping`]s keyed by participant-context id.
///
/// Implementations back the management API CRUD and the renewal-flow lookup. The storage
/// backend (in-memory, Postgres, …) is implementation-dependent.
#[async_trait]
pub trait SigningKeyMappingRepository: Send + Sync {
    /// Inserts a new mapping for the participant context.
    ///
    /// # Errors
    /// Returns [`SigningKeyMappingError::AlreadyExists`] when a mapping already exists for the
    /// participant context.
    async fn create(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError>;

    /// Replaces the existing mapping for the participant context.
    ///
    /// # Errors
    /// Returns [`SigningKeyMappingError::NotFound`] when no mapping exists for the participant context.
    async fn update(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError>;

    /// Returns the mapping for `participant_context_id`.
    ///
    /// # Errors
    /// Returns [`SigningKeyMappingError::NotFound`] when no mapping exists.
    async fn find(&self, participant_context_id: &str) -> Result<SigningKeyMapping, SigningKeyMappingError>;

    /// Removes the mapping for `participant_context_id`.
    ///
    /// # Errors
    /// Returns [`SigningKeyMappingError::NotFound`] when no mapping exists.
    async fn delete(&self, participant_context_id: &str) -> Result<(), SigningKeyMappingError>;
}

/// In-memory [`SigningKeyMappingRepository`] for testing and development.
#[derive(Default)]
pub struct MemorySigningKeyMappingStore {
    store: RwLock<HashMap<String, SigningKeyMapping>>,
}

impl MemorySigningKeyMappingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SigningKeyMappingRepository for MemorySigningKeyMappingStore {
    async fn create(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError> {
        let mut store = self.store.write().await;
        if store.contains_key(&mapping.participant_context_id) {
            return Err(SigningKeyMappingError::already_exists(&mapping.participant_context_id));
        }
        store.insert(mapping.participant_context_id.clone(), mapping);
        Ok(())
    }

    async fn update(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError> {
        let mut store = self.store.write().await;
        if !store.contains_key(&mapping.participant_context_id) {
            return Err(SigningKeyMappingError::not_found(&mapping.participant_context_id));
        }
        store.insert(mapping.participant_context_id.clone(), mapping);
        Ok(())
    }

    async fn find(&self, participant_context_id: &str) -> Result<SigningKeyMapping, SigningKeyMappingError> {
        let store = self.store.read().await;
        store
            .get(participant_context_id)
            .cloned()
            .ok_or_else(|| SigningKeyMappingError::not_found(participant_context_id))
    }

    async fn delete(&self, participant_context_id: &str) -> Result<(), SigningKeyMappingError> {
        let mut store = self.store.write().await;
        store
            .remove(participant_context_id)
            .map(|_| ())
            .ok_or_else(|| SigningKeyMappingError::not_found(participant_context_id))
    }
}

/// Convenience alias for sharing a repository across the runtime.
pub type SharedSigningKeyMappingRepository = Arc<dyn SigningKeyMappingRepository>;
