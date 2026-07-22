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

//! Per-participant-context transfer-type mappings.
//!
//! Associates a participant context with the full set of transfer-type → [`TransferType`]
//! mappings the [`SigletDataFlowHandler`] should use for that context. Operators configure these
//! at runtime through the management API; the signaling handler loads a context's mappings on
//! each request and falls back to the statically-configured mappings when none are stored.
//!
//! Unlike the static, global [`SigletConfig::transfer_types`] this is keyed by participant
//! context, so a multi-participant deployment can point each context at its own backends/auth.
//!
//! [`SigletDataFlowHandler`]: crate::handler::SigletDataFlowHandler
//! [`SigletConfig::transfer_types`]: crate::config::SigletConfig::transfer_types
//! [`TransferType`]: crate::config::TransferType

use crate::config::TransferType;
use async_trait::async_trait;
use bon::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

pub mod postgres;

#[cfg(test)]
mod tests;

/// Errors produced by a [`TransferTypeMappingRepository`].
#[derive(Debug, Error)]
pub enum TransferTypeMappingError {
    #[error("No transfer type mapping for participant context: {participant_context_id}")]
    NotFound { participant_context_id: String },

    #[error("Transfer type mapping already exists for participant context: {participant_context_id}")]
    AlreadyExists { participant_context_id: String },

    #[error("Storage error: {0}")]
    Storage(String),
}

impl TransferTypeMappingError {
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

/// A participant context's complete set of transfer-type mappings.
///
/// `participant_context_id` is the lookup key (the `id` of the participant context, matching
/// `DataFlow.participant_context_id`). `mappings` holds the same profile → [`TransferType`] shape
/// [`SigletDataFlowHandler`] keys on, so a stored mapping wholesale replaces the static
/// configuration for that context.
///
/// [`SigletDataFlowHandler`]: crate::handler::SigletDataFlowHandler
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
#[serde(rename_all = "camelCase")]
pub struct TransferTypeMapping {
    pub participant_context_id: String,
    /// Keyed by transfer type / `DataFlow.profile`, mirroring
    /// `SigletDataFlowHandler.transfer_type_mappings`.
    pub mappings: HashMap<String, TransferType>,
}

/// Persists and retrieves [`TransferTypeMapping`]s keyed by participant-context id.
///
/// Implementations back the management API CRUD and the signaling-flow lookup. The storage
/// backend (in-memory, Postgres, …) is implementation-dependent.
#[async_trait]
pub trait TransferTypeMappingRepository: Send + Sync {
    /// Inserts a new mapping for the participant context.
    ///
    /// # Errors
    /// Returns [`TransferTypeMappingError::AlreadyExists`] when a mapping already exists for the
    /// participant context.
    async fn create(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError>;

    /// Replaces the existing mapping for the participant context.
    ///
    /// # Errors
    /// Returns [`TransferTypeMappingError::NotFound`] when no mapping exists for the participant context.
    async fn update(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError>;

    /// Returns the mapping for `participant_context_id`.
    ///
    /// # Errors
    /// Returns [`TransferTypeMappingError::NotFound`] when no mapping exists.
    async fn find(&self, participant_context_id: &str) -> Result<TransferTypeMapping, TransferTypeMappingError>;

    /// Removes the mapping for `participant_context_id`.
    ///
    /// # Errors
    /// Returns [`TransferTypeMappingError::NotFound`] when no mapping exists.
    async fn delete(&self, participant_context_id: &str) -> Result<(), TransferTypeMappingError>;
}

/// In-memory [`TransferTypeMappingRepository`] for testing and development.
#[derive(Default)]
pub struct MemoryTransferTypeMappingStore {
    store: RwLock<HashMap<String, TransferTypeMapping>>,
}

impl MemoryTransferTypeMappingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TransferTypeMappingRepository for MemoryTransferTypeMappingStore {
    async fn create(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError> {
        let mut store = self.store.write().await;
        if store.contains_key(&mapping.participant_context_id) {
            return Err(TransferTypeMappingError::already_exists(
                &mapping.participant_context_id,
            ));
        }
        store.insert(mapping.participant_context_id.clone(), mapping);
        Ok(())
    }

    async fn update(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError> {
        let mut store = self.store.write().await;
        if !store.contains_key(&mapping.participant_context_id) {
            return Err(TransferTypeMappingError::not_found(&mapping.participant_context_id));
        }
        store.insert(mapping.participant_context_id.clone(), mapping);
        Ok(())
    }

    async fn find(&self, participant_context_id: &str) -> Result<TransferTypeMapping, TransferTypeMappingError> {
        let store = self.store.read().await;
        store
            .get(participant_context_id)
            .cloned()
            .ok_or_else(|| TransferTypeMappingError::not_found(participant_context_id))
    }

    async fn delete(&self, participant_context_id: &str) -> Result<(), TransferTypeMappingError> {
        let mut store = self.store.write().await;
        store
            .remove(participant_context_id)
            .map(|_| ())
            .ok_or_else(|| TransferTypeMappingError::not_found(participant_context_id))
    }
}

/// Convenience alias for sharing a repository across the runtime.
pub type SharedTransferTypeMappingRepository = Arc<dyn TransferTypeMappingRepository>;
