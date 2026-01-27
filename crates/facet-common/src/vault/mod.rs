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

pub mod hashicorp;

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

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Secret not found for identifier: {identifier}")]
    SecretNotFound { identifier: String },

    #[error("Token has expired and must be renewed")]
    TokenExpired,

    #[error("General token error: {0}")]
    GeneralError(String),
}

/// In-memory vault client for testing.
pub struct MemoryVaultClient {
    secrets: RwLock<HashMap<String, String>>,
}

#[async_trait]
impl VaultClient for MemoryVaultClient {
    async fn resolve_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<String, VaultError> {
        self.secrets
            .read()
            .unwrap()
            .get(get_path(participant_context, path).as_str())
            .cloned()
            .ok_or(VaultError::SecretNotFound {
                identifier: path.to_string(),
            })
    }

    async fn store_secret(
        &self,
        participant_context: &ParticipantContext,
        path: &str,
        secret: &str,
    ) -> Result<(), VaultError> {
        self.secrets.write().unwrap().insert(get_path(participant_context, path), secret.to_string());
        Ok(())
    }

    async fn remove_secret(&self, participant_context: &ParticipantContext, path: &str) -> Result<(), VaultError> {
        self.secrets.write().unwrap().remove(get_path(participant_context, path).as_str());
        Ok(())
    }
}

fn get_path(participant_context: &ParticipantContext, path: &str) -> String {
    format!("{}/{}", participant_context.id, path)
}
