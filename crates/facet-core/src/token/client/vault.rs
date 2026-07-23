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

use crate::context::ParticipantContext;
use crate::token::TokenError;
use crate::token::client::{RefreshedTokenData, TokenData, TokenStore};
use crate::vault::{VaultClient, VaultError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct VaultTokenRecord {
    participant_id: String,
    counter_party_id: String,
    token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>,
    refresh_endpoint: String,
    endpoint: String,
}

/// A `TokenStore` implementation backed by Vault KV storage.
///
/// Tokens are stored as single JSON documents at the path `{participant_context.id}/{identifier}`.
/// When an optional `subpath` is configured, an extra segment is inserted, giving
/// `{participant_context.id}/{subpath}/{identifier}` — this lets operators organize client-side
/// tokens under a destination subfolder without changing the stored `identifier`.
/// Vault provides encryption at rest natively, so no separate encryption key is required.
///
/// Every read goes directly to Vault with no in-process cache, ensuring that all instances
/// always see the most recent token, including tokens refreshed by other processes.
pub struct VaultTokenStore {
    vault_client: Arc<dyn VaultClient>,
    /// Optional path segment inserted between the participant context id and the identifier.
    subpath: Option<String>,
}

impl VaultTokenStore {
    pub fn new(vault_client: Arc<dyn VaultClient>) -> Self {
        Self {
            vault_client,
            subpath: None,
        }
    }

    /// Creates a store that inserts `subpath` between the participant context id and the
    /// identifier. A `None`, empty, or slash-only subpath behaves exactly like [`Self::new`].
    pub fn with_subpath(vault_client: Arc<dyn VaultClient>, subpath: Option<String>) -> Self {
        Self { vault_client, subpath }
    }

    /// Builds the key passed to the `VaultClient`, prepending the configured subpath when set.
    /// Surrounding slashes are trimmed so the resulting Vault path never contains `//`.
    fn key(&self, identifier: &str) -> String {
        match self.subpath.as_deref().map(|s| s.trim().trim_matches('/')) {
            Some(sub) if !sub.is_empty() => format!("{sub}/{identifier}"),
            _ => identifier.to_string(),
        }
    }
}

fn map_vault_err(e: VaultError, identifier: &str) -> TokenError {
    match e {
        VaultError::SecretNotFound(_) => TokenError::token_not_found(identifier),
        _ => TokenError::database_error(e.to_string()),
    }
}

#[async_trait]
impl TokenStore for VaultTokenStore {
    async fn get_token(
        &self,
        participant_context: &ParticipantContext,
        identifier: &str,
    ) -> Result<TokenData, TokenError> {
        let json = self
            .vault_client
            .resolve_secret(participant_context, &self.key(identifier))
            .await
            .map_err(|e| map_vault_err(e, identifier))?;

        let record: VaultTokenRecord = serde_json::from_str(&json)
            .map_err(|e| TokenError::database_error(format!("Failed to deserialize token record: {}", e)))?;

        Ok(TokenData::builder()
            .identifier(identifier)
            .participant_context(participant_context.id.clone())
            .participant_id(record.participant_id)
            .counter_party_id(record.counter_party_id)
            .token(record.token)
            .refresh_token(record.refresh_token)
            .expires_at(record.expires_at)
            .refresh_endpoint(record.refresh_endpoint)
            .endpoint(record.endpoint)
            .build())
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        let record = VaultTokenRecord {
            participant_id: data.participant_id.clone(),
            counter_party_id: data.counter_party_id.clone(),
            token: data.token,
            refresh_token: data.refresh_token,
            expires_at: data.expires_at,
            refresh_endpoint: data.refresh_endpoint,
            endpoint: data.endpoint,
        };
        let json = serde_json::to_string(&record)
            .map_err(|e| TokenError::database_error(format!("Failed to serialize token record: {}", e)))?;

        let pc = ParticipantContext::builder().id(&data.participant_context).build();
        self.vault_client
            .store_secret(&pc, &self.key(&data.identifier), &json)
            .await
            .map_err(|e| TokenError::database_error(e.to_string()))
    }

    async fn update_token(
        &self,
        participant_context: &str,
        identifier: &str,
        data: RefreshedTokenData,
    ) -> Result<(), TokenError> {
        let pc = ParticipantContext::builder().id(participant_context).build();
        let key = self.key(identifier);

        // Read current record to preserve the immutable `endpoint` field
        let json = self
            .vault_client
            .resolve_secret(&pc, &key)
            .await
            .map_err(|e| map_vault_err(e, identifier))?;

        let current: VaultTokenRecord = serde_json::from_str(&json)
            .map_err(|e| TokenError::database_error(format!("Failed to deserialize token record: {}", e)))?;

        let updated = VaultTokenRecord {
            participant_id: current.participant_id.clone(),
            counter_party_id: current.counter_party_id.clone(),
            token: data.token,
            refresh_token: data.refresh_token,
            expires_at: data.expires_at,
            refresh_endpoint: data.refresh_endpoint,
            endpoint: current.endpoint,
        };
        let updated_json = serde_json::to_string(&updated)
            .map_err(|e| TokenError::database_error(format!("Failed to serialize token record: {}", e)))?;

        self.vault_client
            .store_secret(&pc, &key, &updated_json)
            .await
            .map_err(|e| TokenError::database_error(e.to_string()))
    }

    async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError> {
        let pc = ParticipantContext::builder().id(participant_context).build();
        self.vault_client
            .remove_secret(&pc, &self.key(identifier))
            .await
            .map_err(|e| map_vault_err(e, identifier))
    }

    async fn close(&self) {}
}
