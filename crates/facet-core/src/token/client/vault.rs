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
/// Vault provides encryption at rest natively, so no separate encryption key is required.
///
/// Every read goes directly to Vault with no in-process cache, ensuring that all instances
/// always see the most recent token, including tokens refreshed by other processes.
pub struct VaultTokenStore {
    vault_client: Arc<dyn VaultClient>,
}

impl VaultTokenStore {
    pub fn new(vault_client: Arc<dyn VaultClient>) -> Self {
        Self { vault_client }
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
            .resolve_secret(participant_context, identifier)
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
            .store_secret(&pc, &data.identifier, &json)
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

        // Read current record to preserve the immutable `endpoint` field
        let json = self
            .vault_client
            .resolve_secret(&pc, identifier)
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
            .store_secret(&pc, identifier, &updated_json)
            .await
            .map_err(|e| TokenError::database_error(e.to_string()))
    }

    async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError> {
        let pc = ParticipantContext::builder().id(participant_context).build();
        self.vault_client
            .remove_secret(&pc, identifier)
            .await
            .map_err(|e| map_vault_err(e, identifier))
    }

    async fn close(&self) {}
}
