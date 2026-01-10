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

use crate::token::{TokenData, TokenError, TokenStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use facet_common::util::{default_clock, Clock};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory token store for testing and development.
///
/// Maintains tokens in a thread-safe hashmap with multitenancy support.
/// Tokens are isolated by the participant context. Not suitable for production use.
pub struct MemoryTokenStore {
    tokens: RwLock<HashMap<(String, String), TokenRecord>>,
    clock: Arc<dyn Clock>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            clock: default_clock(),
        }
    }

    #[cfg(test)]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            clock,
        }
    }

    /// Remove all tokens that were last accessed before the specified time
    pub async fn remove_tokens_accessed_before(&self, cutoff: DateTime<Utc>) -> Result<usize, TokenError> {
        let mut tokens = self.tokens.write().await;
        let initial_count = tokens.len();
        tokens.retain(|_, record| record.last_accessed > cutoff);
        let removed_count = initial_count - tokens.len();
        Ok(removed_count)
    }
}

impl Default for MemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

struct TokenRecord {
    participant_context: String,
    identifier: String,
    token: String,
    refresh_token: String,
    refresh_endpoint: String,
    expires_at: DateTime<Utc>,
    last_accessed: DateTime<Utc>,
}

#[async_trait]
impl TokenStore for MemoryTokenStore {
    async fn get_token(&self, participant_context: &str, identifier: &str) -> Result<TokenData, TokenError> {
        let mut guard = self.tokens.write().await;
        let key = (participant_context.to_string(), identifier.to_string());

        let record = guard.get(&key).ok_or_else(|| TokenError::token_not_found(identifier))?;

        // Verify participant context matches (defense in depth)
        if record.participant_context != participant_context {
            return Err(TokenError::token_not_found(identifier));
        }

        let now = self.clock.now();
        let token_data = TokenData {
            participant_context: record.participant_context.clone(),
            identifier: record.identifier.clone(),
            token: record.token.clone(),
            refresh_token: record.refresh_token.clone(),
            expires_at: record.expires_at,
            refresh_endpoint: record.refresh_endpoint.clone(),
        };

        // Update last_accessed after cloning the data
        guard.entry(key).and_modify(|record| {
            record.last_accessed = now;
        });

        Ok(token_data)
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        let record = TokenRecord {
            participant_context: data.participant_context.clone(),
            identifier: data.identifier.clone(),
            token: data.token,
            expires_at: data.expires_at,
            refresh_token: data.refresh_token,
            refresh_endpoint: data.refresh_endpoint,
            last_accessed: self.clock.now(),
        };

        let key = (data.participant_context, data.identifier);
        self.tokens.write().await.insert(key, record);
        Ok(())
    }

    async fn update_token(&self, data: TokenData) -> Result<(), TokenError> {
        let mut tokens = self.tokens.write().await;
        let key = (data.participant_context.clone(), data.identifier.clone());

        if !tokens.contains_key(&key) {
            return Err(TokenError::token_not_found(&data.identifier));
        }

        let now = self.clock.now();
        tokens.entry(key).and_modify(|record| {
            record.token = data.token.clone();
            record.refresh_token = data.refresh_token.clone();
            record.expires_at = data.expires_at;
            record.refresh_endpoint = data.refresh_endpoint;
            record.last_accessed = now;
        });

        Ok(())
    }

    async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError> {
        let mut tokens = self.tokens.write().await;
        let key = (participant_context.to_string(), identifier.to_string());
        tokens.remove(&key).ok_or_else(|| TokenError::token_not_found(identifier))?;
        Ok(())
    }
    
    async fn close(&self) {}
}

