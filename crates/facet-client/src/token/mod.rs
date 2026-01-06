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

pub mod mem;
pub mod postgres;

#[cfg(test)]
mod tests;

pub use mem::MemoryTokenStore;
pub use postgres::PostgresTokenStore;

const FIVE_SECONDS_MILLIS: i64 = 5_000;

use crate::lock::{LockGuard, LockManager};
use crate::util::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found for identifier: {identifier}")]
    TokenNotFound { identifier: String },

    #[error("Cannot update non-existent token '{identifier}'")]
    CannotUpdateNonExistent { identifier: String },

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl TokenError {
    pub fn token_not_found(identifier: impl Into<String>) -> Self {
        TokenError::TokenNotFound {
            identifier: identifier.into(),
        }
    }

    pub fn cannot_update_non_existent(identifier: impl Into<String>) -> Self {
        TokenError::CannotUpdateNonExistent {
            identifier: identifier.into(),
        }
    }

    pub fn database_error(message: impl Into<String>) -> Self {
        TokenError::DatabaseError(message.into())
    }
}

/// Manages token lifecycle with automatic refresh and distributed coordination.
///
/// Coordinates retrieval and refresh of tokens from a remote authorization server,
/// using a lock manager to prevent concurrent refresh attempts. Automatically refreshes
/// expiring tokens before returning them.
#[derive(Clone, Builder)]
pub struct TokenClientApi {
    lock_manager: Arc<dyn LockManager>,
    token_store: Arc<dyn TokenStore>,
    token_client: Arc<dyn TokenClient>,
    #[builder(default = FIVE_SECONDS_MILLIS)]
    refresh_before_expiry_ms: i64,
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl TokenClientApi {
    pub async fn get_token(&self, identifier: &str, owner: &str) -> Result<String, TokenError> {
        let data = self.token_store.get_token(identifier).await?;

        let token = if self.clock.now() >= (data.expires_at - ChronoDuration::milliseconds(self.refresh_before_expiry_ms)) {
            // Token is expiring, refresh it
            self.lock_manager.lock(identifier, owner).await.map_err(|e| TokenError::database_error(format!("Failed to acquire lock: {}", e)))?;

            let guard = LockGuard {
                lock_manager: self.lock_manager.clone(),
                identifier: identifier.to_string(),
                owner: owner.to_string(),
            };

            let refreshed_data = self.token_client.refresh_token(&data.refresh_token, &data.refresh_endpoint).await?;
            self.token_store.update_token(refreshed_data.clone()).await?;
            drop(guard);
            refreshed_data.token
        } else {
            data.token
        };

        Ok(token)
    }

    pub async fn create_token(
        &self,
        identifier: &str,
        token: &str,
        refresh_token: &str,
        refresh_endpoint: &str,
        expires_at: DateTime<Utc>,
        owner: &str,
    ) -> Result<(), TokenError> {
        self.lock_manager.lock(identifier, owner).await.map_err(|e| TokenError::database_error(format!("Failed to acquire lock: {}", e)))?;

        let guard = LockGuard {
            lock_manager: self.lock_manager.clone(),
            identifier: identifier.to_string(),
            owner: owner.to_string(),
        };

        let data = TokenData {
            identifier: identifier.to_string(),
            token: token.to_string(),
            refresh_token: refresh_token.to_string(),
            expires_at,
            refresh_endpoint: refresh_endpoint.to_string(),
        };

        let _ = self.token_store.save_token(data).await?;
        drop(guard);
        Ok(())
    }
}

/// Refreshes expired tokens with a remote authorization server.
///
/// Implementations handle the details of communicating with a token endpoint to obtain fresh tokens using a refresh
/// token.
#[async_trait]
pub trait TokenClient: Send + Sync {
    async fn refresh_token(&self, refresh_token: &str, refresh_endpoint: &str) -> Result<TokenData, TokenError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenData {
    pub identifier: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_endpoint: String,
}

/// Persists and retrieves tokens with optional expiration tracking.
///
/// Implementations provide storage and retrieval of token data, typically including access tokens, refresh tokens, and
/// expiration times. The storage backend (in-memory, database, etc.) is implementation-dependent.
#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn get_token(&self, identifier: &str) -> Result<TokenData, TokenError>;
    async fn save_token(&self, data: TokenData) -> Result<(), TokenError>;
    async fn update_token(&self, data: TokenData) -> Result<(), TokenError>;
    async fn remove_token(&self, identifier: &str) -> Result<(), TokenError>;
    async fn close(&self);
}




