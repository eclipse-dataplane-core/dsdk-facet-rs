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
pub use mem::MemoryTokenStore;

const FIVE_SECONDS_MILLIS: i64 = 5_000;

use crate::lock::{LockGuard, LockManager};
use anyhow::Result;
use async_trait::async_trait;
use bon::Builder;
use chrono::Utc;
use std::sync::Arc;

/// Manages token lifecycle with automatic refresh and distributed coordination.
///
/// Coordinates retrieval and refresh of tokens from a remote authorization server,
/// using a lock manager to prevent concurrent refresh attempts. Automatically refreshes
/// expiring tokens before returning them.
/// ```
#[derive(Clone, Builder)]
pub struct TokenClientApi {
    lock_manager: Arc<dyn LockManager>,
    token_store: Arc<dyn TokenStore>,
    token_client: Arc<dyn TokenClient>,
    #[builder(default = FIVE_SECONDS_MILLIS)]
    refresh_before_expiry_ms: i64,
}

impl TokenClientApi {
    pub async fn get_token(&self, identifier: &str, owner: &str) -> Result<String> {
        let data = self.token_store.get_token(identifier).await?;

        let token = if (Utc::now().timestamp_millis() + self.refresh_before_expiry_ms) > data.expires_at {
            // Token is expiring, refresh it
            self.lock_manager.lock(identifier, owner).await?;

            let guard = LockGuard {
                lock_manager: self.lock_manager.clone(),
                identifier: identifier.to_string(),
                owner: owner.to_string(),
            };

            let refreshed_data = self
                .token_client
                .refresh_token(&data.refresh_token, &data.refresh_endpoint)
                .await?;
            self.token_store.update_token(refreshed_data.clone()).await?;
            drop(guard);
            refreshed_data.token
        } else {
            data.token
        };

        Ok(token)
    }
}

/// Refreshes expired tokens with a remote authorization server.
///
/// Implementations handle the details of communicating with a token endpoint to obtain fresh tokens using a refresh
/// token.
#[async_trait]
pub trait TokenClient: Send + Sync {
    async fn refresh_token(&self, refresh_token: &str, refresh_endpoint: &str) -> Result<TokenData>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenData {
    pub identifier: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64, // token expiration timestamp in milliseconds
    pub refresh_endpoint: String,
}

/// Persists and retrieves tokens with optional expiration tracking.
///
/// Implementations provide storage and retrieval of token data, typically including access tokens, refresh tokens, and
/// expiration times. The storage backend (in-memory, database, etc.) is implementation-dependent.
#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn get_token(&self, identifier: &str) -> Result<TokenData>;
    async fn save_token(&self, data: TokenData) -> Result<()>;
    async fn update_token(&self, data: TokenData) -> Result<()>;
    async fn remove_token(&self, identifier: &str) -> Result<()>;
    async fn close(&self);
}
