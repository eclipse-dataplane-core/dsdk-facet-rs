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

pub mod endpoint_policy;
pub mod mem;
pub mod oauth;
pub mod vault;

#[cfg(test)]
mod tests;

pub use endpoint_policy::RefreshEndpointPolicy;
pub use mem::MemoryTokenStore;
pub use vault::VaultTokenStore;

const FIVE_SECONDS_MILLIS: i64 = 5_000;

use crate::context::ParticipantContext;
use crate::lock::LockManager;
use crate::token::TokenError;
use crate::util::clock::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

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
    pub async fn get_token(
        &self,
        participant_context: &ParticipantContext,
        identifier: &str,
        owner: &str,
    ) -> Result<TokenResult, TokenError> {
        let data = self.token_store.get_token(participant_context, identifier).await?;

        // Capture endpoint now — it does not change during refresh
        let endpoint = data.endpoint.clone();

        // Check token validity
        if !self.needs_refresh(data.expires_at) {
            return Ok(TokenResult {
                token: data.token,
                endpoint,
            });
        }

        // Token is expiring, acquire lock for refresh
        let _guard = self
            .lock_manager
            .lock(&lock_key(&participant_context.id, identifier), owner)
            .await
            .map_err(|e| TokenError::general_error(format!("Failed to acquire lock: {}", e)))?;

        // Re-fetch token after acquiring lock (another thread may have already refreshed)
        let data = self.token_store.get_token(participant_context, identifier).await?;

        // override participant context identifiers with the one from the token store to ensure consistency during refresh
        let pc = ParticipantContext::builder()
            .id(participant_context.id.clone())
            .identifier(data.participant_id)
            .build();

        let token = if self.needs_refresh(data.expires_at) {
            // Token still expired after recheck, perform refresh
            let refreshed_data = self
                .token_client
                .refresh_token(
                    &pc,
                    &data.counter_party_id,
                    &data.token,
                    &data.refresh_token,
                    &data.refresh_endpoint,
                )
                .await?;
            let token = refreshed_data.token.clone();
            self.token_store
                .update_token(&participant_context.id, identifier, refreshed_data)
                .await?;
            token
        } else {
            // Token was already refreshed by another thread while we waited for the lock
            data.token
        };

        Ok(TokenResult { token, endpoint })
    }

    /// Whether a token expiring at `expires_at` is within the refresh window. An `expires_at` so
    /// close to the minimum timestamp that the window cannot be subtracted counts as expired rather
    /// than overflowing: the value comes from a counterparty-supplied `expiresIn`.
    fn needs_refresh(&self, expires_at: chrono::DateTime<Utc>) -> bool {
        expires_at
            .checked_sub_signed(TimeDelta::milliseconds(self.refresh_before_expiry_ms))
            .is_none_or(|refresh_at| self.clock.now() >= refresh_at)
    }

    pub async fn save_token(&self, token_data: TokenData, owner: &str) -> Result<(), TokenError> {
        let guard = self
            .lock_manager
            .lock(
                &lock_key(&token_data.participant_context, &token_data.identifier),
                owner,
            )
            .await
            .map_err(|e| TokenError::general_error(format!("Failed to acquire lock: {}", e)))?;

        self.token_store.save_token(token_data).await?;
        drop(guard);
        Ok(())
    }

    pub async fn delete_token(
        &self,
        participant_context: &str,
        identifier: &str,
        owner: &str,
    ) -> Result<(), TokenError> {
        let guard = self
            .lock_manager
            .lock(&lock_key(participant_context, identifier), owner)
            .await
            .map_err(|e| TokenError::general_error(format!("Failed to acquire lock: {}", e)))?;

        self.token_store.remove_token(participant_context, identifier).await?;
        drop(guard);
        Ok(())
    }
}

/// Lock key for a stored token. Scoped by participant context, since two participant contexts may
/// hold tokens under the same identifier (flow id).
fn lock_key(participant_context: &str, identifier: &str) -> String {
    format!("{}/{}", participant_context, identifier)
}

/// Refreshes expired tokens with a remote authorization server.
///
/// Implementations handle the details of communicating with a token endpoint to obtain fresh tokens using a refresh
/// token.
#[async_trait]
pub trait TokenClient: Send + Sync {
    async fn refresh_token(
        &self,
        participant_context: &ParticipantContext,
        endpoint_identifier: &str,
        access_token: &str,
        refresh_token: &str,
        refresh_endpoint: &str,
    ) -> Result<RefreshedTokenData, TokenError>;
}

/// The result of a successful `get_token` call, containing the access token and data endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenResult {
    /// The access token to include in requests to the data endpoint.
    pub token: String,
    /// The URL of the data endpoint this token grants access to.
    pub endpoint: String,
}

#[derive(Clone, PartialEq, Eq, Builder)]
#[builder(on(String, into))]
pub struct TokenData {
    pub identifier: String,
    pub participant_context: String,
    pub participant_id: String,
    pub counter_party_id: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub refresh_endpoint: String,
    /// The URL of the data endpoint this token grants access to.
    pub endpoint: String,
}

// Tokens are bearer credentials: `Debug` never prints them.
impl std::fmt::Debug for TokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenData")
            .field("identifier", &self.identifier)
            .field("participant_context", &self.participant_context)
            .field("participant_id", &self.participant_id)
            .field("counter_party_id", &self.counter_party_id)
            .field("token", &crate::token::manager::REDACTED)
            .field("refresh_token", &crate::token::manager::REDACTED)
            .field("expires_at", &self.expires_at)
            .field("refresh_endpoint", &self.refresh_endpoint)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Token data returned by a refresh operation.
///
/// Contains only the fields that change during a refresh. The `endpoint` is intentionally
/// excluded — it is immutable after the token is first saved via [`TokenStore::save_token`]
/// and must never be overwritten by a refresh.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshedTokenData {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub refresh_endpoint: String,
}

impl std::fmt::Debug for RefreshedTokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshedTokenData")
            .field("token", &crate::token::manager::REDACTED)
            .field("refresh_token", &crate::token::manager::REDACTED)
            .field("expires_at", &self.expires_at)
            .field("refresh_endpoint", &self.refresh_endpoint)
            .finish()
    }
}

/// Persists and retrieves tokens with optional expiration tracking.
///
/// Implementations provide storage and retrieval of token data, including access tokens, refresh tokens, and
/// expiration times. The storage backend (in-memory, database, etc.) is implementation-dependent.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Retrieves a token by participant context and identifier.
    ///
    /// # Arguments
    /// * `participant_context` - Participant identifier for isolation
    /// * `identifier` - Token identifier
    ///
    /// # Errors
    /// Returns `TokenError::TokenNotFound` if the token does not exist, or database/decryption errors.
    async fn get_token(
        &self,
        participant_context: &ParticipantContext,
        identifier: &str,
    ) -> Result<TokenData, TokenError>;

    /// Saves or updates a token.
    ///
    /// # Arguments
    /// * `data` - Token data to persist
    ///
    /// # Errors
    /// Returns database operation errors.
    async fn save_token(&self, data: TokenData) -> Result<(), TokenError>;

    /// Updates the mutable fields of a stored token after a refresh.
    ///
    /// Only updates the fields that change during a refresh (`token`, `refresh_token`,
    /// `expires_at`, `refresh_endpoint`). The `endpoint` is intentionally not touched.
    ///
    /// # Arguments
    /// * `participant_context` - Participant identifier for isolation
    /// * `identifier` - Token identifier
    /// * `data` - Refreshed token data
    ///
    /// # Errors
    /// Returns `TokenError::TokenNotFound` if no token exists for the given key,
    /// or database operation errors.
    async fn update_token(
        &self,
        participant_context: &str,
        identifier: &str,
        data: RefreshedTokenData,
    ) -> Result<(), TokenError>;

    /// Deletes a token.
    ///
    /// # Arguments
    /// * `participant_context` - Participant identifier for isolation
    /// * `identifier` - Token identifier
    /// Returns `TokenError::TokenNotFound` if the token does not exist, or database/decryption errors.
    async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError>;

    /// Closes any resources held by the store.
    async fn close(&self);
}
