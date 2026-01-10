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

pub mod jwt;
pub mod mem;
pub mod oauth;
pub mod postgres;

#[cfg(test)]
mod tests;

pub use mem::MemoryTokenStore;
pub use postgres::PostgresTokenStore;

const FIVE_SECONDS_MILLIS: i64 = 5_000;

use crate::lock::LockManager;
use async_trait::async_trait;
use bon::Builder;
use chrono::{DateTime, TimeDelta, Utc};
use facet_common::util::{default_clock, Clock};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;
use thiserror::Error;

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
        participant_context: &str,
        identifier: &str,
        owner: &str,
    ) -> Result<String, TokenError> {
        let data = self.token_store.get_token(participant_context, identifier).await?;

        // Check token validity
        if self.clock.now() < (data.expires_at - TimeDelta::milliseconds(self.refresh_before_expiry_ms)) {
            return Ok(data.token);
        }

        // Token is expiring, acquire lock for refresh
        let guard = self
            .lock_manager
            .lock(identifier, owner)
            .await
            .map_err(|e| TokenError::general_error(format!("Failed to acquire lock: {}", e)))?;

        // Re-fetch token after acquiring lock (another thread may have already refreshed)
        let data = self.token_store.get_token(participant_context, identifier).await?;

        let token = if self.clock.now() >= (data.expires_at - TimeDelta::milliseconds(self.refresh_before_expiry_ms)) {
            // Token still expired after recheck, perform refresh
            let refreshed_data = self
                .token_client
                .refresh_token(
                    participant_context,
                    identifier,
                    &data.refresh_token,
                    &data.refresh_endpoint,
                )
                .await?;
            self.token_store.update_token(refreshed_data.clone()).await?;
            refreshed_data.token
        } else {
            // Token was already refreshed by another thread while we waited for the lock
            data.token
        };

        drop(guard);
        Ok(token)
    }

    pub async fn save_token(
        &self,
        participant_context: &str,
        identifier: &str,
        token: &str,
        refresh_token: &str,
        refresh_endpoint: &str,
        expires_at: DateTime<Utc>,
        owner: &str,
    ) -> Result<(), TokenError> {
        let guard = self
            .lock_manager
            .lock(identifier, owner)
            .await
            .map_err(|e| TokenError::general_error(format!("Failed to acquire lock: {}", e)))?;

        let data = TokenData {
            participant_context: participant_context.to_string(),
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
    async fn refresh_token(
        &self,
        participant_context: &str,
        endpoint_identifier: &str,
        refresh_token: &str,
        refresh_endpoint: &str,
    ) -> Result<TokenData, TokenError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenData {
    pub identifier: String,
    pub participant_context: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_endpoint: String,
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
    async fn get_token(&self, participant_context: &str, identifier: &str) -> Result<TokenData, TokenError>;

    /// Saves or updates a token.
    ///
    /// # Arguments
    /// * `data` - Token data to persist
    ///
    /// # Errors
    /// Returns database operation errors.
    async fn save_token(&self, data: TokenData) -> Result<(), TokenError>;

    /// Updates a token.
    ///
    /// # Arguments
    /// * `data` - Token data to persist
    ///
    /// # Errors
    /// Returns database operation errors.
    async fn update_token(&self, data: TokenData) -> Result<(), TokenError>;

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

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found for identifier: {identifier}")]
    TokenNotFound { identifier: String },

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("General token error: {0}")]
    GeneralError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Generation failed: {0}")]
    GenerationError(#[from] JwtGenerationError), // Auto-converts jsonwebtoken errors
}

impl TokenError {
    pub fn token_not_found(identifier: impl Into<String>) -> Self {
        TokenError::TokenNotFound {
            identifier: identifier.into(),
        }
    }

    pub fn database_error(message: impl Into<String>) -> Self {
        TokenError::DatabaseError(message.into())
    }

    pub fn network_error(message: impl Into<String>) -> Self {
        TokenError::NetworkError(message.into())
    }

    pub fn general_error(message: impl Into<String>) -> Self {
        TokenError::GeneralError(message.into())
    }
}

#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct TokenClaims {
    #[builder(into)]
    pub sub: String,
    #[builder(into)]
    pub iss: String,
    #[builder(into)]
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[builder(default)]
    #[serde(flatten)]
    pub custom: Map<String, Value>,
}

pub trait JwtGenerator: Send + Sync {
    fn generate_token(&self, participant_context: &str, claims: TokenClaims) -> Result<String, JwtGenerationError>;
}

#[derive(Debug, Error)]
pub enum JwtGenerationError {
    #[error("Failed to generate token: {0}")]
    GenerationError(String),
}

/// Verifies JWT tokens and validates claims.
pub trait JwtVerifier: Send + Sync {
    fn verify_token(&self, participant_context: &str, token: &str) -> Result<TokenClaims, JwtVerificationError>;
}

/// Errors that can occur during JWT verification.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Verification error: {0}")]
    VerificationFailed(String),
}
