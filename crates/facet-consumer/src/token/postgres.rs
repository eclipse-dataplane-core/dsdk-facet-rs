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
use bon::Builder;
use chrono::DateTime;
use facet_common::util::clock::{default_clock, Clock};
use facet_common::util::encryption::{decrypt, encrypt};
use sodiumoxide::crypto::secretbox;
use sqlx::PgPool;
use std::sync::Arc;
use facet_common::context::ParticipantContext;

/// Postgres-backed token store using SQLx connection pooling.
///
/// `PostgresTokenStore` provides persistent, distributed token storage backed by a Postgres database.
/// It enables multiple services or instances to share and coordinate token management with
/// automatic expiration tracking and cleanup.
///
/// # Features
///
/// - **Distributed Token Storage**: Tokens are persisted in Postgres, enabling coordination across
///   multiple services or instances.
/// - **Automatic Expiration Tracking**: Tracks token expiration times and supports automatic cleanup
///   of stale tokens.
/// - **Token Encryption**: Tokens are encrypted at rest. However, encryption key rotation is not supported.
/// - **Multitenancy Support**: Tokens are isolated by participant context, ensuring tenant data separation.
/// - **Concurrent Access**: Thread-safe operations via connection pooling.
///
/// # Setup
///
/// Generate the `encryption_key` at startup using `crate::util::encryption_key()`. The password and salt
/// must be consistent across instances and restarts and should be stored securely:
///
/// ```no_run
/// # use facet_consumer::token::PostgresTokenStore;
/// # use sqlx::PgPool;
///
/// # async fn launch() -> Result<(), Box<dyn std::error::Error>> {
/// let pool = PgPool::connect("").await?;
/// let password = std::env::var("ENCRYPTION_PASSWORD")?;
/// let salt_hex = std::env::var("ENCRYPTION_SALT")?;
/// let key = facet_common::util::encryption::encryption_key(&password, &salt_hex)?;
///
/// let store = PostgresTokenStore::builder()
///     .pool(pool)
///     .encryption_key(key)
///     .build();
///
/// # Ok(())
/// # }
/// ```
#[derive(Builder)]
pub struct PostgresTokenStore {
    pool: PgPool,
    encryption_key: secretbox::Key,
    
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl PostgresTokenStore {
    /// Initializes the tokens table and indexes.
    ///
    /// Creates the `tokens` table and indexes if they don't already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), TokenError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to begin transaction: {}", e)))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tokens (
                participant_context VARCHAR(255) NOT NULL,
                identifier VARCHAR(255) NOT NULL,
                token BYTEA NOT NULL,
                token_nonce BYTEA NOT NULL,
                refresh_token BYTEA NOT NULL,
                refresh_token_nonce BYTEA NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                refresh_endpoint VARCHAR(2048) NOT NULL,
                last_accessed TIMESTAMP WITH TIME ZONE NOT NULL,
                PRIMARY KEY (participant_context, identifier)
            )",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to create tokens table: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)")
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to create expires_at index: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_participant_context ON tokens(participant_context)")
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to create participant_context index: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to commit transaction: {}", e)))?;
        Ok(())
    }
}

#[async_trait]
impl TokenStore for PostgresTokenStore {
    async fn get_token(&self, participant_context: &ParticipantContext, identifier: &str) -> Result<TokenData, TokenError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to begin transaction: {}", e)))?;

        let record: TokenRecord = sqlx::query_as(
            "SELECT participant_context, identifier, token, token_nonce, refresh_token, refresh_token_nonce, expires_at, refresh_endpoint
         FROM tokens WHERE participant_context = $1 AND identifier = $2",
        )
            .bind(participant_context.id.clone())
            .bind(identifier)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to fetch token: {}", e)))?
            .ok_or_else(|| TokenError::token_not_found(identifier))?;

        // Verify the participant context matches (defense in depth)
        if record.participant_context != participant_context.id {
            return Err(TokenError::token_not_found(identifier));
        }

        // Decrypt token
        let token_nonce = secretbox::Nonce::from_slice(&record.token_nonce)
            .ok_or_else(|| TokenError::database_error("Invalid token nonce".to_string()))?;
        let decrypted_token =
            decrypt(&self.encryption_key, &record.token, &token_nonce).map_err(|e| TokenError::database_error(e.0))?;
        let token = String::from_utf8(decrypted_token)
            .map_err(|e| TokenError::database_error(format!("Invalid UTF-8 in token: {}", e)))?;

        // Decrypt refresh_token
        let refresh_nonce = secretbox::Nonce::from_slice(&record.refresh_token_nonce)
            .ok_or_else(|| TokenError::database_error("Invalid refresh_token nonce".to_string()))?;
        let decrypted_refresh = decrypt(&self.encryption_key, &record.refresh_token, &refresh_nonce)
            .map_err(|e| TokenError::database_error(e.0))?;
        let refresh_token = String::from_utf8(decrypted_refresh)
            .map_err(|e| TokenError::database_error(format!("Invalid UTF-8 in refresh_token: {}", e)))?;

        let now = self.clock.now();

        // Update last_accessed within the transaction for atomicity
        sqlx::query("UPDATE tokens SET last_accessed = $3 WHERE participant_context = $1 AND identifier = $2")
            .bind(participant_context.id.clone())
            .bind(identifier)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to update last_accessed: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(TokenData {
            participant_context: record.participant_context,
            identifier: record.identifier,
            token,
            refresh_token,
            expires_at: record.expires_at,
            refresh_endpoint: record.refresh_endpoint,
        })
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        // Encrypt token
        let (encrypted_token, token_nonce) = encrypt(&self.encryption_key, data.token.as_bytes());

        // Encrypt refresh_token
        let (encrypted_refresh_token, refresh_nonce) = encrypt(&self.encryption_key, data.refresh_token.as_bytes());

        let now = self.clock.now();

        sqlx::query(
            "INSERT INTO tokens (participant_context, identifier, token, token_nonce, refresh_token, refresh_token_nonce, expires_at, refresh_endpoint, last_accessed)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (participant_context, identifier)
             DO UPDATE SET
                token = EXCLUDED.token,
                token_nonce = EXCLUDED.token_nonce,
                refresh_token = EXCLUDED.refresh_token,
                refresh_token_nonce = EXCLUDED.refresh_token_nonce,
                expires_at = EXCLUDED.expires_at,
                refresh_endpoint = EXCLUDED.refresh_endpoint,
                last_accessed = EXCLUDED.last_accessed",
        )
            .bind(&data.participant_context)
            .bind(&data.identifier)
            .bind(encrypted_token)
            .bind(token_nonce.as_ref())
            .bind(encrypted_refresh_token)
            .bind(refresh_nonce.as_ref())
            .bind(data.expires_at)
            .bind(&data.refresh_endpoint)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to save token: {}", e)))?;

        Ok(())
    }

    async fn update_token(&self, data: TokenData) -> Result<(), TokenError> {
        // Encrypt token
        let (encrypted_token, token_nonce) = encrypt(&self.encryption_key, data.token.as_bytes());

        // Encrypt refresh_token
        let (encrypted_refresh_token, refresh_nonce) = encrypt(&self.encryption_key, data.refresh_token.as_bytes());

        let now = self.clock.now();

        let rows_affected = sqlx::query(
            "UPDATE tokens SET
                token = $3,
                token_nonce = $4,
                refresh_token = $5,
                refresh_token_nonce = $6,
                expires_at = $7,
                refresh_endpoint = $8,
                last_accessed = $9
             WHERE participant_context = $1 AND identifier = $2",
        )
        .bind(&data.participant_context)
        .bind(&data.identifier)
        .bind(encrypted_token)
        .bind(token_nonce.as_ref())
        .bind(encrypted_refresh_token)
        .bind(refresh_nonce.as_ref())
        .bind(data.expires_at)
        .bind(&data.refresh_endpoint)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| TokenError::database_error(format!("Failed to update token: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(TokenError::token_not_found(&data.identifier));
        }

        Ok(())
    }

    async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError> {
        let rows_affected = sqlx::query("DELETE FROM tokens WHERE participant_context = $1 AND identifier = $2")
            .bind(participant_context)
            .bind(identifier)
            .execute(&self.pool)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to remove token: {}", e)))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(TokenError::token_not_found(identifier));
        }

        Ok(())
    }

    async fn close(&self) {
        self.pool.close().await;
    }
}

#[derive(sqlx::FromRow)]
struct TokenRecord {
    participant_context: String,
    identifier: String,
    token: Vec<u8>,
    token_nonce: Vec<u8>,
    refresh_token: Vec<u8>,
    refresh_token_nonce: Vec<u8>,
    expires_at: DateTime<chrono::Utc>,
    refresh_endpoint: String,
}
