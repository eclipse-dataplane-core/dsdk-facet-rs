
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
use sqlx::PgPool;

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
/// - **Concurrent Access**: Thread-safe operations via connection pooling.
///
/// # Examples
///
/// ```ignore
/// use sqlx::PgPool;
/// use facet_client::token::postgres::PostgresTokenStore;
/// use facet_client::token::{TokenStore, TokenData};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a connection pool
/// let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
///
/// // Initialize the token store
/// let store = PostgresTokenStore::builder().pool(pool).build();
/// store.initialize().await?;
///
/// // Save and retrieve a token
/// let token_data = TokenData {
///     identifier: "user1".into(),
///     token: "access_token_value".into(),
///     refresh_token: "refresh_token_value".into(),
///     expires_at: 1234567890,
///     refresh_endpoint: "https://auth.example.com/refresh".into(),
/// };
/// store.save_token(token_data).await?;
/// let retrieved = store.get_token("user1").await?;
/// # Ok(())
/// # }
/// ```
#[derive(Builder)]
pub struct PostgresTokenStore {
    pool: PgPool,
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
        let mut tx = self.pool.begin().await.map_err(|e| {
            TokenError::database_error(format!("Failed to begin transaction: {}", e))
        })?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tokens (
                identifier VARCHAR(255) PRIMARY KEY,
                token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                refresh_endpoint VARCHAR(2048) NOT NULL,
                last_accessed BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
            )",
        )
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to create tokens table: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)")
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to create expires_at index: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_last_accessed ON tokens(last_accessed)")
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to create last_accessed index: {}", e)))?;

        tx.commit().await.map_err(|e| {
            TokenError::database_error(format!("Failed to commit transaction: {}", e))
        })?;
        Ok(())
    }
}

#[async_trait]
impl TokenStore for PostgresTokenStore {
    async fn get_token(&self, identifier: &str) -> Result<TokenData, TokenError> {
        let mut tx = self.pool.begin().await.map_err(|e| {
            TokenError::database_error(format!("Failed to begin transaction: {}", e))
        })?;

        let record: (String, String, String, i64, String, i64) = sqlx::query_as(
            "SELECT identifier, token, refresh_token, expires_at, refresh_endpoint, last_accessed
             FROM tokens WHERE identifier = $1",
        )
            .bind(identifier)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to fetch token: {}", e)))?
            .ok_or_else(|| TokenError::token_not_found(identifier))?;

        // Update last_accessed timestamp within the same transaction
        sqlx::query(
            "UPDATE tokens SET last_accessed = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
             WHERE identifier = $1",
        )
            .bind(identifier)
            .execute(&mut *tx)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to update last_accessed: {}", e)))?;

        tx.commit().await.map_err(|e| {
            TokenError::database_error(format!("Failed to commit transaction: {}", e))
        })?;

        Ok(TokenData {
            identifier: record.0,
            token: record.1,
            refresh_token: record.2,
            expires_at: record.3,
            refresh_endpoint: record.4,
        })
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(TokenError::SystemTimeError)?
            .as_millis() as i64;

        sqlx::query(
            "INSERT INTO tokens (identifier, token, refresh_token, expires_at, refresh_endpoint, last_accessed)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (identifier) DO UPDATE SET
                token = EXCLUDED.token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at,
                refresh_endpoint = EXCLUDED.refresh_endpoint,
                last_accessed = EXCLUDED.last_accessed",
        )
            .bind(&data.identifier)
            .bind(&data.token)
            .bind(&data.refresh_token)
            .bind(data.expires_at)
            .bind(&data.refresh_endpoint)
            .bind(now_millis)
            .execute(&self.pool)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to save token: {}", e)))?;

        Ok(())
    }

    async fn update_token(&self, data: TokenData) -> Result<(), TokenError> {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(TokenError::SystemTimeError)?
            .as_millis() as i64;

        let rows_affected = sqlx::query(
            "UPDATE tokens SET
                token = $2,
                refresh_token = $3,
                expires_at = $4,
                refresh_endpoint = $5,
                last_accessed = $6
             WHERE identifier = $1",
        )
            .bind(&data.identifier)
            .bind(&data.token)
            .bind(&data.refresh_token)
            .bind(data.expires_at)
            .bind(&data.refresh_endpoint)
            .bind(now_millis)
            .execute(&self.pool)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to update token: {}", e)))?
            .rows_affected();

        if rows_affected == 0 {
            return Err(TokenError::cannot_update_non_existent(&data.identifier));
        }

        Ok(())
    }

    async fn remove_token(&self, identifier: &str) -> Result<(), TokenError> {
        sqlx::query("DELETE FROM tokens WHERE identifier = $1")
            .bind(identifier)
            .execute(&self.pool)
            .await
            .map_err(|e| TokenError::database_error(format!("Failed to remove token: {}", e)))?;

        Ok(())
    }

    async fn close(&self) {
        self.pool.close().await;
    }
}