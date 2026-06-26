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

use async_trait::async_trait;
use dsdk_facet_core::jwt::{SigningKeyMapping, SigningKeyMappingError, SigningKeyMappingRepository};
use sqlx::PgPool;

/// Postgres-backed [`SigningKeyMappingRepository`] using SQLx connection pooling.
///
/// Persists the per-participant-context association between a Vault transit key name and the
/// `kid` advertised in proof-JWT headers, enabling multiple Siglet instances to share the
/// mappings configured through the management API.
pub struct PostgresSigningKeyMappingStore {
    pool: PgPool,
}

impl PostgresSigningKeyMappingStore {
    /// Creates a new store with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates the `signing_key_mappings` table if it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), SigningKeyMappingError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS signing_key_mappings (
                participant_context_id TEXT NOT NULL PRIMARY KEY,
                key_name               TEXT NOT NULL,
                kid                    TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SigningKeyMappingError::storage(format!("Failed to create signing_key_mappings table: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl SigningKeyMappingRepository for PostgresSigningKeyMappingStore {
    async fn create(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError> {
        sqlx::query(
            "INSERT INTO signing_key_mappings (participant_context_id, key_name, kid)
             VALUES ($1, $2, $3)",
        )
        .bind(&mapping.participant_context_id)
        .bind(&mapping.key_name)
        .bind(&mapping.kid)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                SigningKeyMappingError::already_exists(&mapping.participant_context_id)
            }
            _ => SigningKeyMappingError::storage(format!("Failed to create signing key mapping: {}", e)),
        })?;

        Ok(())
    }

    async fn update(&self, mapping: SigningKeyMapping) -> Result<(), SigningKeyMappingError> {
        let rows_affected = sqlx::query(
            "UPDATE signing_key_mappings
             SET key_name = $2, kid = $3
             WHERE participant_context_id = $1",
        )
        .bind(&mapping.participant_context_id)
        .bind(&mapping.key_name)
        .bind(&mapping.kid)
        .execute(&self.pool)
        .await
        .map_err(|e| SigningKeyMappingError::storage(format!("Failed to update signing key mapping: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(SigningKeyMappingError::not_found(&mapping.participant_context_id));
        }

        Ok(())
    }

    async fn find(&self, participant_context_id: &str) -> Result<SigningKeyMapping, SigningKeyMappingError> {
        let record: SigningKeyMappingRecord = sqlx::query_as(
            "SELECT participant_context_id, key_name, kid
             FROM signing_key_mappings
             WHERE participant_context_id = $1",
        )
        .bind(participant_context_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SigningKeyMappingError::storage(format!("Failed to fetch signing key mapping: {}", e)))?
        .ok_or_else(|| SigningKeyMappingError::not_found(participant_context_id))?;

        Ok(record.into())
    }

    async fn delete(&self, participant_context_id: &str) -> Result<(), SigningKeyMappingError> {
        let rows_affected = sqlx::query(
            "DELETE FROM signing_key_mappings
             WHERE participant_context_id = $1",
        )
        .bind(participant_context_id)
        .execute(&self.pool)
        .await
        .map_err(|e| SigningKeyMappingError::storage(format!("Failed to delete signing key mapping: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(SigningKeyMappingError::not_found(participant_context_id));
        }

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct SigningKeyMappingRecord {
    participant_context_id: String,
    key_name: String,
    kid: String,
}

impl From<SigningKeyMappingRecord> for SigningKeyMapping {
    fn from(record: SigningKeyMappingRecord) -> Self {
        SigningKeyMapping::builder()
            .participant_context_id(record.participant_context_id)
            .key_name(record.key_name)
            .kid(record.kid)
            .build()
    }
}
