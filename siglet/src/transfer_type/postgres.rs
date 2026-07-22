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

//! Postgres-backed [`TransferTypeMappingRepository`].
//!
//! Persists each participant context's full transfer-type map as a single JSONB value, enabling
//! multiple Siglet instances to share the mappings configured through the management API. Mirrors
//! [`dsdk_facet_postgres::signing_key_mapping::PostgresSigningKeyMappingStore`].

use super::{TransferType, TransferTypeMapping, TransferTypeMappingError, TransferTypeMappingRepository};
use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::types::Json;
use std::collections::HashMap;

/// Postgres-backed [`TransferTypeMappingRepository`] using SQLx connection pooling.
pub struct PostgresTransferTypeMappingStore {
    pool: PgPool,
}

impl PostgresTransferTypeMappingStore {
    /// Creates a new store with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates the `transfer_type_mappings` table if it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), TransferTypeMappingError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS transfer_type_mappings (
                participant_context_id TEXT  NOT NULL PRIMARY KEY,
                mappings               JSONB NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            TransferTypeMappingError::storage(format!("Failed to create transfer_type_mappings table: {}", e))
        })?;

        Ok(())
    }
}

#[async_trait]
impl TransferTypeMappingRepository for PostgresTransferTypeMappingStore {
    async fn create(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError> {
        sqlx::query(
            "INSERT INTO transfer_type_mappings (participant_context_id, mappings)
             VALUES ($1, $2)",
        )
        .bind(&mapping.participant_context_id)
        .bind(Json(&mapping.mappings))
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                TransferTypeMappingError::already_exists(&mapping.participant_context_id)
            }
            _ => TransferTypeMappingError::storage(format!("Failed to create transfer type mapping: {}", e)),
        })?;

        Ok(())
    }

    async fn update(&self, mapping: TransferTypeMapping) -> Result<(), TransferTypeMappingError> {
        let rows_affected = sqlx::query(
            "UPDATE transfer_type_mappings
             SET mappings = $2
             WHERE participant_context_id = $1",
        )
        .bind(&mapping.participant_context_id)
        .bind(Json(&mapping.mappings))
        .execute(&self.pool)
        .await
        .map_err(|e| TransferTypeMappingError::storage(format!("Failed to update transfer type mapping: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(TransferTypeMappingError::not_found(&mapping.participant_context_id));
        }

        Ok(())
    }

    async fn find(&self, participant_context_id: &str) -> Result<TransferTypeMapping, TransferTypeMappingError> {
        let record: TransferTypeMappingRecord = sqlx::query_as(
            "SELECT participant_context_id, mappings
             FROM transfer_type_mappings
             WHERE participant_context_id = $1",
        )
        .bind(participant_context_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| TransferTypeMappingError::storage(format!("Failed to fetch transfer type mapping: {}", e)))?
        .ok_or_else(|| TransferTypeMappingError::not_found(participant_context_id))?;

        Ok(record.into())
    }

    async fn delete(&self, participant_context_id: &str) -> Result<(), TransferTypeMappingError> {
        let rows_affected = sqlx::query(
            "DELETE FROM transfer_type_mappings
             WHERE participant_context_id = $1",
        )
        .bind(participant_context_id)
        .execute(&self.pool)
        .await
        .map_err(|e| TransferTypeMappingError::storage(format!("Failed to delete transfer type mapping: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(TransferTypeMappingError::not_found(participant_context_id));
        }

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct TransferTypeMappingRecord {
    participant_context_id: String,
    mappings: Json<HashMap<String, TransferType>>,
}

impl From<TransferTypeMappingRecord> for TransferTypeMapping {
    fn from(record: TransferTypeMappingRecord) -> Self {
        TransferTypeMapping::builder()
            .participant_context_id(record.participant_context_id)
            .mappings(record.mappings.0)
            .build()
    }
}
