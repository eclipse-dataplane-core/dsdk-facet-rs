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

use crate::auth::{AuthorizationError, AuthorizationEvaluator, Operation, Rule, RuleStore};
use crate::context::ParticipantContext;
use sqlx::PgPool;

/// Postgres-backed authorization evaluator using SQLx connection pooling.
///
/// `PostgresAuthorizationEvaluator` provides authorization evaluation backed by a Postgres database.
/// It enables distributed authorization policy enforcement across multiple services or instances.
///
/// # Examples
///
/// ```ignore
/// use sqlx::PgPool;
/// use facet_common::auth::postgres::PostgresAuthorizationEvaluator;
///
/// // Create a connection pool
/// let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
///
/// // Initialize the authorization evaluator
/// let evaluator = PostgresAuthorizationEvaluator::new(pool);
/// evaluator.initialize().await?;
/// ```
pub struct PostgresAuthorizationEvaluator {
    pool: PgPool,
}

impl PostgresAuthorizationEvaluator {
    /// Creates a new PostgresAuthorizationEvaluator with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initializes the authorization rules table.
    ///
    /// Creates the `authorization_rules` table if it does not already exist, along with
    /// indexes to optimize rule operations:
    /// - Primary key on (participant_identifier, audience, scope, resource)
    /// - `idx_authorization_rules_participant`: For efficient participant rule lookups
    /// - `idx_authorization_rules_scope`: For efficient scope-based queries
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), AuthorizationError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to begin transaction: {}", e)))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS authorization_rules (
                participant_identifier VARCHAR(255) NOT NULL,
                scope VARCHAR(255) NOT NULL,
                resource TEXT NOT NULL,
                actions TEXT NOT NULL,
                PRIMARY KEY (participant_identifier, scope, resource)
            )",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to create authorization_rules table: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_authorization_rules_participant
             ON authorization_rules(participant_identifier)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to create participant index: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_authorization_rules_scope
             ON authorization_rules(participant_identifier, scope)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to create scope index: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl RuleStore for PostgresAuthorizationEvaluator {
    async fn get_rules(&self, participant_context: &ParticipantContext) -> Result<Vec<Rule>, AuthorizationError> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT scope, resource, actions
             FROM authorization_rules
             WHERE participant_identifier = $1",
        )
        .bind(&participant_context.id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to fetch rules: {}", e)))?;

        let mut rules = Vec::new();
        for (scope, resource, actions_str) in rows {
            let actions: Vec<String> = actions_str.split(',').map(|s| s.to_string()).collect();
            let rule = Rule::new(scope, actions, resource).map_err(|e| {
                AuthorizationError::StoreError(format!(
                    "Failed loading rule for participant {}: {}",
                    participant_context.id, e
                ))
            })?;
            rules.push(rule);
        }

        Ok(rules)
    }

    async fn save_rule(&self, participant_context: &ParticipantContext, rule: Rule) -> Result<(), AuthorizationError> {
        let actions_str = rule.actions.join(",");

        sqlx::query(
            "INSERT INTO authorization_rules (participant_identifier, scope, resource, actions)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (participant_identifier, scope, resource)
             DO UPDATE SET actions = EXCLUDED.actions",
        )
        .bind(&participant_context.id)
        .bind(&rule.scope)
        .bind(&rule.resource)
        .bind(&actions_str)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to save rule: {}", e)))?;

        Ok(())
    }

    async fn remove_rule(
        &self,
        participant_context: &ParticipantContext,
        rule: Rule,
    ) -> Result<(), AuthorizationError> {
        sqlx::query(
            "DELETE FROM authorization_rules
             WHERE participant_identifier = $1
               AND scope = $2
               AND resource = $3",
        )
        .bind(&participant_context.id)
        .bind(&rule.scope)
        .bind(&rule.resource)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to remove rule: {}", e)))?;

        Ok(())
    }

    async fn remove_rules(&self, participant_context: &ParticipantContext) -> Result<(), AuthorizationError> {
        sqlx::query("DELETE FROM authorization_rules WHERE participant_identifier = $1")
            .bind(&participant_context.id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to remove rules: {}", e)))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthorizationEvaluator for PostgresAuthorizationEvaluator {
    async fn evaluate(
        &self,
        participant_context: &ParticipantContext,
        operation: Operation,
    ) -> Result<bool, AuthorizationError> {
        // Query directly for rules matching both participant and scope
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT resource, actions
             FROM authorization_rules
             WHERE participant_identifier = $1 AND scope = $2",
        )
        .bind(&participant_context.id)
        .bind(&operation.scope)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthorizationError::StoreError(format!("Failed to fetch rules: {}", e)))?;

        // Check if any rules exist for this participant and scope
        if rows.is_empty() {
            return Ok(false);
        }

        // Evaluate each rule
        for (resource, actions_str) in rows {
            let actions: Vec<String> = actions_str.split(',').map(|s| s.to_string()).collect();
            let rule = Rule::new(operation.scope.clone(), actions, resource).map_err(|e| {
                AuthorizationError::StoreError(format!(
                    "Failed loading rule for participant {}: {}",
                    participant_context.id, e
                ))
            })?;

            if rule.actions.contains(&operation.action) && rule.matches_resource(&operation.resource) {
                return Ok(true);
            }
        }

        Ok(false)
    }

}
