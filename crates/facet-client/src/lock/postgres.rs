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

use crate::lock::{LockError, LockManager};
use crate::util::{default_clock, Clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::TimeDelta;
use sqlx::PgPool;
use std::sync::Arc;

/// Postgres-backed distributed lock manager using SQLx connection pooling.
///
/// `PostgresLockManager` provides thread-safe, distributed locking backed by a Postgres database.
/// It enables multiple services, instances, or tasks to coordinate exclusive access to shared resources.
///
/// # Features
///
/// - **Distributed Coordination**: Locks are persisted in Postgres, enabling coordination across
///   multiple services or instances.
/// - **Exclusive Locks**: Only one owner can hold a lock for a given identifier at any time.
/// - **Reentrant Locks**: The same owner can safely request a lock multiple times.
/// - **Timeout Support**: Expired locks are automatically cleaned up to prevent deadlocks.
///
/// # How It Works
///
/// Locks are stored in a `distributed_locks` table with four columns:
/// - `identifier`: The resource name being locked (primary key)
/// - `owner`: The identifier of the lock holder
/// - `acquired_at`: Timestamp in UTC when the lock was acquired
/// - `reentrant_count`: Number of times the lock has been acquired by the same owner
///
/// When acquiring a lock:
/// 1. Expired locks (older than the configured timeout) are automatically cleaned up
/// 2. An insert is attempted; if the identifier already exists, it returns `NOTHING`
/// 3. If the insert succeeds, the lock is acquired with `reentrant_count = 1`
/// 4. If the insert fails, ownership is checked:
///    - Same owner: reentrant lock (increments `reentrant_count`, refreshes timestamp)
///    - Different owner: lock held by another owner (returns error)
///
/// When releasing a lock:
/// 1. The `reentrant_count` is decremented
/// 2. If the count reaches 0, the lock is deleted
/// 3. Ownership is verified before any modification to prevent unauthorized lock release
///
/// # Examples
///
/// ## Basic Usage
///
/// ```ignore
/// use sqlx::PgPool;
/// use facet_client::lock::postgres::PostgresLockManager;
/// use facet_client::lock::LockManager;
///
/// // Create a connection pool
/// let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
///
/// // Initialize the lock manager
/// let manager = PostgresLockManager::new(pool);
/// manager.initialize().await?;
///
/// // Acquire and release a lock
/// manager.lock("resource1", "service-a").await?;
/// // Perform critical work...
/// manager.unlock("resource1", "service-a").await?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
///
/// ## With Lock Guard
///
/// For automatic cleanup use [`LockGuard`]:
///
/// ```
/// # use std::sync::Arc;
/// # use facet_client::lock::{LockManager, LockGuard};
/// # use facet_client::lock::postgres::PostgresLockManager;
/// # async fn example(manager: Arc<dyn LockManager>) -> Result<(), Box<dyn std::error::Error>> {
/// manager.lock("resource1", "service-a").await?;
/// let guard = LockGuard {
///     lock_manager: manager.clone(),
///     identifier: "resource1".to_string(),
///     owner: "service-a".to_string(),
/// };
/// // Lock is automatically released when `guard` is dropped
/// # Ok(())
/// # }
/// ```
///
/// [`LockGuard`]: crate::lock::LockGuard
#[derive(Builder)]
pub struct PostgresLockManager {
    pool: PgPool,

    /// Lock timeout duration. Expired locks are automatically cleaned up.
    ///
    /// Defaults to 30 seconds if not specified.
    #[builder(default = TimeDelta::seconds(30))]
    timeout: TimeDelta,

    /// Clock for time operations. Defaults to the system clock.
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl PostgresLockManager {
    /// Initializes the distributed locks table.
    ///
    /// Creates the `distributed_locks` table if it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), LockError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to begin transaction: {}", e)))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS distributed_locks (
                identifier VARCHAR(255) PRIMARY KEY,
                owner VARCHAR(255) NOT NULL,
                acquired_at TIMESTAMP WITH TIME ZONE NOT NULL,
                reentrant_count INTEGER NOT NULL DEFAULT 1
            )",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to create locks table: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_distributed_locks_acquired_at ON distributed_locks(acquired_at)")
            .execute(&mut *tx)
            .await
            .map_err(|e| LockError::database_error(format!("Failed to create index: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to commit transaction: {}", e)))?;
        Ok(())
    }

    /// Internal lock acquisition with retry support for race conditions.
    ///
    /// When a lock is released during acquisition (between UPDATE and SELECT),
    /// this method automatically retries up to MAX_RETRIES times.
    async fn lock_internal(&self, identifier: &str, owner: &str, retry_count: u32) -> Result<(), LockError> {
        const MAX_RETRIES: u32 = 5;

        // Wrap entire lock acquisition logic in a transaction
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to begin transaction: {}", e)))?;

        let now = self.clock.now();
        let cutoff_time = now - self.timeout;

        // Cleanup expired locks
        sqlx::query("DELETE FROM distributed_locks WHERE acquired_at < $1")
            .bind(cutoff_time)
            .execute(&mut *tx)
            .await
            .map_err(|e| LockError::database_error(format!("Failed to cleanup expired locks: {}", e)))?;

        // Try to insert the lock with the acquired timestamp and initial count of 1
        let result = sqlx::query(
            "INSERT INTO distributed_locks (identifier, owner, acquired_at, reentrant_count)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (identifier) DO NOTHING",
        )
        .bind(identifier)
        .bind(owner)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to insert lock: {}", e)))?;

        // Check if insert succeeded
        if result.rows_affected() > 0 {
            // Lock acquired successfully
            tx.commit()
                .await
                .map_err(|e| LockError::database_error(format!("Failed to commit transaction: {}", e)))?;
            return Ok(());
        }

        // Lock already exists due to conflict
        // Try to update the timestamp and increment count if we own it (handles the reentrant case)
        let update_result = sqlx::query(
            "UPDATE distributed_locks
             SET acquired_at = $1, reentrant_count = reentrant_count + 1
             WHERE identifier = $2 AND owner = $3",
        )
        .bind(now)
        .bind(identifier)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to update lock: {}", e)))?;

        if update_result.rows_affected() > 0 {
            // Successfully updated timestamp and count - reentrant lock by same owner
            tx.commit()
                .await
                .map_err(|e| LockError::database_error(format!("Failed to commit transaction: {}", e)))?;
            return Ok(());
        }

        // Update failed - lock is held by a different owner, or was just released
        // Fetch the actual owner forthe  error message (may be None if lock was released)
        let existing_owner: Option<(String,)> = sqlx::query_as(
            "SELECT owner FROM distributed_locks WHERE identifier = $1",
        )
        .bind(identifier)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to query lock: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to commit transaction: {}", e)))?;

        match existing_owner {
            Some((owner_name,)) => {
                // Lock exists and is held by a different owner
                Err(LockError::lock_already_held(identifier, &owner_name))
            }
            None => {
                // Lock was released between UPDATE and SELECT - this is a rare race condition
                // Retry the acquisition if we haven't exceeded the retry limit
                if retry_count >= MAX_RETRIES {
                    Err(LockError::internal_error(
                        "Lock acquisition failed: exceeded retry limit due to concurrent releases",
                    ))
                } else {
                    // Recursively retry (box the future to avoid infinite size)
                    Box::pin(self.lock_internal(identifier, owner, retry_count + 1)).await
                }
            }
        }
    }
}

#[async_trait]
impl LockManager for PostgresLockManager {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        self.lock_internal(identifier, owner, 0).await
    }

    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        // Wrap unlock operations in a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to begin transaction: {}", e)))?;

        // Decrement the reentrant count, but only if it's greater than 0 to prevent negative counts
        let rows_affected = sqlx::query(
            "UPDATE distributed_locks
             SET reentrant_count = reentrant_count - 1
             WHERE identifier = $1 AND owner = $2 AND reentrant_count > 0",
        )
        .bind(identifier)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to update lock count: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            // Check if lock exists with a different owner to provide better error message
            let existing_owner: Option<(String,)> = sqlx::query_as(
                "SELECT owner FROM distributed_locks WHERE identifier = $1",
            )
            .bind(identifier)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| LockError::database_error(format!("Failed to query lock: {}", e)))?;

            return match existing_owner {
                Some((other_owner,)) if other_owner != owner => {
                    Err(LockError::wrong_owner(identifier, &other_owner, owner))
                }
                _ => Err(LockError::lock_not_found(identifier, owner)),
            };
        }

        // Delete the lock if the count reaches 0
        sqlx::query(
            "DELETE FROM distributed_locks
             WHERE identifier = $1 AND owner = $2 AND reentrant_count <= 0",
        )
        .bind(identifier)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::database_error(format!("Failed to delete lock: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| LockError::database_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }

    async fn release_locks(&self, owner: &str) -> Result<(), LockError> {
        sqlx::query("DELETE FROM distributed_locks WHERE owner = $1")
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(|e| LockError::database_error(format!("Failed to release locks: {}", e)))?;

        Ok(())
    }
}
