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

use crate::lock::{LockError, LockGuard, LockManager};
use crate::util::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::TimeDelta;
use sqlx::PgPool;
use std::sync::Arc;

const MAX_RETRIES: u32 = 5;

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
/// 2. A single `INSERT ... ON CONFLICT DO UPDATE` query is executed:
///    - If no conflict: Lock is acquired with `reentrant_count = 1`
///    - If conflict AND same owner: Reentrant lock (increments `reentrant_count`, refreshes timestamp)
///    - If conflict AND different owner: Query returns no rows, then ownership is checked
/// 3. If another owner holds the lock returns an error
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
/// Locks automatically return a guard for automatic cleanup:
///
/// ```ignore
/// # use std::sync::Arc;
/// # use facet_client::lock::LockManager;
/// # use facet_client::lock::postgres::PostgresLockManager;
/// # async fn example(manager: Arc<PostgresLockManager>) -> Result<(), Box<dyn std::error::Error>> {
/// let _guard = manager.lock("resource1", "service-a").await?;
/// // Lock is automatically released when `guard` is dropped
/// # Ok(())
/// # }
/// ```
///
/// [`LockGuard`]: LockGuard
#[derive(Builder, Clone)]
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

    #[builder(default = MAX_RETRIES)]
    retries: u32,
}

impl PostgresLockManager {
    /// Initializes the distributed locks table.
    ///
    /// Creates the `distributed_locks` table if it does not already exist, along with
    /// indexes to optimize lock operations:
    /// - `idx_distributed_locks_acquired_at`: For efficient cleanup of expired locks
    /// - `idx_distributed_locks_identifier_owner`: For efficient reentrant lock checks and unlock operations
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<(), LockError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LockError::store_error(format!("Failed to begin transaction: {}", e)))?;

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
        .map_err(|e| LockError::store_error(format!("Failed to create locks table: {}", e)))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_distributed_locks_acquired_at ON distributed_locks(acquired_at)")
            .execute(&mut *tx)
            .await
            .map_err(|e| LockError::store_error(format!("Failed to create index: {}", e)))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_distributed_locks_identifier_owner ON distributed_locks(identifier, owner)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| LockError::store_error(format!("Failed to create composite index: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| LockError::store_error(format!("Failed to commit transaction: {}", e)))?;
        Ok(())
    }

    /// Internal lock acquisition with retry support for race conditions.
    ///
    /// When a lock is released during acquisition (between INSERT/UPDATE and SELECT),
    /// this method automatically retries up to MAX_RETRIES times.
    async fn lock_internal(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        for attempt in 0..=self.retries {
            // Wrap entire lock acquisition logic in a transaction
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| LockError::store_error(format!("Failed to begin transaction: {}", e)))?;

            let now = self.clock.now();
            let cutoff_time = now - self.timeout;

            // Clean up expired locks only on the first attempt
            if attempt == 0 {
                sqlx::query("DELETE FROM distributed_locks WHERE acquired_at < $1")
                    .bind(cutoff_time)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| LockError::store_error(format!("Failed to cleanup expired locks: {}", e)))?;
            }

            // Try to insert or update the lock
            // - If no conflict: INSERT succeeds, returns the new row with reentrant_count=1
            // - If conflict AND owner match: UPDATE succeeds, returns the updated row with incremented count
            // - If conflict AND owner do not match: WHERE clause fails, returns no rows
            let result: Option<(i32,)> = sqlx::query_as(
                "INSERT INTO distributed_locks (identifier, owner, acquired_at, reentrant_count)
                 VALUES ($1, $2, $3, 1)
                 ON CONFLICT (identifier) DO UPDATE
                 SET acquired_at = EXCLUDED.acquired_at,
                     reentrant_count = distributed_locks.reentrant_count + 1
                 WHERE distributed_locks.owner = EXCLUDED.owner
                 RETURNING reentrant_count",
            )
            .bind(identifier)
            .bind(owner)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| LockError::store_error(format!("Failed to acquire lock: {}", e)))?;

            if result.is_some() {
                // Lock acquired successfully (either new lock or reentrant)
                tx.commit()
                    .await
                    .map_err(|e| LockError::store_error(format!("Failed to commit transaction: {}", e)))?;
                return Ok(());
            }

            // No row returned - conflict exists, but the owner does not match, or lock was just released
            // Query to determine which case we're in
            let existing_owner: Option<(String,)> =
                sqlx::query_as("SELECT owner FROM distributed_locks WHERE identifier = $1")
                    .bind(identifier)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| LockError::store_error(format!("Failed to query lock: {}", e)))?;

            tx.commit()
                .await
                .map_err(|e| LockError::store_error(format!("Failed to commit transaction: {}", e)))?;

            match existing_owner {
                Some((owner_name,)) => {
                    // Lock exists and is held by a different owner - no retry needed
                    return Err(LockError::lock_already_held(identifier, &owner_name, owner));
                }
                None => {
                    // Lock was released between INSERT and SELECT - this is a rare race condition
                    // Continue to retry if we haven't exceeded the limit
                    if attempt >= MAX_RETRIES {
                        return Err(LockError::internal_error(
                            "Lock acquisition failed: exceeded retry limit due to concurrent releases",
                        ));
                    }
                    // Loop will continue for another attempt
                }
            }
        }

        // Should never reach here due to the loop logic, but added for completeness
        Err(LockError::internal_error(
            "Lock acquisition failed: unexpected end of retry loop",
        ))
    }
}

#[async_trait]
impl LockManager for PostgresLockManager {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<LockGuard, LockError> {
        self.lock_internal(identifier, owner).await?;
        Ok(LockGuard::new(Arc::new(self.clone()), identifier, owner))
    }

    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        // Wrap unlock operations in a transaction to ensure atomicity
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LockError::store_error(format!("Failed to begin transaction: {}", e)))?;

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
        .map_err(|e| LockError::store_error(format!("Failed to update lock count: {}", e)))?
        .rows_affected();

        if rows_affected == 0 {
            // Check if the lock exists with a different owner
            let existing_owner: Option<(String,)> =
                sqlx::query_as("SELECT owner FROM distributed_locks WHERE identifier = $1")
                    .bind(identifier)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| LockError::store_error(format!("Failed to query lock: {}", e)))?;

            return match existing_owner {
                Some((other_owner,)) if other_owner != owner => {
                    Err(LockError::lock_already_held(identifier, &other_owner, owner))
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
        .map_err(|e| LockError::store_error(format!("Failed to delete lock: {}", e)))?;

        tx.commit()
            .await
            .map_err(|e| LockError::store_error(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }

    fn unlock_blocking(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        // Try block_in_place if we're in a multithreaded runtime
        if let Ok(result) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.unlock(identifier, owner)))
        })) {
            return result;
        }

        // block_in_place failed - we're in a single-threaded runtime or async context
        // For PostgresLockManager, we can't create a new runtime because PgPool is tied
        // to the original runtime. Return an error - the lock will expire via timeout.
        Err(LockError::internal_error(
            "Cannot unlock from Drop in this runtime context. Lock will expire via timeout.",
        ))
    }

    async fn release_locks(&self, owner: &str) -> Result<(), LockError> {
        sqlx::query("DELETE FROM distributed_locks WHERE owner = $1")
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(|e| LockError::store_error(format!("Failed to release locks: {}", e)))?;

        Ok(())
    }
}
