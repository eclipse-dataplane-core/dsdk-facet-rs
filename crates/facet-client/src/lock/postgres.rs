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

use crate::lock::LockManager;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bon::Builder;
use sqlx::PgPool;

/// Postgres-backed distributed lock manager using SQLx connection pooling.
///
/// `PostgresLockManager` provides thread-safe, distributed locking backed by a Postgres database.
/// It enables multiple services, instances, or tasks to coordinate exclusive access to shared resources.
///
/// # Features
///
/// - **Distributed Coordination**: Locks are persisted in Postgre, enabling coordination across
///   multiple services or instances.
/// - **Exclusive Locks**: Only one owner can hold a lock for a given identifier at any time.
/// - **Reentrant Locks**: The same owner can safely request a lock multiple times.
/// - **Timeout Support**: Expired locks are automatically cleaned up to prevent deadlocks.
///
/// # How It Works
///
/// Locks are stored in a `distributed_locks` table with three columns:
/// - `identifier`: The resource name being locked (primary key)
/// - `owner`: The identifier of the lock holder
/// - `acquired_at`: Timestamp in milliseconds when the lock was acquired
///
/// When acquiring a lock:
/// 1. Expired locks (older than 30 seconds) are automatically cleaned up
/// 2. An insert is attempted; if the identifier already exists, it returns `NOTHING`
/// 3. If the insert succeeds, the lock is acquired
/// 4. If the insert fails, ownership is checked:
///    - Same owner: reentrant lock (allowed, returns `Ok`)
///    - Different owner: lock held by another owner (returns error)
///
/// When releasing a lock, ownership is verified before deletion to prevent
/// unauthorized lock release.
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
/// # Ok::<_, anyhow::Error>(())
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

    /// Lock timeout in milliseconds. Expired locks are automatically cleaned up.
    ///
    /// Defaults to 30 seconds (30,000 ms) if not specified.
    #[builder(default = 30_000)]
    timeout_ms: i64,
}

impl PostgresLockManager {
    /// Initializes the distributed locks table.
    ///
    /// Creates the `distributed_locks` table if it doesn't already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS distributed_locks (
            identifier VARCHAR(255) PRIMARY KEY,
            owner VARCHAR(255) NOT NULL,
            acquired_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        )
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_distributed_locks_acquired_at ON distributed_locks(acquired_at)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[async_trait]
impl LockManager for PostgresLockManager {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<()> {
        // Wrap entire lock acquisition logic in a transaction
        let mut tx = self.pool.begin().await?;

        // Cleanup expired locks (using server time)
        sqlx::query(
            "DELETE FROM distributed_locks
         WHERE EXTRACT(EPOCH FROM (NOW() - acquired_at)) * 1000 > $1",
        )
            .bind(self.timeout_ms)
            .execute(&mut *tx)
            .await?;

        // Try to insert the lock with server timestamp
        let result = sqlx::query(
            "INSERT INTO distributed_locks (identifier, owner, acquired_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (identifier) DO NOTHING",
        )
            .bind(identifier)
            .bind(owner)
            .execute(&mut *tx)
            .await?;

        // Check if insert succeeded
        if result.rows_affected() > 0 {
            // Lock acquired successfully
            tx.commit().await?;
            return Ok(());
        }

        // Lock already exists, verify ownership within the current transaction to avoid race conditions
        let (existing_owner,): (String,) = sqlx::query_as(
            "SELECT owner FROM distributed_locks WHERE identifier = $1",
        )
            .bind(identifier)
            .fetch_one(&mut *tx)
            .await?;

        tx.commit().await?;

        if existing_owner == owner {
            // Same owner - reentrant lock allowed
            Ok(())
        } else {
            // Different owner holds the lock
            Err(anyhow!(
            "Lock for identifier '{}' is already held by '{}'",
            identifier,
            existing_owner
        ))
        }
    }

    async fn unlock(&self, identifier: &str, owner: &str) -> Result<()> {
        let rows_deleted = sqlx::query("DELETE FROM distributed_locks WHERE identifier = $1 AND owner = $2")
            .bind(identifier)
            .bind(owner)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if rows_deleted == 0 {
            return Err(anyhow!(
                "No lock found for identifier '{}' owned by '{}'",
                identifier,
                owner
            ));
        }

        Ok(())
    }
}
