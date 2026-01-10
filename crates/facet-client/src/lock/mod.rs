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
use log::warn;
use std::sync::Arc;
use thiserror::Error;

pub mod mem;
pub mod postgres;
mod tests;

pub use mem::MemoryLockManager;
pub use postgres::PostgresLockManager;

/// Provide distributed locking for coordinating access to shared resources.
///
/// Enables clients to acquire and release locks on named resources. Lock semantics
/// are implementation-dependent, but all implementations must enforce exclusive access: only
/// one owner may hold a lock for a given identifier at any time.
#[async_trait]
pub trait LockManager: Send + Sync {
    /// Locks a resource on behalf of the owner and returns a guard.
    ///
    /// The returned guard will automatically unlock the resource when dropped.
    ///
    /// # Arguments
    /// * `identifier` - Resource identifier
    /// * `owner` - Owner identifier
    ///
    /// # Errors
    /// Returns LockAlreadyHeld if the lock is held by another owner.
    async fn lock(&self, identifier: &str, owner: &str) -> Result<LockGuard, LockError>;

    /// Unlocks a resource held by the owner.
    ///
    /// # Arguments
    /// * `identifier` - Resource identifier
    /// * `owner` - Owner identifier
    ///
    /// # Errors
    /// Returns LockAlreadyHeld if the lock is held by another owner or LockNotFound if the resource is not locked by
    /// the owner, i.e. it has been released or expired
    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError>;

    /// Blocking version of unlock, used internally by LockGuard's Drop implementation.
    ///
    /// This method blocks the current thread until the unlock completes.
    /// Implementations should use appropriate blocking mechanisms for their backend.
    ///
    /// # Arguments
    /// * `identifier` - Resource identifier
    /// * `owner` - Owner identifier
    fn unlock_blocking(&self, identifier: &str, owner: &str) -> Result<(), LockError>;

    /// Releases all locks held by the owner. Returns normally if no locks are held.
    ///
    /// # Arguments
    /// * `owner` - Owner identifier
    async fn release_locks(&self, owner: &str) -> Result<(), LockError>;
}

/// Guard that releases a lock when dropped.
///
/// Automatically releases a lock acquired via [`LockManager::lock`], ensuring cleanup
/// even if the enclosing scope exits abnormally. The lock is released asynchronously
/// in a spawned task.
///
/// # Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use facet_client::lock::{LockManager, MemoryLockManager};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = Arc::new(MemoryLockManager::new());
/// let _guard = manager.lock("resource", "owner").await?;
/// // Lock is automatically released when guard is dropped
/// # Ok(())
/// # }
/// ```
pub struct LockGuard {
    lock_manager: Arc<dyn LockManager>,
    identifier: String,
    owner: String,
}

impl LockGuard {
    pub(crate) fn new(
        lock_manager: Arc<dyn LockManager>,
        identifier: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            lock_manager,
            identifier: identifier.into(),
            owner: owner.into(),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Err(e) = self.lock_manager.unlock_blocking(&self.identifier, &self.owner) {
            warn!(
                "Failed to release lock for identifier '{}' owned by '{}': {}",
                self.identifier, self.owner, e
            );
        }
    }
}

/// Errors that can occur during lock operations.
#[derive(Debug, Error)]
pub enum LockError {
    #[error("Lock conflict for '{identifier}': owned by '{owner}', but operation requested by '{attempted_owner}'")]
    LockAlreadyHeld {
        identifier: String,
        owner: String,
        attempted_owner: String,
    },

    #[error("No lock found for identifier '{identifier}' owned by '{owner}'")]
    LockNotFound { identifier: String, owner: String },

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Internal lock error: {0}")]
    InternalError(String),
}

impl LockError {
    pub fn lock_already_held(
        identifier: impl Into<String>,
        owner: impl Into<String>,
        attempted_owner: impl Into<String>,
    ) -> Self {
        LockError::LockAlreadyHeld {
            identifier: identifier.into(),
            owner: owner.into(),
            attempted_owner: attempted_owner.into(),
        }
    }

    pub fn lock_not_found(identifier: impl Into<String>, owner: impl Into<String>) -> Self {
        LockError::LockNotFound {
            identifier: identifier.into(),
            owner: owner.into(),
        }
    }

    pub fn store_error(message: impl Into<String>) -> Self {
        LockError::StoreError(message.into())
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        LockError::InternalError(message.into())
    }

    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::LockAlreadyHeld { .. } | Self::StoreError(_))
    }
}
