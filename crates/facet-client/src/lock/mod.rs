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
    /// Locks a resource on behalf of the owner.
    ///
    /// # Arguments
    /// * `identifier` - Resource identifier    
    /// * `owner` - Owner identifier
    ///
    /// # Errors
    /// Returns LockAlreadyHeld if the lock is held by another owner.
    async fn lock(&self, identifier: &str, owner: &str) -> Result<(), LockError>;

    /// Unlocks a resource held by the owner.
    ///
    /// # Arguments
    /// * `identifier` - Resource identifier
    /// * `owner` - Owner identifier
    ///
    /// # Errors
    /// Returns WrongOwner if the lock is held by another owner or LockNotFound if the resource is not locked by
    /// the owner, i.e. it has been released or expired
    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError>;

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
/// # use facet_client::lock::{LockManager, LockGuard};
/// # async fn example(manager: Arc<dyn LockManager>) -> Result<(), Box<dyn std::error::Error>> {
/// manager.lock("resource", "owner").await?;
/// let guard = LockGuard {
///     lock_manager: manager,
///     identifier: "resource".into(),
///     owner: "owner".into(),
/// };
/// // Lock is automatically released when guard is dropped
/// # Ok(())
/// # }
/// ```
pub struct LockGuard {
    pub lock_manager: Arc<dyn LockManager>,
    pub identifier: String,
    pub owner: String,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let lock_manager = self.lock_manager.clone();
        let identifier = self.identifier.clone();
        let owner = self.owner.clone();

        // Try to get the current runtime handle
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // We're in a Tokio runtime, spawn the cleanup task
                handle.spawn(async move {
                    if let Err(e) = lock_manager.unlock(&identifier, &owner).await {
                        warn!(
                            "Failed to release lock for identifier '{}' owned by '{}': {}",
                            identifier, owner, e
                        );
                    }
                });
            }
            Err(_) => {
                // No Tokio runtime available - ignore and the lock will time out
            }
        }
    }
}

/// Errors that can occur during lock operations.
#[derive(Debug, Error)]
pub enum LockError {
    #[error("Lock for identifier '{identifier}' is already held by '{owner}'")]
    LockAlreadyHeld { identifier: String, owner: String },

    #[error("No lock found for identifier '{identifier}' owned by '{owner}'")]
    LockNotFound { identifier: String, owner: String },

    #[error("Lock for identifier '{identifier}' is held by '{existing_owner}', not '{owner}'")]
    WrongOwner {
        identifier: String,
        existing_owner: String,
        owner: String,
    },

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Internal lock error: {0}")]
    InternalError(String),
}

impl LockError {
    pub fn lock_already_held(identifier: impl Into<String>, owner: impl Into<String>) -> Self {
        LockError::LockAlreadyHeld {
            identifier: identifier.into(),
            owner: owner.into(),
        }
    }

    pub fn lock_not_found(identifier: impl Into<String>, owner: impl Into<String>) -> Self {
        LockError::LockNotFound {
            identifier: identifier.into(),
            owner: owner.into(),
        }
    }

    pub fn wrong_owner(
        identifier: impl Into<String>,
        existing_owner: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        LockError::WrongOwner {
            identifier: identifier.into(),
            existing_owner: existing_owner.into(),
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