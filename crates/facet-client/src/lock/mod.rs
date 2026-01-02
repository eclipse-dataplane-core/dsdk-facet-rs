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

use anyhow::Result;
use async_trait::async_trait;
use log::warn;
use std::sync::Arc;

pub mod mem;
pub mod postgres;

pub use mem::MemoryLockManager;
pub use postgres::PostgresLockManager;

/// Provide distributed locking for coordinating access to shared resources.
///
/// Enables clients to acquire and release locks on named resources. Lock semantics
/// are implementation-dependent, but all implementations must enforce exclusive access: only
/// one owner may hold a lock for a given identifier at any time.
#[async_trait]
pub trait LockManager: Send + Sync {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<()>;
    async fn unlock(&self, identifier: &str, owner: &str) -> Result<()>;
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
    pub lock_manager: Arc<dyn LockManager + 'static>,
    pub identifier: String,
    pub owner: String,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let lock_manager = self.lock_manager.clone();
        let identifier = self.identifier.clone();
        let owner = self.owner.clone();

        tokio::spawn(async move {
            if let Err(e) = lock_manager.unlock(&identifier, &owner).await {
                warn!(
                    "Failed to release lock for identifier '{}' owned by '{}': {}",
                    identifier, owner, e
                );
            }
        });
    }
}
