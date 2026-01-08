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
use crate::util::{Clock, default_clock};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

struct LockRecord {
    owner: String,
    acquired_at: DateTime<Utc>,
    reentrant_count: usize,
}

/// In-memory lock manager for testing and single-instance scenarios.
///
/// Stores locks in a thread-safe hashmap with automatic expiration.
/// Not suitable for distributed coordination across multiple processes.
///
/// # Example
///
/// ```
/// # use std::sync::Arc;
/// # use facet_client::lock::{LockManager, MemoryLockManager};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = Arc::new(MemoryLockManager::new());
/// manager.lock("resource", "owner").await?;
/// // ... do work ...
/// manager.unlock("resource", "owner").await?;
/// # Ok(())
/// # }
/// ```
pub struct MemoryLockManager {
    locks: Mutex<HashMap<String, LockRecord>>,
    timeout: TimeDelta,
    clock: Arc<dyn Clock>,
}

impl MemoryLockManager {
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
            timeout: TimeDelta::seconds(30),
            clock: default_clock(),
        }
    }

    #[cfg(test)]
    pub fn with_timeout_and_clock(timeout: TimeDelta, clock: Arc<dyn Clock>) -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
            timeout,
            clock,
        }
    }

    fn is_expired(&self, lock: &LockRecord, timeout: TimeDelta) -> bool {
        let now = self.clock.now();
        let elapsed = now.signed_duration_since(lock.acquired_at);
        elapsed > timeout
    }

    fn cleanup_expired_lock(&self, locks: &mut HashMap<String, LockRecord>, identifier: &str, timeout: TimeDelta) {
        if let Some(lock) = locks.get(identifier) {
            if self.is_expired(lock, timeout) {
                locks.remove(identifier);
            }
        }
    }
}

impl Default for MemoryLockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LockManager for MemoryLockManager {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        let mut locks = self.locks.lock().await;

        self.cleanup_expired_lock(&mut locks, identifier, self.timeout);

        if let Some(existing_lock) = locks.get_mut(identifier) {
            if existing_lock.owner == owner {
                // Reentrant lock: increment count and refresh timestamp to keep lock alive
                existing_lock.reentrant_count += 1;
                existing_lock.acquired_at = self.clock.now();
                return Ok(());
            }

            return Err(LockError::lock_already_held(identifier, &existing_lock.owner));
        }

        locks.insert(
            identifier.to_string(),
            LockRecord {
                owner: owner.to_string(),
                acquired_at: self.clock.now(),
                reentrant_count: 1,
            },
        );
        Ok(())
    }

    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        let mut locks = self.locks.lock().await;

        if let Some(lock) = locks.get_mut(identifier) {
            if lock.owner != owner {
                return Err(LockError::wrong_owner(identifier, &lock.owner, owner));
            }

            lock.reentrant_count -= 1;

            if lock.reentrant_count == 0 {
                locks.remove(identifier);
            }

            return Ok(());
        }

        Err(LockError::lock_not_found(identifier, owner))
    }

    async fn release_locks(&self, owner: &str) -> Result<(), LockError> {
        let mut locks = self.locks.lock().await;

        locks.retain(|_, lock| lock.owner != owner);

        Ok(())
    }
}

