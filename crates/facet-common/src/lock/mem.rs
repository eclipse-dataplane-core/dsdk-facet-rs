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

use crate::lock::{LockError, LockGuard, LockManager, UnlockOps};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use crate::util::clock::{default_clock, Clock};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct LockRecord {
    owner: String,
    acquired_at: DateTime<Utc>,
    reentrant_count: usize,
}

struct MemoryLockManagerInner {
    locks: Mutex<HashMap<String, LockRecord>>,
    timeout: TimeDelta,
    clock: Arc<dyn Clock>,
}

/// In-memory lock manager for testing and single-instance scenarios.
///
/// Stores locks in a thread-safe hashmap with automatic expiration.
/// Not suitable for distributed coordination across multiple processes.
///
/// This type is cheaply cloneable - cloning only increments a reference count.
///
/// # Example
///
/// ```
/// # use facet_common::lock::{LockManager, MemoryLockManager};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = MemoryLockManager::new();
/// let _guard = manager.lock("resource", "owner").await?;
/// // ... do work ...
/// // Lock is automatically released when _guard is dropped
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MemoryLockManager {
    inner: Arc<MemoryLockManagerInner>,
}

impl MemoryLockManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MemoryLockManagerInner {
                locks: Mutex::new(HashMap::new()),
                timeout: TimeDelta::seconds(30),
                clock: default_clock(),
            }),
        }
    }

    #[cfg(test)]
    pub fn with_timeout_and_clock(timeout: TimeDelta, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(MemoryLockManagerInner {
                locks: Mutex::new(HashMap::new()),
                timeout,
                clock,
            }),
        }
    }

    fn is_expired(&self, lock: &LockRecord, timeout: TimeDelta) -> bool {
        let now = self.inner.clock.now();
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
impl UnlockOps for MemoryLockManager {
    async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError> {
        let mut locks = self.inner.locks.lock().unwrap();

        if let Some(lock) = locks.get_mut(identifier) {
            if lock.owner != owner {
                return Err(LockError::lock_already_held(identifier, &lock.owner, owner));
            }

            lock.reentrant_count -= 1;

            if lock.reentrant_count == 0 {
                locks.remove(identifier);
            }

            return Ok(());
        }

        Err(LockError::lock_not_found(identifier, owner))
    }
}

#[async_trait]
impl LockManager for MemoryLockManager {
    async fn lock(&self, identifier: &str, owner: &str) -> Result<LockGuard, LockError> {
        let mut locks = self.inner.locks.lock().unwrap();

        self.cleanup_expired_lock(&mut locks, identifier, self.inner.timeout);

        if let Some(existing_lock) = locks.get_mut(identifier) {
            if existing_lock.owner == owner {
                // Reentrant lock: increment count and refresh timestamp to keep lock alive
                existing_lock.reentrant_count += 1;
                existing_lock.acquired_at = self.inner.clock.now();
                return Ok(LockGuard::new(Arc::new(self.clone()), identifier, owner));
            }

            return Err(LockError::lock_already_held(identifier, &existing_lock.owner, owner));
        }

        locks.insert(
            identifier.to_string(),
            LockRecord {
                owner: owner.to_string(),
                acquired_at: self.inner.clock.now(),
                reentrant_count: 1,
            },
        );

        Ok(LockGuard::new(Arc::new(self.clone()), identifier, owner))
    }

    async fn lock_count(&self, identifier: &str, owner: &str) -> Result<u32, LockError> {
        let locks = self.inner.locks.lock().unwrap();

        if let Some(lock) = locks.get(identifier) {
            if lock.owner == owner && !self.is_expired(lock, self.inner.timeout) {
                return Ok(lock.reentrant_count as u32);
            }
        }

        Ok(0)
    }

    async fn release_locks(&self, owner: &str) -> Result<(), LockError> {
        let mut locks = self.inner.locks.lock().unwrap();

        locks.retain(|_, lock| lock.owner != owner);

        Ok(())
    }
}
