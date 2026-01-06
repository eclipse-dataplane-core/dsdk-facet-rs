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
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct LockRecord {
    owner: String,
    acquired_at: Instant,
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
    timeout: Duration,
}

impl MemoryLockManager {
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    fn is_expired(lock: &LockRecord, timeout: Duration) -> bool {
        lock.acquired_at.elapsed() > timeout
    }

    fn cleanup_expired_lock(locks: &mut HashMap<String, LockRecord>, identifier: &str, timeout: Duration) {
        if let Some(lock) = locks.get(identifier) {
            if Self::is_expired(lock, timeout) {
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

        Self::cleanup_expired_lock(&mut locks, identifier, self.timeout);

        if let Some(existing_lock) = locks.get_mut(identifier) {
            if existing_lock.owner == owner {
                existing_lock.reentrant_count += 1;
                return Ok(());
            }

            return Err(LockError::lock_already_held(identifier, &existing_lock.owner));
        }

        locks.insert(
            identifier.to_string(),
            LockRecord {
                owner: owner.to_string(),
                acquired_at: Instant::now(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn test_lock_acquire_success() {
        let manager = MemoryLockManager::new();
        let result = manager.lock("resource1", "owner1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lock_exclusive() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("First lock failed");
        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_err());

        if let Err(LockError::LockAlreadyHeld { identifier, owner }) = result {
            assert_eq!(identifier, "resource1");
            assert_eq!(owner, "owner1");
        } else {
            panic!("Expected LockAlreadyHeld error");
        }
    }

    #[tokio::test]
    async fn test_lock_reentrant() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("First lock failed");
        let result = manager.lock("resource1", "owner1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unlock_success() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");
        let result = manager.unlock("resource1", "owner1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unlock_wrong_owner() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");
        let result = manager.unlock("resource1", "owner2").await;
        assert!(result.is_err());

        if let Err(LockError::WrongOwner {
                       identifier,
                       existing_owner,
                       owner,
                   }) = result
        {
            assert_eq!(identifier, "resource1");
            assert_eq!(existing_owner, "owner1");
            assert_eq!(owner, "owner2");
        } else {
            panic!("Expected WrongOwner error");
        }
    }

    #[tokio::test]
    async fn test_unlock_nonexistent_lock() {
        let manager = MemoryLockManager::new();
        let result = manager.unlock("nonexistent", "owner1").await;
        assert!(result.is_err());

        if let Err(LockError::LockNotFound { identifier, owner }) = result {
            assert_eq!(identifier, "nonexistent");
            assert_eq!(owner, "owner1");
        } else {
            panic!("Expected LockNotFound error");
        }
    }

    #[tokio::test]
    async fn test_reentrant_unlock() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("First lock failed");
        manager.lock("resource1", "owner1").await.expect("Second lock failed");

        manager
            .unlock("resource1", "owner1")
            .await
            .expect("First unlock failed");

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_err());

        manager
            .unlock("resource1", "owner1")
            .await
            .expect("Second unlock failed");

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lock_timeout_expiration() {
        let manager = MemoryLockManager::with_timeout(StdDuration::from_millis(20));
        manager.lock("resource1", "owner1").await.expect("Lock failed");

        tokio::time::sleep(StdDuration::from_millis(40)).await;

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_resources() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
        manager.lock("resource2", "owner1").await.expect("Lock 2 failed");

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_err());

        let result = manager.lock("resource3", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lock_acquire_after_release() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");
        manager.unlock("resource1", "owner1").await.expect("Unlock failed");

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lock_exclusive_error_message() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("First lock failed");
        let result = manager.lock("resource1", "owner2").await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("already held"));
        assert!(error_msg.contains("owner1"));
    }

    #[tokio::test]
    async fn test_unlock_wrong_owner_error_message() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");
        let result = manager.unlock("resource1", "owner2").await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("held by"));
        assert!(error_msg.contains("owner1"));
        assert!(error_msg.contains("owner2"));
    }

    #[tokio::test]
    async fn test_concurrent_lock_acquisition() {
        let manager = std::sync::Arc::new(MemoryLockManager::new());

        manager.lock("resource", "owner1").await.expect("Lock failed");

        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            manager_clone.lock("resource", "owner2").await
        });

        let result = handle.await.unwrap();
        assert!(result.is_err());
    }
}