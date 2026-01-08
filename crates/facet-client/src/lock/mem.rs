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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MockClock;

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
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));
        let manager =
            MemoryLockManager::with_timeout_and_clock(TimeDelta::milliseconds(20), clock.clone() as Arc<dyn Clock>);

        manager.lock("resource1", "owner1").await.expect("Lock failed");

        // Advance time by 40ms to exceed the 20ms timeout
        clock.advance(TimeDelta::milliseconds(60));

        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok(), "Lock should be acquired after timeout expiration");
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
        let handle = tokio::spawn(async move { manager_clone.lock("resource", "owner2").await });

        let result = handle.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reentrant_lock_refreshes_timestamp() {
        // This test verifies that reentrant locks refresh the timestamp
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));
        let manager = MemoryLockManager::with_timeout_and_clock(
            TimeDelta::seconds(30),
            clock.clone() as Arc<dyn Clock>,
        );

        // T=0: Owner1 acquires lock
        manager.lock("resource", "owner1").await.expect("Lock failed");

        // T=25: Advance time by 25 seconds (within 30s timeout)
        clock.advance(TimeDelta::seconds(25));

        // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp to T=25
        manager.lock("resource", "owner1").await.expect("Reentrant lock failed");

        // T=35: Advance time by another 10 seconds (total 35 seconds from T=0, but only 10 from T=25)
        clock.advance(TimeDelta::seconds(10));

        // T=35: Owner2 tries to acquire the lock
        // Without the fix: Lock would have expired at T=30 (T=0 + 30s), owner2 would acquire it
        // With the fix: Lock was refreshed at T=25, expires at T=55, so still held by owner1
        let result = manager.lock("resource", "owner2").await;

        // With the fix applied, lock should still be held by owner1
        assert!(result.is_err(), "Lock should still be held by owner1 due to timestamp refresh at T=25");
        if let Err(LockError::LockAlreadyHeld { identifier, owner }) = result {
            assert_eq!(identifier, "resource");
            assert_eq!(owner, "owner1");
        } else {
            panic!("Expected LockAlreadyHeld error");
        }
    }

    #[tokio::test]
    async fn test_reentrant_lock_should_keep_lock_alive() {
        // This test shows the expected behavior: reentrant locks should refresh timestamp
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));
        let manager = MemoryLockManager::with_timeout_and_clock(
            TimeDelta::seconds(30),
            clock.clone() as Arc<dyn Clock>,
        );

        // T=0: Owner1 acquires lock
        manager.lock("resource", "owner1").await.expect("Lock failed");

        // T=25: Advance time by 25 seconds
        clock.advance(TimeDelta::seconds(25));

        // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp to T=25
        manager.lock("resource", "owner1").await.expect("Reentrant lock failed");

        // T=45: Advance time by another 20 seconds (total 45s from T=0, but only 20s from T=25)
        clock.advance(TimeDelta::seconds(20));

        // T=45: Owner2 tries to acquire the lock
        // Should FAIL because timestamp was refreshed at T=25, lock expires at T=55, current is T=45
        let result = manager.lock("resource", "owner2").await;

        assert!(result.is_err(), "Lock should still be held by owner1 after timestamp refresh");
        if let Err(LockError::LockAlreadyHeld { identifier, owner }) = result {
            assert_eq!(identifier, "resource");
            assert_eq!(owner, "owner1");
        } else {
            panic!("Expected LockAlreadyHeld error");
        }
    }

    #[tokio::test]
    async fn test_release_locks_single_lock() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");

        let result = manager.release_locks("owner1").await;
        assert!(result.is_ok());

        // Verify lock was released by trying to acquire it with a different owner
        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_release_locks_multiple_locks() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
        manager.lock("resource2", "owner1").await.expect("Lock 2 failed");
        manager.lock("resource3", "owner1").await.expect("Lock 3 failed");

        let result = manager.release_locks("owner1").await;
        assert!(result.is_ok());

        // Verify all locks were released
        assert!(manager.lock("resource1", "owner2").await.is_ok());
        assert!(manager.lock("resource2", "owner2").await.is_ok());
        assert!(manager.lock("resource3", "owner2").await.is_ok());
    }

    #[tokio::test]
    async fn test_release_locks_does_not_affect_other_owners() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
        manager.lock("resource2", "owner2").await.expect("Lock 2 failed");
        manager.lock("resource3", "owner1").await.expect("Lock 3 failed");

        let result = manager.release_locks("owner1").await;
        assert!(result.is_ok());

        // owner1's locks should be released
        assert!(manager.lock("resource1", "owner3").await.is_ok());
        assert!(manager.lock("resource3", "owner3").await.is_ok());

        // owner2's lock should still be held
        let result = manager.lock("resource2", "owner3").await;
        assert!(result.is_err());
        if let Err(LockError::LockAlreadyHeld { identifier, owner }) = result {
            assert_eq!(identifier, "resource2");
            assert_eq!(owner, "owner2");
        } else {
            panic!("Expected LockAlreadyHeld error");
        }
    }

    #[tokio::test]
    async fn test_release_locks_with_reentrant_locks() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("First lock failed");
        manager.lock("resource1", "owner1").await.expect("Second lock failed");
        manager.lock("resource1", "owner1").await.expect("Third lock failed");

        let result = manager.release_locks("owner1").await;
        assert!(result.is_ok());

        // Lock should be completely released regardless of reentrant count
        let result = manager.lock("resource1", "owner2").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_release_locks_nonexistent_owner() {
        let manager = MemoryLockManager::new();
        manager.lock("resource1", "owner1").await.expect("Lock failed");

        // Releasing locks for non-existent owner should succeed (no-op)
        let result = manager.release_locks("owner2").await;
        assert!(result.is_ok());

        // Original lock should still be held
        let result = manager.lock("resource1", "owner3").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_release_locks_empty_manager() {
        let manager = MemoryLockManager::new();

        // Releasing locks when no locks exist should succeed (no-op)
        let result = manager.release_locks("owner1").await;
        assert!(result.is_ok());
    }
}
