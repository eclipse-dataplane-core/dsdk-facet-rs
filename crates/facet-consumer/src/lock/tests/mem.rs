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

use crate::lock::{LockError, LockManager, MemoryLockManager};
use chrono::{TimeDelta, Utc};
use facet_common::util::{Clock, MockClock};
use std::sync::Arc;

#[tokio::test]
async fn test_lock_acquire_success() {
    let manager = MemoryLockManager::new();
    let result = manager.lock("resource1", "owner1").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_lock_exclusive() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("First lock failed");
    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_err());

    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(identifier, "resource1");
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_lock_reentrant() {
    let manager = MemoryLockManager::new();
    let _guard1 = manager.lock("resource1", "owner1").await.expect("First lock failed");
    let result = manager.lock("resource1", "owner1").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_unlock_success() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");
    let result = manager.unlock("resource1", "owner1").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_unlock_wrong_owner() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");
    let result = manager.unlock("resource1", "owner2").await;
    assert!(result.is_err());

    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner,
    }) = result
    {
        assert_eq!(identifier, "resource1");
        assert_eq!(attempted_owner, "owner2");
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
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
    let _guard1 = manager.lock("resource1", "owner1").await.expect("First lock failed");
    let _guard2 = manager.lock("resource1", "owner1").await.expect("Second lock failed");

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
    let clock = Arc::new(MockClock::new(Utc::now()));
    let manager = Arc::new(MemoryLockManager::with_timeout_and_clock(
        TimeDelta::milliseconds(20),
        clock.clone() as Arc<dyn Clock>,
    ));

    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");

    // Advance time by 40ms to exceed the 20ms timeout
    clock.advance(TimeDelta::milliseconds(60));

    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_ok(), "Lock should be acquired after timeout expiration");
}

#[tokio::test]
async fn test_multiple_resources() {
    let manager = MemoryLockManager::new();
    let _guard1 = manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
    let _guard2 = manager.lock("resource2", "owner1").await.expect("Lock 2 failed");

    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_err());

    let result = manager.lock("resource3", "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_lock_acquire_after_release() {
    let manager = MemoryLockManager::new();
    let guard = manager.lock("resource1", "owner1").await.expect("Lock failed");

    // Drop the guard to release the lock
    drop(guard);

    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_lock_exclusive_error_message() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("First lock failed");
    let result = manager.lock("resource1", "owner2").await;

    assert!(result.is_err());
    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner,
    }) = result
    {
        let error_msg = LockError::lock_already_held(&identifier, &owner, &attempted_owner).to_string();
        assert!(error_msg.contains("owner1"));
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_unlock_wrong_owner_error_message() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");
    let result = manager.unlock("resource1", "owner2").await;

    assert!(result.is_err());
    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner,
    }) = result
    {
        let error_msg = LockError::lock_already_held(&identifier, &owner, &attempted_owner).to_string();
        assert!(error_msg.contains("owner1"));
    } else {
        panic!("Expected LockAlreadyHeld error");
    }

    // let error_msg = result.unwrap_err().to_string();
    // assert!(error_msg.contains("held by"));
    // assert!(error_msg.contains("owner1"));
    // assert!(error_msg.contains("owner2"));
}

#[tokio::test]
async fn test_concurrent_lock_acquisition() {
    let manager = MemoryLockManager::new();

    let _guard = manager.lock("resource", "owner1").await.expect("Lock failed");

    let manager_clone = manager;
    let handle = tokio::spawn(async move { manager_clone.lock("resource", "owner2").await });

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_reentrant_lock_refreshes_timestamp() {
    // This test verifies that reentrant locks refresh the timestamp
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let manager = Arc::new(MemoryLockManager::with_timeout_and_clock(
        TimeDelta::seconds(30),
        clock.clone() as Arc<dyn Clock>,
    ));

    // T=0: Owner1 acquires lock
    let _guard1 = manager.lock("resource", "owner1").await.expect("Lock failed");

    // T=25: Advance time by 25 seconds (within 30s timeout)
    clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp to T=25
    let _guard2 = manager.lock("resource", "owner1").await.expect("Reentrant lock failed");

    // T=35: Advance time by another 10 seconds (total 35 seconds from T=0, but only 10 from T=25)
    clock.advance(TimeDelta::seconds(10));

    // T=35: Owner2 tries to acquire the lock
    // Without the fix: Lock would have expired at T=30 (T=0 + 30s), owner2 would acquire it
    // With the fix: Lock was refreshed at T=25, expires at T=55, so still held by owner1
    let result = manager.lock("resource", "owner2").await;

    // With the fix applied, the lock should still be held by owner1
    assert!(
        result.is_err(),
        "Lock should still be held by owner1 due to timestamp refresh at T=25"
    );
    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(identifier, "resource");
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_reentrant_lock_should_keep_lock_alive() {
    // This test shows the expected behavior: reentrant locks should refresh the timestamp
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let manager = Arc::new(MemoryLockManager::with_timeout_and_clock(
        TimeDelta::seconds(30),
        clock.clone() as Arc<dyn Clock>,
    ));

    // T=0: Owner1 acquires lock
    let _guard1 = manager.lock("resource", "owner1").await.expect("Lock failed");

    // T=25: Advance time by 25 seconds
    clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp to T=25
    let _guard2 = manager.lock("resource", "owner1").await.expect("Reentrant lock failed");

    // T=45: Advance time by another 20 seconds (total 45s from T=0, but only 20s from T=25)
    clock.advance(TimeDelta::seconds(20));

    // T=45: Owner2 tries to acquire the lock
    // Should FAIL because timestamp was refreshed at T=25, lock expires at T=55, current is T=45
    let result = manager.lock("resource", "owner2").await;

    assert!(
        result.is_err(),
        "Lock should still be held by owner1 after timestamp refresh"
    );
    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(identifier, "resource");
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_release_locks_single_lock() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");

    let result = manager.release_locks("owner1").await;
    assert!(result.is_ok());

    // Verify lock was released by trying to acquire it with a different owner
    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_release_locks_multiple_locks() {
    let manager = MemoryLockManager::new();
    let _guard1 = manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
    let _guard2 = manager.lock("resource2", "owner1").await.expect("Lock 2 failed");
    let _guard3 = manager.lock("resource3", "owner1").await.expect("Lock 3 failed");

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
    let _guard1 = manager.lock("resource1", "owner1").await.expect("Lock 1 failed");
    let _guard2 = manager.lock("resource2", "owner2").await.expect("Lock 2 failed");
    let _guard3 = manager.lock("resource3", "owner1").await.expect("Lock 3 failed");

    let result = manager.release_locks("owner1").await;
    assert!(result.is_ok());

    // owner1's locks should be released
    assert!(manager.lock("resource1", "owner3").await.is_ok());
    assert!(manager.lock("resource3", "owner3").await.is_ok());

    // owner2's lock should still be held
    let result = manager.lock("resource2", "owner3").await;
    assert!(result.is_err());
    if let Err(LockError::LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(identifier, "resource2");
        assert_eq!(owner, "owner2");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_release_locks_with_reentrant_locks() {
    let manager = MemoryLockManager::new();
    let _guard1 = manager.lock("resource1", "owner1").await.expect("First lock failed");
    let _guard2 = manager.lock("resource1", "owner1").await.expect("Second lock failed");
    let _guard3 = manager.lock("resource1", "owner1").await.expect("Third lock failed");

    let result = manager.release_locks("owner1").await;
    assert!(result.is_ok());

    // Lock should be completely released regardless of reentrant count
    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_release_locks_nonexistent_owner() {
    let manager = MemoryLockManager::new();
    let _guard = manager.lock("resource1", "owner1").await.expect("Lock failed");

    // Releasing locks for a non-existent owner should succeed (no-op)
    let result = manager.release_locks("owner2").await;
    assert!(result.is_ok());

    // The original lock should still be held
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
