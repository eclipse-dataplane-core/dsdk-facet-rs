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

mod common;

use crate::common::setup_postgres_container;
use chrono::{TimeDelta, Utc};
use facet_common::util::{Clock, MockClock};
use facet_consumer::lock::postgres::PostgresLockManager;
use facet_consumer::lock::LockError::{LockAlreadyHeld, LockNotFound};
use facet_consumer::lock::LockManager;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_postgres_lock_exclusive_lock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // First owner acquires lock successfully
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // The second owner should fail
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_err());
    if let Err(LockAlreadyHeld {
        identifier: _,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_postgres_lock_reentrant() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Same owner can acquire lock multiple times (reentrant)
    let _guard = manager.lock(&identifier, owner).await.unwrap();
    let _guard = manager.lock(&identifier, owner).await.unwrap();

    // Both should succeed
    assert_eq!(manager.lock(&identifier, owner).await.is_ok(), true);
}

#[tokio::test]
async fn test_postgres_lock_reentrant_unlock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // Owner1 acquires lock twice (reentrant)
    let _guard = manager.lock(&identifier, owner1).await.unwrap();
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // The first unlock should NOT release the lock completely
    drop(_guard);
    manager.unlock(&identifier, owner1).await.unwrap();

    // Owner2 should still not be able to acquire (lock still held by owner1)
    let result = manager.lock(&identifier, owner2).await;
    assert!(
        result.is_err(),
        "Lock should still be held by owner1 after first unlock"
    );

    // The second unlock should release the lock
    manager.unlock(&identifier, owner1).await.unwrap();

    // Now owner2 should be able to acquire
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_ok(), "Lock should be available after second unlock");
}

#[tokio::test]
async fn test_postgres_lock_concurrent_unlock_race() {
    // This test demonstrates a race condition bug where two concurrent unlocks
    // can both succeed even though the lock was only acquired once
    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Run many iterations to increase the probability of hitting the race
    for iteration in 0..50 {
        let id = format!("{}-{}", identifier, iteration);

        // Acquire lock once (count = 1)
        let _guard = manager.lock(&id, owner).await.unwrap();

        // Spawn two concurrent unlock operations
        let manager1 = manager.clone();
        let manager2 = manager.clone();
        let id1 = id.clone();
        let id2 = id.clone();

        let handle1 = tokio::spawn(async move { manager1.unlock(&id1, owner).await });
        let handle2 = tokio::spawn(async move { manager2.unlock(&id2, owner).await });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // BUG: Both unlocks might succeed even though the lock was only acquired once
        // Expected: One should succeed, the other should fail with LockNotFound
        if result1.is_ok() && result2.is_ok() {
            panic!(
                "BUG DETECTED at iteration {}: Both unlocks succeeded even though lock was only acquired once! \
                This means the reentrant_count went negative.",
                iteration
            );
        }

        // Clean up - ensure lock is released
        let _ = manager.unlock(&id, owner).await;
    }
}

#[tokio::test]
async fn test_postgres_lock_unlock_idempotency() {
    // Verify that unlocking a non-existent or already-released lock returns an error
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Acquire and release lock
    let _guard = manager.lock(&identifier, owner).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, owner).await.unwrap();

    // Second unlock should fail - lock already released
    let result = manager.unlock(&identifier, owner).await;
    assert!(result.is_err(), "Unlocking already-released lock should fail");

    if let Err(LockNotFound {
        identifier: id,
        owner: o,
    }) = result
    {
        assert_eq!(id, identifier);
        assert_eq!(o, owner);
    } else {
        panic!("Expected LockNotFound error");
    }
}

#[tokio::test]
async fn test_postgres_unlock_success() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Acquire lock
    let _guard = manager.lock(&identifier, owner).await.unwrap();

    // Unlock successfully
    drop(_guard);
    manager.unlock(&identifier, owner).await.unwrap();

    // Different owner can now acquire the lock
    let result = manager.lock(&identifier, "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_unlock_wrong_owner() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // Owner1 acquires lock
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // Owner2 tries to unlock - should fail
    drop(_guard);
    let result = manager.unlock(&identifier, owner2).await;
    assert!(result.is_err());

    if let Err(LockAlreadyHeld {
        identifier: error_identifier,
        owner: error_owner,
        attempted_owner,
    }) = result
    {
        assert_eq!(error_identifier, identifier);
        assert_eq!(error_owner, "owner1");
        assert_eq!(attempted_owner, "owner2");
    } else {
        panic!("Expected LockAlreadyHeld error, got: {:?}", result);
    }

    // Verify lock is still held by owner1
    assert!(manager.lock(&identifier, owner2).await.is_err());
}

#[tokio::test]
async fn test_postgres_unlock_nonexistent_lock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Try to unlock a lock that does not exist
    let result = manager.unlock(&identifier, owner).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No lock found"));
}

#[tokio::test]
async fn test_postgres_multiple_locks_different_identifiers() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let id1 = Uuid::new_v4().to_string();
    let id2 = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // Different identifiers can be locked by different owners
    let _guard = manager.lock(&id1, owner1).await.unwrap();
    let _guard = manager.lock(&id2, owner2).await.unwrap();

    // Both locks should remain
    assert!(manager.lock(&id1, owner2).await.is_err());
    assert!(manager.lock(&id2, owner1).await.is_err());
}

#[tokio::test]
async fn test_postgres_concurrent_lock_attempts() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let mut handles = vec![];

    // Spawn 10 concurrent tasks trying to acquire the same lock
    for i in 0..10 {
        let manager_clone = manager.clone();
        let id_clone = identifier.clone();
        let owner = format!("owner{}", i);

        let handle = tokio::spawn(async move { manager_clone.lock(&id_clone, &owner).await });

        handles.push(handle);
    }

    // Collect all results first (keeps guards alive)
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await);
    }

    // Count successes - only tasks that successfully acquired the lock (Ok(Ok(guard)))
    let success_count = results.iter().filter(|r| matches!(r, Ok(Ok(_)))).count();

    assert_eq!(success_count, 1, "Only one task should successfully acquire the lock");

    // Guards are dropped here, releasing the locks
}

#[tokio::test]
async fn test_postgres_lock_cleanup_on_timeout() {
    let (pool, _container) = setup_postgres_container().await;

    let initial_time = Utc::now();
    let mock_clock = Arc::new(MockClock::new(initial_time));
    let manager = PostgresLockManager::builder()
        .pool(pool.clone())
        .clock(mock_clock.clone() as Arc<dyn Clock>)
        .build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // Save a lock and then advance the clock past the timeout
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // Advance time
    mock_clock.advance(TimeDelta::seconds(60));

    // Owner2 should be able to acquire the lock (expired one should be cleaned up)
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_ok(), "Should acquire lock after cleanup of expired lock");
}

#[tokio::test]
async fn test_postgres_table_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();

    // Initialize multiple times - should not fail
    manager.initialize().await.unwrap();
    manager.initialize().await.unwrap();
    manager.initialize().await.unwrap();

    // Should be able to use the manager
    let identifier = Uuid::new_v4().to_string();
    let _guard = manager.lock(&identifier, "owner1").await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_sequence() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Sequence: lock -> unlock -> lock (different owner) -> unlock -> lock (first owner again)
    let _guard = manager.lock(&identifier, owner).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, owner).await.unwrap();

    let owner2 = "owner2";
    let _guard = manager.lock(&identifier, owner2).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, owner2).await.unwrap();

    let _guard = manager.lock(&identifier, owner).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_with_special_characters() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = format!("lock-{}-test@domain.com", Uuid::new_v4());
    let owner = "owner@example.com";

    let _guard = manager.lock(&identifier, owner).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_with_long_identifiers() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = "a".repeat(255); // Max length for VARCHAR(255)
    let owner = "b".repeat(255);

    let _guard = manager.lock(&identifier, &owner).await.unwrap();
    drop(_guard);
    manager.unlock(&identifier, &owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_concurrent_lock_and_unlock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let mut handles = vec![];

    // Spawn 5 sequential lock/unlock cycles without sleep
    for i in 0..5 {
        let manager_clone = manager.clone();
        let id_clone = identifier.clone();
        let owner = format!("owner{}", i);

        let handle = tokio::spawn(async move {
            match manager_clone.lock(&id_clone, &owner).await {
                Ok(_) => manager_clone.unlock(&id_clone, &owner).await,
                Err(e) => Err(e),
            }
        });

        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.is_ok() {
            success_count += 1;
        }
    }

    assert!(success_count > 0, "At least some cycles should succeed");
}

#[tokio::test]
async fn test_postgres_lock_state_after_error() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // Owner1 locks the resource
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // Owner2 tries and fails
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_err());

    // Lock should still be held by owner1
    let result = manager.lock(&identifier, owner1).await;
    assert!(result.is_ok(), "Owner1 should still hold the lock");

    // Owner2 should still not be able to lock
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_lock_reentrant_refreshes_timestamp() {
    let (pool, _container) = setup_postgres_container().await;

    let initial_time = Utc::now();
    let mock_clock = Arc::new(MockClock::new(initial_time));
    let manager = PostgresLockManager::builder()
        .pool(pool.clone())
        .timeout(TimeDelta::seconds(30))
        .clock(mock_clock.clone() as Arc<dyn Clock>)
        .build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // T=0: Owner1 acquires lock
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // T=25: Advance time by 25 seconds (within 30s timeout)
    mock_clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // T=60: Advance time by another 35 seconds (total 60 seconds from T=0)
    // This is past the original 30s timeout from T=0, BUT within 30s of the refreshed timestamp at T=25
    mock_clock.advance(TimeDelta::seconds(35));

    // T=60: Owner2 tries to acquire the lock
    // Should FAIL because the timestamp was refreshed at T=25, so the lock expires at T=55
    // Current time is T=60, so the lock should have expired
    let result = manager.lock(&identifier, owner2).await;

    // With the fix, the reentrant acquisition at T=25 refreshed the timestamp
    // So at T=60, the lock expired at T=55 (25 + 30), making it available
    assert!(
        result.is_ok(),
        "Lock should be available after expiration from refreshed timestamp"
    );
}

#[tokio::test]
async fn test_postgres_lock_reentrant_keeps_lock_alive() {
    let (pool, _container) = setup_postgres_container().await;

    let initial_time = Utc::now();
    let mock_clock = Arc::new(MockClock::new(initial_time));
    let manager = PostgresLockManager::builder()
        .pool(pool.clone())
        .timeout(TimeDelta::seconds(30))
        .clock(mock_clock.clone() as Arc<dyn Clock>)
        .build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // T=0: Owner1 acquires lock
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // T=25: Advance time by 25 seconds (within 30s timeout)
    mock_clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - refreshes timestamp to T=25
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    // T=45: Advance time by another 20 seconds (total 45 seconds from T=0, but only 20 from T=25)
    mock_clock.advance(TimeDelta::seconds(20));

    // T=45: Owner2 tries to acquire the lock
    // Should FAIL because timestamp was refreshed at T=25, lock won't expire until T=55
    let result = manager.lock(&identifier, owner2).await;
    assert!(
        result.is_err(),
        "Lock should still be held by owner1 due to refreshed timestamp"
    );

    if let Err(LockAlreadyHeld {
        identifier: _,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }

    // Verify owner1 can still re-acquire (still owns it)
    assert!(manager.lock(&identifier, owner1).await.is_ok());
}

#[tokio::test]
async fn test_postgres_lock_race_condition_on_concurrent_release() {
    // This test attempts to reproduce a race condition where:
    // 1. Owner2 tries to acquire a lock held by owner1 (INSERT fails, UPDATE returns 0)
    // 2. Owner1 releases the lock before owner2's SELECT executes
    // 3. Owner2's SELECT finds no row and returns a confusing error
    //
    // This is a timing-dependent test that may not always trigger the race,
    // but when it does, it should show a "Failed to fetch lock owner" error
    // instead of a cleaner error message.

    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();

    // Run multiple iterations to increase the chances of hitting the race
    for iteration in 0..100 {
        let id = format!("{}-{}", identifier, iteration);

        // Owner1 acquires lock - skip iteration if it fails (due to previous state)
        match manager.lock(&id, "owner1").await {
            Ok(_) => {}
            Err(_) => continue, // Skip this iteration
        }

        // Spawn two concurrent tasks
        let manager2 = manager.clone();
        let id2 = id.clone();
        let handle_acquire = tokio::spawn(async move { manager2.lock(&id2, "owner2").await });

        // Give a tiny bit of time for owner2 to start attempting acquisition
        tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;

        // Owner1 releases the lock
        let _ = manager.unlock(&id, "owner1").await;

        // Check the result from owner2
        let result = handle_acquire.await.unwrap();

        // The bug manifests as an error containing "Failed to fetch lock owner"
        // when the SELECT finds no rows after the lock was released
        if let Err(e) = &result {
            let error_msg = e.to_string();
            if error_msg.contains("Failed to fetch lock owner") {
                // Found the race condition!
                panic!("Race condition detected: {}", error_msg);
            }
            // Other errors are acceptable (LockAlreadyHeld is expected)
        }

        // Clean up - only clean up what was actually acquired, ignore errors
        let _ = manager.unlock(&id, "owner1").await;
        let _ = manager.unlock(&id, "owner2").await;
    }
}

#[tokio::test]
async fn test_postgres_lock_heavy_contention() {
    // Stress test with heavy lock contention to potentially trigger race conditions
    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let mut handles = vec![];

    // Spawn many tasks competing for the same lock
    for i in 0..20 {
        let manager_clone = manager.clone();
        let id_clone = identifier.clone();
        let owner = format!("owner{}", i % 3); // 3 owners competing

        let handle = tokio::spawn(async move {
            let mut errors = Vec::new();
            for _ in 0..10 {
                // Try to acquire
                match manager_clone.lock(&id_clone, &owner).await {
                    Ok(_) => {
                        // Hold briefly
                        tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                        // Release
                        let _ = manager_clone.unlock(&id_clone, &owner).await;
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        // Check for the race condition error
                        if error_msg.contains("Failed to fetch lock owner") {
                            errors.push(error_msg);
                        }
                    }
                }
                // Small delay between attempts
                tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;
            }
            errors
        });

        handles.push(handle);
    }

    // Collect results
    let mut all_race_errors = Vec::new();
    for handle in handles {
        let errors = handle.await.unwrap();
        all_race_errors.extend(errors);
    }

    // If we detected the race condition, fail the test to demonstrate the bug
    if !all_race_errors.is_empty() {
        panic!(
            "Race condition detected in {} cases:\n{}",
            all_race_errors.len(),
            all_race_errors.join("\n")
        );
    }
}

#[tokio::test]
async fn test_postgres_release_locks_single_lock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";

    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    let result = manager.release_locks(owner1).await;
    assert!(result.is_ok());

    // Verify lock was released by trying to acquire it with a different owner
    let result = manager.lock(&identifier, "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_release_locks_multiple_locks() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let id1 = Uuid::new_v4().to_string();
    let id2 = Uuid::new_v4().to_string();
    let id3 = Uuid::new_v4().to_string();
    let owner1 = "owner1";

    let _guard = manager.lock(&id1, owner1).await.unwrap();
    let _guard = manager.lock(&id2, owner1).await.unwrap();
    let _guard = manager.lock(&id3, owner1).await.unwrap();

    let result = manager.release_locks(owner1).await;
    assert!(result.is_ok());

    // Verify all locks were released
    assert!(manager.lock(&id1, "owner2").await.is_ok());
    assert!(manager.lock(&id2, "owner2").await.is_ok());
    assert!(manager.lock(&id3, "owner2").await.is_ok());
}

#[tokio::test]
async fn test_postgres_release_locks_does_not_affect_other_owners() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let id1 = Uuid::new_v4().to_string();
    let id2 = Uuid::new_v4().to_string();
    let id3 = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    let _guard = manager.lock(&id1, owner1).await.unwrap();
    let _guard = manager.lock(&id2, owner2).await.unwrap();
    let _guard = manager.lock(&id3, owner1).await.unwrap();

    let result = manager.release_locks(owner1).await;
    assert!(result.is_ok());

    // owner1's locks should be released
    assert!(manager.lock(&id1, "owner3").await.is_ok());
    assert!(manager.lock(&id3, "owner3").await.is_ok());

    // owner2's lock should still be held
    let result = manager.lock(&id2, "owner3").await;
    assert!(result.is_err());
    if let Err(LockAlreadyHeld {
        identifier,
        owner,
        attempted_owner: _,
    }) = result
    {
        assert_eq!(identifier, id2);
        assert_eq!(owner, "owner2");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }
}

#[tokio::test]
async fn test_postgres_release_locks_with_reentrant_locks() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";

    let _guard = manager.lock(&identifier, owner1).await.unwrap();
    let _guard = manager.lock(&identifier, owner1).await.unwrap();
    let _guard = manager.lock(&identifier, owner1).await.unwrap();

    let result = manager.release_locks(owner1).await;
    assert!(result.is_ok());

    // Lock should be completely released regardless of reentrant count
    let result = manager.lock(&identifier, "owner2").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_release_locks_nonexistent_owner() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let _guard = manager.lock(&identifier, "owner1").await.unwrap();

    // Releasing locks for the non-existent owner should succeed (no-op)
    let result = manager.release_locks("owner2").await;
    assert!(result.is_ok());

    // The original lock should still be held
    let result = manager.lock(&identifier, "owner3").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_release_locks_empty_database() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    // Releasing locks when no locks exist should succeed (no-op)
    let result = manager.release_locks("owner1").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_release_locks_concurrent() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let id1 = Uuid::new_v4().to_string();
    let id2 = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    let _guard = manager.lock(&id1, owner1).await.unwrap();
    let _guard = manager.lock(&id2, owner2).await.unwrap();

    // Concurrently release locks for different owners
    let manager1 = manager.clone();
    let manager2 = manager.clone();

    let handle1 = tokio::spawn(async move { manager1.release_locks(owner1).await });
    let handle2 = tokio::spawn(async move { manager2.release_locks(owner2).await });

    let result1 = handle1.await.unwrap();
    let result2 = handle2.await.unwrap();

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Both locks should be released
    assert!(manager.lock(&id1, "owner3").await.is_ok());
    assert!(manager.lock(&id2, "owner3").await.is_ok());
}
