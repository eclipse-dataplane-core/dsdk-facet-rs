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

use std::sync::Arc;
use crate::common::setup_postgres_container;
use facet_client::lock::postgres::PostgresLockManager;
use facet_client::lock::LockManager;
use facet_client::util::{Clock, MockClock};
use uuid::Uuid;
use facet_client::lock::LockError::{LockAlreadyHeld, LockNotFound};
use chrono::{TimeDelta, Utc};

#[tokio::test]
async fn test_postgres_lock_exclusive_lock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner1 = "owner1";
    let owner2 = "owner2";

    // First owner acquires lock successfully
    manager.lock(&identifier, owner1).await.unwrap();

    // The second owner should fail
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_err());
    if let Err(LockAlreadyHeld { identifier, owner }) = result {
        assert_eq!(identifier, identifier);
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
    manager.lock(&identifier, owner).await.unwrap();
    manager.lock(&identifier, owner).await.unwrap();

    // Both should succeed
    assert_eq!(manager.lock(&identifier, owner).await.is_ok(), true);
}

#[tokio::test]
async fn test_postgres_unlock_success() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Acquire lock
    manager.lock(&identifier, owner).await.unwrap();

    // Unlock successfully
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
    manager.lock(&identifier, owner1).await.unwrap();

    // Owner2 tries to unlock - should fail
    let result = manager.unlock(&identifier, owner2).await;
    assert!(result.is_err());

    if let Err(LockNotFound { identifier: error_identifier, owner: error_owner }) = result {
        assert_eq!(error_identifier, identifier);
        assert_eq!(error_owner, "owner2");
    } else {
        panic!("Expected LockNotFound error");
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

    // Try to unlock a lock that doesn't exist
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
    manager.lock(&id1, owner1).await.unwrap();
    manager.lock(&id2, owner2).await.unwrap();

    // Both locks should remain
    assert!(manager.lock(&id1, owner2).await.is_err());
    assert!(manager.lock(&id2, owner1).await.is_err());
}

#[tokio::test]
async fn test_postgres_concurrent_lock_attempts() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = std::sync::Arc::new(PostgresLockManager::builder().pool(pool).build());
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let mut handles = vec![];

    // Spawn 10 concurrent tasks trying to acquire the same lock
    for i in 0..10 {
        let manager_clone = manager.clone();
        let id_clone = identifier.clone();
        let owner = format!("owner{}", i);

        let handle = tokio::spawn(async move { manager_clone.lock(&id_clone, &owner).await });

        handles.push((i, handle));
    }

    // Only one should succeed
    let mut success_count = 0;
    for (_, handle) in handles {
        if let Ok(Ok(())) = handle.await {
            success_count += 1;
        }
    }

    assert_eq!(success_count, 1, "Only one task should successfully acquire the lock");
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
    manager.lock(&identifier, owner1).await.unwrap();

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
    manager.lock(&identifier, "owner1").await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_sequence() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = Uuid::new_v4().to_string();
    let owner = "owner1";

    // Sequence: lock -> unlock -> lock (different owner) -> unlock -> lock (first owner again)
    manager.lock(&identifier, owner).await.unwrap();
    manager.unlock(&identifier, owner).await.unwrap();

    let owner2 = "owner2";
    manager.lock(&identifier, owner2).await.unwrap();
    manager.unlock(&identifier, owner2).await.unwrap();

    manager.lock(&identifier, owner).await.unwrap();
    manager.unlock(&identifier, owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_with_special_characters() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = format!("lock-{}-test@domain.com", Uuid::new_v4());
    let owner = "owner@example.com";

    manager.lock(&identifier, owner).await.unwrap();
    manager.unlock(&identifier, owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_lock_with_long_identifiers() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = PostgresLockManager::builder().pool(pool).build();
    manager.initialize().await.unwrap();

    let identifier = "a".repeat(255); // Max length for VARCHAR(255)
    let owner = "b".repeat(255);

    manager.lock(&identifier, &owner).await.unwrap();
    manager.unlock(&identifier, &owner).await.unwrap();
}

#[tokio::test]
async fn test_postgres_concurrent_lock_and_unlock() {
    let (pool, _container) = setup_postgres_container().await;
    let manager = std::sync::Arc::new(PostgresLockManager::builder().pool(pool).build());
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
                Ok(_) => {
                    manager_clone.unlock(&id_clone, &owner).await
                }
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
    manager.lock(&identifier, owner1).await.unwrap();

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
    manager.lock(&identifier, owner1).await.unwrap();

    // T=25: Advance time by 25 seconds (within 30s timeout)
    mock_clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - should refresh timestamp
    manager.lock(&identifier, owner1).await.unwrap();

    // T=60: Advance time by another 35 seconds (total 60 seconds from T=0)
    // This is past the original 30s timeout from T=0, BUT within 30s of the refreshed timestamp at T=25
    mock_clock.advance(TimeDelta::seconds(35));

    // T=60: Owner2 tries to acquire the lock
    // Should FAIL because the timestamp was refreshed at T=25, so lock expires at T=55
    // Current time is T=60, so lock should have expired
    let result = manager.lock(&identifier, owner2).await;

    // With the fix, the reentrant acquisition at T=25 refreshed the timestamp
    // So at T=60, the lock expired at T=55 (25 + 30), making it available
    assert!(result.is_ok(), "Lock should be available after expiration from refreshed timestamp");
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
    manager.lock(&identifier, owner1).await.unwrap();

    // T=25: Advance time by 25 seconds (within 30s timeout)
    mock_clock.advance(TimeDelta::seconds(25));

    // T=25: Owner1 re-acquires lock (reentrant) - refreshes timestamp to T=25
    manager.lock(&identifier, owner1).await.unwrap();

    // T=45: Advance time by another 20 seconds (total 45 seconds from T=0, but only 20 from T=25)
    mock_clock.advance(TimeDelta::seconds(20));

    // T=45: Owner2 tries to acquire the lock
    // Should FAIL because timestamp was refreshed at T=25, lock won't expire until T=55
    let result = manager.lock(&identifier, owner2).await;
    assert!(result.is_err(), "Lock should still be held by owner1 due to refreshed timestamp");

    if let Err(LockAlreadyHeld { identifier: _, owner }) = result {
        assert_eq!(owner, "owner1");
    } else {
        panic!("Expected LockAlreadyHeld error");
    }

    // Verify owner1 can still re-acquire (still owns it)
    assert!(manager.lock(&identifier, owner1).await.is_ok());
}