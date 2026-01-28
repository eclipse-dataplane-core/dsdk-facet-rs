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

use crate::lock::{LockManager, MemoryLockManager};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_lock_guard_drop_calls_unlock() {
    let manager = Arc::new(MemoryLockManager::new());

    // Acquire a lock
    let guard = manager.lock("resource1", "owner1").await.expect("Lock failed");

    // Verify the lock exists by trying to acquire it with a different owner
    let result = manager.lock("resource1", "owner2").await;
    assert!(
        result.is_err(),
        "Lock should be held by owner1, preventing owner2 from acquiring it"
    );

    // Drop the guard
    drop(guard);

    // Wait for the lock to be released since unlock is async
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let count = manager
                .lock_count("resource1", "owner1")
                .await
                .expect("Failed to get lock count");
            if count == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Lock release timeout");

    // Now owner2 should be able to acquire the lock
    let result = manager.lock("resource1", "owner2").await;
    assert!(result.is_ok(), "Lock should have been released after guard was dropped");
}
