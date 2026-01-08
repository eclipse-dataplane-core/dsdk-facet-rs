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

use crate::lock::{LockError, LockGuard, LockManager};
use async_trait::async_trait;
use mockall::mock;
use mockall::predicate::eq;
use std::sync::Arc;

mock! {
        LockManagerImpl {}

        #[async_trait]
        impl LockManager for LockManagerImpl {
            async fn lock(&self, identifier: &str, owner: &str) -> Result<(), LockError>;
            async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), LockError>;
            async fn release_locks(&self, owner: &str) -> Result<(), LockError>;
        }
    }

#[tokio::test]
async fn test_lock_guard_drop_calls_unlock() {
    let mut mock = MockLockManagerImpl::new();

    // When the guard is dropped, unlock should be called
    mock.expect_unlock()
        .with(eq("resource1"), eq("owner1"))
        .times(1)
        .returning(|_, _| Ok(()));

    let manager: Arc<dyn LockManager> = Arc::new(mock);

    let handle = tokio::spawn(async move {
        let _guard = LockGuard {
            lock_manager: manager,
            identifier: "resource1".to_string(),
            owner: "owner1".to_string(),
        };
        // Guard is dropped here when the block ends
    });

    // Wait for the spawned task to complete
    handle.await.expect("Task failed");
}
