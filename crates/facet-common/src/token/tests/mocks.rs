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

use crate::lock::{LockGuard, LockManager, UnlockOps};
use crate::token::{TokenClient, TokenData, TokenError, TokenStore};
use crate::context::ParticipantContext;
use mockall::mock;
use mockall::predicate::*;
use std::sync::Arc;

/// Helper function to create a dummy LockGuard for tests
pub(crate) fn create_dummy_lock_guard(identifier: &str, owner: &str) -> LockGuard {
    let mut mock = MockLockManager::new();
    mock.expect_unlock().returning(|_, _| Ok(()));
    mock.expect_release_locks().returning(|_| Ok(()));
    LockGuard::new(Arc::new(mock), identifier, owner)
}

mock! {
   pub LockManager {}

    #[async_trait::async_trait]
    impl UnlockOps for LockManager {
        async fn unlock(&self, identifier: &str, owner: &str) -> Result<(), crate::lock::LockError>;
    }

    #[async_trait::async_trait]
    impl LockManager for LockManager {
        async fn lock(&self, identifier: &str, owner: &str) -> Result<LockGuard, crate::lock::LockError>;
        async fn lock_count(&self, identifier: &str, owner: &str) -> Result<u32, crate::lock::LockError>;
        async fn release_locks(&self, owner: &str) -> Result<(), crate::lock::LockError>;
    }
}

mock! {
    pub TokenClient {}

    #[async_trait::async_trait]
    impl TokenClient for TokenClient {
        async fn refresh_token(&self, participant_context: &ParticipantContext, endpoint_identifier: &str, access_token: &str, refresh_token: &str, refresh_endpoint: &str) -> Result<TokenData, TokenError>;
    }
}

mock! {
    pub TokenStore {}

    #[async_trait::async_trait]
    impl TokenStore for TokenStore {
        async fn get_token(&self, participant_context: &ParticipantContext, identifier: &str) -> Result<TokenData, TokenError>;
        async fn save_token(&self, data: TokenData) -> Result<(), TokenError>;
        async fn update_token(&self, data: TokenData) -> Result<(), TokenError>;
        async fn remove_token(&self, participant_context: &str, identifier: &str) -> Result<(), TokenError>;
        async fn close(&self);
    }
}
