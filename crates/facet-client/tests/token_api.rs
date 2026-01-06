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

use chrono::Utc;
use facet_client::lock::mem::MemoryLockManager;
use facet_client::token::mem::MemoryTokenStore;
use facet_client::token::{TokenClientApi, TokenData, TokenError, TokenStore};
use std::sync::Arc;

#[tokio::test]
async fn test_api_end_to_end() {
    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_client = Arc::new(MockTokenClient {});
    let data = TokenData {
        identifier: "test".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: Utc::now().timestamp_millis() + 10000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .build();

    let _ = token_api.get_token("test", "owner1").await.unwrap();
}

struct MockTokenClient {}

#[async_trait::async_trait]
impl facet_client::token::TokenClient for MockTokenClient {
    async fn refresh_token(&self, _refresh_token: &str, _refresh_endpoint: &str) -> Result<TokenData, TokenError> {
        // FIXME
        Ok(TokenData {
            identifier: "test".to_string(),
            token: "test".to_string(),
            refresh_token: "test".to_string(),
            expires_at: Utc::now().timestamp_millis() + 10000,
            refresh_endpoint: "http://example.com/renew".to_string(),
        })
    }
}
