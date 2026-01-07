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

use chrono::{TimeDelta, Utc};
use facet_client::lock::mem::MemoryLockManager;
use facet_client::token::mem::MemoryTokenStore;
use facet_client::token::{TokenClientApi, TokenData, TokenError, TokenStore};
use facet_client::util::{Clock, default_clock};
use std::sync::Arc;

#[tokio::test]
async fn test_api_end_to_end() {
    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_client = Arc::new(MockTokenClient {});

    let data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "test".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: Utc::now() + TimeDelta::seconds(10),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(default_clock())
        .build();

    let _ = token_api.get_token("participant1", "test", "owner1").await.unwrap();
}

#[tokio::test]
async fn test_token_expiration_triggers_refresh() {
    use facet_client::util::MockClock;

    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_client = Arc::new(MockTokenClient {});

    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "test".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: initial_time + TimeDelta::seconds(10),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(clock.clone() as Arc<dyn Clock>)
        .build();

    // Advance time so the token is about to expire
    clock.advance(TimeDelta::seconds(6)); // Now + 6s, token expires at +10s, refresh threshold is 5s

    let result = token_api.get_token("participant1", "test", "owner1").await;
    // Should trigger refresh since (now + 5s refresh buffer) > expires_at
    assert!(result.is_ok());
}

struct MockTokenClient {}

#[async_trait::async_trait]
impl facet_client::token::TokenClient for MockTokenClient {
    async fn refresh_token(&self, _refresh_token: &str, _refresh_endpoint: &str) -> Result<TokenData, TokenError> {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "test".to_string(),
            token: "refreshed_token".to_string(),
            refresh_token: "test".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(10),
            refresh_endpoint: "http://example.com/renew".to_string(),
        })
    }
}
