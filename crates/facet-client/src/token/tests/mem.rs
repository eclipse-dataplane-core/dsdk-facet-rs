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

use crate::token::{MemoryTokenStore, TokenData, TokenStore};
use crate::util::{Clock, MockClock};
use chrono::{Duration as ChronoDuration, Utc};
use std::sync::Arc;

async fn create_store_with_tokens() -> MemoryTokenStore {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + ChronoDuration::seconds(10);

    store
        .save_token(TokenData {
            identifier: "user1".to_string(),
            token: "token1".to_string(),
            refresh_token: "refresh1".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save token");

    store
        .save_token(TokenData {
            identifier: "user2".to_string(),
            token: "token2".to_string(),
            refresh_token: "refresh2".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save token");

    store
        .save_token(TokenData {
            identifier: "user3".to_string(),
            token: "token3".to_string(),
            refresh_token: "refresh3".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save token");

    store
}

#[tokio::test]
async fn test_new_store_is_empty() {
    let store = MemoryTokenStore::new();
    let data = store.get_token("nonexistent").await;
    assert!(data.is_err());
}

#[tokio::test]
async fn test_save_token_success() {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + ChronoDuration::seconds(10);
    let test_data = TokenData {
        identifier: "user1".to_string(),
        token: "token123".to_string(),
        refresh_token: "refresh123".to_string(),
        expires_at: expiration,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let result = store.save_token(test_data.clone()).await;
    assert!(result.is_ok(), "save_token should return Ok");

    let retrieved = store.get_token("user1").await.expect("Failed to retrieve saved token");
    assert_eq!(retrieved.identifier, "user1", "Identifier should match");
    assert_eq!(retrieved.token, "token123", "Token should match");
    assert_eq!(retrieved.refresh_token, "refresh123", "Refresh token should match");
    assert_eq!(retrieved.expires_at, expiration, "Expiration should match");
    assert_eq!(
        retrieved.refresh_endpoint, "https://example.com/refresh",
        "Refresh endpoint should match"
    );
}

#[tokio::test]
async fn test_save_multiple_tokens() {
    let store = create_store_with_tokens().await;

    assert_eq!(store.get_token("user1").await.unwrap().token, "token1");
    assert_eq!(store.get_token("user2").await.unwrap().token, "token2");
    assert_eq!(store.get_token("user3").await.unwrap().token, "token3");
}

#[tokio::test]
async fn test_remove_tokens_used_before_success() {
    let initial = Utc::now();
    let clock = Arc::new(MockClock::new(initial));
    let store = MemoryTokenStore::with_clock(clock.clone());
    let expiration = initial + ChronoDuration::seconds(10);

    store
        .save_token(TokenData {
            identifier: "user1".to_string(),
            token: "token1".to_string(),
            refresh_token: "refresh1".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save");

    let cutoff = clock.now() + ChronoDuration::seconds(1);

    let removed = store
        .remove_tokens_accessed_before(cutoff)
        .await
        .expect("Failed to remove tokens");

    assert_eq!(removed, 1);
    assert!(store.get_token("user1").await.is_err());
}
