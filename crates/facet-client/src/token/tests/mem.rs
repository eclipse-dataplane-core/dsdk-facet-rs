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
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

async fn create_store_with_tokens() -> MemoryTokenStore {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);

    store
        .save_token(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "provider1".to_string(),
            token: "token1".to_string(),
            refresh_token: "refresh1".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save token");

    store
        .save_token(TokenData {
            identifier: "provider2".to_string(),
            participant_context: "participant1".to_string(),
            token: "token2".to_string(),
            refresh_token: "refresh2".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save token");

    store
        .save_token(TokenData {
            identifier: "provider3".to_string(),
            participant_context: "participant1".to_string(),
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
    let data = store.get_token("participant1", "nonexistent").await;
    assert!(data.is_err());
}

#[tokio::test]
async fn test_save_token_success() {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);
    let test_data = TokenData {
        identifier: "provider1".to_string(),
        participant_context: "participant1".to_string(),
        token: "token123".to_string(),
        refresh_token: "refresh123".to_string(),
        expires_at: expiration,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let result = store.save_token(test_data.clone()).await;
    assert!(result.is_ok(), "save_token should return Ok");

    let retrieved = store
        .get_token("participant1", "provider1")
        .await
        .expect("Failed to retrieve saved token");
    assert_eq!(retrieved.identifier, "provider1", "Identifier should match");
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

    assert_eq!(
        store.get_token("participant1", "provider1").await.unwrap().token,
        "token1"
    );
    assert_eq!(
        store.get_token("participant1", "provider2").await.unwrap().token,
        "token2"
    );
    assert_eq!(
        store.get_token("participant1", "provider3").await.unwrap().token,
        "token3"
    );
}

#[tokio::test]
async fn test_remove_tokens_used_before_success() {
    let initial = Utc::now();
    let clock = Arc::new(MockClock::new(initial));
    let store = MemoryTokenStore::with_clock(clock.clone());
    let expiration = initial + TimeDelta::seconds(10);

    store
        .save_token(TokenData {
            identifier: "provider1".to_string(),
            participant_context: "participant1".to_string(),
            token: "token1".to_string(),
            refresh_token: "refresh1".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
        .await
        .expect("Failed to save");

    let cutoff = clock.now() + TimeDelta::seconds(1);

    let removed = store
        .remove_tokens_accessed_before(cutoff)
        .await
        .expect("Failed to remove tokens");

    assert_eq!(removed, 1);
    assert!(store.get_token("participant1", "provider1").await.is_err());
}

#[tokio::test]
async fn test_context_isolation_save() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let retrieved_p1 = store.get_token("participant1", "provider").await.unwrap();
    let retrieved_p2 = store.get_token("participant2", "provider").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");

    // Verify participant3 cannot access participant1's token
    let result_p3 = store.get_token("participant3", "provider").await;
    assert!(result_p3.is_err());
}

#[tokio::test]
async fn test_context_isolation_get() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let p1_result = store.get_token("participant1", "provider").await.unwrap();
    let p2_result = store.get_token("participant2", "provider").await.unwrap();

    assert_eq!(p1_result.participant_context, "participant1");
    assert_eq!(p1_result.token, "token_p1");
    assert_eq!(p2_result.participant_context, "participant2");
    assert_eq!(p2_result.token, "token_p2");

    // Verify participant3 cannot get either token
    let result_p3 = store.get_token("participant3", "provider").await;
    assert!(result_p3.is_err());
    assert!(result_p3.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_context_isolation_update() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let updated_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1_updated".to_string(),
        refresh_token: "refresh_p1_updated".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    store.update_token(updated_p1).await.unwrap();

    let p1_result = store.get_token("participant1", "provider").await.unwrap();
    let p2_result = store.get_token("participant2", "provider").await.unwrap();

    assert_eq!(p1_result.token, "token_p1_updated");
    assert_eq!(p2_result.token, "token_p2");

    // Verify participant3 cannot update a non-existent token
    let update_p3 = TokenData {
        participant_context: "participant3".to_string(),
        identifier: "provider".to_string(),
        token: "token_p3".to_string(),
        refresh_token: "refresh_p3".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p3.example.com/refresh".to_string(),
    };

    let result_p3 = store.update_token(update_p3).await;
    assert!(result_p3.is_err());
    assert!(result_p3.unwrap_err().to_string().contains("non-existent"));
}

#[tokio::test]
async fn test_context_isolation_remove() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at: now,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    store.remove_token("participant1", "provider").await.unwrap();

    assert!(store.get_token("participant1", "provider").await.is_err());
    assert_eq!(
        store.get_token("participant2", "provider").await.unwrap().token,
        "token_p2"
    );

    // Verify participant3 cannot remove a token they don't own
    let result_p3 = store.remove_token("participant3", "provider").await;
    assert!(result_p3.is_ok()); // Remove is idempotent

    // Verify p2's token still exists after p3 tries to remove it
    assert_eq!(
        store.get_token("participant2", "provider").await.unwrap().token,
        "token_p2"
    );
}
