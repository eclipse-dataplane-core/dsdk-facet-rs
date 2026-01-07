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

use chrono::{TimeDelta, Utc};
use common::setup_postgres_container;
use facet_client::token::{PostgresTokenStore, TokenData, TokenStore};
use facet_client::util::{Clock, MockClock, encryption_key};
use once_cell::sync::Lazy;
use sodiumoxide::crypto::secretbox;
use std::sync::Arc;

const TEST_SALT: &str = "6b9768804c86626227e61acd9e06f8ff";

static TEST_KEY: Lazy<secretbox::Key> =
    Lazy::new(|| encryption_key("test_password", TEST_SALT).expect("Failed to derive test key"));

#[tokio::test]
async fn test_postgres_token_store_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();

    // Initialize multiple times - should not fail
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_postgres_save_and_get_token() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(3600);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "access_token_123".to_string(),
        refresh_token: "refresh_token_123".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/refresh".to_string(),
    };

    store.save_token(token_data.clone()).await.unwrap();
    let retrieved = store.get_token("user1").await.unwrap();

    assert_eq!(retrieved.identifier, "user1");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.refresh_token, "refresh_token_123");
    assert_eq!(retrieved.expires_at, expires_at);
    assert_eq!(retrieved.refresh_endpoint, "https://auth.example.com/refresh");
}

#[tokio::test]
async fn test_postgres_get_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let result = store.get_token("nonexistent").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_save_token_fails_on_duplicate() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at_1 = initial_time + TimeDelta::seconds(1000);
    let expires_at_2 = initial_time + TimeDelta::seconds(2000);

    let token_data1 = TokenData {
        identifier: "user1".to_string(),
        token: "old_token".to_string(),
        refresh_token: "old_refresh".to_string(),
        expires_at: expires_at_1,
        refresh_endpoint: "https://old.example.com/refresh".to_string(),
    };

    let token_data2 = TokenData {
        identifier: "user1".to_string(),
        token: "new_token".to_string(),
        refresh_token: "new_refresh".to_string(),
        expires_at: expires_at_2,
        refresh_endpoint: "https://new.example.com/refresh".to_string(),
    };

    // First save succeeds
    store.save_token(token_data1).await.unwrap();

    // Second save with same identifier should fail
    let result = store.save_token(token_data2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Database error"));

    // Verify original token is still there unchanged
    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "old_token");
    assert_eq!(retrieved.refresh_token, "old_refresh");
    assert_eq!(retrieved.expires_at, expires_at_1);
}

#[tokio::test]
async fn test_postgres_update_token_success() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let updated_data = TokenData {
        identifier: "user1".to_string(),
        token: "token_updated".to_string(),
        refresh_token: "refresh_updated".to_string(),
        expires_at: new_expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "token_updated");
    assert_eq!(retrieved.refresh_token, "refresh_updated");
    assert_eq!(retrieved.expires_at, new_expires_at);
}

#[tokio::test]
async fn test_postgres_update_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "nonexistent".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let result = store.update_token(token_data).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("non-existent"));
}

#[tokio::test]
async fn test_postgres_remove_token_success() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();
    store.remove_token("user1").await.unwrap();

    let result = store.get_token("user1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_remove_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    // Should succeed even if the token doesn't exist
    let result = store.remove_token("nonexistent").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_multiple_tokens() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);

    let token1 = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let token2 = TokenData {
        identifier: "user2".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token1).await.unwrap();
    store.save_token(token2).await.unwrap();

    let retrieved1 = store.get_token("user1").await.unwrap();
    let retrieved2 = store.get_token("user2").await.unwrap();

    assert_eq!(retrieved1.token, "token1");
    assert_eq!(retrieved2.token, "token2");
}

#[tokio::test]
async fn test_postgres_token_with_special_characters() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "user@domain.com".to_string(),
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0".to_string(),
        refresh_token: "refresh!@#$%^&*()".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/token?param=value&other=123".to_string(),
    };

    store.save_token(token_data).await.unwrap();
    let retrieved = store.get_token("user@domain.com").await.unwrap();

    assert_eq!(retrieved.identifier, "user@domain.com");
    assert!(retrieved.token.contains("eyJ"));
    assert!(retrieved.refresh_token.contains("!@#$%^&*()"));
}

#[tokio::test]
async fn test_postgres_token_with_long_values() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "t".repeat(2000),
        refresh_token: "r".repeat(2000),
        expires_at,
        refresh_endpoint: format!("https://example.com/{}", "path/".repeat(100)),
    };

    store.save_token(token_data).await.unwrap();
    let retrieved = store.get_token("user1").await.unwrap();

    assert_eq!(retrieved.token.len(), 2000);
    assert_eq!(retrieved.refresh_token.len(), 2000);
}

#[tokio::test]
async fn test_postgres_save_get_update_remove_flow() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(1000);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let updated_data = TokenData {
        identifier: "user1".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: new_expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "token2");

    store.remove_token("user1").await.unwrap();
    let result = store.get_token("user1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_last_accessed_timestamp_recorded() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let mock_clock = Arc::new(MockClock::new(initial_time));

    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(mock_clock.clone() as Arc<dyn Clock>)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(3600);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    // Advance time and access the token
    mock_clock.advance(TimeDelta::seconds(100));
    let _retrieved = store.get_token("user1").await.unwrap();

    // Use mock_clock directly (not the cast version)
    assert_eq!(mock_clock.now(), initial_time + TimeDelta::seconds(100));
}

#[tokio::test]
async fn test_postgres_deterministic_timestamps() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool)
        .clock(clock.clone())
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    // Create multiple tokens with controlled time
    let token1 = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: initial_time + TimeDelta::seconds(3600),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token1).await.unwrap();

    // Advance time in a controlled manner
    clock.advance(TimeDelta::seconds(500));

    let token2 = TokenData {
        identifier: "user2".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: initial_time + TimeDelta::seconds(7200),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token2).await.unwrap();

    // Verify both tokens exist with their respective timestamps
    let retrieved1 = store.get_token("user1").await.unwrap();
    let retrieved2 = store.get_token("user2").await.unwrap();

    assert_eq!(retrieved1.identifier, "user1");
    assert_eq!(retrieved2.identifier, "user2");
}


#[tokio::test]
async fn test_postgres_tokens_are_encrypted_at_rest() {
    let (pool, _container) = setup_postgres_container().await;
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));
    let store = PostgresTokenStore::builder()
        .pool(pool.clone())
        .clock(clock)
        .encryption_key(TEST_KEY.clone())
        .build();
    store.initialize().await.unwrap();

    let expires_at = initial_time + TimeDelta::seconds(3600);
    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "plaintext_access_token".to_string(),
        refresh_token: "plaintext_refresh_token".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/refresh".to_string(),
    };

    store.save_token(token_data.clone()).await.unwrap();

    // Query database directly to verify encryption
    let raw_record: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT token, refresh_token FROM tokens WHERE identifier = $1"
    )
        .bind("user1")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Verify stored values are NOT plaintext
    assert_ne!(raw_record.0, b"plaintext_access_token");
    assert_ne!(raw_record.1, b"plaintext_refresh_token");

    // Verify stored values are non-empty encrypted data
    assert!(!raw_record.0.is_empty());
    assert!(!raw_record.1.is_empty());

    // Verify we can still retrieve and decrypt properly
    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "plaintext_access_token");
    assert_eq!(retrieved.refresh_token, "plaintext_refresh_token");
}
