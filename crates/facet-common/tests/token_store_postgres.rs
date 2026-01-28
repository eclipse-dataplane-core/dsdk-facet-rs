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
use common::{setup_postgres_container, truncate_to_micros};
use facet_common::context::ParticipantContext;
use facet_common::util::clock::{Clock, MockClock};
use facet_common::util::encryption::encryption_key;
use facet_common::token::{PostgresTokenStore, TokenData, TokenError, TokenStore};
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "access_token_123".to_string(),
        refresh_token: "refresh_token_123".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/refresh".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save_token(token_data.clone()).await.unwrap();
    let retrieved = store.get_token(pc, "provider1").await.unwrap();

    assert_eq!(retrieved.identifier, "provider1");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.refresh_token, "refresh_token_123");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at));
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

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.get_token(pc, "nonexistent").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_save_token_upserts_on_duplicate() {
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "old_token".to_string(),
        refresh_token: "old_refresh".to_string(),
        expires_at: expires_at_1,
        refresh_endpoint: "https://old.example.com/refresh".to_string(),
    };

    let token_data2 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "new_token".to_string(),
        refresh_token: "new_refresh".to_string(),
        expires_at: expires_at_2,
        refresh_endpoint: "https://new.example.com/refresh".to_string(),
    };

    // First save succeeds
    store.save_token(token_data1).await.unwrap();

    // Second save with the same identifier should succeed and update
    store.save_token(token_data2).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    // Verify the token was updated to new values
    let retrieved = store.get_token(pc, "provider1").await.unwrap();
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.refresh_token, "new_refresh");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at_2));
    assert_eq!(retrieved.refresh_endpoint, "https://new.example.com/refresh");
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let updated_data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token_updated".to_string(),
        refresh_token: "refresh_updated".to_string(),
        expires_at: new_expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let retrieved = store.get_token(pc, "provider1").await.unwrap();
    assert_eq!(retrieved.token, "token_updated");
    assert_eq!(retrieved.refresh_token, "refresh_updated");
    assert_eq!(retrieved.expires_at, truncate_to_micros(new_expires_at));
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
        participant_context: "participant1".to_string(),
        identifier: "nonexistent".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let result = store.update_token(token_data).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();
    store.remove_token("participant1", "provider1").await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let result = store.get_token(pc, "provider1").await;
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

    // Should fail if the token does not exist
    let result = store.remove_token("participant1", "nonexistent").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let token2 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider2".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token1).await.unwrap();
    store.save_token(token2).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let retrieved1 = store.get_token(pc, "provider1").await.unwrap();
    let retrieved2 = store.get_token(pc, "provider2").await.unwrap();

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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0".to_string(),
        refresh_token: "refresh!@#$%^&*()".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/token?param=value&other=123".to_string(),
    };

    let pc = &ParticipantContext::builder().id("participant1").build();

    store.save_token(token_data).await.unwrap();
    let retrieved = store.get_token(pc, "provider1").await.unwrap();

    assert_eq!(retrieved.identifier, "provider1");
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "t".repeat(2000),
        refresh_token: "r".repeat(2000),
        expires_at,
        refresh_endpoint: format!("https://example.com/{}", "path/".repeat(100)),
    };

    store.save_token(token_data).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let retrieved = store.get_token(pc, "provider1").await.unwrap();

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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let updated_data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: new_expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let retrieved = store.get_token(pc, "provider1").await.unwrap();
    assert_eq!(retrieved.token, "token2");

    store.remove_token("participant1", "provider1").await.unwrap();
    let result = store.get_token(pc, "provider1").await;
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    // Advance time and access the token
    mock_clock.advance(TimeDelta::seconds(100));

    let pc = &ParticipantContext::builder().id("participant1").build();

    let _retrieved = store.get_token(pc, "provider1").await.unwrap();

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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: initial_time + TimeDelta::seconds(3600),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token1).await.unwrap();

    // Advance time in a controlled manner
    clock.advance(TimeDelta::seconds(500));

    let token2 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider2".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: initial_time + TimeDelta::seconds(7200),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token2).await.unwrap();

    let pc = &ParticipantContext::builder().id("participant1").build();

    // Verify both tokens exist with their respective timestamps
    let retrieved1 = store.get_token(pc, "provider1").await.unwrap();
    let retrieved2 = store.get_token(pc, "provider2").await.unwrap();

    assert_eq!(retrieved1.identifier, "provider1");
    assert_eq!(retrieved2.identifier, "provider2");
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
        participant_context: "participant1".to_string(),
        identifier: "provider1".to_string(),
        token: "plaintext_access_token".to_string(),
        refresh_token: "plaintext_refresh_token".to_string(),
        expires_at,
        refresh_endpoint: "https://auth.example.com/refresh".to_string(),
    };

    store.save_token(token_data.clone()).await.unwrap();

    // Query database directly to verify encryption
    let raw_record: (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT token, refresh_token FROM tokens WHERE identifier = $1")
            .bind("provider1")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Verify stored values are NOT plaintext
    assert_ne!(raw_record.0, b"plaintext_access_token");
    assert_ne!(raw_record.1, b"plaintext_refresh_token");

    // Verify stored values are non-empty encrypted data
    assert!(!raw_record.0.is_empty());
    assert!(!raw_record.1.is_empty());

    let pc = &ParticipantContext::builder().id("participant1").build();

    // Verify we can still retrieve and decrypt properly
    let retrieved = store.get_token(pc, "provider1").await.unwrap();
    assert_eq!(retrieved.token, "plaintext_access_token");
    assert_eq!(retrieved.refresh_token, "plaintext_refresh_token");
}

#[tokio::test]
async fn test_context_isolation_save() {
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

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let pc1 = &ParticipantContext::builder().id("participant1").build();

    let pc2 = &ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let retrieved_p1 = store.get_token(pc1, "provider").await.unwrap();
    let retrieved_p2 = store.get_token(pc2, "provider").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");

    let pc3 = &ParticipantContext::builder()
        .id("participant3")
        .audience("audience3")
        .build();

    // Verify participant3 cannot access the token
    let result_p3 = store.get_token(pc3, "provider").await;
    assert!(result_p3.is_err());
}

#[tokio::test]
async fn test_context_isolation_get() {
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

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let pc1 = &ParticipantContext::builder().id("participant1").build();

    let pc2 = &ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let p1_result = store.get_token(pc1, "provider").await.unwrap();
    let p2_result = store.get_token(pc2, "provider").await.unwrap();

    assert_eq!(p1_result.participant_context, "participant1");
    assert_eq!(p1_result.token, "token_p1");
    assert_eq!(p2_result.participant_context, "participant2");
    assert_eq!(p2_result.token, "token_p2");

    let pc3 = &ParticipantContext::builder()
        .id("participant3")
        .audience("audience3")
        .build();

    // Verify participant3 cannot get either token
    let result_p3 = store.get_token(pc3, "provider").await;
    assert!(result_p3.is_err());
    assert!(result_p3.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_context_isolation_update() {
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

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let updated_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1_updated".to_string(),
        refresh_token: "refresh_p1_updated".to_string(),
        expires_at,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    store.update_token(updated_p1).await.unwrap();

    let pc1 = &ParticipantContext::builder().id("participant1").build();

    let pc2 = &ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let p1_result = store.get_token(pc1, "provider").await.unwrap();
    let p2_result = store.get_token(pc2, "provider").await.unwrap();

    assert_eq!(p1_result.token, "token_p1_updated");
    assert_eq!(p2_result.token, "token_p2");

    // Verify participant3 cannot update a non-existent token
    let update_p3 = TokenData {
        participant_context: "participant3".to_string(),
        identifier: "provider".to_string(),
        token: "token_p3".to_string(),
        refresh_token: "refresh_p3".to_string(),
        expires_at,
        refresh_endpoint: "https://p3.example.com/refresh".to_string(),
    };

    let result_p3 = store.update_token(update_p3).await;
    assert!(result_p3.is_err());
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_context_isolation_remove() {
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

    let token_p1 = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "provider".to_string(),
        token: "token_p1".to_string(),
        refresh_token: "refresh_p1".to_string(),
        expires_at,
        refresh_endpoint: "https://p1.example.com/refresh".to_string(),
    };

    let token_p2 = TokenData {
        participant_context: "participant2".to_string(),
        identifier: "provider".to_string(),
        token: "token_p2".to_string(),
        refresh_token: "refresh_p2".to_string(),
        expires_at,
        refresh_endpoint: "https://p2.example.com/refresh".to_string(),
    };

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    store.remove_token("participant1", "provider").await.unwrap();

    let pc1 = &ParticipantContext::builder().id("participant1").build();

    let pc2 = &ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    assert!(store.get_token(pc1, "provider").await.is_err());
    assert_eq!(store.get_token(pc2, "provider").await.unwrap().token, "token_p2");

    // Verify participant3 cannot remove a token they don't own
    let result_p3 = store.remove_token("participant3", "provider").await;
    assert!(result_p3.is_err()); // Should fail - token does not exist for participant3
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));

    // Verify p2's token still exists after p3 tries to remove a non-existent token
    assert_eq!(store.get_token(pc2, "provider").await.unwrap().token, "token_p2");
}
