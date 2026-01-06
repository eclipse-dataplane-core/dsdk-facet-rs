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

use facet_client::token::{PostgresTokenStore, TokenData, TokenStore};

use common::setup_postgres_container;

#[tokio::test]
async fn test_postgres_token_store_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();

    // Initialize multiple times - should not fail
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_postgres_save_and_get_token() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "access_token_123".to_string(),
        refresh_token: "refresh_token_123".to_string(),
        expires_at: 1234567890,
        refresh_endpoint: "https://auth.example.com/refresh".to_string(),
    };

    store.save_token(token_data.clone()).await.unwrap();
    let retrieved = store.get_token("user1").await.unwrap();

    assert_eq!(retrieved.identifier, "user1");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.refresh_token, "refresh_token_123");
    assert_eq!(retrieved.expires_at, 1234567890);
    assert_eq!(retrieved.refresh_endpoint, "https://auth.example.com/refresh");
}

#[tokio::test]
async fn test_postgres_get_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let result = store.get_token("nonexistent").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_save_token_overwrites_existing() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data1 = TokenData {
        identifier: "user1".to_string(),
        token: "old_token".to_string(),
        refresh_token: "old_refresh".to_string(),
        expires_at: 1000,
        refresh_endpoint: "https://old.example.com/refresh".to_string(),
    };

    let token_data2 = TokenData {
        identifier: "user1".to_string(),
        token: "new_token".to_string(),
        refresh_token: "new_refresh".to_string(),
        expires_at: 2000,
        refresh_endpoint: "https://new.example.com/refresh".to_string(),
    };

    store.save_token(token_data1).await.unwrap();
    store.save_token(token_data2).await.unwrap();

    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.refresh_token, "new_refresh");
    assert_eq!(retrieved.expires_at, 2000);
}

#[tokio::test]
async fn test_postgres_update_token_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: 1000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let updated_data = TokenData {
        identifier: "user1".to_string(),
        token: "token_updated".to_string(),
        refresh_token: "refresh_updated".to_string(),
        expires_at: 2000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "token_updated");
    assert_eq!(retrieved.refresh_token, "refresh_updated");
    assert_eq!(retrieved.expires_at, 2000);
}

#[tokio::test]
async fn test_postgres_update_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "nonexistent".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: 1000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let result = store.update_token(token_data).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("non-existent"));
}

#[tokio::test]
async fn test_postgres_remove_token_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: 1000,
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
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    // Should succeed even if then token doesn't exist
    let result = store.remove_token("nonexistent").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_multiple_tokens() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token1 = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: 1000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    let token2 = TokenData {
        identifier: "user2".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: 2000,
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
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user@domain.com".to_string(),
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0".to_string(),
        refresh_token: "refresh!@#$%^&*()".to_string(),
        expires_at: 1000,
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
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "t".repeat(2000),
        refresh_token: "r".repeat(2000),
        expires_at: 1000,
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
    let store = PostgresTokenStore::builder().pool(pool).build();
    store.initialize().await.unwrap();

    let token_data = TokenData {
        identifier: "user1".to_string(),
        token: "token1".to_string(),
        refresh_token: "refresh1".to_string(),
        expires_at: 1000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.save_token(token_data).await.unwrap();

    let updated_data = TokenData {
        identifier: "user1".to_string(),
        token: "token2".to_string(),
        refresh_token: "refresh2".to_string(),
        expires_at: 2000,
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };

    store.update_token(updated_data).await.unwrap();

    let retrieved = store.get_token("user1").await.unwrap();
    assert_eq!(retrieved.token, "token2");

    store.remove_token("user1").await.unwrap();
    let result = store.get_token("user1").await;
    assert!(result.is_err());
}
