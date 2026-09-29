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

#![allow(clippy::unwrap_used)]
use chrono::{TimeDelta, Utc};
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::manager::{RenewableTokenEntry, RenewableTokenStore};
use dsdk_facet_postgres::renewable_token_store::PostgresRenewableTokenStore;
use dsdk_facet_testcontainers::postgres::{setup_postgres_container, truncate_to_micros};
use serde_json::Value;
use std::collections::HashMap;

fn make_entry(
    id: &str,
    token: &str,
    hash: &str,
    flow_id: &str,
    subject: &str,
    claims: HashMap<String, Value>,
    expires_at: chrono::DateTime<Utc>,
) -> RenewableTokenEntry {
    RenewableTokenEntry::builder()
        .id(id)
        .token(token)
        .hashed_refresh_token(hash)
        .expires_at(expires_at)
        .subject(subject)
        .claims(claims)
        .participant_context_id("participant1")
        .audience("did:web:example.com")
        .flow_id(flow_id)
        .build()
}

#[tokio::test]
async fn test_postgres_renewable_token_store_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);

    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_postgres_save_and_find_by_renewal() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("custom_claim".to_string(), Value::String("custom_value".to_string()));

    let entry = make_entry(
        "token-id-123",
        "access_token_abc",
        "hashed_refresh_abc",
        "test_flow",
        "user@example.com",
        claims.clone(),
        expires_at,
    );

    store.save(entry.clone()).await.unwrap();
    let retrieved = store.find_by_renewal("hashed_refresh_abc").await.unwrap();

    assert_eq!(retrieved.id, "token-id-123");
    assert_eq!(retrieved.token, "access_token_abc");
    assert_eq!(retrieved.hashed_refresh_token, "hashed_refresh_abc");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at));
    assert_eq!(retrieved.subject, "user@example.com");
    assert_eq!(retrieved.claims, claims);
}

#[tokio::test]
async fn test_postgres_save_and_find_by_id() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("role".to_string(), Value::String("admin".to_string()));

    let entry = make_entry(
        "token-id-456",
        "access_token_xyz",
        "hashed_refresh_xyz",
        "test_flow",
        "admin@example.com",
        claims,
        expires_at,
    );

    store.save(entry.clone()).await.unwrap();
    let retrieved = store.find_by_id("token-id-456").await.unwrap();

    assert_eq!(retrieved.id, "token-id-456");
    assert_eq!(retrieved.token, "access_token_xyz");
    assert_eq!(retrieved.hashed_refresh_token, "hashed_refresh_xyz");
    assert_eq!(retrieved.subject, "admin@example.com");
}

#[tokio::test]
async fn test_postgres_find_by_renewal_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.find_by_renewal("nonexistent_hash").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_find_by_id_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.find_by_id("nonexistent_id").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_save_upserts_on_duplicate() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at_1 = initial_time + TimeDelta::seconds(1000);
    let expires_at_2 = initial_time + TimeDelta::seconds(2000);

    let mut claims1 = HashMap::new();
    claims1.insert("version".to_string(), Value::String("1".to_string()));

    let mut claims2 = HashMap::new();
    claims2.insert("version".to_string(), Value::String("2".to_string()));

    let entry1 = make_entry(
        "same-id",
        "old_token",
        "old_hash",
        "test_flow",
        "user@example.com",
        claims1,
        expires_at_1,
    );
    let entry2 = make_entry(
        "same-id",
        "new_token",
        "new_hash",
        "test_flow",
        "user@example.com",
        claims2.clone(),
        expires_at_2,
    );

    store.save(entry1).await.unwrap();
    store.save(entry2).await.unwrap();

    let retrieved = store.find_by_id("same-id").await.unwrap();
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.hashed_refresh_token, "new_hash");
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at_2));
    assert_eq!(retrieved.claims, claims2);
}

#[tokio::test]
async fn test_postgres_update_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(1000);

    let mut claims = HashMap::new();
    claims.insert("claim1".to_string(), Value::String("value1".to_string()));

    let entry = make_entry(
        "token-id-1",
        "token1",
        "old_hash",
        "test_flow",
        "user@example.com",
        claims.clone(),
        expires_at,
    );
    store.save(entry).await.unwrap();

    let new_expires_at = initial_time + TimeDelta::seconds(2000);
    let new_entry = make_entry(
        "token-id-2",
        "token2",
        "new_hash",
        "test_flow",
        "user@example.com",
        claims,
        new_expires_at,
    );

    store.update("old_hash", new_entry).await.unwrap();

    let old_result = store.find_by_renewal("old_hash").await;
    assert!(old_result.is_err());

    let retrieved = store.find_by_renewal("new_hash").await.unwrap();
    assert_eq!(retrieved.id, "token-id-2");
    assert_eq!(retrieved.token, "token2");
    assert_eq!(retrieved.expires_at, truncate_to_micros(new_expires_at));
}

#[tokio::test]
async fn test_postgres_update_nonexistent_token() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(1000);

    let entry = make_entry(
        "new-id",
        "new_token",
        "new_hash",
        "test_flow",
        "user@example.com",
        HashMap::new(),
        expires_at,
    );

    let result = store.update("nonexistent_hash", entry).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_postgres_multiple_tokens() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry1 = make_entry(
        "id-1",
        "token1",
        "hash1",
        "flow1",
        "user1@example.com",
        HashMap::new(),
        expires_at,
    );
    let entry2 = make_entry(
        "id-2",
        "token2",
        "hash2",
        "flow2",
        "user2@example.com",
        HashMap::new(),
        expires_at,
    );

    store.save(entry1).await.unwrap();
    store.save(entry2).await.unwrap();

    let retrieved1 = store.find_by_id("id-1").await.unwrap();
    let retrieved2 = store.find_by_id("id-2").await.unwrap();

    assert_eq!(retrieved1.token, "token1");
    assert_eq!(retrieved2.token, "token2");
}

#[tokio::test]
async fn test_postgres_token_with_special_characters() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("special!@#$%".to_string(), Value::String("value!@#$%".to_string()));

    let entry = make_entry(
        "id-with-dashes-123",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "hash!@#$%^&*()",
        "test_flow",
        "user+tag@example.com",
        claims,
        expires_at,
    );

    store.save(entry.clone()).await.unwrap();
    let retrieved = store.find_by_renewal("hash!@#$%^&*()").await.unwrap();

    assert_eq!(retrieved.id, "id-with-dashes-123");
    assert!(retrieved.token.contains("eyJ"));
    assert_eq!(retrieved.subject, "user+tag@example.com");
}

#[tokio::test]
async fn test_postgres_token_with_long_values() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    for i in 0..50 {
        claims.insert(format!("claim_{}", i), Value::String(format!("value_{}", i)));
    }

    let entry = RenewableTokenEntry::builder()
        .id("i".repeat(250))
        .token("t".repeat(5000))
        .hashed_refresh_token("h".repeat(250))
        .expires_at(expires_at)
        .subject("s".repeat(250))
        .claims(claims.clone())
        .participant_context_id("participant1")
        .audience("did:web:example.com")
        .flow_id("test_flow")
        .build();

    store.save(entry).await.unwrap();

    let retrieved = store.find_by_renewal(&"h".repeat(250)).await.unwrap();
    assert_eq!(retrieved.token.len(), 5000);
    assert_eq!(retrieved.subject.len(), 250);
    assert_eq!(retrieved.claims.len(), 50);
}

#[tokio::test]
async fn test_postgres_save_find_update_flow() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at_1 = initial_time + TimeDelta::seconds(1000);

    let mut claims = HashMap::new();
    claims.insert("session".to_string(), Value::String("abc123".to_string()));

    let entry = make_entry(
        "id-1",
        "token1",
        "hash1",
        "test_flow",
        "user@example.com",
        claims.clone(),
        expires_at_1,
    );
    store.save(entry).await.unwrap();

    let found = store.find_by_renewal("hash1").await.unwrap();
    assert_eq!(found.token, "token1");

    let expires_at_2 = initial_time + TimeDelta::seconds(2000);
    let new_entry = make_entry(
        "id-2",
        "token2",
        "hash2",
        "test_flow",
        "user@example.com",
        claims,
        expires_at_2,
    );

    store.update("hash1", new_entry).await.unwrap();

    let updated = store.find_by_renewal("hash2").await.unwrap();
    assert_eq!(updated.token, "token2");
    assert_eq!(updated.id, "id-2");

    let old_result = store.find_by_renewal("hash1").await;
    assert!(old_result.is_err());
}

#[tokio::test]
async fn test_postgres_claims_serialization() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool.clone());
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let mut claims = HashMap::new();
    claims.insert("claim1".to_string(), Value::String("value1".to_string()));
    claims.insert("claim2".to_string(), Value::String("value2".to_string()));
    claims.insert("claim3".to_string(), Value::String("value3".to_string()));

    let entry = make_entry(
        "id-1",
        "token1",
        "hash1",
        "test_flow",
        "user@example.com",
        claims.clone(),
        expires_at,
    );
    store.save(entry).await.unwrap();

    // Query database directly to verify JSONB storage
    let row: (Value,) = sqlx::query_as("SELECT claims FROM renewable_tokens WHERE id = $1")
        .bind("id-1")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(row.0.is_object());

    let retrieved = store.find_by_id("id-1").await.unwrap();
    assert_eq!(retrieved.claims.len(), 3);
    assert_eq!(
        retrieved.claims.get("claim1").unwrap(),
        &Value::String("value1".to_string())
    );
    assert_eq!(
        retrieved.claims.get("claim2").unwrap(),
        &Value::String("value2".to_string())
    );
    assert_eq!(
        retrieved.claims.get("claim3").unwrap(),
        &Value::String("value3".to_string())
    );
}

#[tokio::test]
async fn test_postgres_empty_claims() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = make_entry(
        "id-1",
        "token1",
        "hash1",
        "test_flow",
        "user@example.com",
        HashMap::new(),
        expires_at,
    );
    store.save(entry).await.unwrap();

    let retrieved = store.find_by_id("id-1").await.unwrap();
    assert_eq!(retrieved.claims.len(), 0);
}

#[tokio::test]
async fn test_postgres_timestamp_precision() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = make_entry(
        "id-1",
        "token1",
        "hash1",
        "test_flow",
        "user@example.com",
        HashMap::new(),
        expires_at,
    );
    store.save(entry).await.unwrap();

    let retrieved = store.find_by_id("id-1").await.unwrap();
    assert_eq!(retrieved.expires_at, truncate_to_micros(expires_at));
}

#[tokio::test]
async fn test_postgres_find_by_flow_id_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = make_entry(
        "test_id",
        "test_token",
        "test_hash",
        "flow_123",
        "test_subject",
        HashMap::new(),
        expires_at,
    );
    store.save(entry.clone()).await.unwrap();

    let retrieved = store.find_by_flow_id("participant1", "flow_123").await.unwrap();
    assert_eq!(retrieved.id, "test_id");
    assert_eq!(retrieved.token, "test_token");
    assert_eq!(retrieved.flow_id, "flow_123");
}

#[tokio::test]
async fn test_postgres_find_by_flow_id_not_found() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.find_by_flow_id("participant1", "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_postgres_remove_by_flow_id_success() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let initial_time = Utc::now();
    let expires_at = initial_time + TimeDelta::seconds(3600);

    let entry = make_entry(
        "test_id",
        "test_token",
        "test_hash",
        "flow_to_remove",
        "test_subject",
        HashMap::new(),
        expires_at,
    );
    store.save(entry.clone()).await.unwrap();

    let found = store.find_by_flow_id("participant1", "flow_to_remove").await.unwrap();
    assert_eq!(found.id, "test_id");

    let result = store.remove_by_flow_id("participant1", "flow_to_remove").await;
    assert!(result.is_ok());

    let not_found_by_flow = store.find_by_flow_id("participant1", "flow_to_remove").await;
    assert!(not_found_by_flow.is_err());
}

#[tokio::test]
async fn test_postgres_remove_by_flow_id_is_scoped_to_participant_context() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresRenewableTokenStore::new(pool);
    store.initialize().await.unwrap();

    let expires_at = Utc::now() + TimeDelta::seconds(3600);
    let entry_a = make_entry(
        "id_a",
        "token_a",
        "hash_a",
        "shared_flow",
        "test_subject",
        HashMap::new(),
        expires_at,
    );
    let mut entry_b = make_entry(
        "id_b",
        "token_b",
        "hash_b",
        "shared_flow",
        "test_subject",
        HashMap::new(),
        expires_at,
    );
    entry_b.participant_context_id = "participant2".to_string();
    store.save(entry_a).await.unwrap();
    store.save(entry_b).await.unwrap();

    assert!(matches!(
        store.remove_by_flow_id("participant3", "shared_flow").await,
        Err(TokenError::TokenNotFound { .. })
    ));

    store.remove_by_flow_id("participant1", "shared_flow").await.unwrap();

    assert!(store.find_by_renewal("hash_a").await.is_err());
    let remaining = store.find_by_flow_id("participant2", "shared_flow").await.unwrap();
    assert_eq!(remaining.id, "id_b");
}
