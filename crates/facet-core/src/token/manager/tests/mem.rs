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

use super::super::{MemoryRenewableTokenStore, RenewableTokenEntry, RenewableTokenStore};
use crate::token::TokenError;
use chrono::{TimeDelta, Utc};
use std::collections::HashMap;

fn make_entry(
    id: &str,
    token: &str,
    hash: &str,
    flow_id: &str,
    expires_at: chrono::DateTime<Utc>,
) -> RenewableTokenEntry {
    RenewableTokenEntry::builder()
        .id(id)
        .token(token)
        .hashed_refresh_token(hash)
        .expires_at(expires_at)
        .subject("test_subject")
        .claims(HashMap::new())
        .participant_context_id("participant1")
        .audience("did:web:example.com")
        .flow_id(flow_id)
        .build()
}

#[tokio::test]
async fn test_save_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let entry = make_entry("id_123", "access_token_123", "hash_abc", "test_flow", expiration);

    let result = store.save(entry.clone()).await;
    assert!(result.is_ok(), "save should succeed");

    let retrieved = store
        .find_by_renewal("hash_abc")
        .await
        .expect("Failed to find saved entry");
    assert_eq!(retrieved.id, "id_123");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.hashed_refresh_token, "hash_abc");
    assert_eq!(retrieved.expires_at, expiration);
    assert_eq!(retrieved.participant_context_id, "participant1");
    assert_eq!(retrieved.audience, "did:web:example.com");
}

#[tokio::test]
async fn test_save_multiple_entries() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry("id1", "token1", "hash1", "flow1", expiration))
        .await
        .unwrap();
    store
        .save(make_entry("id2", "token2", "hash2", "flow2", expiration))
        .await
        .unwrap();
    store
        .save(make_entry("id3", "token3", "hash3", "flow3", expiration))
        .await
        .unwrap();

    assert_eq!(store.find_by_renewal("hash1").await.unwrap().token, "token1");
    assert_eq!(store.find_by_renewal("hash2").await.unwrap().token, "token2");
    assert_eq!(store.find_by_renewal("hash3").await.unwrap().token, "token3");
}

#[tokio::test]
async fn test_save_overwrites_same_hash() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);

    store
        .save(make_entry("id1", "token1", "hash_same", "flow1", expiration1))
        .await
        .unwrap();
    store
        .save(make_entry("id2", "token2", "hash_same", "flow2", expiration2))
        .await
        .unwrap();

    let retrieved = store.find_by_renewal("hash_same").await.unwrap();
    assert_eq!(retrieved.token, "token2");
    assert_eq!(retrieved.expires_at, expiration2);
}

#[tokio::test]
async fn test_find_not_found() {
    let store = MemoryRenewableTokenStore::new();

    let result = store.find_by_renewal("nonexistent").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_update_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);

    store
        .save(make_entry(
            "id_initial",
            "token_initial",
            "old_hash",
            "test_flow",
            expiration1,
        ))
        .await
        .unwrap();

    let updated_entry = make_entry("id_updated", "token_updated", "new_hash", "test_flow", expiration2);
    let result = store.update("old_hash", updated_entry).await;
    assert!(result.is_ok());

    assert!(store.find_by_renewal("old_hash").await.is_err());
    assert!(store.find_by_id("id_initial").await.is_err());

    let new_result = store.find_by_renewal("new_hash").await.unwrap();
    assert_eq!(new_result.token, "token_updated");
    assert_eq!(new_result.expires_at, expiration2);

    let new_id_result = store.find_by_id("id_updated").await.unwrap();
    assert_eq!(new_id_result.token, "token_updated");
}

#[tokio::test]
async fn test_update_not_found() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let entry = make_entry("id_new", "token", "new_hash", "test_flow", expiration);
    let result = store.update("nonexistent_hash", entry).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_cloned_entry_independence() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry(
            "id123",
            "original_token",
            "hash123",
            "test_flow",
            expiration,
        ))
        .await
        .unwrap();

    let mut retrieved1 = store.find_by_renewal("hash123").await.unwrap();
    retrieved1.token = "modified_token".to_string();

    let retrieved2 = store.find_by_renewal("hash123").await.unwrap();
    assert_eq!(retrieved2.token, "original_token");
    assert_ne!(retrieved2.token, retrieved1.token);
}

#[tokio::test]
async fn test_concurrent_save_operations() {
    use std::sync::Arc;

    let store = Arc::new(MemoryRenewableTokenStore::new());
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let mut handles = vec![];

    for i in 0..10 {
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            let entry = RenewableTokenEntry::builder()
                .id(format!("id{}", i))
                .token(format!("token{}", i))
                .hashed_refresh_token(format!("hash{}", i))
                .expires_at(expiration)
                .subject("test_subject")
                .claims(HashMap::new())
                .participant_context_id("participant1")
                .audience("did:web:example.com")
                .flow_id(format!("flow{}", i))
                .build();

            store_clone.save(entry).await.unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    for i in 0..10 {
        let retrieved = store.find_by_renewal(&format!("hash{}", i)).await.unwrap();
        assert_eq!(retrieved.token, format!("token{}", i));
    }
}

#[tokio::test]
async fn test_concurrent_update_operations() {
    use std::sync::Arc;

    let store = Arc::new(MemoryRenewableTokenStore::new());
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry("id0", "initial_token", "hash0", "test_flow", expiration))
        .await
        .unwrap();

    let mut handles = vec![];

    for i in 1..6 {
        let store_clone = store.clone();
        let old_hash = format!("hash{}", i - 1);

        let handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(i as u64 * 10)).await;

            let entry = RenewableTokenEntry::builder()
                .id(format!("id{}", i))
                .token(format!("token{}", i))
                .hashed_refresh_token(format!("hash{}", i))
                .expires_at(expiration)
                .subject("test_subject")
                .claims(HashMap::new())
                .participant_context_id("participant1")
                .audience("did:web:example.com")
                .flow_id("test_flow")
                .build();

            store_clone.update(&old_hash, entry).await
        });
        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    assert!(results.iter().any(|r| r.is_ok()));
}

#[tokio::test]
async fn test_find_by_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    let entry = make_entry("unique_id_123", "access_token_123", "hash_abc", "test_flow", expiration);
    store.save(entry.clone()).await.unwrap();

    let retrieved = store.find_by_id("unique_id_123").await.unwrap();
    assert_eq!(retrieved.id, "unique_id_123");
    assert_eq!(retrieved.token, "access_token_123");
    assert_eq!(retrieved.hashed_refresh_token, "hash_abc");
    assert_eq!(retrieved.expires_at, expiration);
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    let store = MemoryRenewableTokenStore::new();

    let result = store.find_by_id("nonexistent_id").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_find_by_id_multiple_entries() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry(
            "id_alpha",
            "token_alpha",
            "hash_alpha",
            "flow_alpha",
            expiration,
        ))
        .await
        .unwrap();
    store
        .save(make_entry(
            "id_beta",
            "token_beta",
            "hash_beta",
            "flow_beta",
            expiration,
        ))
        .await
        .unwrap();
    store
        .save(make_entry(
            "id_gamma",
            "token_gamma",
            "hash_gamma",
            "flow_gamma",
            expiration,
        ))
        .await
        .unwrap();

    assert_eq!(store.find_by_id("id_alpha").await.unwrap().token, "token_alpha");
    assert_eq!(store.find_by_id("id_beta").await.unwrap().token, "token_beta");
    assert_eq!(store.find_by_id("id_gamma").await.unwrap().token, "token_gamma");
}

#[tokio::test]
async fn test_find_by_id_after_update() {
    let store = MemoryRenewableTokenStore::new();
    let expiration1 = Utc::now() + TimeDelta::seconds(1000);
    let expiration2 = Utc::now() + TimeDelta::seconds(2000);

    store
        .save(make_entry(
            "id_original",
            "token_original",
            "hash_original",
            "test_flow",
            expiration1,
        ))
        .await
        .unwrap();

    let found = store.find_by_id("id_original").await.unwrap();
    assert_eq!(found.token, "token_original");

    store
        .update(
            "hash_original",
            make_entry("id_updated", "token_updated", "hash_updated", "test_flow", expiration2),
        )
        .await
        .unwrap();

    assert!(store.find_by_id("id_original").await.is_err());

    let new_result = store.find_by_id("id_updated").await.unwrap();
    assert_eq!(new_result.token, "token_updated");
    assert_eq!(new_result.expires_at, expiration2);
}

#[tokio::test]
async fn test_dual_index_consistency() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry(
            "test_id_456",
            "test_token_456",
            "test_hash_456",
            "test_flow",
            expiration,
        ))
        .await
        .unwrap();

    let by_hash = store.find_by_renewal("test_hash_456").await.unwrap();
    let by_id = store.find_by_id("test_id_456").await.unwrap();

    assert_eq!(by_hash.id, by_id.id);
    assert_eq!(by_hash.token, by_id.token);
    assert_eq!(by_hash.hashed_refresh_token, by_id.hashed_refresh_token);
    assert_eq!(by_hash.expires_at, by_id.expires_at);
}

#[tokio::test]
async fn test_find_by_flow_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry("test_id", "test_token", "test_hash", "flow_123", expiration))
        .await
        .unwrap();

    let retrieved = store.find_by_flow_id("participant1", "flow_123").await.unwrap();
    assert_eq!(retrieved.id, "test_id");
    assert_eq!(retrieved.token, "test_token");
    assert_eq!(retrieved.flow_id, "flow_123");
}

#[tokio::test]
async fn test_find_by_flow_id_not_found() {
    let store = MemoryRenewableTokenStore::new();

    let result = store.find_by_flow_id("participant1", "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_remove_by_flow_id_success() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry(
            "test_id",
            "test_token",
            "test_hash",
            "flow_to_remove",
            expiration,
        ))
        .await
        .unwrap();

    let found = store.find_by_flow_id("participant1", "flow_to_remove").await.unwrap();
    assert_eq!(found.id, "test_id");

    assert!(store.remove_by_flow_id("participant1", "flow_to_remove").await.is_ok());
    assert!(store.find_by_flow_id("participant1", "flow_to_remove").await.is_err());
    assert!(store.find_by_renewal("test_hash").await.is_err());
    assert!(store.find_by_id("test_id").await.is_err());
}

#[tokio::test]
async fn test_delete_by_flow_id_not_found() {
    let store = MemoryRenewableTokenStore::new();

    let result = store.remove_by_flow_id("participant1", "nonexistent_flow").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_remove_by_flow_id_is_scoped_to_participant_context() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry("id_a", "token_a", "hash_a", "shared_flow", expiration))
        .await
        .unwrap();
    let mut other = make_entry("id_b", "token_b", "hash_b", "shared_flow", expiration);
    other.participant_context_id = "participant2".to_string();
    store.save(other).await.unwrap();

    assert!(matches!(
        store.remove_by_flow_id("participant3", "shared_flow").await,
        Err(TokenError::TokenNotFound { .. })
    ));

    store.remove_by_flow_id("participant1", "shared_flow").await.unwrap();

    assert!(store.find_by_renewal("hash_a").await.is_err());
    let remaining = store.find_by_flow_id("participant2", "shared_flow").await.unwrap();
    assert_eq!(remaining.id, "id_b");
    assert!(store.find_by_renewal("hash_b").await.is_ok());
}

#[tokio::test]
async fn test_remove_by_flow_id_removes_every_entry_of_the_flow() {
    let store = MemoryRenewableTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save(make_entry("id_1", "token_1", "hash_1", "flow_twice", expiration))
        .await
        .unwrap();
    store
        .save(make_entry("id_2", "token_2", "hash_2", "flow_twice", expiration))
        .await
        .unwrap();

    assert_eq!(
        store.find_by_flow_id("participant1", "flow_twice").await.unwrap().id,
        "id_2"
    );

    store.remove_by_flow_id("participant1", "flow_twice").await.unwrap();

    assert!(store.find_by_renewal("hash_1").await.is_err());
    assert!(store.find_by_renewal("hash_2").await.is_err());
    assert!(store.find_by_id("id_1").await.is_err());
}
