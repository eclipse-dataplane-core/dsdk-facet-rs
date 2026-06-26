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
use dsdk_facet_core::jwt::{SigningKeyMapping, SigningKeyMappingError, SigningKeyMappingRepository};
use dsdk_facet_postgres::signing_key_mapping::PostgresSigningKeyMappingStore;
use dsdk_facet_testcontainers::postgres::setup_postgres_container;

fn mapping(pc: &str, key_name: &str, kid: &str) -> SigningKeyMapping {
    SigningKeyMapping::builder()
        .participant_context_id(pc)
        .key_name(key_name)
        .kid(kid)
        .build()
}

#[tokio::test]
async fn test_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);

    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_create_and_find() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    store
        .create(mapping("pc-1", "client-signing-pc-1", "client-signing-pc-1-3"))
        .await
        .unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.participant_context_id, "pc-1");
    assert_eq!(found.key_name, "client-signing-pc-1");
    assert_eq!(found.kid, "client-signing-pc-1-3");
}

#[tokio::test]
async fn test_create_conflict_returns_already_exists() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();
    let result = store.create(mapping("pc-1", "key-2", "kid-2")).await;
    assert!(matches!(
        result.unwrap_err(),
        SigningKeyMappingError::AlreadyExists { .. }
    ));

    // the original mapping is untouched
    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.key_name, "key-1");
}

#[tokio::test]
async fn test_find_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.find("missing").await;
    assert!(matches!(result.unwrap_err(), SigningKeyMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_update_replaces_existing() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    store.create(mapping("pc-1", "key-old", "kid-old")).await.unwrap();
    store.update(mapping("pc-1", "key-new", "kid-new")).await.unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.key_name, "key-new");
    assert_eq!(found.kid, "kid-new");
}

#[tokio::test]
async fn test_update_nonexistent_returns_not_found() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.update(mapping("missing", "key-1", "kid-1")).await;
    assert!(matches!(result.unwrap_err(), SigningKeyMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_delete() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();
    store.delete("pc-1").await.unwrap();

    assert!(matches!(
        store.find("pc-1").await.unwrap_err(),
        SigningKeyMappingError::NotFound { .. }
    ));
}

#[tokio::test]
async fn test_delete_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresSigningKeyMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.delete("missing").await;
    assert!(matches!(result.unwrap_err(), SigningKeyMappingError::NotFound { .. }));
}
