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

//! Container-gated integration tests for [`PostgresTransferTypeMappingStore`].
//!
//! Requires a Docker-compatible runtime (via `dsdk-facet-testcontainers`); mirrors
//! `crates/facet-postgres/tests/signing_key_mapping_postgres.rs`.

#![allow(clippy::unwrap_used)]

use dsdk_facet_testcontainers::postgres::setup_postgres_container;
use siglet::config::{TokenSource, TransferType};
use siglet::transfer_type::postgres::PostgresTransferTypeMappingStore;
use siglet::transfer_type::{TransferTypeMapping, TransferTypeMappingError, TransferTypeMappingRepository};
use std::collections::HashMap;

fn transfer_type(name: &str, endpoint: &str, token_source: TokenSource) -> TransferType {
    TransferType::builder()
        .transfer_type(name.to_string())
        .endpoint_type("HTTP".to_string())
        .endpoint(endpoint.to_string())
        .token_source(token_source)
        .build()
}

fn mapping(pc: &str, entries: &[(&str, &str)]) -> TransferTypeMapping {
    let mappings: HashMap<String, TransferType> = entries
        .iter()
        .map(|(name, endpoint)| (name.to_string(), transfer_type(name, endpoint, TokenSource::Provider)))
        .collect();
    TransferTypeMapping::builder()
        .participant_context_id(pc)
        .mappings(mappings)
        .build()
}

#[tokio::test]
async fn test_initialization_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);

    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn test_create_and_find_round_trips_jsonb_map() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    store
        .create(mapping("pc-1", &[("http-pull", "http://a"), ("http-push", "http://b")]))
        .await
        .unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.participant_context_id, "pc-1");
    assert_eq!(found.mappings.len(), 2);
    assert_eq!(found.mappings["http-pull"].endpoint.as_deref(), Some("http://a"));
    assert_eq!(found.mappings["http-push"].endpoint.as_deref(), Some("http://b"));
}

#[tokio::test]
async fn test_create_conflict_returns_already_exists() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    store
        .create(mapping("pc-1", &[("http-pull", "http://a")]))
        .await
        .unwrap();
    let result = store.create(mapping("pc-1", &[("http-pull", "http://c")])).await;
    assert!(matches!(
        result.unwrap_err(),
        TransferTypeMappingError::AlreadyExists { .. }
    ));

    // the original mapping is untouched
    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.mappings["http-pull"].endpoint.as_deref(), Some("http://a"));
}

#[tokio::test]
async fn test_find_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.find("missing").await;
    assert!(matches!(result.unwrap_err(), TransferTypeMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_update_replaces_whole_map() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    store
        .create(mapping("pc-1", &[("http-pull", "http://a"), ("http-push", "http://b")]))
        .await
        .unwrap();
    store
        .update(mapping("pc-1", &[("http-pull", "http://new")]))
        .await
        .unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.mappings.len(), 1);
    assert_eq!(found.mappings["http-pull"].endpoint.as_deref(), Some("http://new"));
}

#[tokio::test]
async fn test_update_nonexistent_returns_not_found() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.update(mapping("missing", &[("http-pull", "http://a")])).await;
    assert!(matches!(result.unwrap_err(), TransferTypeMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_delete() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    store
        .create(mapping("pc-1", &[("http-pull", "http://a")]))
        .await
        .unwrap();
    store.delete("pc-1").await.unwrap();

    assert!(matches!(
        store.find("pc-1").await.unwrap_err(),
        TransferTypeMappingError::NotFound { .. }
    ));
}

#[tokio::test]
async fn test_delete_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.delete("missing").await;
    assert!(matches!(result.unwrap_err(), TransferTypeMappingError::NotFound { .. }));
}
