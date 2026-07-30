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
use siglet::config::{ClaimMapping, EndpointMapping, TokenSource, TransferType};
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

#[tokio::test]
async fn test_claim_mappings_round_trip_through_jsonb() {
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool);
    store.initialize().await.unwrap();

    let mut tt = transfer_type("http-pull", "https://pull.example.com", TokenSource::Provider);
    tt.claim_mappings = vec![
        ClaimMapping::builder().from("flow.datasetId").to("assetId").build(),
        ClaimMapping::builder()
            .from("flow.metadata.tier")
            .to("tier")
            .optional(true)
            .build(),
    ];
    tt.endpoint_mappings = vec![
        EndpointMapping::builder()
            .key("app".to_string())
            .value("app1".to_string())
            .endpoint("https://app1.example.com".to_string())
            .claim_mappings(vec![ClaimMapping::builder().from("'app1'").to("app").build()])
            .build(),
    ];

    let mut mappings = HashMap::new();
    mappings.insert("http-pull".to_string(), tt);
    store
        .create(
            TransferTypeMapping::builder()
                .participant_context_id("pc-claims")
                .mappings(mappings)
                .build(),
        )
        .await
        .unwrap();

    let found = store.find("pc-claims").await.unwrap();
    let stored = &found.mappings["http-pull"];

    assert_eq!(stored.claim_mappings.len(), 2);
    assert_eq!(stored.claim_mappings[0].from, "flow.datasetId");
    assert_eq!(stored.claim_mappings[0].to, "assetId");
    assert!(!stored.claim_mappings[0].optional);
    assert!(stored.claim_mappings[1].optional);

    assert_eq!(stored.endpoint_mappings[0].claim_mappings.len(), 1);
    assert_eq!(stored.endpoint_mappings[0].claim_mappings[0].to, "app");
}

#[tokio::test]
async fn test_row_without_claim_mappings_reads_back_as_empty() {
    // Back-compat guard: rows written before claim mapping existed have no `claimMappings` key in
    // their JSONB payload and must still deserialize, so no migration is required.
    let (pool, _container) = setup_postgres_container().await;
    let store = PostgresTransferTypeMappingStore::new(pool.clone());
    store.initialize().await.unwrap();

    let legacy = serde_json::json!({
        "http-pull": {
            "transferType": "http-pull",
            "endpointType": "HTTP",
            "endpoint": "https://pull.example.com",
            "tokenSource": "provider",
            "endpointMappings": [{
                "key": "app",
                "value": "app1",
                "endpoint": "https://app1.example.com"
            }]
        }
    });

    sqlx::query("INSERT INTO transfer_type_mappings (participant_context_id, mappings) VALUES ($1, $2)")
        .bind("pc-legacy")
        .bind(sqlx::types::Json(&legacy))
        .execute(&pool)
        .await
        .unwrap();

    let found = store.find("pc-legacy").await.unwrap();
    let stored = &found.mappings["http-pull"];
    assert!(stored.claim_mappings.is_empty());
    assert!(stored.endpoint_mappings[0].claim_mappings.is_empty());
}
