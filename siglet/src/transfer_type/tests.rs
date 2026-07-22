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

use super::{
    MemoryTransferTypeMappingStore, TransferTypeMapping, TransferTypeMappingError, TransferTypeMappingRepository,
};
use crate::config::{TokenSource, TransferType};
use std::collections::HashMap;

fn transfer_type(name: &str, endpoint: &str) -> TransferType {
    TransferType::builder()
        .transfer_type(name.to_string())
        .endpoint_type("HTTP".to_string())
        .endpoint(endpoint.to_string())
        .token_source(TokenSource::Provider)
        .build()
}

fn mapping(pc_id: &str, entries: &[(&str, &str)]) -> TransferTypeMapping {
    let mappings: HashMap<String, TransferType> = entries
        .iter()
        .map(|(name, endpoint)| (name.to_string(), transfer_type(name, endpoint)))
        .collect();
    TransferTypeMapping::builder()
        .participant_context_id(pc_id)
        .mappings(mappings)
        .build()
}

#[tokio::test]
async fn create_then_find() {
    let store = MemoryTransferTypeMappingStore::new();
    store
        .create(mapping("pc-1", &[("http-pull", "http://a"), ("http-push", "http://b")]))
        .await
        .unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.participant_context_id, "pc-1");
    assert_eq!(found.mappings.len(), 2);
    assert_eq!(found.mappings["http-pull"].endpoint.as_deref(), Some("http://a"));
}

#[tokio::test]
async fn create_duplicate_returns_already_exists() {
    let store = MemoryTransferTypeMappingStore::new();
    store
        .create(mapping("pc-1", &[("http-pull", "http://a")]))
        .await
        .unwrap();

    let err = store
        .create(mapping("pc-1", &[("http-pull", "http://c")]))
        .await
        .unwrap_err();
    assert!(matches!(err, TransferTypeMappingError::AlreadyExists { .. }));
}

#[tokio::test]
async fn update_replaces_whole_map() {
    let store = MemoryTransferTypeMappingStore::new();
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
async fn update_missing_returns_not_found() {
    let store = MemoryTransferTypeMappingStore::new();
    let err = store
        .update(mapping("missing", &[("http-pull", "http://a")]))
        .await
        .unwrap_err();
    assert!(matches!(err, TransferTypeMappingError::NotFound { .. }));
}

#[tokio::test]
async fn find_missing_returns_not_found() {
    let store = MemoryTransferTypeMappingStore::new();
    let err = store.find("missing").await.unwrap_err();
    assert!(matches!(err, TransferTypeMappingError::NotFound { .. }));
}

#[tokio::test]
async fn delete_then_find_returns_not_found() {
    let store = MemoryTransferTypeMappingStore::new();
    store
        .create(mapping("pc-1", &[("http-pull", "http://a")]))
        .await
        .unwrap();

    store.delete("pc-1").await.unwrap();
    let err = store.find("pc-1").await.unwrap_err();
    assert!(matches!(err, TransferTypeMappingError::NotFound { .. }));
}

#[tokio::test]
async fn delete_missing_returns_not_found() {
    let store = MemoryTransferTypeMappingStore::new();
    let err = store.delete("missing").await.unwrap_err();
    assert!(matches!(err, TransferTypeMappingError::NotFound { .. }));
}
