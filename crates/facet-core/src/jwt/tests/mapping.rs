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

use crate::jwt::{
    MemorySigningKeyMappingStore, SigningKeyMapping, SigningKeyMappingError, SigningKeyMappingRepository,
};

fn mapping(pc: &str, key_name: &str, kid: &str) -> SigningKeyMapping {
    SigningKeyMapping::builder()
        .participant_context_id(pc)
        .key_name(key_name)
        .kid(kid)
        .build()
}

#[tokio::test]
async fn test_create_and_find() {
    let store = MemorySigningKeyMappingStore::new();
    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.key_name, "key-1");
    assert_eq!(found.kid, "kid-1");
}

#[tokio::test]
async fn test_create_conflict_returns_already_exists() {
    let store = MemorySigningKeyMappingStore::new();
    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();

    let err = store.create(mapping("pc-1", "key-2", "kid-2")).await.unwrap_err();
    assert!(matches!(err, SigningKeyMappingError::AlreadyExists { .. }));

    // the original mapping is untouched
    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.key_name, "key-1");
}

#[tokio::test]
async fn test_find_missing_returns_not_found() {
    let store = MemorySigningKeyMappingStore::new();
    let err = store.find("missing").await.unwrap_err();
    assert!(matches!(err, SigningKeyMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_update_replaces_existing() {
    let store = MemorySigningKeyMappingStore::new();
    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();
    store.update(mapping("pc-1", "key-2", "kid-2")).await.unwrap();

    let found = store.find("pc-1").await.unwrap();
    assert_eq!(found.key_name, "key-2");
    assert_eq!(found.kid, "kid-2");
}

#[tokio::test]
async fn test_update_missing_returns_not_found() {
    let store = MemorySigningKeyMappingStore::new();
    let err = store.update(mapping("pc-1", "key-1", "kid-1")).await.unwrap_err();
    assert!(matches!(err, SigningKeyMappingError::NotFound { .. }));
}

#[tokio::test]
async fn test_delete() {
    let store = MemorySigningKeyMappingStore::new();
    store.create(mapping("pc-1", "key-1", "kid-1")).await.unwrap();

    store.delete("pc-1").await.unwrap();
    assert!(matches!(
        store.find("pc-1").await.unwrap_err(),
        SigningKeyMappingError::NotFound { .. }
    ));
}

#[tokio::test]
async fn test_delete_missing_returns_not_found() {
    let store = MemorySigningKeyMappingStore::new();
    let err = store.delete("missing").await.unwrap_err();
    assert!(matches!(err, SigningKeyMappingError::NotFound { .. }));
}
