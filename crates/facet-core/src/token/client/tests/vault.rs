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

use crate::context::ParticipantContext;
use crate::token::TokenError;
use crate::token::client::{RefreshedTokenData, TokenData, TokenStore, VaultTokenStore};
use crate::vault::MemoryVaultClient;
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

fn make_store() -> VaultTokenStore {
    VaultTokenStore::new(Arc::new(MemoryVaultClient::new()))
}

fn sample_token(participant_context: &str, identifier: &str, token: &str) -> TokenData {
    TokenData::builder()
        .participant_context(participant_context)
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier(identifier)
        .token(token)
        .refresh_token(format!("refresh-{}", token))
        .expires_at(Utc::now() + TimeDelta::seconds(3600))
        .refresh_endpoint("https://provider.example.com/token/refresh")
        .endpoint("https://provider.example.com/data")
        .build()
}

#[tokio::test]
async fn test_get_nonexistent_returns_not_found() {
    let store = make_store();
    let pc = ParticipantContext::builder().id("pc1").build();
    let result = store.get_token(&pc, "missing").await;
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_save_and_get_round_trip() {
    let store = make_store();
    let expiration = Utc::now() + TimeDelta::seconds(3600);

    store
        .save_token(
            TokenData::builder()
                .participant_context("pc1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("id1")
                .token("access")
                .refresh_token("refresh")
                .expires_at(expiration)
                .refresh_endpoint("https://example.com/refresh")
                .endpoint("https://example.com/data")
                .build(),
        )
        .await
        .unwrap();

    let pc = ParticipantContext::builder().id("pc1").build();
    let got = store.get_token(&pc, "id1").await.unwrap();

    assert_eq!(got.identifier, "id1");
    assert_eq!(got.participant_context, "pc1");
    assert_eq!(got.token, "access");
    assert_eq!(got.refresh_token, "refresh");
    assert_eq!(got.expires_at, expiration);
    assert_eq!(got.refresh_endpoint, "https://example.com/refresh");
    assert_eq!(got.endpoint, "https://example.com/data");
}

#[tokio::test]
async fn test_save_upserts_on_duplicate() {
    let store = make_store();
    let t1 = Utc::now() + TimeDelta::seconds(1000);
    let t2 = Utc::now() + TimeDelta::seconds(2000);

    store
        .save_token(
            TokenData::builder()
                .participant_context("pc1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("id1")
                .token("old")
                .refresh_token("old-refresh")
                .expires_at(t1)
                .refresh_endpoint("https://old.example.com/refresh")
                .endpoint("https://old.example.com/data")
                .build(),
        )
        .await
        .unwrap();

    store
        .save_token(
            TokenData::builder()
                .participant_context("pc1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("id1")
                .token("new")
                .refresh_token("new-refresh")
                .expires_at(t2)
                .refresh_endpoint("https://new.example.com/refresh")
                .endpoint("https://new.example.com/data")
                .build(),
        )
        .await
        .unwrap();

    let pc = ParticipantContext::builder().id("pc1").build();
    let got = store.get_token(&pc, "id1").await.unwrap();

    assert_eq!(got.token, "new");
    assert_eq!(got.refresh_token, "new-refresh");
    assert_eq!(got.expires_at, t2);
    assert_eq!(got.endpoint, "https://new.example.com/data");
}

#[tokio::test]
async fn test_update_token_preserves_endpoint() {
    let store = make_store();
    let expiration = Utc::now() + TimeDelta::seconds(3600);
    let original_endpoint = "https://provider.example.com/data/asset-1";

    store
        .save_token(
            TokenData::builder()
                .participant_context("pc1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("flow-1")
                .token("old-token")
                .refresh_token("old-refresh")
                .expires_at(expiration)
                .refresh_endpoint("https://provider.example.com/refresh")
                .endpoint(original_endpoint)
                .build(),
        )
        .await
        .unwrap();

    store
        .update_token(
            "pc1",
            "flow-1",
            RefreshedTokenData {
                token: "new-token".to_string(),
                refresh_token: "new-refresh".to_string(),
                expires_at: expiration + TimeDelta::hours(1),
                refresh_endpoint: "https://provider.example.com/refresh".to_string(),
            },
        )
        .await
        .unwrap();

    let pc = ParticipantContext::builder().id("pc1").build();
    let got = store.get_token(&pc, "flow-1").await.unwrap();

    assert_eq!(got.token, "new-token");
    assert_eq!(got.refresh_token, "new-refresh");
    assert_eq!(got.endpoint, original_endpoint, "endpoint must not change on update");
}

#[tokio::test]
async fn test_update_token_nonexistent_returns_not_found() {
    let store = make_store();
    let result = store
        .update_token(
            "pc1",
            "nonexistent",
            RefreshedTokenData {
                token: "t".to_string(),
                refresh_token: "r".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            },
        )
        .await;
    assert!(matches!(result.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_remove_token_deletes_entry() {
    let store = make_store();
    store.save_token(sample_token("pc1", "id1", "tok")).await.unwrap();

    store.remove_token("pc1", "id1").await.unwrap();

    let pc = ParticipantContext::builder().id("pc1").build();
    assert!(matches!(
        store.get_token(&pc, "id1").await.unwrap_err(),
        TokenError::TokenNotFound { .. }
    ));
}

#[tokio::test]
async fn test_context_isolation_different_participants_same_identifier() {
    let store = make_store();
    store
        .save_token(sample_token("pc1", "provider", "token-p1"))
        .await
        .unwrap();
    store
        .save_token(sample_token("pc2", "provider", "token-p2"))
        .await
        .unwrap();

    let pc1 = ParticipantContext::builder().id("pc1").build();
    let pc2 = ParticipantContext::builder().id("pc2").build();

    assert_eq!(store.get_token(&pc1, "provider").await.unwrap().token, "token-p1");
    assert_eq!(store.get_token(&pc2, "provider").await.unwrap().token, "token-p2");
}

#[tokio::test]
async fn test_context_isolation_get_wrong_participant_returns_not_found() {
    let store = make_store();
    store.save_token(sample_token("pc1", "provider", "tok")).await.unwrap();

    let pc_other = ParticipantContext::builder().id("pc-other").build();
    assert!(matches!(
        store.get_token(&pc_other, "provider").await.unwrap_err(),
        TokenError::TokenNotFound { .. }
    ));
}

#[tokio::test]
async fn test_context_isolation_update_does_not_affect_other_participant() {
    let store = make_store();
    store
        .save_token(sample_token("pc1", "provider", "token-p1"))
        .await
        .unwrap();
    store
        .save_token(sample_token("pc2", "provider", "token-p2"))
        .await
        .unwrap();

    store
        .update_token(
            "pc1",
            "provider",
            RefreshedTokenData {
                token: "token-p1-updated".to_string(),
                refresh_token: "refresh-p1-updated".to_string(),
                expires_at: Utc::now() + TimeDelta::hours(2),
                refresh_endpoint: "https://provider.example.com/refresh".to_string(),
            },
        )
        .await
        .unwrap();

    let pc1 = ParticipantContext::builder().id("pc1").build();
    let pc2 = ParticipantContext::builder().id("pc2").build();

    assert_eq!(
        store.get_token(&pc1, "provider").await.unwrap().token,
        "token-p1-updated"
    );
    assert_eq!(store.get_token(&pc2, "provider").await.unwrap().token, "token-p2");
}

#[tokio::test]
async fn test_context_isolation_remove_does_not_affect_other_participant() {
    let store = make_store();
    store
        .save_token(sample_token("pc1", "provider", "token-p1"))
        .await
        .unwrap();
    store
        .save_token(sample_token("pc2", "provider", "token-p2"))
        .await
        .unwrap();

    store.remove_token("pc1", "provider").await.unwrap();

    let pc1 = ParticipantContext::builder().id("pc1").build();
    let pc2 = ParticipantContext::builder().id("pc2").build();

    assert!(matches!(
        store.get_token(&pc1, "provider").await.unwrap_err(),
        TokenError::TokenNotFound { .. }
    ));
    assert_eq!(store.get_token(&pc2, "provider").await.unwrap().token, "token-p2");
}
