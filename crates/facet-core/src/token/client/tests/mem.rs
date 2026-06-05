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

use super::super::{MemoryTokenStore, RefreshedTokenData, TokenData, TokenStore};
use crate::context::ParticipantContext;
use crate::token::TokenError;
use crate::util::clock::{Clock, MockClock};
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

async fn create_store_with_tokens() -> MemoryTokenStore {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("provider1")
                .token("token1")
                .refresh_token("refresh1")
                .expires_at(expiration)
                .refresh_endpoint("https://example.com/refresh")
                .endpoint("https://provider1.example.com/data")
                .build(),
        )
        .await
        .expect("Failed to save token");

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("provider2")
                .token("token2")
                .refresh_token("refresh2")
                .expires_at(expiration)
                .refresh_endpoint("https://example.com/refresh")
                .endpoint("https://provider2.example.com/data")
                .build(),
        )
        .await
        .expect("Failed to save token");

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("provider3")
                .token("token3")
                .refresh_token("refresh3")
                .expires_at(expiration)
                .refresh_endpoint("https://example.com/refresh")
                .endpoint("https://provider3.example.com/data")
                .build(),
        )
        .await
        .expect("Failed to save token");

    store
}

#[tokio::test]
async fn test_new_store_is_empty() {
    let store = MemoryTokenStore::new();

    let pc = ParticipantContext::builder().id("participant1").build();

    let data = store.get_token(&pc, "nonexistent").await;
    assert!(data.is_err());
}

#[tokio::test]
async fn test_save_token_success() {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);
    let test_data = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider1")
        .token("token123")
        .refresh_token("refresh123")
        .expires_at(expiration)
        .refresh_endpoint("https://example.com/refresh")
        .endpoint("https://example.com/data")
        .build();

    let result = store.save_token(test_data.clone()).await;
    assert!(result.is_ok(), "save_token should return Ok");

    let pc = ParticipantContext::builder().id("participant1").build();

    let retrieved = store
        .get_token(&pc, "provider1")
        .await
        .expect("Failed to retrieve saved token");
    assert_eq!(retrieved.identifier, "provider1", "Identifier should match");
    assert_eq!(retrieved.token, "token123", "Token should match");
    assert_eq!(retrieved.refresh_token, "refresh123", "Refresh token should match");
    assert_eq!(retrieved.expires_at, expiration, "Expiration should match");
    assert_eq!(
        retrieved.refresh_endpoint, "https://example.com/refresh",
        "Refresh endpoint should match"
    );
    assert_eq!(retrieved.endpoint, "https://example.com/data", "Endpoint should match");
}

#[tokio::test]
async fn test_save_multiple_tokens() {
    let store = create_store_with_tokens().await;

    let pc = ParticipantContext::builder().id("participant1").build();

    assert_eq!(store.get_token(&pc, "provider1").await.unwrap().token, "token1");
    assert_eq!(store.get_token(&pc, "provider2").await.unwrap().token, "token2");
    assert_eq!(store.get_token(&pc, "provider3").await.unwrap().token, "token3");
}

#[tokio::test]
async fn test_save_token_upserts_on_duplicate() {
    let store = MemoryTokenStore::new();
    let initial_time = Utc::now();
    let expires_at_1 = initial_time + TimeDelta::seconds(1000);
    let expires_at_2 = initial_time + TimeDelta::seconds(2000);

    let token_data1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider1")
        .token("old_token")
        .refresh_token("old_refresh")
        .expires_at(expires_at_1)
        .refresh_endpoint("https://old.example.com/refresh")
        .endpoint("https://old.example.com/data")
        .build();

    let token_data2 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider1")
        .token("new_token")
        .refresh_token("new_refresh")
        .expires_at(expires_at_2)
        .refresh_endpoint("https://new.example.com/refresh")
        .endpoint("https://new.example.com/data")
        .build();

    // First save succeeds
    store.save_token(token_data1).await.unwrap();

    // Second save with the same identifier should succeed and update
    store.save_token(token_data2).await.unwrap();

    let pc1 = ParticipantContext::builder().id("participant1").build();

    // Verify the token was updated to new values
    let retrieved = store.get_token(&pc1, "provider1").await.unwrap();
    assert_eq!(retrieved.token, "new_token");
    assert_eq!(retrieved.refresh_token, "new_refresh");
    assert_eq!(retrieved.expires_at, expires_at_2);
    assert_eq!(retrieved.refresh_endpoint, "https://new.example.com/refresh");
    assert_eq!(retrieved.endpoint, "https://new.example.com/data");
}

#[tokio::test]
async fn test_remove_tokens_used_before_success() {
    let initial = Utc::now();
    let clock = Arc::new(MockClock::new(initial));
    let store = MemoryTokenStore::with_clock(clock.clone());
    let expiration = initial + TimeDelta::seconds(10);

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("provider1")
                .token("token1")
                .refresh_token("refresh1")
                .expires_at(expiration)
                .refresh_endpoint("https://example.com/refresh")
                .endpoint("https://example.com/data")
                .build(),
        )
        .await
        .expect("Failed to save");

    let cutoff = clock.now() + TimeDelta::seconds(1);

    let removed = store
        .remove_tokens_accessed_before(cutoff)
        .await
        .expect("Failed to remove tokens");

    assert_eq!(removed, 1);

    let pc = ParticipantContext::builder().id("participant1").build();

    assert!(store.get_token(&pc, "provider1").await.is_err());
}

#[tokio::test]
async fn test_endpoint_is_stored_and_retrieved() {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier("flow-1")
                .token("access-token")
                .refresh_token("refresh-token")
                .expires_at(expiration)
                .refresh_endpoint("https://provider.example.com/refresh")
                .endpoint("https://provider.example.com/data/asset-1")
                .build(),
        )
        .await
        .unwrap();

    let pc = ParticipantContext::builder().id("participant1").build();
    let retrieved = store.get_token(&pc, "flow-1").await.unwrap();

    assert_eq!(retrieved.endpoint, "https://provider.example.com/data/asset-1");
}

#[tokio::test]
async fn test_update_token_preserves_endpoint() {
    let store = MemoryTokenStore::new();
    let expiration = Utc::now() + TimeDelta::seconds(10);
    let original_endpoint = "https://provider.example.com/data/asset-1";

    store
        .save_token(
            TokenData::builder()
                .participant_context("participant1")
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

    // update_token simulates what happens on a token refresh: only the token credentials change
    store
        .update_token(
            "participant1",
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

    let pc = ParticipantContext::builder().id("participant1").build();
    let retrieved = store.get_token(&pc, "flow-1").await.unwrap();

    assert_eq!(retrieved.token, "new-token", "Token should be updated");
    assert_eq!(
        retrieved.endpoint, original_endpoint,
        "Endpoint must not change on update"
    );
}

#[tokio::test]
async fn test_context_isolation_save() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p1")
        .refresh_token("refresh_p1")
        .expires_at(now)
        .refresh_endpoint("https://p1.example.com/refresh")
        .endpoint("https://p1.example.com/data")
        .build();

    let token_p2 = TokenData::builder()
        .participant_context("participant2")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p2")
        .refresh_token("refresh_p2")
        .expires_at(now)
        .refresh_endpoint("https://p2.example.com/refresh")
        .endpoint("https://p2.example.com/data")
        .build();

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let pc1 = ParticipantContext::builder().id("participant1").build();

    let pc2 = ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let retrieved_p1 = store.get_token(&pc1, "provider").await.unwrap();
    let retrieved_p2 = store.get_token(&pc2, "provider").await.unwrap();

    assert_eq!(retrieved_p1.token, "token_p1");
    assert_eq!(retrieved_p2.token, "token_p2");

    let pc3 = ParticipantContext::builder()
        .id("participant3")
        .audience("audience3")
        .build();

    // Verify participant3 cannot access participant1's token
    let result_p3 = store.get_token(&pc3, "provider").await;
    assert!(result_p3.is_err());
}

#[tokio::test]
async fn test_context_isolation_get() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p1")
        .refresh_token("refresh_p1")
        .expires_at(now)
        .refresh_endpoint("https://p1.example.com/refresh")
        .endpoint("https://p1.example.com/data")
        .build();

    let token_p2 = TokenData::builder()
        .participant_context("participant2")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p2")
        .refresh_token("refresh_p2")
        .expires_at(now)
        .refresh_endpoint("https://p2.example.com/refresh")
        .endpoint("https://p2.example.com/data")
        .build();

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let pc1 = ParticipantContext::builder().id("participant1").build();

    let pc2 = ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let p1_result = store.get_token(&pc1, "provider").await.unwrap();
    let p2_result = store.get_token(&pc2, "provider").await.unwrap();

    assert_eq!(p1_result.participant_context, "participant1");
    assert_eq!(p1_result.token, "token_p1");
    assert_eq!(p2_result.participant_context, "participant2");
    assert_eq!(p2_result.token, "token_p2");

    let pc3 = ParticipantContext::builder()
        .id("participant3")
        .audience("audience3")
        .build();

    // Verify participant3 cannot get either token
    let result_p3 = store.get_token(&pc3, "provider").await;
    assert!(result_p3.is_err());
    assert!(result_p3.unwrap_err().to_string().contains("Token not found"));
}

#[tokio::test]
async fn test_context_isolation_update() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p1")
        .refresh_token("refresh_p1")
        .expires_at(now)
        .refresh_endpoint("https://p1.example.com/refresh")
        .endpoint("https://p1.example.com/data")
        .build();

    let token_p2 = TokenData::builder()
        .participant_context("participant2")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p2")
        .refresh_token("refresh_p2")
        .expires_at(now)
        .refresh_endpoint("https://p2.example.com/refresh")
        .endpoint("https://p2.example.com/data")
        .build();

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    let updated_p1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p1_updated")
        .refresh_token("refresh_p1_updated")
        .expires_at(now)
        .refresh_endpoint("https://p1.example.com/refresh")
        .endpoint("https://p1.example.com/data")
        .build();

    store
        .update_token(
            "participant1",
            "provider",
            RefreshedTokenData {
                token: updated_p1.token,
                refresh_token: updated_p1.refresh_token,
                expires_at: updated_p1.expires_at,
                refresh_endpoint: updated_p1.refresh_endpoint,
            },
        )
        .await
        .unwrap();

    let pc1 = ParticipantContext::builder().id("participant1").build();

    let pc2 = ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    let p1_result = store.get_token(&pc1, "provider").await.unwrap();
    let p2_result = store.get_token(&pc2, "provider").await.unwrap();

    assert_eq!(p1_result.token, "token_p1_updated");
    assert_eq!(p2_result.token, "token_p2");

    // Verify participant3 cannot update a non-existent token
    let update_p3 = TokenData::builder()
        .participant_context("participant3")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p3")
        .refresh_token("refresh_p3")
        .expires_at(now)
        .refresh_endpoint("https://p3.example.com/refresh")
        .endpoint("https://p3.example.com/data")
        .build();

    let result_p3 = store
        .update_token(
            "participant3",
            "provider",
            RefreshedTokenData {
                token: update_p3.token,
                refresh_token: update_p3.refresh_token,
                expires_at: update_p3.expires_at,
                refresh_endpoint: update_p3.refresh_endpoint,
            },
        )
        .await;
    assert!(result_p3.is_err());
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));
}

#[tokio::test]
async fn test_context_isolation_remove() {
    let store = MemoryTokenStore::new();
    let now = Utc::now();

    let token_p1 = TokenData::builder()
        .participant_context("participant1")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p1")
        .refresh_token("refresh_p1")
        .expires_at(now)
        .refresh_endpoint("https://p1.example.com/refresh")
        .endpoint("https://p1.example.com/data")
        .build();

    let token_p2 = TokenData::builder()
        .participant_context("participant2")
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("provider")
        .token("token_p2")
        .refresh_token("refresh_p2")
        .expires_at(now)
        .refresh_endpoint("https://p2.example.com/refresh")
        .endpoint("https://p2.example.com/data")
        .build();

    store.save_token(token_p1).await.unwrap();
    store.save_token(token_p2).await.unwrap();

    store.remove_token("participant1", "provider").await.unwrap();

    let pc1 = ParticipantContext::builder().id("participant1").build();

    let pc2 = ParticipantContext::builder()
        .id("participant2")
        .audience("audience2")
        .build();

    assert!(store.get_token(&pc1, "provider").await.is_err());
    assert_eq!(store.get_token(&pc2, "provider").await.unwrap().token, "token_p2");

    // Verify participant3 cannot remove a token they don't own
    let result_p3 = store.remove_token("participant3", "provider").await;
    assert!(result_p3.is_err()); // Should fail - token does not exist for participant3
    assert!(matches!(result_p3.unwrap_err(), TokenError::TokenNotFound { .. }));

    // Verify p2's token still exists after p3 tries to remove a non-existent token
    assert_eq!(store.get_token(&pc2, "provider").await.unwrap().token, "token_p2");
}
