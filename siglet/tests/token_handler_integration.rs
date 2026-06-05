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

use chrono::Utc;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwkSet, TokenClaims};
use dsdk_facet_core::lock::MemoryLockManager;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{
    MemoryTokenStore, RefreshedTokenData, TokenClient, TokenClientApi, TokenData, TokenStore,
};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use dsdk_facet_testcontainers::utils::{get_available_port, wait_for_port_ready};
use serde_json::Value;
use siglet::handler::token::TokenApiHandler;
use siglet::server::auth::AuthLayer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

struct NoOpTokenClient;

struct NoOpTokenManager;

#[async_trait::async_trait]
impl TokenManager for NoOpTokenManager {
    async fn generate_pair(
        &self,
        _participant_context: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, Value>,
        _flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!("not needed for this test")
    }

    async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!("not needed for this test")
    }

    async fn revoke_token(&self, _participant_context: &ParticipantContext, _flow_id: &str) -> Result<(), TokenError> {
        unimplemented!("not needed for this test")
    }

    async fn validate_token(&self, _audience: &str, _token: &str) -> Result<TokenClaims, TokenError> {
        unimplemented!("not needed for this test")
    }

    async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
        unimplemented!("not needed for this test")
    }
}

#[async_trait::async_trait]
impl TokenClient for NoOpTokenClient {
    async fn refresh_token(
        &self,
        _participant_context: &ParticipantContext,
        _endpoint_identifier: &str,
        _access_token: &str,
        _refresh_token: &str,
        _refresh_endpoint: &str,
    ) -> Result<RefreshedTokenData, TokenError> {
        unimplemented!("not needed for this test")
    }
}

#[tokio::test]
async fn test_token_operations() {
    let participant_context_id = "ctx-123";
    let flow_id = "flow-abc";
    let expected_token = "access-token-value";

    let token_store = Arc::new(MemoryTokenStore::new());

    // Prime the store with a non-expiring token
    token_store
        .save_token(
            TokenData::builder()
                .participant_context(participant_context_id)
                .participant_id("participant-1")
                .counter_party_id("counter-party-1")
                .identifier(flow_id)
                .token(expected_token)
                .refresh_token("refresh-token-value")
                .expires_at(Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("http://localhost/refresh")
                .endpoint("https://example.com/data")
                .build(),
        )
        .await
        .unwrap();

    let token_client_api = Arc::new(
        TokenClientApi::builder()
            .lock_manager(Arc::new(MemoryLockManager::new()))
            .token_store(token_store)
            .token_client(Arc::new(NoOpTokenClient))
            .build(),
    );

    let handler = TokenApiHandler::builder()
        .token_client_api(token_client_api)
        .token_manager(Arc::new(NoOpTokenManager))
        .build();

    let port = get_available_port();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, handler.router(AuthLayer::Disabled))
            .await
            .unwrap();
    });

    wait_for_port_ready(addr, Duration::from_secs(5)).await.unwrap();

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/tokens/{}/{}",
        port, participant_context_id, flow_id
    );

    // Non-existent token returns 404
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/tokens/{}/unknown-id",
            port, participant_context_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    // Existing token is returned
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["token"], expected_token);
    assert_eq!(body["endpoint"], "https://example.com/data");

    // Delete the token
    let response = client.delete(&url).send().await.unwrap();
    assert_eq!(response.status(), 204);

    // Token is no longer accessible after deletion
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 404);
}
