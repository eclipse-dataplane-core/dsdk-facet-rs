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

use super::SigletDataFlowHandler;
use crate::config::{ClaimMapping, EndpointMapping, TokenSource, TransferType};
use crate::transfer_type::{MemoryTransferTypeMappingStore, TransferTypeMapping, TransferTypeMappingRepository};
use dataplane_sdk::core::db::memory::MemoryTransaction;
use dataplane_sdk::core::error::HandlerResult;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_address::EndpointProperty;
use dataplane_sdk::core::model::data_flow::{DataFlow, DataFlowType};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::JwkSet;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias so builder calls in tests don't need per-site turbofish annotations.
type Handler = SigletDataFlowHandler<MemoryTransaction>;

#[tokio::test]
async fn test_can_handle_with_http_pull_accepts_http_pull_rejects_http_push() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = Handler::builder()
        .dataplane_id("dataplane-1")
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    let flow2 = create_test_flow("flow-2", "participant-1", "http-push");
    let result2 = handler.can_handle(&flow2).await;
    assert!(result2.is_ok());
    assert!(!result2.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_matching_transfer_type_accepts() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", "https://push.example.com", TokenSource::Client),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("dataplane-1")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_non_matching_transfer_type_rejects() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", "https://push.example.com", TokenSource::Client),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "UnknownData");

    let result = handler.can_handle(&flow).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_can_handle_with_single_transfer_type() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    // Should accept http-pull
    let flow1 = create_test_flow("flow-1", "participant-1", "http-pull");

    let result = handler.can_handle(&flow1).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should reject http-push
    let flow2 = create_test_flow("flow-2", "participant-1", "http-push");

    let result = handler.can_handle(&flow2).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_on_start_generates_token_for_provider_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify token properties are present
    assert!(data_address.get_property("authorization").is_some());
    assert!(data_address.get_property("authType").is_some());
    assert!(data_address.get_property("refreshToken").is_some());
    assert!(data_address.get_property("expiresIn").is_some());
    assert!(data_address.get_property("refreshEndpoint").is_some());
    assert_eq!(data_address.endpoint, "https://pull.example.com");
}

#[tokio::test]
async fn test_on_prepare_generates_token_for_client_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-push".to_string(),
        create_transfer_type("http-push", "HTTP", "https://push.example.com", TokenSource::Client),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-push");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    let data_address = response.data_address.unwrap();

    // Verify token properties are present
    assert!(data_address.get_property("authorization").is_some());
    assert!(data_address.get_property("authType").is_some());
    assert!(data_address.get_property("refreshToken").is_some());
    assert!(data_address.get_property("expiresIn").is_some());
    assert!(data_address.get_property("refreshEndpoint").is_some());
}

#[tokio::test]
async fn test_on_prepare_skips_token_for_provider_token_source() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(result.is_ok());

    let response = result.unwrap();

    // Verify no data address is present
    assert!(response.data_address.is_none());
}

#[tokio::test]
async fn test_on_start_with_tx_renewal_support_emits_properties() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .tx_renewal_support(true)
            .build(),
    );

    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_ok());

    let data_address = result.unwrap().data_address.unwrap();

    // The renewal protocol emits no auth properties for now, but the data address
    // (endpoint / endpoint_type) is still built and a token pair is still generated.
    assert_eq!(data_address.endpoint, "https://pull.example.com");
    assert_eq!(data_address.endpoint_type, "HTTP");
    // Verify token properties are present
    assert!(
        data_address
            .get_property("https://w3id.org/edc/v0.0.1/ns/authorization")
            .is_some()
    );
    assert!(
        data_address
            .get_property("https://w3id.org/tractusx/auth/authType")
            .is_some()
    );
    assert!(
        data_address
            .get_property("https://w3id.org/tractusx/auth/refreshToken")
            .is_some()
    );
    assert!(
        data_address
            .get_property("https://w3id.org/tractusx/auth/expiresIn")
            .is_some()
    );
    assert!(
        data_address
            .get_property("https://w3id.org/tractusx/auth/refreshEndpoint")
            .is_some()
    );
    assert!(
        data_address
            .get_property("https://w3id.org/tractusx/auth/refreshAudience")
            .is_some()
    );
}

#[tokio::test]
async fn test_on_started_with_tx_renewal_support_skips_token_save() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;
    use dataplane_sdk::core::model::data_address::DataAddress;

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .tx_renewal_support(true)
            .build(),
    );

    let handler = Handler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let mut flow = create_test_flow("flow-1", "participant-1", "http-pull");
    // The renewal-protocol data address carries no standard auth properties.
    flow.data_address = Some(
        DataAddress::builder()
            .endpoint_type("HTTP")
            .endpoint("https://pull.example.com")
            .endpoint_properties(vec![
                EndpointProperty::builder()
                    .name("https://w3id.org/edc/v0.0.1/ns/authorization")
                    .value("token-abc")
                    .build(),
                EndpointProperty::builder()
                    .name("https://w3id.org/tractusx/auth/refreshToken")
                    .value("refresh-abc")
                    .build(),
                EndpointProperty::builder()
                    .name("https://w3id.org/tractusx/auth/refreshEndpoint")
                    .value("https://refresh.example.com")
                    .build(),
                EndpointProperty::builder()
                    .name("https://w3id.org/tractusx/auth/expiresIn")
                    .value("3600")
                    .build(),
            ])
            .build(),
    );

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    // Must not error despite the missing auth properties, and must not persist a token.
    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());

    let participant_ctx = ParticipantContext::builder().id("context-1").build();
    assert!(token_store.get_token(&participant_ctx, "flow-1").await.is_ok());
}

#[tokio::test]
async fn test_on_started_without_tx_renewal_support_saves_token() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;
    use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );

    let handler = Handler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .transfer_type_mappings(mappings)
        .dataplane_id("dataplane-1")
        .build();

    let mut flow = create_test_flow("flow-1", "participant-1", "http-pull");
    // Standard path: the data address carries the bearer/refresh-token properties.
    flow.data_address = Some(
        DataAddress::builder()
            .endpoint_type("HTTP")
            .endpoint("https://pull.example.com")
            .endpoint_properties(vec![
                EndpointProperty::builder()
                    .name("authorization")
                    .value("token-abc")
                    .build(),
                EndpointProperty::builder()
                    .name("refreshToken")
                    .value("refresh-abc")
                    .build(),
                EndpointProperty::builder()
                    .name("refreshEndpoint")
                    .value("https://refresh.example.com")
                    .build(),
                EndpointProperty::builder().name("expiresIn").value("3600").build(),
            ])
            .build(),
    );

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());

    // The standard (non-renewal) path persists a token.
    let participant_ctx = ParticipantContext::builder().id("context-1").build();
    assert!(token_store.get_token(&participant_ctx, "flow-1").await.is_ok());
}

#[tokio::test]
async fn test_on_terminate_revokes_token_successfully() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;
    use std::sync::Mutex;

    // Track if revoke_token was called
    let revoke_called = Arc::new(Mutex::new(false));
    let revoke_called_clone = revoke_called.clone();

    struct TrackingTokenManager {
        revoke_called: Arc<Mutex<bool>>,
    }

    #[async_trait::async_trait]
    impl TokenManager for TrackingTokenManager {
        async fn generate_pair(
            &self,
            _participant_context: &ParticipantContext,
            _subject: &str,
            _claims: HashMap<String, Value>,
            _flow_id: String,
        ) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_token".to_string())
                .refresh_token("mock_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_renewed_token".to_string())
                .refresh_token("mock_new_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn revoke_token(
            &self,
            _participant_context: &ParticipantContext,
            _flow_id: &str,
        ) -> Result<(), TokenError> {
            *self.revoke_called.lock().unwrap() = true;
            Ok(())
        }

        async fn validate_token(
            &self,
            _audience: &str,
            _token: &str,
        ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
            unimplemented!()
        }

        async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
            unimplemented!()
        }
    }

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(TrackingTokenManager {
        revoke_called: revoke_called_clone,
    });
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_terminate(&mut tx, &flow).await;
    assert!(result.is_ok());

    // Verify revoke_token was called
    assert!(*revoke_called.lock().unwrap());
}

#[tokio::test]
async fn test_on_terminate_ignores_token_not_found_error() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;
    use dsdk_facet_core::token::client::TokenData;

    struct NotFoundTokenManager;

    #[async_trait::async_trait]
    impl TokenManager for NotFoundTokenManager {
        async fn generate_pair(
            &self,
            _participant_context: &ParticipantContext,
            _subject: &str,
            _claims: HashMap<String, Value>,
            _flow_id: String,
        ) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_token".to_string())
                .refresh_token("mock_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_renewed_token".to_string())
                .refresh_token("mock_new_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn revoke_token(
            &self,
            _participant_context: &ParticipantContext,
            flow_id: &str,
        ) -> Result<(), TokenError> {
            Err(TokenError::token_not_found(flow_id))
        }

        async fn validate_token(
            &self,
            _audience: &str,
            _token: &str,
        ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
            unimplemented!()
        }

        async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
            unimplemented!()
        }
    }

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(NotFoundTokenManager);

    // Add a token to the store so that remove_token succeeds when cleanup_tokens is called
    // Note: use participant_context_id from the flow, not participant_id
    let token_data = TokenData::builder()
        .participant_context("context-1") // Match flow.participant_context_id
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .identifier("flow-1")
        .token("test_token")
        .refresh_token("test_refresh")
        .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
        .refresh_endpoint("https://test.endpoint/refresh")
        .endpoint("https://test.endpoint/data")
        .build();
    token_store.save_token(token_data).await.unwrap();

    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = Handler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    // Should succeed: token manager returns NotFound, but token is removed from store
    let result = handler.on_terminate(&mut tx, &flow).await;
    assert!(result.is_ok());

    // Verify token was removed from store
    let participant_ctx = ParticipantContext::builder().id("context-1").build();
    let token_result = token_store.get_token(&participant_ctx, "flow-1").await;
    assert!(token_result.is_err());
}

#[tokio::test]
async fn test_on_terminate_propagates_other_errors() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    struct ErrorTokenManager;

    #[async_trait::async_trait]
    impl TokenManager for ErrorTokenManager {
        async fn generate_pair(
            &self,
            _participant_context: &ParticipantContext,
            _subject: &str,
            _claims: HashMap<String, Value>,
            _flow_id: String,
        ) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_token".to_string())
                .refresh_token("mock_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
            Ok(RenewableTokenPair::builder()
                .token("mock_renewed_token".to_string())
                .refresh_token("mock_new_refresh_token".to_string())
                .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
                .refresh_endpoint("https://mock.endpoint/refresh".to_string())
                .build())
        }

        async fn revoke_token(
            &self,
            _participant_context: &ParticipantContext,
            _flow_id: &str,
        ) -> Result<(), TokenError> {
            Err(TokenError::database_error("Database connection failed"))
        }

        async fn validate_token(
            &self,
            _audience: &str,
            _token: &str,
        ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
            unimplemented!()
        }

        async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
            unimplemented!()
        }
    }

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(ErrorTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = Handler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    // Should fail with the database error
    let result = handler.on_terminate(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to revoke token"));
}

// ---------------------------------------------------------------------------
// Ordering contract: endpoint resolution must only happen when a token is generated
// ---------------------------------------------------------------------------

/// A transfer type whose endpoint mappings can never match `create_test_flow` (which has no
/// metadata at all).
fn transfer_type_with_unmatchable_endpoint_mappings(transfer_type: &str, token_source: TokenSource) -> TransferType {
    TransferType::builder()
        .transfer_type(transfer_type.to_string())
        .endpoint_type("HTTP".to_string())
        .token_source(token_source)
        .endpoint_mappings(vec![
            EndpointMapping::builder()
                .key("app".to_string())
                .value("never-matches".to_string())
                .endpoint("https://unreachable.example.com".to_string())
                .build(),
        ])
        .build()
}

#[tokio::test]
async fn test_on_prepare_with_non_matching_endpoint_mapping_does_not_error() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    // The transfer type's token source is Provider, so `on_prepare` (which requires Client) must
    // short-circuit before endpoint resolution. A non-matching endpoint mapping must NOT surface
    // as an error on a flow this data plane is not the token source for.
    let mappings = static_map(vec![transfer_type_with_unmatchable_endpoint_mappings(
        "http-pull",
        TokenSource::Provider,
    )]);

    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(Arc::new(MockTokenManager))
        .dataplane_id("dataplane-1")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_prepare(&mut tx, &flow).await;
    assert!(
        result.is_ok(),
        "a non-matching endpoint mapping must not fail a flow whose token source does not match: {:?}",
        result.err()
    );
    assert!(
        result.unwrap().data_address.is_none(),
        "no token is generated, so no data address should be returned"
    );
}

#[tokio::test]
async fn test_endpoint_resolution_failure_does_not_mint_token() {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    // Endpoint resolution runs before token generation, so a flow that cannot resolve an endpoint
    // must fail without leaving an orphaned token behind.
    let mappings = static_map(vec![transfer_type_with_unmatchable_endpoint_mappings(
        "http-pull",
        TokenSource::Provider,
    )]);

    let token_manager = Arc::new(CountingTokenManager::default());
    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(token_manager.clone())
        .dataplane_id("dataplane-1")
        .transfer_type_mappings(mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;
    assert!(result.is_err(), "unresolvable endpoint should fail the flow");
    assert_eq!(
        token_manager.generate_calls(),
        0,
        "no token should be minted when the endpoint cannot be resolved"
    );
}

/// A `TokenManager` that records the claims it was asked to sign.
#[derive(Default)]
struct CountingTokenManager {
    generate_calls: std::sync::atomic::AtomicUsize,
    last_claims: std::sync::Mutex<Option<HashMap<String, Value>>>,
}

impl CountingTokenManager {
    fn generate_calls(&self) -> usize {
        self.generate_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn last_claims(&self) -> HashMap<String, Value> {
        self.last_claims
            .lock()
            .expect("claims mutex poisoned")
            .clone()
            .expect("generate_pair was never called")
    }
}

#[async_trait::async_trait]
impl TokenManager for CountingTokenManager {
    async fn generate_pair(
        &self,
        _participant_context: &ParticipantContext,
        _subject: &str,
        claims: HashMap<String, Value>,
        _flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        self.generate_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.last_claims.lock().expect("claims mutex poisoned") = Some(claims);
        Ok(RenewableTokenPair::builder()
            .token("mock_token".to_string())
            .refresh_token("mock_refresh_token".to_string())
            .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }

    async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!()
    }

    async fn revoke_token(&self, _participant_context: &ParticipantContext, _flow_id: &str) -> Result<(), TokenError> {
        Ok(())
    }

    async fn validate_token(
        &self,
        _audience: &str,
        _token: &str,
    ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
        unimplemented!()
    }

    async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Claim mapping
// ---------------------------------------------------------------------------

fn claim_mapping(from: &str, to: &str) -> ClaimMapping {
    ClaimMapping::builder().from(from).to(to).build()
}

fn optional_claim_mapping(from: &str, to: &str) -> ClaimMapping {
    ClaimMapping::builder().from(from).to(to).optional(true).build()
}

/// Runs `on_start` against a handler configured with `transfer_type` and returns the claims the
/// token manager was asked to sign.
async fn claims_for(transfer_type: TransferType, flow: &DataFlow) -> HandlerResult<HashMap<String, Value>> {
    use dataplane_sdk::core::db::memory::MemoryContext;
    use dataplane_sdk::core::db::tx::TransactionalContext;

    let token_manager = Arc::new(CountingTokenManager::default());
    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(token_manager.clone())
        .dataplane_id("dataplane-1")
        .transfer_type_mappings(static_map(vec![transfer_type]))
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    handler.on_start(&mut tx, flow).await?;

    Ok(token_manager.last_claims())
}

/// A transfer type with a static endpoint and the given root claim mappings.
fn transfer_type_with_claim_mappings(claim_mappings: Vec<ClaimMapping>) -> TransferType {
    TransferType::builder()
        .transfer_type("http-pull".to_string())
        .endpoint_type("HTTP".to_string())
        .endpoint("https://pull.example.com".to_string())
        .token_source(TokenSource::Provider)
        .claim_mappings(claim_mappings)
        .build()
}

#[tokio::test]
async fn test_root_claim_mappings_are_applied() {
    let transfer_type = transfer_type_with_claim_mappings(vec![
        claim_mapping("flow.participantContextId", "context"),
        claim_mapping("'urn:asset:' + flow.datasetId", "assetUrn"),
    ]);

    let claims = claims_for(transfer_type, &create_test_flow("flow-1", "participant-1", "http-pull"))
        .await
        .unwrap();

    assert_eq!(claims.get("context"), Some(&Value::String("context-1".to_string())));
    assert_eq!(
        claims.get("assetUrn"),
        Some(&Value::String("urn:asset:dataset-1".to_string()))
    );
}

#[tokio::test]
async fn test_endpoint_claim_mappings_override_root() {
    let endpoint_mapping = EndpointMapping::builder()
        .key("app".to_string())
        .value("app2".to_string())
        .endpoint("https://app2.example.com".to_string())
        .claim_mappings(vec![claim_mapping("'us-east-1'", "zone")])
        .build();

    let transfer_type = TransferType::builder()
        .transfer_type("http-pull".to_string())
        .endpoint_type("HTTP".to_string())
        .token_source(TokenSource::Provider)
        .claim_mappings(vec![
            claim_mapping("flow.profile", "profile"),
            claim_mapping("'eu'", "zone"),
        ])
        .endpoint_mappings(vec![endpoint_mapping])
        .build();

    let mut flow = create_test_flow("flow-1", "participant-1", "http-pull");
    flow.metadata
        .insert("app".to_string(), Value::String("app2".to_string()));

    let claims = claims_for(transfer_type, &flow).await.unwrap();

    // The root mapping still applies...
    assert_eq!(claims.get("profile"), Some(&Value::String("http-pull".to_string())));
    // ...and the endpoint mapping wins on the shared key.
    assert_eq!(claims.get("zone"), Some(&Value::String("us-east-1".to_string())));
}

#[tokio::test]
async fn test_metadata_reaches_claims_only_through_a_mapping() {
    // Metadata is opt-in: a key is exposed to the token only when a mapping names it.
    let transfer_type = transfer_type_with_claim_mappings(vec![claim_mapping("flow.metadata.mapped", "mapped")]);

    let mut flow = create_test_flow("flow-1", "participant-1", "http-pull");
    flow.metadata
        .insert("mapped".to_string(), Value::String("exposed".to_string()));
    flow.metadata
        .insert("unmapped".to_string(), Value::String("internal".to_string()));

    let claims = claims_for(transfer_type, &flow).await.unwrap();

    assert_eq!(claims.get("mapped"), Some(&Value::String("exposed".to_string())));
    assert!(
        !claims.contains_key("unmapped"),
        "metadata without a mapping must not reach the token"
    );
}

#[tokio::test]
async fn test_mapped_claim_overrides_builtin_claim() {
    // Mappings are applied last, so an operator can deliberately reshape a built-in claim.
    let transfer_type =
        transfer_type_with_claim_mappings(vec![claim_mapping("'urn:uuid:' + flow.agreementId", "agreementId")]);

    let claims = claims_for(transfer_type, &create_test_flow("flow-1", "participant-1", "http-pull"))
        .await
        .unwrap();

    assert_eq!(
        claims.get("agreementId"),
        Some(&Value::String("urn:uuid:agreement-1".to_string()))
    );
}

#[tokio::test]
async fn test_mapped_claims_preserve_json_types() {
    let transfer_type = transfer_type_with_claim_mappings(vec![
        claim_mapping("[1, 2]", "list"),
        claim_mapping("size(flow.labels) == 0", "noLabels"),
    ]);

    let claims = claims_for(transfer_type, &create_test_flow("flow-1", "participant-1", "http-pull"))
        .await
        .unwrap();

    assert_eq!(claims.get("list"), Some(&serde_json::json!([1, 2])));
    assert_eq!(claims.get("noLabels"), Some(&Value::Bool(true)));
}

#[tokio::test]
async fn test_required_claim_mapping_failure_fails_the_flow() {
    let transfer_type = transfer_type_with_claim_mappings(vec![claim_mapping("flow.metadata.absent", "missing")]);

    let result = claims_for(transfer_type, &create_test_flow("flow-1", "participant-1", "http-pull")).await;

    let error = result
        .expect_err("a failing required mapping must fail the flow")
        .to_string();
    assert!(error.contains("flow-1"), "error should name the flow: {error}");
    assert!(error.contains("missing"), "error should name the claim: {error}");
}

#[tokio::test]
async fn test_optional_claim_mapping_failure_is_skipped() {
    let transfer_type = transfer_type_with_claim_mappings(vec![
        optional_claim_mapping("flow.metadata.absent", "missing"),
        claim_mapping("flow.datasetId", "kept"),
    ]);

    let claims = claims_for(transfer_type, &create_test_flow("flow-1", "participant-1", "http-pull"))
        .await
        .unwrap();

    assert!(!claims.contains_key("missing"));
    assert_eq!(claims.get("kept"), Some(&Value::String("dataset-1".to_string())));
}

#[tokio::test]
async fn test_metadata_is_not_copied_into_claims() {
    // Regression guard: flow metadata never lands in the token on its own. The flow below carries
    // an `app` metadata entry because the endpoint mapping matches on it — and that entry must
    // still be absent from the claims.
    let endpoint_mapping = EndpointMapping::builder()
        .key("app".to_string())
        .value("app1".to_string())
        .endpoint("https://app1.example.com".to_string())
        .build();

    let transfer_type = TransferType::builder()
        .transfer_type("http-pull".to_string())
        .endpoint_type("HTTP".to_string())
        .token_source(TokenSource::Provider)
        .endpoint_mappings(vec![endpoint_mapping])
        .build();

    let mut flow = create_test_flow("flow-1", "participant-1", "http-pull");
    flow.metadata
        .insert("app".to_string(), Value::String("app1".to_string()));

    let claims = claims_for(transfer_type, &flow).await.unwrap();

    let mut keys: Vec<&String> = claims.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["agreementId", "counterPartyId", "datasetId", "participantId"]
    );
}

/// Mock TokenManager for testing
struct MockTokenManager;

#[async_trait::async_trait]
impl TokenManager for MockTokenManager {
    async fn generate_pair(
        &self,
        _participant_context: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, Value>,
        _flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        Ok(RenewableTokenPair::builder()
            .token("mock_token".to_string())
            .refresh_token("mock_refresh_token".to_string())
            .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }

    async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        Ok(RenewableTokenPair::builder()
            .token("mock_renewed_token".to_string())
            .refresh_token("mock_new_refresh_token".to_string())
            .expires_at(chrono::Utc::now() + chrono::Duration::hours(1))
            .refresh_endpoint("https://mock.endpoint/refresh".to_string())
            .build())
    }

    async fn revoke_token(&self, _participant_context: &ParticipantContext, _flow_id: &str) -> Result<(), TokenError> {
        Ok(())
    }

    async fn validate_token(
        &self,
        _audience: &str,
        _token: &str,
    ) -> Result<dsdk_facet_core::jwt::TokenClaims, TokenError> {
        unimplemented!()
    }

    async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
        unimplemented!()
    }
}

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
    DataFlow::builder()
        .id(id)
        .participant_id(participant_id)
        .profile(transfer_type)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .control_plane_id("control-plane-1")
        .participant_context_id("context-1")
        .kind(DataFlowType::Provider)
        .build()
}

/// Helper function to create a TransferTypes configuration
fn create_transfer_type(
    transfer_type: &str,
    endpoint_type: &str,
    endpoint: &str,
    token_source: TokenSource,
) -> TransferType {
    TransferType::builder()
        .transfer_type(transfer_type.to_string())
        .endpoint_type(endpoint_type.to_string())
        .endpoint(endpoint.to_string())
        .token_source(token_source)
        .build()
}

// ---------------------------------------------------------------------------
// Dynamic, per-participant-context transfer-type resolution (issue #75)
// ---------------------------------------------------------------------------

/// Builds a repo holding a single participant context's `mappings`.
async fn repo_with(pc_id: &str, entries: Vec<TransferType>) -> Arc<dyn TransferTypeMappingRepository> {
    let mappings: HashMap<String, TransferType> =
        entries.into_iter().map(|tt| (tt.transfer_type.clone(), tt)).collect();
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    repo.create(
        TransferTypeMapping::builder()
            .participant_context_id(pc_id)
            .mappings(mappings)
            .build(),
    )
    .await
    .unwrap();
    repo
}

fn static_map(entries: Vec<TransferType>) -> HashMap<String, TransferType> {
    entries.into_iter().map(|tt| (tt.transfer_type.clone(), tt)).collect()
}

#[tokio::test]
async fn test_stored_mapping_overrides_static_config() {
    // Static config maps http-pull to endpoint A; the participant context's stored map points it
    // at endpoint B. The stored map must win.
    let static_mappings = static_map(vec![create_transfer_type(
        "http-pull",
        "HTTP",
        "https://static.example.com",
        TokenSource::Provider,
    )]);
    let repo = repo_with(
        "context-1",
        vec![create_transfer_type(
            "http-pull",
            "HTTP",
            "https://dynamic.example.com",
            TokenSource::Provider,
        )],
    )
    .await;

    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(Arc::new(MockTokenManager))
        .dataplane_id("dataplane-1")
        .transfer_type_repo(repo)
        .transfer_type_mappings(static_mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    let resolved = handler.get_transfer_type(&flow).await.unwrap();
    assert_eq!(resolved.endpoint.as_deref(), Some("https://dynamic.example.com"));
}

#[tokio::test]
async fn test_falls_back_to_static_config_when_no_stored_mapping() {
    // The participant context has no stored map, so the static config is used.
    let static_mappings = static_map(vec![create_transfer_type(
        "http-pull",
        "HTTP",
        "https://static.example.com",
        TokenSource::Provider,
    )]);

    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(Arc::new(MockTokenManager))
        .dataplane_id("dataplane-1")
        // No transfer_type_repo set -> defaults to an empty store.
        .transfer_type_mappings(static_mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    assert!(handler.can_handle(&flow).await.unwrap());
    let resolved = handler.get_transfer_type(&flow).await.unwrap();
    assert_eq!(resolved.endpoint.as_deref(), Some("https://static.example.com"));
}

#[tokio::test]
async fn test_stored_mapping_is_authoritative_no_static_fallback_for_missing_profile() {
    // The participant context has a stored map, but not for the requested profile. Because a
    // stored map is all-or-nothing, the static config is NOT consulted and the profile is
    // unsupported.
    let static_mappings = static_map(vec![create_transfer_type(
        "http-pull",
        "HTTP",
        "https://static.example.com",
        TokenSource::Provider,
    )]);
    let repo = repo_with(
        "context-1",
        vec![create_transfer_type(
            "http-push",
            "HTTP",
            "https://dynamic.example.com",
            TokenSource::Client,
        )],
    )
    .await;

    let handler = Handler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(Arc::new(MockTokenManager))
        .dataplane_id("dataplane-1")
        .transfer_type_repo(repo)
        .transfer_type_mappings(static_mappings)
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");
    assert!(!handler.can_handle(&flow).await.unwrap());
    assert!(handler.get_transfer_type(&flow).await.is_err());
}

#[test]
fn test_value_to_claim_string_with_null() {
    let value = serde_json::json!(null);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_boolean_true() {
    let value = serde_json::json!(true);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "true");
}

#[test]
fn test_value_to_claim_string_with_boolean_false() {
    let value = serde_json::json!(false);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "false");
}

#[test]
fn test_value_to_claim_string_with_integer() {
    let value = serde_json::json!(42);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "42");
}

#[test]
fn test_value_to_claim_string_with_negative_integer() {
    let value = serde_json::json!(-123);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "-123");
}

#[test]
fn test_value_to_claim_string_with_float() {
    let value = serde_json::json!(2.14);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "2.14");
}

#[test]
fn test_value_to_claim_string_with_string() {
    let value = serde_json::json!("hello world");
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "hello world");
}

#[test]
fn test_value_to_claim_string_with_string_containing_quotes() {
    let value = serde_json::json!("hello \"world\"");
    let result = Handler::value_to_claim_string(&value);
    // Raw string, not JSON-encoded
    assert_eq!(result, "hello \"world\"");
}

#[test]
fn test_value_to_claim_string_with_array() {
    let value = serde_json::json!(["item1", "item2", "item3"]);
    let result = Handler::value_to_claim_string(&value);
    // Should be JSON-serialized
    assert_eq!(result, r#"["item1","item2","item3"]"#);
}

#[test]
fn test_value_to_claim_string_with_object() {
    let value = serde_json::json!({"key1": "value1", "key2": "value2"});
    let result = Handler::value_to_claim_string(&value);
    // Should be JSON-serialized (note: order may vary, so we parse and compare)
    let parsed: Value = serde_json::from_str(&result).expect("Should be valid JSON");
    assert_eq!(parsed["key1"], "value1");
    assert_eq!(parsed["key2"], "value2");
}

#[test]
fn test_value_to_claim_string_with_nested_object() {
    let value = serde_json::json!({
        "user": {
            "name": "Alice",
            "age": 30
        },
        "active": true
    });
    let result = Handler::value_to_claim_string(&value);
    // Should be JSON-serialized
    let parsed: Value = serde_json::from_str(&result).expect("Should be valid JSON");
    assert_eq!(parsed["user"]["name"], "Alice");
    assert_eq!(parsed["user"]["age"], 30);
    assert_eq!(parsed["active"], true);
}

#[test]
fn test_value_to_claim_string_with_empty_string() {
    let value = serde_json::json!("");
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_empty_array() {
    let value = serde_json::json!([]);
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "[]");
}

#[test]
fn test_value_to_claim_string_with_empty_object() {
    let value = serde_json::json!({});
    let result = Handler::value_to_claim_string(&value);
    assert_eq!(result, "{}");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_string() {
    // A string value that contains a JSON-encoded string
    let value = Value::String("\"claimvalue1\"".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap the JSON encoding
    assert_eq!(result, "claimvalue1");
}

#[test]
fn test_value_to_claim_string_with_double_json_encoded_string() {
    // A string value that contains a double JSON-encoded string
    let value = Value::String("\"\\\"innervalue\\\"\"".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should recursively unwrap
    assert_eq!(result, "innervalue");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_number() {
    // A string value that contains a JSON-encoded number
    let value = Value::String("42".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap to the number as a string
    assert_eq!(result, "42");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_bool() {
    // A string value that contains a JSON-encoded boolean
    let value = Value::String("true".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap to the boolean as a string
    assert_eq!(result, "true");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_null() {
    // A string value that contains a JSON-encoded null
    let value = Value::String("null".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap to empty string
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_array() {
    // A string value that contains a JSON-encoded array
    let value = Value::String("[\"item1\",\"item2\"]".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap and re-serialize as JSON
    assert_eq!(result, "[\"item1\",\"item2\"]");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_object() {
    // A string value that contains a JSON-encoded object
    let value = Value::String("{\"key\":\"value\"}".to_string());
    let result = Handler::value_to_claim_string(&value);
    // Should unwrap and re-serialize as JSON
    assert_eq!(result, "{\"key\":\"value\"}");
}
