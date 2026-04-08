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
use crate::config::{TokenSource, TransferType};
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_flow::{DataFlow, DataFlowType};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_can_handle_with_http_pull_accepts_http_pull_rejects_http_push() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(MockTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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

    let handler = SigletDataFlowHandler::builder()
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
            _claims: HashMap<String, String>,
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
    let handler = SigletDataFlowHandler::builder()
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
            _claims: HashMap<String, String>,
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
    }

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(NotFoundTokenManager);

    // Add a token to the store so that remove_token succeeds when cleanup_tokens is called
    // Note: use participant_context_id from the flow, not participant_id
    let token_data = TokenData {
        identifier: "flow-1".to_string(),
        participant_context: "context-1".to_string(), // Match flow.participant_context_id
        token: "test_token".to_string(),
        refresh_token: "test_refresh".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        refresh_endpoint: "https://test.endpoint/refresh".to_string(),
        endpoint: "https://test.endpoint/data".to_string(),
    };
    token_store.save_token(token_data).await.unwrap();

    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = SigletDataFlowHandler::builder()
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
            _claims: HashMap<String, String>,
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
    }

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = Arc::new(ErrorTokenManager);
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        create_transfer_type("http-pull", "HTTP", "https://pull.example.com", TokenSource::Provider),
    );
    let handler = SigletDataFlowHandler::builder()
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

/// Mock TokenManager for testing
struct MockTokenManager;

#[async_trait::async_trait]
impl TokenManager for MockTokenManager {
    async fn generate_pair(
        &self,
        _participant_context: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, String>,
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
}

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
    DataFlow::builder()
        .id(id)
        .participant_id(participant_id)
        .transfer_type(transfer_type)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
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

#[test]
fn test_value_to_claim_string_with_null() {
    let value = serde_json::json!(null);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_boolean_true() {
    let value = serde_json::json!(true);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "true");
}

#[test]
fn test_value_to_claim_string_with_boolean_false() {
    let value = serde_json::json!(false);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "false");
}

#[test]
fn test_value_to_claim_string_with_integer() {
    let value = serde_json::json!(42);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "42");
}

#[test]
fn test_value_to_claim_string_with_negative_integer() {
    let value = serde_json::json!(-123);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "-123");
}

#[test]
fn test_value_to_claim_string_with_float() {
    let value = serde_json::json!(2.14);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "2.14");
}

#[test]
fn test_value_to_claim_string_with_string() {
    let value = serde_json::json!("hello world");
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "hello world");
}

#[test]
fn test_value_to_claim_string_with_string_containing_quotes() {
    let value = serde_json::json!("hello \"world\"");
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Raw string, not JSON-encoded
    assert_eq!(result, "hello \"world\"");
}

#[test]
fn test_value_to_claim_string_with_array() {
    let value = serde_json::json!(["item1", "item2", "item3"]);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should be JSON-serialized
    assert_eq!(result, r#"["item1","item2","item3"]"#);
}

#[test]
fn test_value_to_claim_string_with_object() {
    let value = serde_json::json!({"key1": "value1", "key2": "value2"});
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should be JSON-serialized (note: order may vary, so we parse and compare)
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("Should be valid JSON");
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
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should be JSON-serialized
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("Should be valid JSON");
    assert_eq!(parsed["user"]["name"], "Alice");
    assert_eq!(parsed["user"]["age"], 30);
    assert_eq!(parsed["active"], true);
}

#[test]
fn test_value_to_claim_string_with_empty_string() {
    let value = serde_json::json!("");
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_empty_array() {
    let value = serde_json::json!([]);
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "[]");
}

#[test]
fn test_value_to_claim_string_with_empty_object() {
    let value = serde_json::json!({});
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    assert_eq!(result, "{}");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_string() {
    // A string value that contains a JSON-encoded string
    let value = serde_json::Value::String("\"claimvalue1\"".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap the JSON encoding
    assert_eq!(result, "claimvalue1");
}

#[test]
fn test_value_to_claim_string_with_double_json_encoded_string() {
    // A string value that contains a double JSON-encoded string
    let value = serde_json::Value::String("\"\\\"innervalue\\\"\"".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should recursively unwrap
    assert_eq!(result, "innervalue");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_number() {
    // A string value that contains a JSON-encoded number
    let value = serde_json::Value::String("42".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap to the number as a string
    assert_eq!(result, "42");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_bool() {
    // A string value that contains a JSON-encoded boolean
    let value = serde_json::Value::String("true".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap to the boolean as a string
    assert_eq!(result, "true");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_null() {
    // A string value that contains a JSON-encoded null
    let value = serde_json::Value::String("null".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap to empty string
    assert_eq!(result, "");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_array() {
    // A string value that contains a JSON-encoded array
    let value = serde_json::Value::String("[\"item1\",\"item2\"]".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap and re-serialize as JSON
    assert_eq!(result, "[\"item1\",\"item2\"]");
}

#[test]
fn test_value_to_claim_string_with_json_encoded_object() {
    // A string value that contains a JSON-encoded object
    let value = serde_json::Value::String("{\"key\":\"value\"}".to_string());
    let result = SigletDataFlowHandler::value_to_claim_string(&value);
    // Should unwrap and re-serialize as JSON
    assert_eq!(result, "{\"key\":\"value\"}");
}
