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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use dataplane_sdk::core::db::memory::MemoryContext;
use dataplane_sdk::core::db::tx::TransactionalContext;
use dataplane_sdk::core::handler::DataFlowHandler;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::model::data_flow::{DataFlow, DataFlowType};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::jwtutils::{
    StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem,
};
use dsdk_facet_core::jwt::{KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenStore};
use dsdk_facet_core::token::manager::{JwtTokenManager, MemoryRenewableTokenStore};
use dsdk_facet_core::util::clock::{Clock, MockClock};
use serde_json::Value;
use siglet::config::{EndpointMapping, TokenSource, TransferType};
use siglet::handler::{
    CLAIM_AGREEMENT_ID, CLAIM_COUNTER_PARTY_ID, CLAIM_DATASET_ID, CLAIM_PARTICIPANT_ID, SigletDataFlowHandler,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_on_start_creates_token() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Extract the JWT token from the data address
    let data_address = response.data_address.expect("Data address should be present");
    let token = data_address
        .get_property("authorization")
        .expect("Authorization token should be present");

    // Parse the JWT structure
    let token_parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        token_parts.len(),
        3,
        "JWT should have 3 parts (header.payload.signature)"
    );

    // Decode the payload (second part) from base64
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token_parts[1])
        .expect("Failed to decode JWT payload");
    let payload_str = String::from_utf8(payload_bytes).expect("Failed to convert payload to string");
    let jwt_payload: Value = serde_json::from_str(&payload_str).expect("Failed to parse JWT payload as JSON");

    // Verify the metadata claims are present in the JWT
    assert_eq!(
        jwt_payload.get("key1").and_then(|v| v.as_str()),
        Some("value1"),
        "key1 should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get("key2").and_then(|v| v.as_str()),
        Some("value2"),
        "key2 should be present in JWT with correct value"
    );

    // Verify additional flow-based claims are present in the JWT
    assert_eq!(
        jwt_payload.get(CLAIM_AGREEMENT_ID).and_then(|v| v.as_str()),
        Some("agreement-1"),
        "agreementId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_PARTICIPANT_ID).and_then(|v| v.as_str()),
        Some("participant-1"),
        "participantId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_COUNTER_PARTY_ID).and_then(|v| v.as_str()),
        Some("counter-party-1"),
        "counterPartyId should be present in JWT with correct value"
    );
    assert_eq!(
        jwt_payload.get(CLAIM_DATASET_ID).and_then(|v| v.as_str()),
        Some("dataset-1"),
        "datasetId should be present in JWT with correct value"
    );

    let result = handler.on_suspend(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_suspend_succeeds() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_ok());
    let result = handler.on_suspend(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_started_saves_token_to_store() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();
    let expires_at = Utc::now() + TimeDelta::hours(1);

    let expires_in_seconds = (expires_at.timestamp() - Utc::now().timestamp()).to_string();

    let data_endpoint = "https://example.com/data";
    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint(data_endpoint)
        .endpoint_properties(vec![
            create_endpoint_property("authorization", "access-token-value"),
            create_endpoint_property("refreshToken", "refresh-token-value"),
            create_endpoint_property("refreshEndpoint", "https://example.com/refresh"),
            create_endpoint_property("expiresIn", &expires_in_seconds),
        ])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());

    // Verify token was saved under participant_context_id ("context-1"), not participant_id
    let participant_ctx = ParticipantContext::builder().id("context-1").build();
    let saved_token = token_store.get_token(&participant_ctx, "flow-1").await;
    assert!(saved_token.is_ok());

    let token_data = saved_token.unwrap();
    assert_eq!(token_data.identifier, "flow-1");
    assert_eq!(token_data.participant_context, "context-1");
    assert_eq!(token_data.token, "access-token-value");
    assert_eq!(token_data.refresh_token, "refresh-token-value");
    assert_eq!(token_data.refresh_endpoint, "https://example.com/refresh");
    assert_eq!(token_data.endpoint, data_endpoint);
}

/// Verifies that on_started keys the saved token on participant_context_id, not participant_id.
///
/// These two fields have distinct meanings: participant_id is the DID/identity of the participant
/// (e.g. "did:web:consumer.example.com") while participant_context_id is the local tenant key
/// used for store isolation (e.g. "ctx-abc123"). Using participant_id as the store key would cause
/// every subsequent get_token lookup (which uses participant_context_id) to miss.
#[tokio::test]
async fn test_on_started_stores_token_under_participant_context_id() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store.clone())
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let expires_at = Utc::now() + TimeDelta::hours(1);
    let expires_in_seconds = (expires_at.timestamp() - Utc::now().timestamp()).to_string();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint("https://example.com/data")
        .endpoint_properties(vec![
            create_endpoint_property("authorization", "token-value"),
            create_endpoint_property("refreshToken", "refresh-value"),
            create_endpoint_property("refreshEndpoint", "https://example.com/refresh"),
            create_endpoint_property("expiresIn", &expires_in_seconds),
        ])
        .build();

    // Use clearly distinct values so any mix-up is immediately visible
    let flow = DataFlow::builder()
        .id("flow-distinct")
        .participant_id("did:web:consumer.example.com") // identity DID — NOT the store key
        .participant_context_id("ctx-abc123") // local context — IS the store key
        .transfer_type("http-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("did:web:provider.example.com")
        .callback_address("https://example.com/callback")
        .data_address(data_address)
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    handler.on_started(&mut tx, &flow).await.unwrap();

    // Must be retrievable via participant_context_id
    let ctx_by_context_id = ParticipantContext::builder().id("ctx-abc123").build();
    let saved = token_store.get_token(&ctx_by_context_id, "flow-distinct").await;
    assert!(saved.is_ok(), "token should be found under participant_context_id");
    assert_eq!(saved.unwrap().participant_context, "ctx-abc123");

    // Must NOT be retrievable via participant_id
    let ctx_by_participant_id = ParticipantContext::builder().id("did:web:consumer.example.com").build();
    let missing = token_store.get_token(&ctx_by_participant_id, "flow-distinct").await;
    assert!(missing.is_err(), "token must not be stored under participant_id");
}

#[tokio::test]
async fn test_on_started_without_data_address_succeeds() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let flow = create_test_flow("flow-1", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_on_started_missing_endpoint_errors() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint("https://example.com/data")
        .endpoint_properties(vec![])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("authorization"));
}

#[tokio::test]
async fn test_on_started_missing_token_errors() {
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let data_address = DataAddress::builder()
        .endpoint_type("HttpData")
        .endpoint("https://example.com/data")
        .endpoint_properties(vec![])
        .build();

    let flow = create_test_flow_with_data_address("flow-1", "participant-1", "http-pull", data_address);

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();

    let result = handler.on_started(&mut tx, &flow).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("authorization"));
}

/// Verifies that a metadata value of JSON null produces an empty-string claim in the JWT.
///
/// value_to_claim_string maps JSON null → "". This test pins that behavior at the callsite,
/// so it is visible to anyone reading the claim-generation path, not just the private helper.
#[tokio::test]
async fn test_on_start_metadata_null_produces_empty_claim() {
    let mut metadata = HashMap::new();
    metadata.insert("nullable_field".to_string(), Value::Null);

    let flow = DataFlow::builder()
        .id("flow-null")
        .participant_id("participant-1")
        .transfer_type("http-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let jwt_payload = decode_jwt_payload(&response);
    assert_eq!(
        jwt_payload.get("nullable_field").and_then(|v| v.as_str()),
        Some(""),
        "JSON null metadata value should produce an empty-string claim"
    );
}

/// Verifies that a JSON-encoded string in metadata is unwrapped to its inner value in the JWT.
///
/// value_to_claim_string unwraps double-encoded strings: `"\"hello\""` → `hello`.
/// This test pins that behavior at the callsite, so the transformation is visible
/// when reading the claim-generation path.
#[tokio::test]
async fn test_on_start_json_encoded_metadata_unwrapped_in_claim() {
    let mut metadata = HashMap::new();
    // Simulates a provider that JSON-encodes string values before putting them in metadata
    metadata.insert(
        "encoded_field".to_string(),
        Value::String("\"inner-value\"".to_string()),
    );

    let flow = DataFlow::builder()
        .id("flow-encoded")
        .participant_id("participant-1")
        .transfer_type("http-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let token_store = Arc::new(MemoryTokenStore::new());
    let token_manager = create_jwt_token_manager();
    let handler = SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let jwt_payload = decode_jwt_payload(&response);
    assert_eq!(
        jwt_payload.get("encoded_field").and_then(|v| v.as_str()),
        Some("inner-value"),
        "JSON-encoded string metadata value should be unwrapped in the claim"
    );
}

// ============================================================================
// Endpoint Mapping Tests
// ============================================================================

#[tokio::test]
async fn test_on_start_endpoint_mapping_resolves_by_metadata() {
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(s3_pull_mappings_with_endpoints())
        .build();

    let mut metadata = HashMap::new();
    metadata.insert("app".to_string(), Value::String("app1".to_string()));

    let flow = DataFlow::builder()
        .id("flow-1")
        .participant_id("participant-1")
        .transfer_type("s3-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let data_address = response.data_address.expect("Data address should be present");
    assert_eq!(
        data_address.endpoint,
        "https://s3.eu-west-1.amazonaws.com/climate-bucket"
    );
}

#[tokio::test]
async fn test_on_start_endpoint_mapping_selects_correct_entry() {
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(s3_pull_mappings_with_endpoints())
        .build();

    let mut metadata = HashMap::new();
    metadata.insert("app".to_string(), Value::String("app2".to_string()));

    let flow = DataFlow::builder()
        .id("flow-2")
        .participant_id("participant-1")
        .transfer_type("s3-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let data_address = response.data_address.expect("Data address should be present");
    assert_eq!(
        data_address.endpoint,
        "https://s3.us-east-1.amazonaws.com/finance-bucket"
    );
}

#[tokio::test]
async fn test_on_start_endpoint_mapping_errors_on_no_match() {
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(s3_pull_mappings_with_endpoints())
        .build();

    // metadata key present but value does not match any configured mapping
    let mut metadata = HashMap::new();
    metadata.insert("app".to_string(), Value::String("app-unknown".to_string()));

    let flow = DataFlow::builder()
        .id("flow-3")
        .participant_id("participant-1")
        .transfer_type("s3-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_err(), "should error when no mapping matches");
}

#[tokio::test]
async fn test_on_start_endpoint_mapping_errors_on_missing_key() {
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(s3_pull_mappings_with_endpoints())
        .build();

    // metadata does not contain the key the mappings look for at all
    let flow = DataFlow::builder()
        .id("flow-no-meta")
        .participant_id("participant-1")
        .transfer_type("s3-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let result = handler.on_start(&mut tx, &flow).await;

    assert!(result.is_err(), "should error when metadata key is absent");
}

#[tokio::test]
async fn test_on_start_endpoint_mapping_arbitrary_metadata_key() {
    // Endpoint mappings can use any metadata key, not just well-known fields
    let mut transfer_type_mappings = HashMap::new();
    transfer_type_mappings.insert(
        "s3-pull".to_string(),
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![
                EndpointMapping::builder()
                    .key("customBucketId".to_string())
                    .value("bucket-xyz".to_string())
                    .endpoint("https://s3.example.com/xyz-bucket".to_string())
                    .build(),
            ])
            .build(),
    );

    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(transfer_type_mappings)
        .build();

    let mut metadata = HashMap::new();
    metadata.insert("customBucketId".to_string(), Value::String("bucket-xyz".to_string()));

    let flow = DataFlow::builder()
        .id("flow-custom")
        .participant_id("participant-1")
        .transfer_type("s3-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .callback_address("https://example.com/callback")
        .participant_context_id("context-1")
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build();

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let data_address = response.data_address.expect("Data address should be present");
    assert_eq!(data_address.endpoint, "https://s3.example.com/xyz-bucket");
}

#[tokio::test]
async fn test_on_start_static_endpoint_when_no_mappings() {
    // Sanity check: existing static-endpoint behavior is unchanged when no mappings are configured
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(create_jwt_token_manager())
        .dataplane_id("test-dataplane")
        .transfer_type_mappings(http_pull_mappings())
        .build();

    let flow = create_test_flow("flow-static", "participant-1", "http-pull");

    let context = MemoryContext;
    let mut tx = context.begin().await.unwrap();
    let response = handler.on_start(&mut tx, &flow).await.unwrap();

    let data_address = response.data_address.expect("Data address should be present");
    assert_eq!(data_address.endpoint, "https://pull.example.com");
}

/// Decodes the JWT payload from the authorization property of a DataFlowResponseMessage.
fn decode_jwt_payload(response: &dataplane_sdk::core::model::messages::DataFlowResponseMessage) -> Value {
    let data_address = response.data_address.as_ref().expect("Data address should be present");
    let token = data_address
        .get_property("authorization")
        .expect("Authorization token should be present");
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("Failed to decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("Failed to parse JWT payload")
}

/// Helper to create a JwtTokenManager with real JWT generator/verifier for testing
fn create_jwt_token_manager() -> Arc<JwtTokenManager> {
    let fixed_time = DateTime::from_timestamp(1000000000, 0).unwrap();
    let clock = Arc::new(MockClock::new(fixed_time)) as Arc<dyn Clock>;

    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate test keypair");

    let signing_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(keypair.private_key.clone())
            .iss("did:web:issuer.com")
            .kid("test_kid_1")
            .key_format(KeyFormat::PEM)
            .build(),
    );

    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(keypair.public_key.clone())
            .key_format(KeyFormat::PEM)
            .build(),
    );

    let generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(signing_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .clock(clock.clone())
            .build(),
    );

    let verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(verification_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .leeway_seconds(86400 * 365 * 30) // 30-years leeway for testing with mock times
            .build(),
    );

    let token_store = Arc::new(MemoryRenewableTokenStore::new());

    Arc::new(
        JwtTokenManager::builder()
            .issuer("did:web:issuer.com")
            .refresh_endpoint("http://localhost:8080/refresh")
            .server_secret(b"this_is_exactly_32bytes_long!!!!".to_vec())
            .token_duration(3600) // 1 hour
            .renewal_token_duration(86400) // 24 hours
            .clock(clock)
            .token_store(token_store)
            .token_generator(generator)
            .client_verifier(verifier.clone())
            .provider_verifier(verifier)
            .build(),
    )
}

/// Helper to create endpoint properties for DataAddress
fn create_endpoint_property(name: &str, value: &str) -> EndpointProperty {
    EndpointProperty::builder().name(name).value(value).build()
}

/// Helper function to create a test DataFlow with required fields
fn create_test_flow(id: &str, participant_id: &str, transfer_type: &str) -> DataFlow {
    let mut metadata = HashMap::new();
    metadata.insert("key1".to_string(), Value::String("value1".to_string()));
    metadata.insert("key2".to_string(), Value::String("value2".to_string()));
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
        .metadata(metadata)
        .kind(DataFlowType::Provider)
        .build()
}

/// Helper function to create a test DataFlow with data address
fn create_test_flow_with_data_address(
    id: &str,
    participant_id: &str,
    transfer_type: &str,
    data_address: DataAddress,
) -> DataFlow {
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
        .data_address(data_address)
        .kind(DataFlowType::Provider)
        .build()
}

/// Helper to build transfer type mappings for http-pull tests
fn http_pull_mappings() -> HashMap<String, TransferType> {
    let mut mappings = HashMap::new();
    mappings.insert(
        "http-pull".to_string(),
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    );
    mappings
}

/// Helper to build s3-pull transfer type mappings keyed by a metadata field
fn s3_pull_mappings_with_endpoints() -> HashMap<String, TransferType> {
    let mut mappings = HashMap::new();
    mappings.insert(
        "s3-pull".to_string(),
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![
                EndpointMapping::builder()
                    .key("app".to_string())
                    .value("app1".to_string())
                    .endpoint("https://s3.eu-west-1.amazonaws.com/climate-bucket".to_string())
                    .build(),
                EndpointMapping::builder()
                    .key("app".to_string())
                    .value("app2".to_string())
                    .endpoint("https://s3.us-east-1.amazonaws.com/finance-bucket".to_string())
                    .build(),
            ])
            .build(),
    );
    mappings
}
