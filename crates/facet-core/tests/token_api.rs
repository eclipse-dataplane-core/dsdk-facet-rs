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
use chrono::{TimeDelta, Utc};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::test_fixtures::{
    StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem,
};
use dsdk_facet_core::jwt::{JwtVerifier, LocalJwtGenerator, LocalJwtVerifier};
use dsdk_facet_core::lock::MemoryLockManager;
use dsdk_facet_core::token::client::oauth::OAuth2TokenClient;
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenClientApi, TokenData, TokenStore};
use dsdk_facet_core::util::clock::default_clock;
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const DID: &str = "did:test.com";

#[tokio::test]
async fn test_api_end_to_end_with_refresh() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let private_key = keypair.private_key.clone();

    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());

    let signing_key_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(private_key)
            .kid("#key-1")
            .build(),
    );
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(signing_key_resolver)
        .build();
    let token_client = Arc::new(OAuth2TokenClient::builder().jwt_generator(Arc::new(generator)).build());

    let mock_server = MockServer::start().await;

    // Create a bearer token verifier that verifies the JWT signature and claims
    let public_key = keypair.public_key.clone();
    let verification_context = ParticipantContext::builder()
        .id("mock-verifier")
        .audience("counter-party-1") // Must match the audience in the JWT (endpoint_identifier)
        .build();
    let bearer_verifier = BearerTokenVerifier::new(public_key, verification_context, DID.to_string());

    Mock::given(method("POST"))
        .and(path("/token/refresh"))
        .and(bearer_verifier)
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=old_refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let refresh_endpoint = format!("{}/token/refresh", mock_server.uri());

    let data = TokenData::builder()
        .participant_context("participant1")
        .participant_id(DID)
        .counter_party_id("counter-party-1")
        .identifier("token1")
        .token("old_token")
        .refresh_token("old_refresh_token")
        .expires_at(Utc::now() - TimeDelta::hours(10))
        .refresh_endpoint(refresh_endpoint)
        .endpoint("https://provider.example.com/data/asset-1")
        .build();
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(default_clock())
        .build();

    let pc1 = ParticipantContext::builder()
        .id("participant1")
        .identifier(DID)
        .audience("audience1")
        .build();

    let result = token_api.get_token(&pc1, "token1", "participant1").await;
    dbg!(&result);
    assert!(result.is_ok());
    let token_result = result.unwrap();
    assert_eq!(token_result.token, "new_access_token");
    assert_eq!(token_result.endpoint, "https://provider.example.com/data/asset-1");

    // Test delete_token
    let delete_result = token_api.delete_token("participant1", "token1", "participant1").await;
    assert!(delete_result.is_ok());

    // Verify token is deleted by attempting to retrieve it
    let get_after_delete = token_api.get_token(&pc1, "token1", "participant1").await;
    assert!(get_after_delete.is_err());
}

/// Custom matcher that verifies the bearer token in the Authorization header
struct BearerTokenVerifier {
    verifier: Arc<LocalJwtVerifier>,
    participant_context: ParticipantContext,
    expected_did: String,
}

impl BearerTokenVerifier {
    fn new(public_key: Vec<u8>, participant_context: ParticipantContext, expected_did: String) -> Self {
        let verification_key_resolver = Arc::new(StaticVerificationKeyResolver::builder().key(public_key).build());

        let verifier = Arc::new(
            LocalJwtVerifier::builder()
                .verification_key_resolver(verification_key_resolver)
                .build(),
        );

        Self {
            verifier,
            participant_context,
            expected_did,
        }
    }
}

impl Match for BearerTokenVerifier {
    fn matches(&self, request: &Request) -> bool {
        // Extract the Authorization header
        let auth_header = match request.headers.get("authorization") {
            Some(header) => header.to_str().unwrap_or(""),
            None => return false,
        };

        // Extract the bearer token
        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return false,
        };

        // Verify the token. Wiremock's Match trait is sync, so bridge via a dedicated thread
        // with its own runtime to avoid nested-runtime panics.
        let verifier = self.verifier.clone();
        let audience = self.participant_context.audience.clone();
        let token_str = token.to_string();
        let claims = match std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(verifier.verify_token(&audience, &token_str))
        })
        .join()
        .unwrap_or(Err(dsdk_facet_core::jwt::JwtVerificationError::VerificationFailed(
            "thread join failed".to_string(),
        ))) {
            Ok(claims) => claims,
            Err(_) => return false,
        };

        // Verify issuer and subject match the expected DID
        claims.iss == self.expected_did && claims.sub == self.expected_did
    }
}
