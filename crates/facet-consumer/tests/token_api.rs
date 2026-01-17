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

mod common;

use crate::common::setup_postgres_container;
use chrono::{TimeDelta, Utc};
use facet_common::context::ParticipantContext;
use facet_common::jwt::jwtutils::{generate_ed25519_keypair_pem, StaticSigningKeyResolver, StaticVerificationKeyResolver};
use facet_common::jwt::{LocalJwtGenerator, LocalJwtVerifier, JwtVerifier};
use facet_common::util::{default_clock, encryption_key};
use facet_consumer::lock::PostgresLockManager;
use facet_consumer::token::oauth::OAuth2TokenClient;
use facet_consumer::token::{PostgresTokenStore, TokenClientApi, TokenData, TokenStore};
use once_cell::sync::Lazy;
use sodiumoxide::crypto::secretbox;
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const DID: &str = "did:test.com";
const TEST_SALT: &str = "6b9768804c86626227e61acd9e06f8ff";

static TEST_KEY: Lazy<secretbox::Key> =
    Lazy::new(|| encryption_key("test_password", TEST_SALT).expect("Failed to derive test key"));

#[tokio::test]
async fn test_api_end_to_end_with_refresh() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let private_key = keypair.private_key.clone();

    let (pool, _container) = setup_postgres_container().await;
    let lock_manager = Arc::new(PostgresLockManager::builder().pool(pool.clone()).build());
    lock_manager.initialize().await.unwrap();

    let token_store = Arc::new(
        PostgresTokenStore::builder()
            .pool(pool)
            .encryption_key(TEST_KEY.clone())
            .build(),
    );
    token_store.initialize().await.unwrap();

    let signing_key_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(private_key)
            .iss(DID)
            .kid("#key-1")
            .build(),
    );
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(signing_key_resolver)
        .build();
    let token_client = Arc::new(
        OAuth2TokenClient::builder()
            .identifier(DID)
            .jwt_generator(Arc::new(generator))
            .build(),
    );

    let mock_server = MockServer::start().await;

    // Create a bearer token verifier that verifies the JWT signature and claims
    let public_key = keypair.public_key.clone();
    let verification_context = ParticipantContext::builder()
        .identifier("mock-verifier")
        .audience("token1") // Must match the audience in the JWT (endpoint_identifier)
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

    let data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "token1".to_string(),
        token: "old_token".to_string(),
        refresh_token: "old_refresh_token".to_string(),
        expires_at: Utc::now() - TimeDelta::hours(10),
        refresh_endpoint,
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(default_clock())
        .build();

    let pc1 = &ParticipantContext::builder()
        .identifier("participant1")
        .audience("audience1")
        .build();

    let result = token_api.get_token(pc1, "token1", "participant1").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "new_access_token");

    // Test delete_token
    let delete_result = token_api.delete_token("participant1", "token1", "participant1").await;
    assert!(delete_result.is_ok());

    // Verify token is deleted by attempting to retrieve it
    let get_after_delete = token_api.get_token(pc1, "token1", "participant1").await;
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
        let verification_key_resolver = Arc::new(
            StaticVerificationKeyResolver::builder()
                .key(public_key)
                .build()
        );

        let verifier = Arc::new(
            LocalJwtVerifier::builder()
                .verification_key_resolver(verification_key_resolver)
                .build()
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

        // Verify the token
        let claims = match self.verifier.verify_token(&self.participant_context, token) {
            Ok(claims) => claims,
            Err(_) => return false,
        };

        // Verify issuer and subject match the expected DID
        claims.iss == self.expected_did && claims.sub == self.expected_did
    }
}


