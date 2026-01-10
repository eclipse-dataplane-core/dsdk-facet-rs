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

use crate::token::jwt::LocalJwtGenerator;
use crate::token::oauth::OAuth2TokenClient;
use crate::token::tests::jwt_fixtures::generate_ed25519_keypair_pem;
use crate::token::TokenClient;
use std::sync::Arc;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_refresh_token_success() {
    let mock_server = MockServer::start().await;

    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let private_key = keypair.private_key.clone();

    let jwt_generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(Arc::new(move |_| private_key.clone()))
            .build(),
    );

    let client = OAuth2TokenClient::builder()
        .identifier("test-client".to_string())
        .jwt_generator(jwt_generator)
        .build();

    Mock::given(method("POST"))
        .and(path("/token/refresh"))
        .and(query_param("grant_type", "refresh_token"))
        .and(query_param("refresh_token", "old_refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let refresh_endpoint = format!("{}/token/refresh", mock_server.uri());
    let token_data = client
        .refresh_token(
            "test-participant",
            "test-identifier",
            "old_refresh_token",
            &refresh_endpoint,
        )
        .await
        .expect("Token refresh should succeed");

    assert_eq!(token_data.participant_context, "test-participant");
    assert_eq!(token_data.identifier, "test-identifier");
    assert_eq!(token_data.token, "new_access_token");
    assert_eq!(token_data.refresh_token, "new_refresh_token");
    assert_eq!(token_data.refresh_endpoint, refresh_endpoint);
}
