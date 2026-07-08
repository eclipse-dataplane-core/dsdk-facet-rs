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

use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::test_fixtures::{
    StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem,
};
use dsdk_facet_core::jwt::{JwkSet, JwkSetProvider, KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use dsdk_facet_core::token::client::TokenClient;
use dsdk_facet_core::token::client::oauth::OAuth2TokenClient;
use dsdk_facet_core::token::manager::{
    JwtTokenManager, MemoryRenewableTokenStore, TokenManager, ValidatedServerSecret,
};
use dsdk_facet_testcontainers::utils::{get_available_port, wait_for_port_ready};
use siglet::handler::refresh::TokenRefreshHandler;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

struct NoOpJwkSetProvider;

#[async_trait::async_trait]
impl JwkSetProvider for NoOpJwkSetProvider {
    async fn jwk_set(&self) -> JwkSet {
        JwkSet { keys: vec![] }
    }
}

const PROVIDER_DID: &str = "did:web:provider.example.com";
const CONSUMER_DID: &str = "did:web:consumer.example.com";
const SERVER_SECRET: &[u8] = b"this_is_exactly_32bytes_long!!!!";

#[tokio::test]
async fn test_token_renewal() {
    // Separate keypairs: provider signs access tokens, consumer signs client auth JWTs
    let provider_keypair = generate_ed25519_keypair_pem().unwrap();
    let consumer_keypair = generate_ed25519_keypair_pem().unwrap();

    // Provider participant context — audience validates aud in the incoming client auth JWT
    let participant_context = ParticipantContext::builder()
        .id("ctx-provider")
        .identifier(PROVIDER_DID)
        .audience(PROVIDER_DID)
        .build();

    // Provider-side token generator: signs access tokens issued to consumers
    let provider_generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(Arc::new(
                StaticSigningKeyResolver::builder()
                    .key(provider_keypair.private_key.clone())
                    .kid("provider-key-1")
                    .key_format(KeyFormat::PEM)
                    .build(),
            ))
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );

    // Verifier resolves the consumer's public key to authenticate renewal requests
    let verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(Arc::new(
                StaticVerificationKeyResolver::builder()
                    .key(consumer_keypair.public_key.clone())
                    .key_format(KeyFormat::PEM)
                    .build(),
            ))
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .leeway_seconds(86400 * 365 * 30)
            .build(),
    );

    let secret = ValidatedServerSecret::try_from(SERVER_SECRET.to_vec()).unwrap();
    let token_manager: Arc<dyn TokenManager> = Arc::new(
        JwtTokenManager::builder()
            .issuer(PROVIDER_DID)
            .refresh_endpoint("http://placeholder/token")
            .server_secret(secret)
            .token_store(Arc::new(MemoryRenewableTokenStore::new()))
            .token_generator(provider_generator)
            .client_verifier(verifier.clone())
            .provider_verifier(verifier)
            .jwk_set_provider(Arc::new(NoOpJwkSetProvider))
            .build(),
    );

    // Issue initial token pair — subject must match OAuth2TokenClient.identifier for sub check in renew()
    let initial_pair = token_manager
        .generate_pair(&participant_context, CONSUMER_DID, HashMap::new(), "flow-1".to_string())
        .await
        .unwrap();

    // Consumer-side generator: signs the client auth JWT presented to the renewal endpoint
    let oauth_client = OAuth2TokenClient::builder()
        .jwt_generator(Arc::new(
            LocalJwtGenerator::builder()
                .signing_key_resolver(Arc::new(
                    StaticSigningKeyResolver::builder()
                        .key(consumer_keypair.private_key.clone())
                        .kid("consumer-key-1")
                        .key_format(KeyFormat::PEM)
                        .build(),
                ))
                .signing_algorithm(SigningAlgorithm::EdDSA)
                .build(),
        ))
        .build();

    // Launch the handler
    let handler = TokenRefreshHandler::builder().token_manager(token_manager).build();

    let port = get_available_port();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, handler.router()).await.unwrap();
    });

    wait_for_port_ready(addr, Duration::from_secs(5)).await.unwrap();

    let refresh_endpoint = format!("http://127.0.0.1:{}/token", port);

    // endpoint_identifier becomes aud in the client auth JWT — must equal participant_context.audience
    let consumer_ctx = ParticipantContext::builder()
        .id("ctx-consumer")
        .identifier(CONSUMER_DID)
        .build();
    let result = oauth_client
        .refresh_token(
            &consumer_ctx,
            PROVIDER_DID,
            &initial_pair.token,
            &initial_pair.refresh_token,
            &refresh_endpoint,
        )
        .await
        .unwrap();

    assert!(!result.token.is_empty());
    assert_ne!(result.token, initial_pair.token);
    assert!(!result.refresh_token.is_empty());
    assert_ne!(result.refresh_token, initial_pair.refresh_token);
}
