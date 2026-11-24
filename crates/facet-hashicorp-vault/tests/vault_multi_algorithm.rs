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

//! End-to-end check of every supported Vault key type × JWS algorithm combination.
//!
//! For each case a transit key of the given type is created in a real Vault, a JWT is signed via
//! `VaultJwtGenerator`, and the token is verified twice:
//! - with `LocalJwtVerifier` backed by `VaultVerificationKeyResolver` (the siglet path), and
//! - with plain `jsonwebtoken` using the JWK published by the resolver's JWKS (the path an
//!   external data plane takes).
//!
//! Mocks cannot catch mistakes in Vault's sign parameters (RSA padding, PSS salt length, ECDSA
//! signature marshaling, base64 variant), so this test exercises them against Vault itself.

#![allow(clippy::unwrap_used)]

use base64::Engine;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{
    JwkSetProvider, JwtGenerator, JwtVerifier, KeyType, LocalJwtVerifier, PrefixTransitKeyResolver, SigningAlgorithm,
    TokenClaims, VaultJwtGenerator, VaultVerificationKeyResolver,
};
use dsdk_facet_core::vault::VaultSigningClient;
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use dsdk_facet_testcontainers::{
    keycloak::setup_keycloak_container, utils::create_network, vault::setup_vault_container,
};
use std::sync::Arc;

const KEY_PREFIX: &str = "jwt";
const AUDIENCE: &str = "test-audience";

const CASES: &[(KeyType, SigningAlgorithm)] = &[
    (KeyType::Ed25519, SigningAlgorithm::EdDSA),
    (KeyType::EcdsaP256, SigningAlgorithm::ES256),
    (KeyType::EcdsaP384, SigningAlgorithm::ES384),
    (KeyType::Rsa2048, SigningAlgorithm::RS256),
    (KeyType::Rsa2048, SigningAlgorithm::PS256),
    (KeyType::Rsa3072, SigningAlgorithm::RS384),
    (KeyType::Rsa3072, SigningAlgorithm::PS384),
    (KeyType::Rsa4096, SigningAlgorithm::RS512),
    (KeyType::Rsa4096, SigningAlgorithm::PS512),
];

fn context(id: &str) -> ParticipantContext {
    ParticipantContext {
        id: id.to_string(),
        identifier: "test-identifier".to_string(),
        audience: AUDIENCE.to_string(),
    }
}

#[tokio::test]
async fn test_sign_and_verify_all_algorithms() {
    let network = create_network().await;
    let (keycloak_setup, _keycloak_container) = setup_keycloak_container(&network).await;
    let jwks_url = format!(
        "{}/realms/master/protocol/openid-connect/certs",
        keycloak_setup.keycloak_internal_url
    );
    let (vault_url, _root_token, _vault_container) =
        setup_vault_container(&network, &jwks_url, &keycloak_setup.keycloak_container_id).await;

    for &(key_type, algorithm) in CASES {
        // One transit key per case: "{KEY_PREFIX}-{pc.id}", e.g. "jwt-rsa-2048-ps256".
        let pc_id = format!("{}-{}", key_type, algorithm.as_str().to_lowercase());
        let key_name = format!("{}-{}", KEY_PREFIX, pc_id);
        let ctx = context(&pc_id);
        let label = format!("{} / {}", key_type, algorithm);

        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .auth_config(VaultAuthConfig::OAuth2 {
                client_id: keycloak_setup.client_id.clone(),
                client_secret: keycloak_setup.client_secret.clone(),
                token_url: keycloak_setup.token_url.clone(),
                role: None,
            })
            .signing_key_name(key_name.clone())
            .signing_key_type(key_type)
            .build();
        let mut client = HashicorpVaultClient::new(config).unwrap();
        client
            .initialize()
            .await
            .unwrap_or_else(|e| panic!("{label}: init failed: {e}"));
        let client: Arc<dyn VaultSigningClient> = Arc::new(client);

        // Sign.
        let generator = VaultJwtGenerator::builder()
            .signing_client(Arc::clone(&client))
            .key_resolver(Arc::new(
                PrefixTransitKeyResolver::builder()
                    .prefix(KEY_PREFIX)
                    .algorithm(algorithm)
                    .build(),
            ))
            .build();
        let now = chrono::Utc::now().timestamp();
        let claims = TokenClaims::builder()
            .sub("test-subject")
            .iss("test-issuer")
            .aud(AUDIENCE)
            .exp(now + 300)
            .build();
        let token = generator
            .generate_token(&ctx, claims)
            .await
            .unwrap_or_else(|e| panic!("{label}: signing failed: {e}"));

        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], algorithm.as_str(), "{label}: header alg");
        assert_eq!(header["kid"], format!("{}-1", key_name), "{label}: header kid");

        // Verify through the resolver (the siglet path).
        let resolver = Arc::new(
            VaultVerificationKeyResolver::builder()
                .vault_client(Arc::clone(&client))
                .signing_context(ctx.clone())
                .algorithm(algorithm)
                .build(),
        );
        resolver
            .initialize()
            .await
            .unwrap_or_else(|e| panic!("{label}: resolver init failed: {e}"));
        let verifier = LocalJwtVerifier::builder()
            .verification_key_resolver(resolver.clone())
            .build();
        let verified = verifier
            .verify_token(AUDIENCE, &token)
            .await
            .unwrap_or_else(|e| panic!("{label}: LocalJwtVerifier rejected the token: {e}"));
        assert_eq!(verified.sub, "test-subject", "{label}");

        // An allowlist that excludes the algorithm must reject the token.
        let restricted = LocalJwtVerifier::builder()
            .verification_key_resolver(resolver.clone())
            .allowed_algorithms(SigningAlgorithm::ALL.into_iter().filter(|a| *a != algorithm).collect())
            .build();
        assert!(
            restricted.verify_token(AUDIENCE, &token).await.is_err(),
            "{label}: token accepted although its algorithm is not allowed"
        );

        // Verify independently with jsonwebtoken from the published JWK (the external path).
        let jwks = resolver.jwk_set().await;
        assert_eq!(jwks.keys.len(), 1, "{label}: one key version expected");
        let published = &jwks.keys[0];
        assert_eq!(published.alg.as_deref(), Some(algorithm.as_str()), "{label}: JWK alg");
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::to_value(published).unwrap())
            .unwrap_or_else(|e| panic!("{label}: published JWK is not a valid JWK: {e}"));
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(algorithm.into());
        validation.set_audience(&[AUDIENCE]);
        jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
            .unwrap_or_else(|e| panic!("{label}: jsonwebtoken rejected the token: {e}"));
    }
}
