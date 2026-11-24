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

use super::common::*;
use crate::context::ParticipantContext;
use crate::jwt::test_fixtures::{generate_ed25519_keypair_der, generate_ed25519_keypair_pem, generate_rsa_keypair_pem};
use crate::jwt::transit_key::{MappingTransitKeyResolver, PrefixTransitKeyResolver};
use crate::jwt::{
    JwtGenerationError, JwtGenerator, JwtVerifier, KeyFormat, MemorySigningKeyMappingStore, SigningAlgorithm,
    SigningKeyMapping, SigningKeyMappingRepository, TokenClaims, VaultJwtGenerator,
};
use crate::vault::VaultSigningClient;
use base64::Engine;
use chrono::Utc;
use rstest::rstest;
use serde_json::json;
use std::sync::Arc;

#[rstest]
#[case(KeyFormat::PEM)]
#[case(KeyFormat::DER)]
#[case(KeyFormat::Jwk)]
#[tokio::test]
async fn test_token_generation_validation(#[case] key_format: KeyFormat) {
    // JWK is a verification-only key format. For the JWK case, sign with raw DER
    // and verify with a JWK constructed from the same Ed25519 public key.
    let (keypair, signing_format) = match key_format {
        KeyFormat::PEM => (
            generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair"),
            KeyFormat::PEM,
        ),
        KeyFormat::DER | KeyFormat::Jwk => (
            generate_ed25519_keypair_der().expect("Failed to generate DER keypair"),
            KeyFormat::DER,
        ),
    };

    let generator = create_test_generator(
        keypair.private_key,
        "did:web:example.com#key-1",
        signing_format,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience1")
        .exp(now + 10000)
        .custom(serde_json::Map::from_iter([(
            "access_token".to_string(),
            json!("token-value"),
        )]))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let verification_key = match key_format {
        KeyFormat::Jwk => {
            let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&keypair.public_key);
            serde_json::to_vec(&json!({ "kty": "OKP", "crv": "Ed25519", "x": x }))
                .expect("JWK serialization should succeed")
        }
        _ => keypair.public_key,
    };

    let verifier = create_test_verifier(verification_key, key_format, SigningAlgorithm::EdDSA);
    let verified_claims = verifier
        .verify_token(&pc.audience, &token)
        .await
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-123");
    assert_eq!(verified_claims.iss, "user-id-123");
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(
        verified_claims.custom.get("access_token").expect("access_token claim"),
        &json!("token-value")
    );
}

#[tokio::test]
async fn test_rsa_token_generation_validation_pem() {
    let keypair = generate_rsa_keypair_pem().expect("Failed to generate RSA PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::RS256,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-456")
        .iss("issuer-rsa")
        .aud("audience1")
        .exp(now + 10000)
        .custom(serde_json::Map::from_iter([("scope".to_string(), json!("read:data"))]))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::RS256);
    let verified_claims = verifier
        .verify_token(&pc.audience, &token)
        .await
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-456");
    assert_eq!(verified_claims.iss, "issuer-rsa");
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(verified_claims.custom.get("scope").unwrap(), &json!("read:data"));
}

#[tokio::test]
async fn test_generator_sets_iat_automatically_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let before_generation = Utc::now().timestamp();
    let old_iat = 1609459200; // 2021-01-01 00:00:00 UTC
    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(old_iat) // Generator should overwrite this
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let after_generation = Utc::now().timestamp();

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified_claims = verifier
        .verify_token(&pc.audience, &token)
        .await
        .expect("Token verification should succeed");

    assert_ne!(
        verified_claims.iat, old_iat,
        "Generator should ignore the iat value passed in TokenClaims"
    );
    assert!(
        verified_claims.iat >= before_generation && verified_claims.iat <= after_generation,
        "Generator should set iat to current timestamp. Expected between {} and {}, got {}",
        before_generation,
        after_generation,
        verified_claims.iat
    );
}

#[tokio::test]
async fn test_kid_and_iss_are_set_correctly_in_generated_token() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let expected_iss = "did:web:example.com";
    let expected_kid = "did:web:example.com#key-1";

    let generator = create_test_generator(
        keypair.private_key,
        expected_kid,
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss(expected_iss) // Caller sets iss; generator no longer overrides it
        .aud("audience1")
        .exp(now + 10000)
        .build();

    let pc = ParticipantContext::builder().id("participant1").build();

    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    let header = jsonwebtoken::decode_header(&token).expect("Should be able to decode header");
    assert_eq!(header.kid, Some(expected_kid.to_string()), "kid header should match");

    let unverified_claims = jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(&token)
        .expect("Should be able to decode claims")
        .claims;
    assert_eq!(unverified_claims.iss, expected_iss, "iss claim should match");
}

#[tokio::test]
async fn test_vault_jwt_generator_generates_valid_jwt_structure() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("signing").build()))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts: header.payload.signature");

    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "test-key-1");

    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");
    assert_eq!(payload["sub"], "user-123");
    assert_eq!(payload["aud"], "test-audience");
    assert_eq!(payload["exp"], now + 3600);
    assert!(payload["iat"].is_i64(), "iat should be set");
    assert!(!parts[2].is_empty(), "Signature should not be empty");
}

#[tokio::test]
async fn test_vault_jwt_generator_uses_transformed_key_name_in_kid() {
    let mock_vault = Arc::new(MockVaultSigningClient {
        key_name: "transformed-signing-key".to_string(),
        current_version: 1,
        signature_bytes: vec![0u8; 64],
    });

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("signing").build()))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");
    assert_eq!(
        header["kid"], "transformed-signing-key-1",
        "Kid should use transformed key name"
    );
}

#[tokio::test]
async fn test_vault_jwt_generator_sets_iat_automatically() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("signing").build()))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let before_generation = Utc::now().timestamp();
    let old_iat = 1609459200; // 2021-01-01
    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .iat(old_iat)
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let after_generation = Utc::now().timestamp();

    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");

    let actual_iat = payload["iat"].as_i64().expect("iat should be present");
    assert_ne!(actual_iat, old_iat, "iat should be overwritten");
    assert!(
        actual_iat >= before_generation && actual_iat <= after_generation,
        "iat should be current timestamp, got {}",
        actual_iat
    );
}

#[tokio::test]
async fn test_vault_jwt_generator_with_different_key_versions() {
    let mock_vault = Arc::new(MockVaultSigningClient {
        key_name: "versioned-key".to_string(),
        current_version: 3,
        signature_bytes: vec![0u8; 64],
    });

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("signing").build()))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");
    assert_eq!(header["kid"], "versioned-key-3", "Kid should include version number");
}

#[tokio::test]
async fn test_vault_jwt_generator_preserves_custom_claims() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("test-key"));

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(PrefixTransitKeyResolver::builder().prefix("signing").build()))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .custom(serde_json::Map::from_iter([
            ("scope".to_string(), json!("read:data write:data")),
            ("role".to_string(), json!("admin")),
        ]))
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Failed to parse payload");

    assert_eq!(payload["scope"], "read:data write:data");
    assert_eq!(payload["role"], "admin");
}

#[tokio::test]
async fn test_vault_jwt_generator_uses_mapping_key_name_and_kid_verbatim() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("ignored-key"));

    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    repo.create(
        SigningKeyMapping::builder()
            .participant_context_id("participant-1")
            .key_name("client-signing-participant-1")
            .kid("client-signing-participant-1-explicit")
            .build(),
    )
    .await
    .expect("create should succeed");

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(
            MappingTransitKeyResolver::builder()
                .repo(repo as Arc<dyn SigningKeyMappingRepository>)
                .build(),
        ))
        .build();

    let pc = ParticipantContext::builder()
        .id("participant-1")
        .audience("test-audience")
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let jwt = generator
        .generate_token(&pc, claims)
        .await
        .expect("JWT generation should succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("Failed to parse header");
    assert_eq!(
        header["kid"], "client-signing-participant-1-explicit",
        "kid should be taken verbatim from the mapping, not derived from the Vault version"
    );
}

#[tokio::test]
async fn test_vault_jwt_generator_errors_when_mapping_missing() {
    let mock_vault = Arc::new(MockVaultSigningClient::new("ignored-key"));
    let repo = Arc::new(MemorySigningKeyMappingStore::new());

    let generator = VaultJwtGenerator::builder()
        .signing_client(mock_vault as Arc<dyn VaultSigningClient>)
        .key_resolver(Arc::new(
            MappingTransitKeyResolver::builder()
                .repo(repo as Arc<dyn SigningKeyMappingRepository>)
                .build(),
        ))
        .build();

    let pc = ParticipantContext::builder().id("unmapped-pc").build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 3600)
        .build();

    let err = generator
        .generate_token(&pc, claims)
        .await
        .expect_err("generation should fail without a mapping");

    assert!(
        matches!(err, JwtGenerationError::KeyResolution(_)),
        "expected KeyResolution error, got {err:?}"
    );
}

// ============================================================================
// VaultJwtGenerator — key-type cache
// ============================================================================

mod key_type_cache {
    use crate::context::ParticipantContext;
    use crate::jwt::transit_key::{TransitKeyRef, TransitKeyResolver};
    use crate::jwt::{JwtGenerationError, JwtGenerator, KeyType, SigningAlgorithm, TokenClaims, VaultJwtGenerator};
    use crate::util::clock::MockClock;
    use crate::vault::{KeyMetadata, PublicKeyFormat, VaultError, VaultSigningClient};
    use async_trait::async_trait;
    use chrono::{TimeDelta, Utc};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Vault stand-in whose key type can change (key deleted and re-created), and which rejects
    /// sign requests whose algorithm does not fit the current key type, as Vault does.
    struct SwitchableVault {
        key_type: Mutex<KeyType>,
        metadata_calls: AtomicUsize,
        fail_next_sign: AtomicBool,
    }

    impl SwitchableVault {
        fn new(key_type: KeyType) -> Arc<Self> {
            Arc::new(Self {
                key_type: Mutex::new(key_type),
                metadata_calls: AtomicUsize::new(0),
                fail_next_sign: AtomicBool::new(false),
            })
        }

        fn metadata_calls(&self) -> usize {
            self.metadata_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl VaultSigningClient for SwitchableVault {
        fn signing_key_name(&self) -> Option<&str> {
            None
        }

        async fn get_key_metadata(
            &self,
            _participant_context: &ParticipantContext,
            key_name: &str,
            _format: PublicKeyFormat,
        ) -> Result<KeyMetadata, VaultError> {
            self.metadata_calls.fetch_add(1, Ordering::SeqCst);
            Ok(KeyMetadata {
                key_name: key_name.to_string(),
                key_type: *self.key_type.lock().unwrap(),
                keys: vec![],
                current_version: 1,
            })
        }

        async fn sign_content(
            &self,
            _participant_context: &ParticipantContext,
            _key_name: &str,
            algorithm: SigningAlgorithm,
            _content: &[u8],
        ) -> Result<Vec<u8>, VaultError> {
            if self.fail_next_sign.swap(false, Ordering::SeqCst) {
                return Err(VaultError::NetworkError("simulated failure".to_string()));
            }
            let key_type = *self.key_type.lock().unwrap();
            if !key_type.supports(algorithm) {
                return Err(VaultError::InvalidData(format!(
                    "{} cannot sign with a {} key",
                    algorithm, key_type
                )));
            }
            Ok(vec![0u8; 64])
        }
    }

    /// Resolves `{pc.id}` with a fixed kid, so the generator only needs Vault for the key type.
    struct FixedKidResolver;

    #[async_trait]
    impl TransitKeyResolver for FixedKidResolver {
        async fn resolve(&self, pc: &ParticipantContext) -> Result<TransitKeyRef, JwtGenerationError> {
            Ok(TransitKeyRef {
                key_name: pc.id.clone(),
                kid: Some(format!("{}#key-1", pc.id)),
                algorithm: None,
            })
        }
    }

    fn generator(vault: &Arc<SwitchableVault>, clock: &Arc<MockClock>) -> VaultJwtGenerator {
        VaultJwtGenerator::builder()
            .signing_client(vault.clone() as Arc<dyn VaultSigningClient>)
            .key_resolver(Arc::new(FixedKidResolver))
            .clock(clock.clone())
            .key_type_cache_ttl(TimeDelta::minutes(10))
            .build()
    }

    fn pc(id: &str) -> ParticipantContext {
        ParticipantContext::builder().id(id).audience("aud").build()
    }

    fn claims() -> TokenClaims {
        TokenClaims::builder()
            .sub("sub")
            .aud("aud")
            .exp(Utc::now().timestamp() + 300)
            .build()
    }

    fn header_alg(token: &str) -> String {
        format!("{:?}", jsonwebtoken::decode_header(token).unwrap().alg)
    }

    #[tokio::test]
    async fn key_type_is_cached_within_ttl() {
        let vault = SwitchableVault::new(KeyType::Ed25519);
        let clock = Arc::new(MockClock::new(Utc::now()));
        let generator = generator(&vault, &clock);

        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        clock.advance(TimeDelta::minutes(9));
        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();

        assert_eq!(vault.metadata_calls(), 1);
    }

    #[tokio::test]
    async fn key_type_is_reread_after_ttl() {
        let vault = SwitchableVault::new(KeyType::Ed25519);
        let clock = Arc::new(MockClock::new(Utc::now()));
        let generator = generator(&vault, &clock);

        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        clock.advance(TimeDelta::minutes(11));
        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();

        assert_eq!(vault.metadata_calls(), 2);
    }

    #[tokio::test]
    async fn signing_failure_evicts_the_cached_key_type() {
        let vault = SwitchableVault::new(KeyType::Ed25519);
        let clock = Arc::new(MockClock::new(Utc::now()));
        let generator = generator(&vault, &clock);

        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        vault.fail_next_sign.store(true, Ordering::SeqCst);
        assert!(generator.generate_token(&pc("pc-1"), claims()).await.is_err());
        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();

        assert_eq!(
            vault.metadata_calls(),
            2,
            "the call after the failure must re-read the key type"
        );
    }

    #[tokio::test]
    async fn recreated_key_with_another_type_recovers_after_one_failure() {
        let vault = SwitchableVault::new(KeyType::Ed25519);
        let clock = Arc::new(MockClock::new(Utc::now()));
        let generator = generator(&vault, &clock);

        let token = generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        assert_eq!(header_alg(&token), "EdDSA");

        // The key is deleted and re-created as ECDSA P-256 under the same name.
        *vault.key_type.lock().unwrap() = KeyType::EcdsaP256;

        // The stale cached type makes this sign request fail...
        assert!(generator.generate_token(&pc("pc-1"), claims()).await.is_err());
        // ...which evicts it, so the next one picks up the new type.
        let token = generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        assert_eq!(header_alg(&token), "ES256");
    }

    #[tokio::test]
    async fn expired_entries_are_swept() {
        let vault = SwitchableVault::new(KeyType::Ed25519);
        let clock = Arc::new(MockClock::new(Utc::now()));
        let generator = generator(&vault, &clock);

        generator.generate_token(&pc("pc-1"), claims()).await.unwrap();
        generator.generate_token(&pc("pc-2"), claims()).await.unwrap();
        assert_eq!(generator.cached_key_count(), 2);

        clock.advance(TimeDelta::minutes(11));
        generator.generate_token(&pc("pc-3"), claims()).await.unwrap();

        assert_eq!(generator.cached_key_count(), 1, "only pc-3's entry should remain");
    }
}
