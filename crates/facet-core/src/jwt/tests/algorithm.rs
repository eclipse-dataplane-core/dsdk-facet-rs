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

use super::common::{create_test_generator, create_test_verifier};
use crate::context::ParticipantContext;
use crate::jwt::keys::{check_jwk_algorithm, public_key_to_jwk};
use crate::jwt::test_fixtures::{
    StaticVerificationKeyResolver, ec_p256_keypair_pem, ec_p384_keypair_pem, generate_ed25519_keypair_der,
    generate_rsa_keypair_pem,
};
use crate::jwt::{
    AlgorithmError, JwkKeyType, JwtGenerator, JwtVerificationError, JwtVerifier, KeyFormat, KeyType, LocalJwtVerifier,
    SigningAlgorithm, TokenClaims,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rstest::rstest;
use std::sync::Arc;

const AUDIENCE: &str = "audience";

fn claims() -> TokenClaims {
    TokenClaims::builder()
        .sub("subject")
        .iss("issuer")
        .aud(AUDIENCE)
        .exp(Utc::now().timestamp() + 300)
        .build()
}

fn pc() -> ParticipantContext {
    ParticipantContext::builder().id("pc").build()
}

/// The RSA public key in DER `SubjectPublicKeyInfo` (PEM body, base64-decoded).
fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    let pem = String::from_utf8_lossy(pem);
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

fn jwk_verifier(jwk: &crate::jwt::Jwk) -> LocalJwtVerifier {
    LocalJwtVerifier::builder()
        .verification_key_resolver(Arc::new(
            StaticVerificationKeyResolver::builder()
                .key(serde_json::to_vec(jwk).unwrap())
                .key_format(KeyFormat::Jwk)
                .build(),
        ))
        .build()
}

// ---------------------------------------------------------------------------
// Algorithm / key type model
// ---------------------------------------------------------------------------

#[test]
fn algorithm_round_trips_through_str_and_serde() {
    for alg in SigningAlgorithm::ALL {
        assert_eq!(alg.as_str().parse::<SigningAlgorithm>().unwrap(), alg);
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, format!("\"{}\"", alg.as_str()));
        assert_eq!(serde_json::from_str::<SigningAlgorithm>(&json).unwrap(), alg);
        let jwt_alg: jsonwebtoken::Algorithm = alg.into();
        assert_eq!(SigningAlgorithm::try_from(jwt_alg).unwrap(), alg);
    }
}

#[rstest]
#[case("HS256")]
#[case("ES512")]
#[case("none")]
#[case("eddsa")]
fn unsupported_algorithms_are_rejected(#[case] alg: &str) {
    assert!(alg.parse::<SigningAlgorithm>().is_err());
}

#[test]
fn symmetric_jsonwebtoken_algorithms_are_not_mapped() {
    for alg in [
        jsonwebtoken::Algorithm::HS256,
        jsonwebtoken::Algorithm::HS384,
        jsonwebtoken::Algorithm::HS512,
    ] {
        assert!(SigningAlgorithm::try_from(alg).is_err());
    }
}

#[test]
fn key_type_parses_vault_types() {
    for kt in KeyType::ALL {
        assert_eq!(kt.as_str().parse::<KeyType>().unwrap(), kt);
    }
    for unsupported in ["ecdsa-p521", "aes256-gcm96", "hmac", "ml-dsa"] {
        assert!(matches!(
            unsupported.parse::<KeyType>(),
            Err(AlgorithmError::UnsupportedKeyType(_))
        ));
    }
}

#[rstest]
#[case(KeyType::Ed25519, SigningAlgorithm::EdDSA)]
#[case(KeyType::EcdsaP256, SigningAlgorithm::ES256)]
#[case(KeyType::EcdsaP384, SigningAlgorithm::ES384)]
#[case(KeyType::Rsa2048, SigningAlgorithm::RS256)]
#[case(KeyType::Rsa3072, SigningAlgorithm::RS256)]
#[case(KeyType::Rsa4096, SigningAlgorithm::RS256)]
fn key_type_default_algorithm(#[case] key_type: KeyType, #[case] expected: SigningAlgorithm) {
    assert_eq!(key_type.default_algorithm(), expected);
    assert_eq!(key_type.resolve_algorithm(None).unwrap(), expected);
}

#[test]
fn key_type_compatibility_matrix() {
    use SigningAlgorithm::*;
    let rsa = [RS256, RS384, RS512, PS256, PS384, PS512];
    for alg in SigningAlgorithm::ALL {
        assert_eq!(KeyType::Ed25519.supports(alg), alg == EdDSA, "ed25519/{alg}");
        assert_eq!(KeyType::EcdsaP256.supports(alg), alg == ES256, "p256/{alg}");
        assert_eq!(KeyType::EcdsaP384.supports(alg), alg == ES384, "p384/{alg}");
        for kt in [KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096] {
            assert_eq!(kt.supports(alg), rsa.contains(&alg), "{kt}/{alg}");
        }
    }
}

#[test]
fn resolve_algorithm_rejects_incompatible_request() {
    assert_eq!(
        KeyType::Rsa2048
            .resolve_algorithm(Some(SigningAlgorithm::PS384))
            .unwrap(),
        SigningAlgorithm::PS384
    );
    assert!(matches!(
        KeyType::EcdsaP256.resolve_algorithm(Some(SigningAlgorithm::ES384)),
        Err(AlgorithmError::Incompatible { .. })
    ));
    assert!(matches!(
        KeyType::Ed25519.resolve_algorithm(Some(SigningAlgorithm::RS256)),
        Err(AlgorithmError::Incompatible { .. })
    ));
}

// ---------------------------------------------------------------------------
// Public key → JWK
// ---------------------------------------------------------------------------

#[test]
fn ed25519_public_key_to_jwk() {
    let keypair = generate_ed25519_keypair_der().unwrap();
    let jwk = public_key_to_jwk(KeyType::Ed25519, &keypair.public_key, "kid-1", SigningAlgorithm::EdDSA).unwrap();
    assert_eq!(jwk.kty, JwkKeyType::Okp);
    assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
    assert_eq!(jwk.x, Some(URL_SAFE_NO_PAD.encode(&keypair.public_key)));
    assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
    assert_eq!(jwk.kid.as_deref(), Some("kid-1"));
}

#[test]
fn rsa_public_key_to_jwk() {
    let keypair = generate_rsa_keypair_pem().unwrap();
    let der = pem_to_der(&keypair.public_key);
    let jwk = public_key_to_jwk(KeyType::Rsa2048, &der, "kid-1", SigningAlgorithm::PS256).unwrap();
    assert_eq!(jwk.kty, JwkKeyType::Rsa);
    assert_eq!(jwk.e.as_deref(), Some("AQAB"));
    // 2048-bit modulus = 256 bytes = 342 base64url chars (no padding).
    assert_eq!(jwk.n.as_ref().map(String::len), Some(342));
    assert_eq!(jwk.alg.as_deref(), Some("PS256"));
}

#[rstest]
#[case(KeyType::EcdsaP256, SigningAlgorithm::ES256, "P-256", 43)]
#[case(KeyType::EcdsaP384, SigningAlgorithm::ES384, "P-384", 64)]
fn ec_public_key_to_jwk(
    #[case] key_type: KeyType,
    #[case] alg: SigningAlgorithm,
    #[case] crv: &str,
    #[case] coordinate_b64_len: usize,
) {
    let keypair = match key_type {
        KeyType::EcdsaP256 => ec_p256_keypair_pem(),
        _ => ec_p384_keypair_pem(),
    };
    let jwk = public_key_to_jwk(key_type, &keypair.public_key_der(), "kid-1", alg).unwrap();
    assert_eq!(jwk.kty, JwkKeyType::Ec);
    assert_eq!(jwk.crv.as_deref(), Some(crv));
    assert_eq!(jwk.x.as_ref().map(String::len), Some(coordinate_b64_len));
    assert_eq!(jwk.y.as_ref().map(String::len), Some(coordinate_b64_len));
}

#[test]
fn public_key_to_jwk_rejects_mismatched_key() {
    // P-384 key bytes declared as P-256.
    let p384 = ec_p384_keypair_pem().public_key_der();
    assert!(public_key_to_jwk(KeyType::EcdsaP256, &p384, "kid", SigningAlgorithm::ES256).is_err());
    // EC key bytes declared as RSA.
    assert!(public_key_to_jwk(KeyType::Rsa2048, &p384, "kid", SigningAlgorithm::RS256).is_err());
    // Incompatible algorithm.
    let ed = generate_ed25519_keypair_der().unwrap().public_key;
    assert!(public_key_to_jwk(KeyType::Ed25519, &ed, "kid", SigningAlgorithm::ES256).is_err());
}

// ---------------------------------------------------------------------------
// Sign + verify round trips
// ---------------------------------------------------------------------------

#[rstest]
#[case(SigningAlgorithm::RS256)]
#[case(SigningAlgorithm::RS384)]
#[case(SigningAlgorithm::RS512)]
#[case(SigningAlgorithm::PS256)]
#[case(SigningAlgorithm::PS384)]
#[case(SigningAlgorithm::PS512)]
#[tokio::test]
async fn rsa_round_trip_pem_and_jwk(#[case] alg: SigningAlgorithm) {
    let keypair = generate_rsa_keypair_pem().unwrap();
    let token = create_test_generator(keypair.private_key, "kid", KeyFormat::PEM, alg)
        .generate_token(&pc(), claims())
        .await
        .unwrap();

    let pem_verifier = create_test_verifier(keypair.public_key.clone(), KeyFormat::PEM, alg);
    pem_verifier.verify_token(AUDIENCE, &token).await.unwrap();

    let jwk = public_key_to_jwk(KeyType::Rsa2048, &pem_to_der(&keypair.public_key), "kid", alg).unwrap();
    jwk_verifier(&jwk).verify_token(AUDIENCE, &token).await.unwrap();
}

#[rstest]
#[case(KeyType::EcdsaP256, SigningAlgorithm::ES256)]
#[case(KeyType::EcdsaP384, SigningAlgorithm::ES384)]
#[tokio::test]
async fn ec_round_trip_pem_and_jwk(#[case] key_type: KeyType, #[case] alg: SigningAlgorithm) {
    let keypair = match key_type {
        KeyType::EcdsaP256 => ec_p256_keypair_pem(),
        _ => ec_p384_keypair_pem(),
    };
    let token = create_test_generator(keypair.private_key.clone(), "kid", KeyFormat::PEM, alg)
        .generate_token(&pc(), claims())
        .await
        .unwrap();

    let pem_verifier = create_test_verifier(keypair.public_key.clone(), KeyFormat::PEM, alg);
    pem_verifier.verify_token(AUDIENCE, &token).await.unwrap();

    let jwk = public_key_to_jwk(key_type, &keypair.public_key_der(), "kid", alg).unwrap();
    jwk_verifier(&jwk).verify_token(AUDIENCE, &token).await.unwrap();
}

// ---------------------------------------------------------------------------
// Verifier rejections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifier_rejects_algorithm_outside_allowlist() {
    let keypair = ec_p256_keypair_pem();
    let token = create_test_generator(
        keypair.private_key.clone(),
        "kid",
        KeyFormat::PEM,
        SigningAlgorithm::ES256,
    )
    .generate_token(&pc(), claims())
    .await
    .unwrap();
    let jwk = public_key_to_jwk(
        KeyType::EcdsaP256,
        &keypair.public_key_der(),
        "kid",
        SigningAlgorithm::ES256,
    )
    .unwrap();

    let verifier = LocalJwtVerifier::builder()
        .verification_key_resolver(Arc::new(
            StaticVerificationKeyResolver::builder()
                .key(serde_json::to_vec(&jwk).unwrap())
                .key_format(KeyFormat::Jwk)
                .build(),
        ))
        .allowed_algorithms(vec![SigningAlgorithm::EdDSA, SigningAlgorithm::RS256])
        .build();
    let err = verifier.verify_token(AUDIENCE, &token).await.unwrap_err();
    assert!(matches!(err, JwtVerificationError::VerificationFailed(msg) if msg.contains("not allowed")));

    // `signing_algorithm` pins a single algorithm and overrides the allowlist.
    let pinned = LocalJwtVerifier::builder()
        .verification_key_resolver(Arc::new(
            StaticVerificationKeyResolver::builder()
                .key(serde_json::to_vec(&jwk).unwrap())
                .key_format(KeyFormat::Jwk)
                .build(),
        ))
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();
    assert!(pinned.verify_token(AUDIENCE, &token).await.is_err());
}

/// A DID document that publishes a symmetric (`oct`) JWK must not let anyone forge HS256 tokens
/// with the (public) key value.
#[tokio::test]
async fn verifier_rejects_hs256_with_symmetric_jwk() {
    let secret = b"this-secret-is-published-in-a-did-document";
    let oct_jwk = serde_json::json!({
        "kty": "oct",
        "kid": "kid",
        "k": URL_SAFE_NO_PAD.encode(secret),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("kid".to_string());
    let forged = jsonwebtoken::encode(&header, &claims(), &jsonwebtoken::EncodingKey::from_secret(secret)).unwrap();

    let verifier = LocalJwtVerifier::builder()
        .verification_key_resolver(Arc::new(
            StaticVerificationKeyResolver::builder()
                .key(serde_json::to_vec(&oct_jwk).unwrap())
                .key_format(KeyFormat::Jwk)
                .build(),
        ))
        .build();
    assert!(verifier.verify_token(AUDIENCE, &forged).await.is_err());
}

#[tokio::test]
async fn verifier_rejects_alg_that_does_not_match_jwk() {
    // An RSA key whose JWK pins PS256 must not accept an RS256 token, even with a valid signature.
    let keypair = generate_rsa_keypair_pem().unwrap();
    let token = create_test_generator(keypair.private_key, "kid", KeyFormat::PEM, SigningAlgorithm::RS256)
        .generate_token(&pc(), claims())
        .await
        .unwrap();
    let jwk = public_key_to_jwk(
        KeyType::Rsa2048,
        &pem_to_der(&keypair.public_key),
        "kid",
        SigningAlgorithm::PS256,
    )
    .unwrap();
    let err = jwk_verifier(&jwk).verify_token(AUDIENCE, &token).await.unwrap_err();
    assert!(matches!(err, JwtVerificationError::VerificationFailed(msg) if msg.contains("JWK alg")));
}

#[test]
fn check_jwk_algorithm_enforces_curve() {
    let p256 = public_key_to_jwk(
        KeyType::EcdsaP256,
        &ec_p256_keypair_pem().public_key_der(),
        "kid",
        SigningAlgorithm::ES256,
    )
    .unwrap();
    let mut jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::to_value(&p256).unwrap()).unwrap();
    jwk.common.key_algorithm = None;
    assert!(check_jwk_algorithm(&jwk, SigningAlgorithm::ES256).is_ok());
    assert!(check_jwk_algorithm(&jwk, SigningAlgorithm::ES384).is_err());
    assert!(check_jwk_algorithm(&jwk, SigningAlgorithm::RS256).is_err());
    assert!(check_jwk_algorithm(&jwk, SigningAlgorithm::EdDSA).is_err());
}
