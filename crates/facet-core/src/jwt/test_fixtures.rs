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

//! Test fixtures for JWT signing and key management.
//!
//! Contains in-process signing (`LocalJwtGenerator`), static key resolvers,
//! and keypair generators. Only available under `#[cfg(test)]` or the
//! `test-fixtures` feature flag.

use crate::context::ParticipantContext;
use crate::jwt::{
    JwtGenerationError, JwtGenerator, JwtVerificationError, KeyFamily, KeyFormat, KeyMaterial, SigningAlgorithm,
    SigningKeyResolver, TokenClaims, VerificationKeyResolver,
};
use crate::util::clock::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{EncodingKey, Header, encode};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::RngExt;
use rsa::rand_core::OsRng as RsaOsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;

// ============================================================================
// Static key resolvers
// ============================================================================

#[derive(Builder)]
pub struct StaticVerificationKeyResolver {
    pub key: Vec<u8>,
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,
}

#[async_trait]
impl VerificationKeyResolver for StaticVerificationKeyResolver {
    async fn resolve_key(&self, _iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        Ok(KeyMaterial::builder()
            .key(self.key.clone())
            .key_format(self.key_format)
            .kid(kid)
            .build())
    }
}

#[derive(Builder)]
pub struct StaticSigningKeyResolver {
    pub key: Vec<u8>,

    #[builder(into)]
    pub kid: String,

    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,
}

#[async_trait]
impl SigningKeyResolver for StaticSigningKeyResolver {
    async fn resolve_key(&self, _: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError> {
        Ok(KeyMaterial::builder()
            .key_format(self.key_format)
            .key(self.key.clone())
            .kid(self.kid.clone())
            .build())
    }
}

// ============================================================================
// LocalJwtGenerator
// ============================================================================

/// JWT generator that signs tokens in-process using a local private key.
///
/// For testing only — production signing must use Vault transit (`VaultJwtGenerator`).
#[derive(Builder)]
pub struct LocalJwtGenerator {
    signing_key_resolver: Arc<dyn SigningKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,

    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl LocalJwtGenerator {
    fn load_encoding_key(&self, key_format: &KeyFormat, key_bytes: &[u8]) -> Result<EncodingKey, JwtGenerationError> {
        match (self.signing_algorithm.family(), key_format) {
            (KeyFamily::Ed25519, KeyFormat::PEM) => EncodingKey::from_ed_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load Ed25519 PEM key: {}", e))),
            (KeyFamily::Ed25519, KeyFormat::DER) => Ok(EncodingKey::from_ed_der(key_bytes)),
            (KeyFamily::Rsa, KeyFormat::PEM) => EncodingKey::from_rsa_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load RSA PEM key: {}", e))),
            (KeyFamily::Rsa, KeyFormat::DER) => Ok(EncodingKey::from_rsa_der(key_bytes)),
            (KeyFamily::Ec, KeyFormat::PEM) => EncodingKey::from_ec_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load EC PEM key: {}", e))),
            (KeyFamily::Ec, KeyFormat::DER) => Ok(EncodingKey::from_ec_der(key_bytes)),
            (_, KeyFormat::Jwk) => Err(JwtGenerationError::GenerationError(
                "JWK key format is verification-only; signing from JWK is not supported".to_string(),
            )),
        }
    }
}

#[async_trait]
impl JwtGenerator for LocalJwtGenerator {
    async fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        mut claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        let key_result = self.signing_key_resolver.resolve_key(participant_context).await?;

        let algorithm = self.signing_algorithm.into();
        let encoding_key = self.load_encoding_key(&key_result.key_format, &key_result.key)?;
        let mut header = Header::new(algorithm);
        header.kid = Some(key_result.kid);
        claims.iat = self.clock.now().timestamp();
        encode(&header, &claims, &encoding_key)
            .map_err(|e| JwtGenerationError::GenerationError(format!("JWT encoding failed: {}", e)))
    }
}

// ============================================================================
// Keypair types and generators
// ============================================================================

#[derive(Debug, Clone)]
pub struct Ed25519Keypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RsaKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Generates an RSA keypair and returns both private and public keys in PKCS#8 PEM format.
pub fn generate_rsa_keypair_pem() -> Result<RsaKeypair, JwtGenerationError> {
    let bits = 2048;
    let private_key_obj = RsaPrivateKey::new(&mut RsaOsRng, bits)
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to generate RSA key: {}", e)))?;

    let private_key = private_key_obj
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem_doc| pem_doc.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode private key: {}", e)))?;

    let public_key_obj = RsaPublicKey::from(&private_key_obj);
    let public_key = public_key_obj
        .to_public_key_pem(LineEnding::LF)
        .map(|pem| pem.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode public key: {}", e)))?;

    Ok(RsaKeypair {
        private_key,
        public_key,
    })
}

/// Generates an Ed25519 keypair from a fixed 32-byte seed (deterministic).
/// Use this in tests to produce a stable key pair across process restarts.
pub fn generate_ed25519_keypair_der_from_seed(seed: &[u8; 32]) -> Result<Ed25519Keypair, JwtGenerationError> {
    let signing_key = SigningKey::from_bytes(seed);
    let private_key = signing_key
        .to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode private key: {}", e)))?;
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();
    Ok(Ed25519Keypair {
        private_key,
        public_key,
    })
}

/// Generates an Ed25519 keypair in DER format.
pub fn generate_ed25519_keypair_der() -> Result<Ed25519Keypair, JwtGenerationError> {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);

    let private_key = signing_key
        .to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode private key: {}", e)))?;

    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    Ok(Ed25519Keypair {
        private_key,
        public_key,
    })
}

/// Generates an Ed25519 keypair and returns both private and public keys in PKCS#8 PEM format.
pub fn generate_ed25519_keypair_pem() -> Result<Ed25519Keypair, JwtGenerationError> {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);

    let private_key = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem_doc| pem_doc.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode private key: {}", e)))?;

    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key
        .to_public_key_pem(Default::default())
        .map(|pem| pem.as_bytes().to_vec())
        .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to encode public key: {}", e)))?;

    Ok(Ed25519Keypair {
        private_key,
        public_key,
    })
}

// ============================================================================
// Static EC keypairs
// ============================================================================

/// An EC keypair: PKCS#8 PEM private key and SPKI PEM public key.
#[derive(Debug, Clone)]
pub struct EcKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl EcKeypair {
    /// The public key as DER `SubjectPublicKeyInfo` (the PEM body, base64-decoded).
    pub fn public_key_der(&self) -> Vec<u8> {
        use base64::Engine;
        let pem = String::from_utf8_lossy(&self.public_key);
        let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap_or_default()
    }
}

// Fixed test-only keys (generated with `openssl genpkey -algorithm EC`). Generating EC keys at
// runtime would require an extra curve-arithmetic dependency for test code only.
const EC_P256_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoQnEkby8TSQY2+9f\nRwK+S+6mtxtABBCql9yXZpXRUW6hRANCAARieKPVZZPtpt0Fx1o5Yk++vq2fNRp+\n3c1aHndiua65xxce/l5gVVZVt6xpzVxBUr5+t3by49TKPc0UNtpKFBh5\n-----END PRIVATE KEY-----";
const EC_P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYnij1WWT7abdBcdaOWJPvr6tnzUa\nft3NWh53YrmuuccXHv5eYFVWVbesac1cQVK+frd28uPUyj3NFDbaShQYeQ==\n-----END PUBLIC KEY-----";
const EC_P384_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDUk792UeHihxCnXiW8\nM7XiCOdCILx+kcmIOKR5tUWdGfQ5tQHtdHQwsRWSmGda34+hZANiAAQo1fdqRPd+\nsb2954Zvm1yHA8oMrfR6Vm0J1EmXp7V+mznWMYT/snG9qzcbJS55jW5i3P5n2Eo7\nk61nuTzuZa7Ko3lO/3K6RH/AWsXkIdT/V/mN3b2UtN2p0DdGQhCCK8A=\n-----END PRIVATE KEY-----";
const EC_P384_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEKNX3akT3frG9veeGb5tchwPKDK30elZt\nCdRJl6e1fps51jGE/7Jxvas3GyUueY1uYtz+Z9hKO5OtZ7k87mWuyqN5Tv9yukR/\nwFrF5CHU/1f5jd29lLTdqdA3RkIQgivA\n-----END PUBLIC KEY-----";

/// A fixed P-256 keypair for ES256 tests. Not secret; never use outside tests.
pub fn ec_p256_keypair_pem() -> EcKeypair {
    EcKeypair {
        private_key: EC_P256_PRIVATE_PEM.as_bytes().to_vec(),
        public_key: EC_P256_PUBLIC_PEM.as_bytes().to_vec(),
    }
}

/// A fixed P-384 keypair for ES384 tests. Not secret; never use outside tests.
pub fn ec_p384_keypair_pem() -> EcKeypair {
    EcKeypair {
        private_key: EC_P384_PRIVATE_PEM.as_bytes().to_vec(),
        public_key: EC_P384_PUBLIC_PEM.as_bytes().to_vec(),
    }
}
