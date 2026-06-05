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
    JwtGenerationError, JwtGenerator, JwtVerificationError, KeyFormat, KeyMaterial, SigningAlgorithm,
    SigningKeyResolver, TokenClaims, VerificationKeyResolver,
};
use crate::util::clock::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{EncodingKey, Header, encode};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::Rng;
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
        match (&self.signing_algorithm, key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => EncodingKey::from_ed_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load Ed25519 PEM key: {}", e))),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(EncodingKey::from_ed_der(key_bytes)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => EncodingKey::from_rsa_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(EncodingKey::from_rsa_der(key_bytes)),
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
