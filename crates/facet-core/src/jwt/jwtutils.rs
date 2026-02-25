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

use crate::context::ParticipantContext;
use crate::jwt::{
    JwtGenerationError, JwtVerificationError, KeyFormat, KeyMaterial, SigningKeyResolver, VerificationKeyResolver,
};
use crate::vault::VaultClient;
use async_trait::async_trait;
use bon::Builder;
use ed25519_dalek::SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::Rng;
use rsa::rand_core::OsRng as RsaOsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;

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

/// Generates an Ed25519 keypair for DER format.
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

#[derive(Builder)]
pub struct StaticVerificationKeyResolver {
    pub key: Vec<u8>,
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,
}

impl VerificationKeyResolver for StaticVerificationKeyResolver {
    fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        Ok(KeyMaterial::builder()
            .key(self.key.clone())
            .key_format(self.key_format)
            .iss(iss)
            .kid(kid)
            .build())
    }
}

#[derive(Builder)]
pub struct StaticSigningKeyResolver {
    pub key: Vec<u8>,

    #[builder(into)]
    pub iss: String,

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
            .iss(self.iss.clone())
            .kid(self.kid.clone())
            .build())
    }
}

/// A signing key resolver that retrieves keys from a VaultClient.
///
/// This resolver delegates to a VaultClient to fetch signing keys at runtime.
/// The vault stores a JSON-serialized `SigningKeyRecord` containing the
/// private key, its identifier (kid), and key format.
/// The issuer (iss) is derived from the participant context's identifier field.
#[derive(Builder)]
pub struct VaultSigningKeyResolver {
    /// The vault client to use for resolving keys
    vault_client: Arc<dyn VaultClient>,

    /// Base path in the vault where keys are stored
    #[builder(into)]
    base_path: String,
}

#[async_trait]
impl SigningKeyResolver for VaultSigningKeyResolver {
    async fn resolve_key(&self, participant_context: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError> {
        let json_str = self
            .vault_client
            .resolve_secret(participant_context, &self.base_path)
            .await
            .map_err(|e| {
                JwtGenerationError::GenerationError(format!("Failed to resolve signing key from vault: {}", e))
            })?;

        let record: SigningKeyRecord = serde_json::from_str(&json_str).map_err(|e| {
            JwtGenerationError::GenerationError(format!("Failed to deserialize SigningKeyRecord: {}", e))
        })?;

        Ok(KeyMaterial::builder()
            .key_format(record.key_format)
            .key(record.private_key.into_bytes())
            .iss(participant_context.identifier.clone())
            .kid(record.kid)
            .build())
    }
}

/// A record containing a private signing key and its identifier.
///
/// This structure is stored in the vault as JSON.
#[derive(Debug, Clone, Builder, serde::Serialize, serde::Deserialize)]
pub struct SigningKeyRecord {
    /// The private key in the configured format (PEM or DER)
    #[builder(into)]
    pub private_key: String,

    /// The key identifier (kid)
    #[builder(into)]
    pub kid: String,

    /// The format of the private key (PEM or DER)
    #[builder(default = KeyFormat::PEM)]
    pub key_format: KeyFormat,
}
