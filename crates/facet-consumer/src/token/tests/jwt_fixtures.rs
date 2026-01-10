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

use crate::token::JwtGenerationError;
use ed25519_dalek::SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::Rng;
use rsa::rand_core::OsRng as RsaOsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};


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
