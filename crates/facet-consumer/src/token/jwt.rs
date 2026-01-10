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

use crate::token::{JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use bon::Builder;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::sync::Arc;

/// Signing algorithms supported by the JWT generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EdDSA,
    RS256,
}

/// Key formats supported by the JWT generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    PEM,
    DER,
}

impl From<SigningAlgorithm> for Algorithm {
    fn from(algo: SigningAlgorithm) -> Self {
        match algo {
            SigningAlgorithm::EdDSA => Self::EdDSA,
            SigningAlgorithm::RS256 => Self::RS256,
        }
    }
}

/// JWT generator for creating and verifying JWT tokens in-process.
#[derive(Builder)]
pub struct LocalJwtGenerator {
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,

    signing_key_resolver: Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,
}

impl LocalJwtGenerator {
    fn load_encoding_key(&self, key_bytes: &[u8]) -> Result<EncodingKey, JwtGenerationError> {
        match (&self.signing_algorithm, &self.key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => EncodingKey::from_ed_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load Ed25519 PEM key: {}", e))),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(EncodingKey::from_ed_der(key_bytes)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => EncodingKey::from_rsa_pem(key_bytes)
                .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(EncodingKey::from_rsa_der(key_bytes)),
        }
    }
}

impl JwtGenerator for LocalJwtGenerator {
    fn generate_token(&self, participant_context: &str, claims: TokenClaims) -> Result<String, JwtGenerationError> {
        let key_bytes = (self.signing_key_resolver)(participant_context);
        let algorithm = self.signing_algorithm.into();
        let encoding_key = self.load_encoding_key(&key_bytes)?;

        encode(&Header::new(algorithm), &claims, &encoding_key)
            .map_err(|e| JwtGenerationError::GenerationError(format!("JWT encoding failed: {}", e)))
    }
}

/// Resolves public keys for JWT verification.
pub trait VerificationKeyResolver: Send + Sync {
    fn resolve_verification_key(&self, iss: &str, kid: &str) -> Result<Vec<u8>, JwtVerificationError>;
}

/// Verifies JWTs in-process.
#[derive(Builder)]
pub struct LocalJwtVerifier {
    #[builder(default = 300)] // Five minutes
    leeway_seconds: u64, // JWT exp claim is in seconds

    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,

    verification_key_resolver: Arc<dyn VerificationKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,
}

impl LocalJwtVerifier {
    fn load_decoding_key(&self, iss: &str, kid: &str) -> Result<DecodingKey, JwtVerificationError> {
        // TODO pass in DID and
        let key_bytes = self.verification_key_resolver.resolve_verification_key(iss, kid)?;
        match (&self.signing_algorithm, &self.key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => DecodingKey::from_ed_pem(&key_bytes).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to load Ed25519 PEM key: {}", e))
            }),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(DecodingKey::from_ed_der(&key_bytes)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => DecodingKey::from_rsa_pem(&key_bytes)
                .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(DecodingKey::from_rsa_der(&key_bytes)),
        }
    }
}

impl JwtVerifier for LocalJwtVerifier {
    fn verify_token(&self, _participant_context: &str, token: &str) -> Result<TokenClaims, JwtVerificationError> {
        // TODO parse and pass in DID and KID
        let decoding_key = self.load_decoding_key("", "")?;
        let mut validation = Validation::new(self.signing_algorithm.into());
        validation.leeway = self.leeway_seconds;

        // FIXME remove when participant context is handled
        validation.validate_aud = false;

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => JwtVerificationError::TokenExpired,
            ErrorKind::InvalidSignature => JwtVerificationError::InvalidSignature,
            ErrorKind::InvalidToken => JwtVerificationError::InvalidFormat,
            ErrorKind::InvalidKeyFormat => JwtVerificationError::VerificationFailed("Invalid key format".to_string()),
            _ => JwtVerificationError::VerificationFailed(e.to_string()),
        })?;

        // TODO validate audience using participant_context as a resolver
        Ok(token_data.claims)
    }
}
