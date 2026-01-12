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

#[cfg(test)]
mod tests;

pub mod jwtutils;

use crate::context::ParticipantContext;
use bon::Builder;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;

/// JWT token claims structure.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct TokenClaims {
    #[builder(into)]
    pub sub: String,
    #[builder(default)]
    #[builder(into)]
    pub iss: String,
    #[builder(into)]
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[builder(default)]
    #[serde(flatten)]
    pub custom: Map<String, Value>,
}

/// Generates a JWT using the key material associated with a participant context.
pub trait JwtGenerator: Send + Sync {
    fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        claims: TokenClaims,
    ) -> Result<String, JwtGenerationError>;
}

/// Errors that can occur during JWT generation.
#[derive(Debug, Error)]
pub enum JwtGenerationError {
    #[error("Failed to generate token: {0}")]
    GenerationError(String),
}

/// Verifies a JWT and validates claims for the participant context.
///
/// Note that verification does not check the value of the `iss` and `sub` claims. Clients should enforce requirements
/// for these claims as needed.
pub trait JwtVerifier: Send + Sync {
    fn verify_token(
        &self,
        participant_context: &ParticipantContext,
        token: &str,
    ) -> Result<TokenClaims, JwtVerificationError>;
}

/// Errors that can occur during JWT verification.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is not yet valid")]
    TokenNotYetValid,

    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Verification error: {0}")]
    VerificationFailed(String),
}

/// Signing algorithms supported by the JWT generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EdDSA,
    RS256,
}

/// Supported key formats.
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

/// Resolves signing keys for the participant context.
pub trait SigningKeyResolver: Send + Sync {
    fn resolve_key(&self, participant_context: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError>;
}

#[derive(Builder, Clone)]
pub struct KeyMaterial {
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,

    pub key: Vec<u8>,

    #[builder(into)]
    pub iss: String,

    #[builder(into)]
    pub kid: String,
}

/// JWT generator for creating and verifying JWTs in-process.
#[derive(Builder)]
pub struct LocalJwtGenerator {
    signing_key_resolver: Arc<dyn SigningKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,
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
        }
    }
}

impl JwtGenerator for LocalJwtGenerator {
    fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        let key_result = self.signing_key_resolver.resolve_key(participant_context)?;

        let algorithm = self.signing_algorithm.into();
        let encoding_key = self.load_encoding_key(&key_result.key_format, &key_result.key)?;
        let mut theader = Header::new(algorithm);
        theader.kid = Some(key_result.kid);
        let mut claims = TokenClaims { ..claims.clone() };
        claims.iss = key_result.iss;

        encode(&theader, &claims, &encoding_key)
            .map_err(|e| JwtGenerationError::GenerationError(format!("JWT encoding failed: {}", e)))
    }
}

/// Resolves public keys for JWT verification.
pub trait VerificationKeyResolver: Send + Sync {
    fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError>;
}

/// Verifies JWTs in-process.
#[derive(Builder)]
pub struct LocalJwtVerifier {
    #[builder(default = 300)] // Five minutes
    leeway_seconds: u64, // JWT exp claim is in seconds

    verification_key_resolver: Arc<dyn VerificationKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,
}

impl LocalJwtVerifier {
    fn load_decoding_key(&self, iss: &str, kid: &str) -> Result<DecodingKey, JwtVerificationError> {
        let key_material = self.verification_key_resolver.resolve_key(iss, kid)?;
        match (&self.signing_algorithm, key_material.key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => DecodingKey::from_ed_pem(&key_material.key).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to load Ed25519 PEM key: {}", e))
            }),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(DecodingKey::from_ed_der(&key_material.key)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => DecodingKey::from_rsa_pem(&key_material.key)
                .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(DecodingKey::from_rsa_der(&key_material.key)),
        }
    }
}

impl JwtVerifier for LocalJwtVerifier {
    fn verify_token(
        &self,
        participant_context: &ParticipantContext,
        token: &str,
    ) -> Result<TokenClaims, JwtVerificationError> {
        // Extract kid from header (without verification)
        let header = decode_header(token).map_err(|_| JwtVerificationError::InvalidFormat)?;

        let kid = header.kid.ok_or_else(|| JwtVerificationError::InvalidFormat)?;

        // Extract iss from payload (without verification, safe because we verify below)
        let unverified = insecure_decode::<TokenClaims>(token).map_err(|_| JwtVerificationError::InvalidFormat)?;

        let iss = &unverified.claims.iss;

        // Now load the decoding key with the extracted iss and kid
        let decoding_key = self.load_decoding_key(iss, &kid)?;
        let mut validation = Validation::new(self.signing_algorithm.into());
        validation.leeway = self.leeway_seconds;
        validation.validate_nbf = true; // Enable not-before validation
        validation.aud = Some(HashSet::from([participant_context.audience.clone()]));

        // Perform the actual cryptographic verification with the correct key
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => JwtVerificationError::TokenExpired,
            ErrorKind::ImmatureSignature => JwtVerificationError::TokenNotYetValid,
            ErrorKind::InvalidSignature => JwtVerificationError::InvalidSignature,
            ErrorKind::InvalidToken => JwtVerificationError::InvalidFormat,
            ErrorKind::InvalidKeyFormat => JwtVerificationError::VerificationFailed("Invalid key format".to_string()),
            _ => JwtVerificationError::VerificationFailed(e.to_string()),
        })?;

        Ok(token_data.claims)
    }
}
