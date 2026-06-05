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

pub mod did;
pub mod generator;
pub mod jwk;
pub mod resolver;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_fixtures;
pub mod verifier;

pub use did::DidWebVerificationKeyResolver;
#[cfg(test)]
pub(crate) use did::{DidDocument, VerificationMethod};
pub use generator::VaultJwtGenerator;
pub use jwk::{Jwk, JwkKeyOperation, JwkKeyType, JwkPublicKeyUse, JwkSet};
pub use resolver::VaultVerificationKeyResolver;
#[cfg(any(test, feature = "test-fixtures"))]
pub use test_fixtures::{LocalJwtGenerator, StaticSigningKeyResolver, StaticVerificationKeyResolver};
pub use verifier::LocalJwtVerifier;

use crate::context::ParticipantContext;
use crate::vault::VaultError;
use async_trait::async_trait;
use bon::Builder;
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// JWT token claims structure.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
#[allow(clippy::should_implement_trait)]
pub struct TokenClaims {
    #[builder(into)]
    pub sub: String,
    #[builder(default)]
    #[builder(into)]
    pub iss: String,
    #[builder(into)]
    pub aud: String,
    #[builder(default)]
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[builder(default)]
    #[serde(flatten)]
    pub custom: Map<String, Value>,
}

/// Generates a JWT using the key material associated with a participant context.
#[async_trait]
pub trait JwtGenerator: Send + Sync {
    async fn generate_token(
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

    #[error("Vault error during token generation: {0}")]
    VaultError(#[from] VaultError),
}

/// Verifies a JWT and validates claims for the participant context.
///
/// Note that verification does not check the value of the `iss` and `sub` claims. Clients should enforce requirements
/// for these claims as needed.
#[async_trait]
pub trait JwtVerifier: Send + Sync {
    async fn verify_token(&self, audience: &str, token: &str) -> Result<TokenClaims, JwtVerificationError>;
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

    #[error("General error: {0}")]
    GeneralError(String),
}

/// Signing algorithms supported by the JWT generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    EdDSA,
    RS256,
}

/// Supported key formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[async_trait]
pub trait SigningKeyResolver: Send + Sync {
    async fn resolve_key(&self, participant_context: &ParticipantContext) -> Result<KeyMaterial, JwtGenerationError>;
}

#[derive(Debug, Builder, Clone)]
pub struct KeyMaterial {
    #[builder(default = KeyFormat::PEM)]
    key_format: KeyFormat,

    pub key: Vec<u8>,

    #[builder(into)]
    pub kid: String,
}

/// Resolves public keys for JWT verification.
#[async_trait]
pub trait VerificationKeyResolver: Send + Sync {
    async fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError>;
}

/// Provides a JSON Web Key Set (JWKS) containing the public keys used for token verification.
#[async_trait]
pub trait JwkSetProvider: Send + Sync {
    async fn jwk_set(&self) -> JwkSet;
}
