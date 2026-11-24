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

use crate::jwt::keys::check_jwk_algorithm;
use crate::jwt::{
    JwtVerificationError, JwtVerifier, KeyFamily, KeyFormat, SigningAlgorithm, TokenClaims, VerificationKeyResolver,
};
use async_trait::async_trait;
use bon::Builder;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use std::collections::HashSet;
use std::sync::Arc;

/// Verifies JWTs in-process.
///
/// The token's `alg` header is checked against an allowlist *before* the key is resolved, and
/// then against the resolved key (its [`KeyType`] when known, or the JWK's `kty`/`crv`/`alg`).
/// This prevents algorithm-confusion attacks, including HS256 tokens "signed" with a public key
/// or with a symmetric JWK published in a DID document.
///
/// [`KeyType`]: crate::jwt::KeyType
#[derive(Builder)]
pub struct LocalJwtVerifier {
    #[builder(default = 300)] // Five minutes
    leeway_seconds: u64,

    verification_key_resolver: Arc<dyn VerificationKeyResolver>,

    /// Algorithms accepted on incoming tokens. Defaults to every [`SigningAlgorithm`].
    #[builder(default = SigningAlgorithm::ALL.to_vec())]
    allowed_algorithms: Vec<SigningAlgorithm>,

    /// Restricts verification to exactly this algorithm, overriding `allowed_algorithms`.
    signing_algorithm: Option<SigningAlgorithm>,
}

impl LocalJwtVerifier {
    fn is_allowed(&self, algorithm: SigningAlgorithm) -> bool {
        match self.signing_algorithm {
            Some(only) => only == algorithm,
            None => self.allowed_algorithms.contains(&algorithm),
        }
    }

    async fn load_decoding_key(
        &self,
        iss: &str,
        kid: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<DecodingKey, JwtVerificationError> {
        let key_material = self.verification_key_resolver.resolve_key(iss, kid).await?;

        if let Some(key_type) = key_material.key_type
            && !key_type.supports(algorithm)
        {
            return Err(JwtVerificationError::VerificationFailed(format!(
                "Algorithm {} cannot be used with key '{}' of type {}",
                algorithm, kid, key_type
            )));
        }

        let key = &key_material.key;
        match (algorithm.family(), key_material.key_format) {
            (KeyFamily::Ed25519, KeyFormat::PEM) => DecodingKey::from_ed_pem(key).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to load Ed25519 PEM key: {}", e))
            }),
            (KeyFamily::Ed25519, KeyFormat::DER) => Ok(DecodingKey::from_ed_der(key)),
            (KeyFamily::Rsa, KeyFormat::PEM) => DecodingKey::from_rsa_pem(key)
                .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to load RSA PEM key: {}", e))),
            (KeyFamily::Rsa, KeyFormat::DER) => Ok(DecodingKey::from_rsa_der(key)),
            (KeyFamily::Ec, KeyFormat::PEM) => DecodingKey::from_ec_pem(key)
                .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to load EC PEM key: {}", e))),
            (KeyFamily::Ec, KeyFormat::DER) => Ok(DecodingKey::from_ec_der(key)),
            (_, KeyFormat::Jwk) => {
                let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_slice(key)
                    .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to parse JWK: {}", e)))?;

                check_jwk_algorithm(&jwk, algorithm)
                    .map_err(|e| JwtVerificationError::VerificationFailed(format!("Key '{}': {}", kid, e)))?;

                DecodingKey::from_jwk(&jwk).map_err(|e| {
                    JwtVerificationError::VerificationFailed(format!("Failed to load JWK decoding key: {}", e))
                })
            }
        }
    }
}

#[async_trait]
impl JwtVerifier for LocalJwtVerifier {
    async fn verify_token(&self, audience: &str, token: &str) -> Result<TokenClaims, JwtVerificationError> {
        // Extract alg and kid from header (without verification)
        let header = decode_header(token).map_err(|_| JwtVerificationError::InvalidFormat)?;

        // Pin the algorithm to the allowlist before touching any key material.
        let algorithm = SigningAlgorithm::try_from(header.alg)
            .ok()
            .filter(|alg| self.is_allowed(*alg))
            .ok_or_else(|| {
                JwtVerificationError::VerificationFailed(format!("Algorithm {:?} is not allowed", header.alg))
            })?;

        let kid = header.kid.ok_or(JwtVerificationError::InvalidFormat)?;

        // Extract iss from payload (without verification, safe because we verify below)
        let unverified = insecure_decode::<TokenClaims>(token).map_err(|_| JwtVerificationError::InvalidFormat)?;
        let iss = &unverified.claims.iss;

        // Now load the decoding key with the extracted iss and kid
        let decoding_key = self.load_decoding_key(iss, &kid, algorithm).await?;

        let mut validation = Validation::new(algorithm.into());
        validation.leeway = self.leeway_seconds;
        validation.validate_nbf = true;
        validation.aud = Some(HashSet::from([audience.to_string()]));

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
