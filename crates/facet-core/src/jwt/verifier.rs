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

use crate::jwt::{
    JwtVerificationError, JwtVerifier, KeyFormat, SigningAlgorithm, TokenClaims, VerificationKeyResolver,
};
use async_trait::async_trait;
use bon::Builder;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use std::collections::HashSet;
use std::sync::Arc;

/// Verifies JWTs in-process.
#[derive(Builder)]
pub struct LocalJwtVerifier {
    #[builder(default = 300)] // Five minutes
    leeway_seconds: u64,

    verification_key_resolver: Arc<dyn VerificationKeyResolver>,

    #[builder(default = SigningAlgorithm::EdDSA)]
    signing_algorithm: SigningAlgorithm,
}

impl LocalJwtVerifier {
    async fn load_decoding_key(&self, iss: &str, kid: &str) -> Result<DecodingKey, JwtVerificationError> {
        let key_material = self.verification_key_resolver.resolve_key(iss, kid).await?;
        match (&self.signing_algorithm, key_material.key_format) {
            (SigningAlgorithm::EdDSA, KeyFormat::PEM) => DecodingKey::from_ed_pem(&key_material.key).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to load Ed25519 PEM key: {}", e))
            }),
            (SigningAlgorithm::EdDSA, KeyFormat::DER) => Ok(DecodingKey::from_ed_der(&key_material.key)),
            (SigningAlgorithm::RS256, KeyFormat::PEM) => DecodingKey::from_rsa_pem(&key_material.key)
                .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to load RSA PEM key: {}", e))),
            (SigningAlgorithm::RS256, KeyFormat::DER) => Ok(DecodingKey::from_rsa_der(&key_material.key)),
            (_, KeyFormat::Jwk) => {
                let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_slice(&key_material.key)
                    .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to parse JWK: {}", e)))?;
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
        // Extract kid from header (without verification)
        let header = decode_header(token).map_err(|_| JwtVerificationError::InvalidFormat)?;
        let kid = header.kid.ok_or(JwtVerificationError::InvalidFormat)?;

        // Extract iss from payload (without verification, safe because we verify below)
        let unverified = insecure_decode::<TokenClaims>(token).map_err(|_| JwtVerificationError::InvalidFormat)?;
        let iss = &unverified.claims.iss;

        // Now load the decoding key with the extracted iss and kid
        let decoding_key = self.load_decoding_key(iss, &kid).await?;
        let mut validation = Validation::new(self.signing_algorithm.into());
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
