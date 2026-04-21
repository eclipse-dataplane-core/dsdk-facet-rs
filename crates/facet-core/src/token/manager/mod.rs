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

mod mem;

#[cfg(test)]
mod tests;

pub use mem::MemoryRenewableTokenStore;
use std::collections::HashMap;
use std::sync::Arc;

use crate::context::ParticipantContext;
use crate::jwt;
use crate::jwt::{JwkSet, JwkSetProvider, JwtVerifier, TokenClaims};
use crate::token::TokenError;
use crate::util::clock::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use jwt::JwtGenerator;
use rand::RngCore;
use serde_json::{Map, Value};
use sha2::Sha256;
use uuid::Uuid;

/// Minimum required length for server secret (256 bits for HMAC-SHA256)
const MIN_SECRET_LENGTH: usize = 32;

/// A server secret that has been validated to meet minimum security requirements.
///
/// Can only be constructed via `TryFrom<Vec<u8>>`, which enforces the minimum length.
pub struct ValidatedServerSecret(Vec<u8>);

impl ValidatedServerSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

impl std::fmt::Debug for ValidatedServerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValidatedServerSecret([REDACTED])")
    }
}

impl PartialEq for ValidatedServerSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Vec<u8>> for ValidatedServerSecret {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl TryFrom<Vec<u8>> for ValidatedServerSecret {
    type Error = TokenError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() < MIN_SECRET_LENGTH {
            return Err(TokenError::general_error(format!(
                "Server secret must be at least {} bytes, got {}",
                MIN_SECRET_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self(bytes))
    }
}

/// Reserved JWT claim names that cannot be overridden by custom claims
const RESERVED_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "iat", "nbf", "jti"];

/// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Trait `TokenManager` defines an interface for managing token-based authentication mechanisms,
/// providing functionality for generating and renewing token pairs
#[async_trait]
pub trait TokenManager: Send + Sync {
    async fn generate_pair(
        &self,
        participant_context: &ParticipantContext,
        subject: &str,
        claims: HashMap<String, Value>,
        flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError>;

    async fn renew(&self, bound_token: &str, refresh_token: &str) -> Result<RenewableTokenPair, TokenError>;

    async fn revoke_token(&self, participant_context: &ParticipantContext, flow_id: &str) -> Result<(), TokenError>;

    async fn validate_token(&self, audience: &str, token: &str) -> Result<TokenClaims, TokenError>;

    async fn jwk_set(&self) -> Result<JwkSet, TokenError>;
}

/// A struct representing a pair of tokens used for authentication and periodic renewal.
///
/// The `RenewableTokenPair` struct contains the necessary information for managing authentication tokens,
/// including the main token, a refresh token, an expiration timestamp, and the endpoint for obtaining new tokens.
///
/// # Attributes
///
/// * `token` (`String`): The primary token used for authentication.
/// * `refresh_token` (`String`): A token used to obtain a new primary token when the current one expires.
/// * `expires_at` (`DateTime<Utc>`): The timestamp indicating when the primary token will expire.
///   This is represented in UTC time.
/// * `refresh_endpoint` (`String`): The URL endpoint where the refresh token can be exchanged for a new token pair.
///
#[derive(Builder, Debug, Clone, PartialEq, Eq)]
pub struct RenewableTokenPair {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_endpoint: String,
}

/// Represents an entry for a renewable token used in authentication and session management.
///
/// This struct holds information about an authentication token, its corresponding hashed
/// refresh token, and its expiration time.
///
/// # Fields
/// - `id`:
///   A unique identifier for this token entry, typically a UUID or JTI (JWT ID).
///
/// - `token`:
///   The current authentication token in use. This is typically a JWT or a similar token
///   format, represented as a `String`.
///
/// - `hashed_refresh_token`:
///   The hashed version of the refresh token. This is used to securely store the refresh
///   token and verify it when provided by clients requesting a token renewal.
///
/// - `expires_at`:
///   The timestamp indicating when the authentication token expires.
///
/// - `subject`:
///   The subject (sub) associated with this token, identifying the principal.
///
/// - `claims`:
///   Additional claims associated with the token, stored as key-value pairs.
///
/// - `flow_id`:
///   An identifier for the flow or session associated with this token.
#[derive(Clone, Debug, Builder)]
pub struct RenewableTokenEntry {
    #[builder(into)]
    pub id: String,
    #[builder(into)]
    pub token: String,
    #[builder(into)]
    pub hashed_refresh_token: String,
    pub expires_at: DateTime<Utc>,
    #[builder(into)]
    pub subject: String, // the counter-party that the token is issued to
    pub claims: HashMap<String, Value>,
    #[builder(into)]
    pub participant_context_id: String, // the participant context that the token is valid for
    #[builder(into)]
    pub audience: String, // the participant context audience, e.g. its DID
    #[builder(into)]
    pub flow_id: String,
}

/// Stores renewable token pairs.
#[async_trait]
pub trait RenewableTokenStore: Send + Sync {
    async fn save(&self, entry: RenewableTokenEntry) -> Result<(), TokenError>;

    async fn find_by_renewal(&self, hash: &str) -> Result<RenewableTokenEntry, TokenError>;

    async fn find_by_id(&self, id: &str) -> Result<RenewableTokenEntry, TokenError>;

    async fn find_by_flow_id(&self, flow_id: &str) -> Result<RenewableTokenEntry, TokenError>;

    async fn remove_by_flow_id(&self, flow_id: &str) -> Result<(), TokenError>;

    async fn update(&self, old_hash: &str, new_entry: RenewableTokenEntry) -> Result<(), TokenError>;
}

#[derive(Builder)]
pub struct JwtTokenManager {
    #[builder(into)]
    issuer: String,
    /// Short stable ID used to derive the signing key name via `JwtGenerator`.
    /// Defaults to `issuer` when not set.
    #[builder(into)]
    issuer_id: Option<String>,
    #[builder(into)]
    refresh_endpoint: String,
    server_secret: ValidatedServerSecret,
    #[builder(default = 3600)]
    token_duration: i64,
    #[builder(default = 172800)]
    renewal_token_duration: i64,
    #[builder(default = 32)]
    refresh_token_bytes: usize,
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
    token_store: Arc<dyn RenewableTokenStore>,
    token_generator: Arc<dyn JwtGenerator>,
    client_verifier: Arc<dyn JwtVerifier>,
    provider_verifier: Arc<dyn JwtVerifier>,
    jwk_set_provider: Arc<dyn JwkSetProvider>,
}

impl JwtTokenManager {
    /// Validates that custom claims don't contain reserved JWT claim names
    fn validate_custom_claims(claims: &HashMap<String, Value>) -> Result<(), TokenError> {
        for reserved in RESERVED_CLAIMS {
            if claims.contains_key(*reserved) {
                return Err(TokenError::general_error(format!(
                    "Custom claims cannot contain reserved claim: {}",
                    reserved
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn create_renewal_token(&self) -> Result<(String, String), TokenError> {
        // Generate the refresh token using cryptographically secure random bytes
        let mut refresh_token_bytes = vec![0u8; self.refresh_token_bytes];
        rand::rng().fill_bytes(&mut refresh_token_bytes);
        let refresh_token = hex::encode(&refresh_token_bytes);

        let hash = self.hash(&refresh_token)?;
        Ok((refresh_token, hash))
    }

    pub(crate) fn hash(&self, token: &str) -> Result<String, TokenError> {
        let mut mac = HmacSha256::new_from_slice(self.server_secret.as_bytes())
            .map_err(|_| TokenError::general_error("Invalid server secret"))?;
        mac.update(token.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn create_claims(&self, aud: &str, jti: &str, subject: &str, claims: &HashMap<String, Value>) -> TokenClaims {
        let mut custom: Map<String, Value> = claims.clone().into_iter().collect();
        custom.insert("jti".to_string(), Value::String(jti.to_string()));

        TokenClaims::builder()
            .iss(self.issuer.clone())
            .sub(subject)
            .aud(aud)
            .exp(self.clock.now().timestamp() + self.token_duration)
            .custom(custom)
            .build()
    }

    /// Builds the participant context representing this token manager's issuer.
    /// Used to select the correct signing key via `JwtGenerator`.
    fn issuer_context(&self) -> ParticipantContext {
        let id = self.issuer_id.as_deref().unwrap_or(&self.issuer);
        ParticipantContext::builder().id(id).identifier(&self.issuer).build()
    }

    fn renewal_expiration(&self) -> Result<DateTime<Utc>, TokenError> {
        let expires_at = DateTime::from_timestamp(self.clock.now().timestamp() + self.renewal_token_duration, 0)
            .ok_or_else(|| {
                TokenError::general_error("Failed to calculate token expiration time - timestamp is out of valid range")
            })?;
        Ok(expires_at)
    }
}

#[async_trait]
impl TokenManager for JwtTokenManager {
    async fn generate_pair(
        &self,
        participant_context: &ParticipantContext,
        subject: &str,
        claims: HashMap<String, Value>,
        flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        // Validate custom claims don't override reserved JWT claims
        Self::validate_custom_claims(&claims)?;

        let jti = Uuid::new_v4().to_string();
        let aud = participant_context.audience.as_str();
        let token_claims = self.create_claims(aud, &jti, subject, &claims);

        // Use the Siglet issuer context for issuing and signing the token
        let issuer_context = &self.issuer_context();
        let token = self
            .token_generator
            .generate_token(issuer_context, token_claims)
            .await?;

        let (refresh_token, hashed_refresh_token) = self.create_renewal_token()?;

        let expires_at = self.renewal_expiration()?;

        // Create and save the renewable token entry
        let entry = RenewableTokenEntry::builder()
            .id(jti)
            .token(token.clone())
            .hashed_refresh_token(hashed_refresh_token)
            .expires_at(expires_at)
            .subject(subject)
            .claims(claims)
            .participant_context_id(participant_context.id.clone())
            .audience(participant_context.audience.clone())
            .flow_id(flow_id)
            .build();

        self.token_store.save(entry).await?;

        Ok(RenewableTokenPair {
            token,
            refresh_token,
            expires_at,
            refresh_endpoint: self.refresh_endpoint.clone(),
        })
    }

    async fn renew(&self, bound_token: &str, refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        let hashed = self.hash(refresh_token)?;
        let entry = self
            .token_store
            .find_by_renewal(&hashed)
            .await
            .map_err(|_| TokenError::NotAuthorized("Invalid refresh token".to_string()))?;

        let verified_claims = self.client_verifier.verify_token(&entry.audience, bound_token).await?;
        if verified_claims.sub != entry.subject {
            return Err(TokenError::NotAuthorized("Subject mismatch".to_string()));
        }

        let embedded_token = verified_claims
            .custom
            .get("token")
            .ok_or_else(|| TokenError::NotAuthorized("Missing token claim".to_string()))?;
        if embedded_token != entry.token.as_str() {
            return Err(TokenError::NotAuthorized("Invalid token".to_string()));
        }

        let new_expires_at = self.renewal_expiration()?;

        let (new_refresh_token, new_hashed) = self.create_renewal_token()?;

        let new_jti = Uuid::new_v4().to_string();
        let aud = entry.audience.as_str();
        let new_claims = self.create_claims(aud, &new_jti, verified_claims.sub.as_str(), &entry.claims);

        let token = self
            .token_generator
            .generate_token(&self.issuer_context(), new_claims)
            .await?;

        let new_entry = RenewableTokenEntry::builder()
            .id(new_jti)
            .token(token.clone())
            .hashed_refresh_token(new_hashed)
            .expires_at(new_expires_at)
            .subject(entry.subject)
            .claims(entry.claims)
            .participant_context_id(entry.participant_context_id)
            .audience(entry.audience.clone())
            .flow_id(entry.flow_id)
            .build();

        self.token_store.update(&hashed, new_entry).await?;

        Ok(RenewableTokenPair {
            token,
            refresh_token: new_refresh_token,
            expires_at: new_expires_at,
            refresh_endpoint: self.refresh_endpoint.clone(),
        })
    }

    async fn revoke_token(&self, _participant_context: &ParticipantContext, flow_id: &str) -> Result<(), TokenError> {
        self.token_store.remove_by_flow_id(flow_id).await
    }

    async fn validate_token(&self, audience: &str, token: &str) -> Result<TokenClaims, TokenError> {
        let claims = self.provider_verifier.verify_token(audience, token).await?;
        let jti = claims
            .custom
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or(TokenError::Invalid)?;
        self.token_store
            .find_by_id(jti)
            .await
            .map_err(|_| TokenError::NotAuthorized("Token not found".to_string()))?;
        Ok(claims)
    }

    async fn jwk_set(&self) -> Result<JwkSet, TokenError> {
        Ok(self.jwk_set_provider.jwk_set().await)
    }
}
