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

use super::{RefreshEndpointPolicy, RefreshedTokenData, TokenClient};
use crate::context::ParticipantContext;
use crate::jwt::{JwtGenerator, TokenClaims};
use crate::token::TokenError;
use crate::util::clock::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::TimeDelta;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_EXPIRATION_SECONDS: i64 = 300; // 5 minutes

/// Upper bound on a counterparty-supplied `expires_in` (30 days). Larger values are clamped rather
/// than trusted: they would otherwise overflow the expiry computation.
const MAX_EXPIRES_IN_SECONDS: i64 = 30 * 24 * 3600;

/// How much of an error response body is kept for debug logging.
const MAX_LOGGED_BODY_BYTES: usize = 512;

#[derive(Clone, Builder)]
pub struct OAuth2TokenClient {
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
    /// Must not follow redirects: a redirect would re-send the refresh token and proof JWT to a
    /// location the endpoint policy never checked. The default client is built that way.
    #[builder(default = no_redirect_client())]
    http_client: Client,
    jwt_generator: Arc<dyn JwtGenerator>,
    #[builder(default = DEFAULT_EXPIRATION_SECONDS)]
    expiration_seconds: i64,
    /// Which refresh endpoints may be called. Defaults to HTTPS-only.
    #[builder(default)]
    endpoint_policy: RefreshEndpointPolicy,
}

fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
}

#[async_trait]
impl TokenClient for OAuth2TokenClient {
    async fn refresh_token(
        &self,
        participant_context: &ParticipantContext,
        endpoint_identifier: &str,
        access_token: &str,
        refresh_token: &str,
        refresh_endpoint: &str,
    ) -> Result<RefreshedTokenData, TokenError> {
        // Checked before anything is signed: the endpoint came from the counterparty.
        let url = self.endpoint_policy.check(refresh_endpoint)?;

        let now = self.clock.now().timestamp();
        let mut custom_claims = Map::new();
        custom_claims.insert("token".to_string(), Value::String(access_token.to_string()));
        custom_claims.insert("jti".to_string(), Value::String(Uuid::new_v4().to_string()));

        let claims = TokenClaims::builder()
            .iss(&participant_context.identifier)
            .sub(&participant_context.identifier)
            .aud(endpoint_identifier)
            .exp(now + self.expiration_seconds)
            .custom(custom_claims)
            .build();
        let jwt = self.jwt_generator.generate_token(participant_context, claims).await?;

        let response = self
            .http_client
            .post(url)
            .form(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .map_err(|e| TokenError::network_error(format!("Failed to send refresh request: {}", e)))?;

        if !response.status().is_success() {
            // The body is written by the remote endpoint; keep it out of the error (which is
            // logged at error level) and only log a bounded prefix at debug level.
            let status = response.status();
            if log::log_enabled!(log::Level::Debug) {
                let body = response.text().await.unwrap_or_default();
                let end = body.floor_char_boundary(MAX_LOGGED_BODY_BYTES);
                log::debug!("Token refresh failed with status {}: {}", status, &body[..end]);
            }
            return Err(TokenError::network_error(format!(
                "Token refresh failed with status {}",
                status
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| TokenError::network_error(format!("Failed to parse token response: {}", e)))?;

        let expires_in = token_response.expires_in.clamp(0, MAX_EXPIRES_IN_SECONDS);
        let expires_at = self.clock.now() + TimeDelta::seconds(expires_in);
        let new_refresh_token = token_response
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());

        Ok(RefreshedTokenData {
            token: token_response.access_token,
            refresh_token: new_refresh_token,
            expires_at,
            refresh_endpoint: refresh_endpoint.to_string(),
        })
    }
}
