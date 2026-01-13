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

use crate::token::{TokenClient, TokenData, TokenError};
use async_trait::async_trait;
use bon::Builder;
use chrono::TimeDelta;
use facet_common::context::ParticipantContext;
use facet_common::jwt::{JwtGenerator, LocalJwtGenerator, TokenClaims};
use facet_common::util::{Clock, default_clock};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::Arc;

const DEFAULT_EXPIRATION_SECONDS: i64 = 300; // 5 minutes

#[derive(Clone, Builder)]
pub struct OAuth2TokenClient {
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
    #[builder(default = Client::new())]
    http_client: Client,
    #[builder(into)]
    identifier: String,
    jwt_generator: Arc<LocalJwtGenerator>,
    #[builder(default = DEFAULT_EXPIRATION_SECONDS)]
    expiration_seconds: i64,
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
    ) -> Result<TokenData, TokenError> {
        let now = self.clock.now().timestamp();
        let mut custom_claims = Map::new();
        custom_claims.insert("token".to_string(), Value::String(access_token.to_string()));

        let claims = TokenClaims::builder()
            .iss(&self.identifier)
            .sub(&self.identifier)
            .aud(endpoint_identifier)
            .exp(now + self.expiration_seconds)
            .custom(custom_claims)
            .build();
        let jwt = self.jwt_generator.generate_token(participant_context, claims)?;

        let response = self
            .http_client
            .post(refresh_endpoint)
            .form(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .map_err(|e| TokenError::network_error(format!("Failed to send refresh request: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
            return Err(TokenError::network_error(format!(
                "Token refresh failed with status {}: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| TokenError::network_error(format!("Failed to parse token response: {}", e)))?;

        let expires_at = self.clock.now() + TimeDelta::seconds(token_response.expires_in);
        let new_refresh_token = token_response
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());

        Ok(TokenData {
            participant_context: participant_context.identifier.clone(),
            identifier: endpoint_identifier.to_string(),
            token: token_response.access_token,
            refresh_token: new_refresh_token,
            expires_at,
            refresh_endpoint: refresh_endpoint.to_string(),
        })
    }
}
