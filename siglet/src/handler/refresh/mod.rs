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
use axum::{Form, Json, Router, extract::State, http::HeaderMap, routing::post};
use bon::Builder;
use chrono::Utc;
use dsdk_facet_core::token::manager::TokenManager;
use error::RefreshApiError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod error;

/// Query parameters for the token refresh endpoint as defined by the OAuth2 refresh_token grant.
#[derive(Deserialize)]
struct RefreshParams {
    grant_type: String,
    refresh_token: String,
}

/// OAuth2-compatible token response as required by the Tractus-X refresh profile.
#[derive(Serialize)]
pub struct TokenRefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Remaining lifetime of the access token in seconds (OAuth2 `expires_in` field).
    pub expires_in: i64,
}

/// Axum handler for the provider-side token refresh API.
///
/// Implements `POST /token?grant_type=refresh_token&refresh_token=<token>` as specified by the
/// Tractus-X DataPlane Signaling token refresh profile.
#[derive(Clone, Builder)]
pub struct TokenRefreshHandler {
    token_manager: Arc<dyn TokenManager>,
}

impl TokenRefreshHandler {
    pub fn router(self) -> Router {
        Router::new()
            .route("/token/refresh", post(refresh_token))
            .with_state(self)
    }
}

async fn refresh_token(
    State(TokenRefreshHandler { token_manager }): State<TokenRefreshHandler>,
    headers: HeaderMap,
    Form(params): Form<RefreshParams>,
) -> Result<Json<TokenRefreshResponse>, RefreshApiError> {
    if params.grant_type != "refresh_token" {
        return Err(RefreshApiError::UnsupportedGrantType(params.grant_type));
    }

    let bound_token = extract_bearer(&headers)?;

    token_manager
        .renew(bound_token, &params.refresh_token)
        .await
        .map(|pair| {
            let expires_in = pair.expires_at.timestamp() - Utc::now().timestamp();
            Ok(Json(TokenRefreshResponse {
                access_token: pair.token,
                refresh_token: pair.refresh_token,
                token_type: "Bearer".to_string(),
                expires_in,
            }))
        })?
}

/// Extracts the Bearer token from the Authorization header.
fn extract_bearer(headers: &HeaderMap) -> Result<&str, RefreshApiError> {
    let auth_err = |msg: &'static str| RefreshApiError::InvalidAuthHeader(msg.to_string());

    let value = headers
        .get("authorization")
        .ok_or_else(|| auth_err("Missing Authorization header"))?;

    let s = value.to_str().map_err(|_| auth_err("Invalid Authorization header"))?;

    s.strip_prefix("Bearer ")
        .ok_or_else(|| auth_err("Authorization must use Bearer scheme"))
}
