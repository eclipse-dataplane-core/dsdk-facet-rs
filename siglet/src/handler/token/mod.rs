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
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use bon::Builder;
use dsdk_facet_core::jwt::TokenClaims;
use dsdk_facet_core::token::client::TokenClientApi;
use dsdk_facet_core::token::manager::TokenManager;
use dsdk_facet_core::{context::ParticipantContext, jwt::JwkSet};
use error::TokenApiError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod error;

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub audience: String,
}

/// Handler for token retrieval operations
#[derive(Clone, Builder)]
pub struct TokenApiHandler {
    token_client_api: Arc<TokenClientApi>,
    token_manager: Arc<dyn TokenManager>,
}

impl TokenApiHandler {
    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/tokens/{participant_context_id}/{id}",
                get(get_token).delete(delete_token),
            )
            .route("/tokens/verify", post(verify_token))
            .route("/keys", get(get_jwk_set))
            .with_state(self)
    }
}

async fn get_token(
    State(TokenApiHandler { token_client_api, .. }): State<TokenApiHandler>,
    Path((participant_context_id, id)): Path<(String, String)>,
) -> Result<Json<TokenResponse>, TokenApiError> {
    let participant_context = ParticipantContext::builder().id(participant_context_id).build();
    token_client_api
        .get_token(&participant_context, &id, &id)
        .await
        .map(|result| Ok(Json(TokenResponse { token: result.token })))?
}

async fn get_jwk_set(
    State(TokenApiHandler { token_manager, .. }): State<TokenApiHandler>,
) -> Result<Json<JwkSet>, TokenApiError> {
    token_manager.jwk_set().await.map(|set| Ok(Json(set)))?
}

async fn delete_token(
    State(TokenApiHandler { token_client_api, .. }): State<TokenApiHandler>,
    Path((participant_context_id, id)): Path<(String, String)>,
) -> Result<StatusCode, TokenApiError> {
    token_client_api
        .delete_token(&participant_context_id, &id, &id)
        .await
        .map(|_| Ok(StatusCode::NO_CONTENT))?
}

async fn verify_token(
    State(TokenApiHandler { token_manager, .. }): State<TokenApiHandler>,
    Json(body): Json<VerifyTokenRequest>,
) -> Result<Json<TokenClaims>, TokenApiError> {
    token_manager
        .validate_token(&body.audience, &body.token)
        .await
        .map(|claims| Ok(Json(claims)))?
}
