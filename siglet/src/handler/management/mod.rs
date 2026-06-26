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

//! Management API for per-participant-context signing-key mappings.
//!
//! These key mappings drive the consumer-side token renewal flow: each associates a participant
//! context with the Vault transit key name and the `kid` used to sign its proof JWTs (see
//! [`dsdk_facet_core::jwt::MappingTransitKeyResolver`]). Operators configure them at runtime
//! through this CRUD API.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post, put},
};
use bon::Builder;
use dsdk_facet_core::jwt::{SigningKeyMapping, SigningKeyMappingRepository};
use reqwest::StatusCode;
use serde::Deserialize;
use std::sync::Arc;

use crate::server::auth::AuthLayer;
use error::ManagementApiError;

pub mod error;

#[cfg(test)]
mod tests;

/// Body for updating a key mapping via `PUT /key-mappings/{id}`, where the participant context
/// id is taken from the path.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMappingRequest {
    pub key_name: String,
    pub kid: String,
}

/// Handler exposing CRUD over [`SigningKeyMapping`]s.
#[derive(Clone, Builder)]
pub struct ManagementApiHandler {
    repo: Arc<dyn SigningKeyMappingRepository>,
}

impl ManagementApiHandler {
    /// Builds the management-API router with per-operation scope authorization.
    ///
    /// The read group (`GET`) is guarded by `read_auth` and the write group (`POST`/`PUT`/`DELETE`)
    /// by `write_auth`, so each method requires its own scope (`siglet-mgmt-api:read` /
    /// `siglet-mgmt-api:write`). Routes are keyed on `{id}` (the participant context id) rather than
    /// `participant_context_id` so the auth layer does not bind the JWT `sub` to the path — this is
    /// an admin API that manages key mappings across many participant contexts. Pass
    /// [`AuthLayer::Disabled`] for both to skip verification (dev/tests).
    ///
    /// Auth is applied via `route_layer`, so it runs only when a request matches a route. Requests
    /// to unmatched paths fall through to a 404 instead of being rejected by the auth layer.
    pub fn router(self, read_auth: AuthLayer, write_auth: AuthLayer) -> Router {
        let read = Router::new()
            .route("/key-mappings/{id}", get(get_key_mapping))
            .route_layer(read_auth)
            .with_state(self.clone());

        let write = Router::new()
            .route("/key-mappings", post(create_key_mapping))
            .route("/key-mappings/{id}", put(update_key_mapping).delete(delete_key_mapping))
            .route_layer(write_auth)
            .with_state(self);

        read.merge(write)
    }
}

async fn get_key_mapping(
    State(ManagementApiHandler { repo }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<Json<SigningKeyMapping>, ManagementApiError> {
    Ok(Json(repo.find(&id).await?))
}

async fn create_key_mapping(
    State(ManagementApiHandler { repo }): State<ManagementApiHandler>,
    Json(key_mapping): Json<SigningKeyMapping>,
) -> Result<StatusCode, ManagementApiError> {
    repo.create(key_mapping).await?;
    Ok(StatusCode::CREATED)
}

async fn update_key_mapping(
    State(ManagementApiHandler { repo }): State<ManagementApiHandler>,
    Path(id): Path<String>,
    Json(body): Json<KeyMappingRequest>,
) -> Result<StatusCode, ManagementApiError> {
    repo.update(
        SigningKeyMapping::builder()
            .participant_context_id(&id)
            .key_name(body.key_name)
            .kid(body.kid)
            .build(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_key_mapping(
    State(ManagementApiHandler { repo }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<StatusCode, ManagementApiError> {
    repo.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
