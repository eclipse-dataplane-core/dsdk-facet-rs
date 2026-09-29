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

//! Management API for per-participant-context runtime configuration.
//!
//! Exposes two CRUD resources over the same router/port:
//!
//! - **Signing-key mappings** (`/key-mappings`) drive the consumer-side token renewal flow: each
//!   associates a participant context with the Vault transit key name and the `kid` used to sign
//!   its proof JWTs (see [`dsdk_facet_core::jwt::MappingTransitKeyResolver`]).
//! - **Transfer-type mappings** (`/transfer-type-mappings`) associate a participant context with
//!   its full set of transfer-type → endpoint mappings, overriding the static configuration for
//!   that context (see [`crate::transfer_type`]).
//!
//! Operators configure both at runtime through this API.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post, put},
};
use bon::Builder;
use dsdk_facet_core::jwt::{SigningKeyMapping, SigningKeyMappingRepository};
use dsdk_facet_core::util::path::validate_path_segment;
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{TransferType, validate_claim_mappings};
use crate::server::auth::AuthLayer;
use crate::transfer_type::{TransferTypeMapping, TransferTypeMappingRepository};
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

/// Handler exposing CRUD over [`SigningKeyMapping`]s and [`TransferTypeMapping`]s.
#[derive(Clone, Builder)]
pub struct ManagementApiHandler {
    repo: Arc<dyn SigningKeyMappingRepository>,
    transfer_type_repo: Arc<dyn TransferTypeMappingRepository>,
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
            .route("/transfer-type-mappings/{id}", get(get_transfer_type_mapping))
            .route_layer(read_auth)
            .with_state(self.clone());

        let write = Router::new()
            .route("/key-mappings", post(create_key_mapping))
            .route("/key-mappings/{id}", put(update_key_mapping).delete(delete_key_mapping))
            .route("/transfer-type-mappings", post(create_transfer_type_mapping))
            .route(
                "/transfer-type-mappings/{id}",
                put(update_transfer_type_mapping).delete(delete_transfer_type_mapping),
            )
            .route_layer(write_auth)
            .with_state(self);

        read.merge(write)
    }
}

/// Validates a participant context id or Vault key name taken from the path or body.
///
/// Both end up as Vault path segments (a key name in `/v1/transit/sign/{key_name}`), so a value
/// such as `../keys/other` must be rejected before it is stored.
fn validate_segment(field: &str, value: &str) -> Result<(), ManagementApiError> {
    validate_path_segment(value).map_err(|e| ManagementApiError::Validation(vec![format!("{}: {}", field, e)]))
}

/// Validates the fields of a signing-key mapping. `kid` is only a JWT header value, never a path,
/// so it just has to be present.
fn validate_key_mapping(mapping: &SigningKeyMapping) -> Result<(), ManagementApiError> {
    validate_segment("participantContextId", &mapping.participant_context_id)?;
    validate_segment("keyName", &mapping.key_name)?;
    if mapping.kid.trim().is_empty() {
        return Err(ManagementApiError::Validation(vec![
            "kid: must not be empty".to_string(),
        ]));
    }
    Ok(())
}

async fn get_key_mapping(
    State(ManagementApiHandler { repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<Json<SigningKeyMapping>, ManagementApiError> {
    validate_segment("id", &id)?;
    Ok(Json(repo.find(&id).await?))
}

async fn create_key_mapping(
    State(ManagementApiHandler { repo, .. }): State<ManagementApiHandler>,
    Json(key_mapping): Json<SigningKeyMapping>,
) -> Result<StatusCode, ManagementApiError> {
    validate_key_mapping(&key_mapping)?;
    repo.create(key_mapping).await?;
    Ok(StatusCode::CREATED)
}

async fn update_key_mapping(
    State(ManagementApiHandler { repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
    Json(body): Json<KeyMappingRequest>,
) -> Result<StatusCode, ManagementApiError> {
    let mapping = SigningKeyMapping::builder()
        .participant_context_id(&id)
        .key_name(body.key_name)
        .kid(body.kid)
        .build();
    validate_key_mapping(&mapping)?;
    repo.update(mapping).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_key_mapping(
    State(ManagementApiHandler { repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<StatusCode, ManagementApiError> {
    validate_segment("id", &id)?;
    repo.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_transfer_type_mapping(
    State(ManagementApiHandler { transfer_type_repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<Json<TransferTypeMapping>, ManagementApiError> {
    validate_segment("id", &id)?;
    Ok(Json(transfer_type_repo.find(&id).await?))
}

/// Validates the claim mappings of every transfer type in a submitted map.
///
/// Mappings written here never pass through `SigletConfig::validate`, so without this a bad
/// expression would be accepted and then fail every flow for the participant context. Reuses the
/// configuration validator so both entry points enforce identical rules.
fn validate_transfer_types(mappings: &HashMap<String, TransferType>) -> Result<(), ManagementApiError> {
    let mut errors = Vec::new();

    for (key, transfer_type) in mappings {
        validate_claim_mappings(
            &transfer_type.claim_mappings,
            &format!("mappings.{}.claimMappings", key),
            &mut errors,
        );
        for (idx, endpoint_mapping) in transfer_type.endpoint_mappings.iter().enumerate() {
            validate_claim_mappings(
                &endpoint_mapping.claim_mappings,
                &format!("mappings.{}.endpointMappings[{}].claimMappings", key, idx),
                &mut errors,
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ManagementApiError::Validation(errors))
    }
}

async fn create_transfer_type_mapping(
    State(ManagementApiHandler { transfer_type_repo, .. }): State<ManagementApiHandler>,
    Json(mapping): Json<TransferTypeMapping>,
) -> Result<StatusCode, ManagementApiError> {
    validate_segment("participantContextId", &mapping.participant_context_id)?;
    validate_transfer_types(&mapping.mappings)?;
    transfer_type_repo.create(mapping).await?;
    Ok(StatusCode::CREATED)
}

/// Replaces the whole transfer-type map for the participant context taken from the path.
async fn update_transfer_type_mapping(
    State(ManagementApiHandler { transfer_type_repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
    Json(mappings): Json<HashMap<String, TransferType>>,
) -> Result<StatusCode, ManagementApiError> {
    validate_segment("id", &id)?;
    validate_transfer_types(&mappings)?;
    transfer_type_repo
        .update(
            TransferTypeMapping::builder()
                .participant_context_id(&id)
                .mappings(mappings)
                .build(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_transfer_type_mapping(
    State(ManagementApiHandler { transfer_type_repo, .. }): State<ManagementApiHandler>,
    Path(id): Path<String>,
) -> Result<StatusCode, ManagementApiError> {
    validate_segment("id", &id)?;
    transfer_type_repo.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
