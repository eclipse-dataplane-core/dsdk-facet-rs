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

use crate::transfer_type::TransferTypeMappingError;
use axum::{Json, http::StatusCode, response::IntoResponse};
use dsdk_facet_core::jwt::SigningKeyMappingError;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManagementApiError {
    #[error(transparent)]
    Mapping(#[from] SigningKeyMappingError),
    #[error(transparent)]
    TransferType(#[from] TransferTypeMappingError),
}

impl IntoResponse for ManagementApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ManagementApiError::Mapping(SigningKeyMappingError::NotFound { .. }) => {
                (StatusCode::NOT_FOUND, "Signing key mapping not found".to_string())
            }
            ManagementApiError::Mapping(SigningKeyMappingError::AlreadyExists { .. }) => {
                (StatusCode::CONFLICT, "Signing key mapping already exists".to_string())
            }
            e @ ManagementApiError::Mapping(SigningKeyMappingError::Storage(_)) => {
                tracing::error!("Unexpected error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            ManagementApiError::TransferType(TransferTypeMappingError::NotFound { .. }) => {
                (StatusCode::NOT_FOUND, "Transfer type mapping not found".to_string())
            }
            ManagementApiError::TransferType(TransferTypeMappingError::AlreadyExists { .. }) => {
                (StatusCode::CONFLICT, "Transfer type mapping already exists".to_string())
            }
            e @ ManagementApiError::TransferType(TransferTypeMappingError::Storage(_)) => {
                tracing::error!("Unexpected error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({ "error": error_message }));
        (status, body).into_response()
    }
}
