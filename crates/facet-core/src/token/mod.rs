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

use crate::jwt::{JwtGenerationError, JwtVerificationError};
use thiserror::Error;

pub mod client;
pub mod manager;

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Invalid token")]
    Invalid,

    #[error("Token not found for identifier: {identifier}")]
    TokenNotFound { identifier: String },

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("General token error: {0}")]
    GeneralError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Generation failed: {0}")]
    GenerationError(#[from] JwtGenerationError), // Auto-converts jsonwebtoken errors

    #[error("Verification failed: {0}")]
    VerificationError(#[from] JwtVerificationError), // Auto-converts jsonwebtoken errors
}

impl TokenError {
    pub fn token_not_found(identifier: impl Into<String>) -> Self {
        TokenError::TokenNotFound {
            identifier: identifier.into(),
        }
    }

    pub fn database_error(message: impl Into<String>) -> Self {
        TokenError::DatabaseError(message.into())
    }

    pub fn network_error(message: impl Into<String>) -> Self {
        TokenError::NetworkError(message.into())
    }

    pub fn general_error(message: impl Into<String>) -> Self {
        TokenError::GeneralError(message.into())
    }
}
