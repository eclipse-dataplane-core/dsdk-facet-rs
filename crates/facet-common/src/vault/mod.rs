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

pub mod hashicorp;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use thiserror::Error;

/// A client for interacting with a secure secrets vault.
#[async_trait]
pub trait VaultClient: Send + Sync {
    async fn resolve_secret(&self, path: &str) -> Result<String, VaultError>;
    async fn store_secret(&self, path: &str, secret: &str) -> Result<(), VaultError>;
    async fn remove_secret(&self, path: &str) -> Result<(), VaultError>;
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Secret not found for identifier: {identifier}")]
    SecretNotFound { identifier: String },

    #[error("Token has expired and must be renewed")]
    TokenExpired,

    #[error("General token error: {0}")]
    GeneralError(String),
}
