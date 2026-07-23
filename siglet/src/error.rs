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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigletError {
    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("DataPlane SDK error")]
    DataPlane(#[source] anyhow::Error),

    #[error("Configuration error")]
    Configuration(#[from] anyhow::Error),

    #[error("Vault initialization error {0}")]
    Vault(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Token operation error")]
    Token(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Network binding error")]
    Network(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Server task panicked")]
    TaskPanic(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}
