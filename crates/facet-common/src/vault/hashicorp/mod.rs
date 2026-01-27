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

#[doc(hidden)]
pub mod auth;
mod client;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod renewal;
#[doc(hidden)]
pub mod state;

pub use client::HashicorpVaultClient;
pub use config::{ErrorCallback, HashicorpVaultConfig, HashicorpVaultConfigBuilder};
