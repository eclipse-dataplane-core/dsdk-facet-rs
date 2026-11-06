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

//! End-to-End tests for Kubernetes + Vault integration
//!
//! These tests require a Kind cluster with Vault deployed.
//! Run setup first: `cd e2e && ./scripts/setup.sh`
//!
//! Run tests with: `cargo test --package dsdk-facet-e2e-tests --features e2e`

pub mod utils;

#[cfg(all(test, feature = "e2e"))]
pub mod tests;
