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

use bon::Builder;
use chrono::{DateTime, Utc};

/// Internal state for the Vault client.
#[doc(hidden)]
#[cfg_attr(test, derive(Debug))]
#[derive(Builder)]
#[builder(on(String, into))]
pub struct VaultClientState {
    /// The current Vault token
    pub(super) token: String,
    /// When the token was last created
    pub(super) last_created: DateTime<Utc>,
    /// When the token was last renewed
    pub(super) last_renewed: Option<DateTime<Utc>>,
    /// The lease duration in seconds
    pub(super) lease_duration: u64,
    /// The last error encountered during token renewal, if any
    pub(super) last_error : Option<String>,
    /// Number of consecutive renewal failures
    #[builder(default)]
    pub(super) consecutive_failures: u32,
    /// Number of consecutive failures before the client is considered unhealthy
    pub(super) health_threshold: u32,
}

impl VaultClientState {
    /// Validates the VaultClientState invariants.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `token` is empty
    /// - `lease_duration` is 0
    /// - `health_threshold` is 0
    /// - `last_renewed` is before `last_created`
    #[doc(hidden)]
    #[cfg(test)]
    pub fn validate(&self) {
        assert!(!self.token.is_empty(), "token cannot be empty");
        assert!(self.lease_duration > 0, "lease_duration must be greater than 0");
        assert!(self.health_threshold > 0, "health_threshold must be greater than 0");
        if let Some(renewed) = self.last_renewed {
            assert!(
                renewed >= self.last_created,
                "last_renewed must be >= last_created"
            );
        }
    }

    /// Returns a clone of the current Vault token
    pub fn token(&self) -> String {
        self.token.clone()
    }

    /// Returns when the token was last created
    pub fn last_created(&self) -> DateTime<Utc> {
        self.last_created
    }

    /// Returns when the token was last renewed, if ever
    pub fn last_renewed(&self) -> Option<DateTime<Utc>> {
        self.last_renewed
    }

    /// Returns the token lease duration in seconds
    pub fn lease_duration(&self) -> u64 {
        self.lease_duration
    }

    /// Returns the last error message, if any
    pub fn last_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// Returns the number of consecutive renewal failures
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns true if the client is healthy (consecutive failures < health_threshold)
    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures < self.health_threshold
    }
}
