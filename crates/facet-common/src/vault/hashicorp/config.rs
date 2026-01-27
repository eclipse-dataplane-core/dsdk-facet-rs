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

use crate::util::clock::{Clock, default_clock};
use crate::vault::VaultError;
use bon::Builder;
use std::sync::Arc;
use std::time::Duration;

pub(crate) const CONTENT_KEY: &str = "content";
pub const DEFAULT_ROLE: &str = "provisioner";

// Default values for configurable parameters
pub(crate) const DEFAULT_TOKEN_RENEWAL_PERCENTAGE: f64 = 0.8;
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 10;
pub(crate) const DEFAULT_HEALTH_THRESHOLD: u32 = 3;
pub(crate) const DEFAULT_RENEWAL_JITTER: f64 = 0.1; // 10% jitter

/// Type alias for the error callback function
pub type ErrorCallback = Arc<dyn Fn(&VaultError) + Send + Sync>;

/// Configuration for the Hashicorp Vault client using JWT authentication.
#[derive(Builder, Clone)]
pub struct HashicorpVaultConfig {
    /// The Vault server URL (e.g., "https://vault.example.com:8200")
    #[builder(into)]
    pub vault_url: String,
    /// OAuth2 client ID for obtaining the JWT token
    #[builder(into)]
    pub client_id: String,
    /// OAuth2 client secret for obtaining the JWT token
    #[builder(into)]
    pub client_secret: String,
    /// OAuth2 token endpoint URL
    #[builder(into)]
    pub token_url: String,
    /// Optional mount path for the KV v2 secrets engine (defaults to "secret")
    pub mount_path: Option<String>,
    /// Whether to use soft delete (true) or hard delete with metadata removal (false)
    #[builder(default)]
    pub soft_delete: bool,
    /// The role to use for JWT authentication (defaults to "provisioner")
    pub role: Option<String>,
    /// Optional callback function invoked when token renewal errors occur
    pub on_renewal_error: Option<ErrorCallback>,
    /// Number of consecutive failures before the client is considered unhealthy (defaults to 3)
    #[builder(default = DEFAULT_HEALTH_THRESHOLD)]
    pub health_threshold: u32,
    /// Percentage of lease duration at which to renew token (0.0-1.0, defaults to 0.8 = 80%)
    #[builder(default = DEFAULT_TOKEN_RENEWAL_PERCENTAGE)]
    pub token_renewal_percentage: f64,
    /// HTTP request timeout for Vault operations (defaults to 10 seconds)
    #[builder(default = DEFAULT_REQUEST_TIMEOUT)]
    pub request_timeout: Duration,
    /// Maximum consecutive renewal failures before stopping renewal loop (defaults to 10)
    #[builder(default = DEFAULT_MAX_CONSECUTIVE_FAILURES)]
    pub max_consecutive_failures: u32,
    /// Jitter percentage applied to renewal interval (0.0-1.0, defaults to 0.1 = ±10%)
    #[builder(default = DEFAULT_RENEWAL_JITTER)]
    pub renewal_jitter: f64,
    #[builder(default = default_clock())]
    pub(crate) clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for HashicorpVaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashicorpVaultConfig")
            .field("vault_url", &self.vault_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("token_url", &self.token_url)
            .field("mount_path", &self.mount_path)
            .field("soft_delete", &self.soft_delete)
            .field("role", &self.role)
            .field(
                "on_renewal_error",
                &self.on_renewal_error.as_ref().map(|_| "<callback>"),
            )
            .field("health_threshold", &self.health_threshold)
            .field("token_renewal_percentage", &self.token_renewal_percentage)
            .field("request_timeout", &self.request_timeout)
            .field("max_consecutive_failures", &self.max_consecutive_failures)
            .field("renewal_jitter", &self.renewal_jitter)
            .finish()
    }
}
