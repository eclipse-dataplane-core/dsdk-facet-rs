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
use dsdk_facet_core::util::clock::{Clock, default_clock};
use dsdk_facet_core::vault::VaultError;
use std::path::PathBuf;
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

/// Type alias for JWT kid (key ID) transformer function
pub type JwtKidTransformer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Configuration for Vault authentication methods.
#[derive(Clone, Debug)]
pub enum VaultAuthConfig {
    /// OAuth2 cleint credentials grant authentication using JWT.
    OAuth2 {
        /// OAuth2 client ID for obtaining the JWT token
        client_id: String,
        /// OAuth2 client secret for obtaining the JWT token
        client_secret: String,
        /// OAuth2 token endpoint URL
        token_url: String,
        /// The role to use for JWT authentication (defaults to "provisioner" if None)
        role: Option<String>,
    },
    /// Kubernetes service account authentication using a token file.
    /// The token is expected to be written by a Vault agent sidecar.
    KubernetesServiceAccount {
        /// Path to the file containing the Vault token
        token_file_path: PathBuf,
    },
}

/// Configuration for the Hashicorp Vault client.
#[derive(Builder, Clone)]
pub struct HashicorpVaultConfig {
    /// The Vault server URL (e.g., "https://vault.example.com:8200")
    #[builder(into)]
    pub vault_url: String,
    /// Authentication configuration
    pub auth_config: VaultAuthConfig,
    /// Optional mount path for the KV v2 secrets engine (defaults to "secret")
    pub mount_path: Option<String>,
    /// Whether to use soft delete (true) or hard delete with metadata removal (false)
    #[builder(default)]
    pub soft_delete: bool,
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
    /// Optional mount path for the Transit secrets engine (defaults to "transit")
    pub transit_mount_path: Option<String>,
    /// Optional name of the signing key to use in the Transit engine
    pub signing_key_name: Option<String>,
    /// Optional transformer to customize the JWT kid (key ID) in returned KeyMetadata.
    /// This transforms the signing key name before it's included in JWT kid header.
    /// The transformation only affects the returned metadata and JWT kid, not the
    /// actual key name used for Vault API operations.
    ///
    /// # Example
    /// ```ignore
    /// use std::sync::Arc;
    ///
    /// // Add prefix to key name for JWT kid
    /// let transformer = Arc::new(|name| format!("#{}", name));
    ///
    /// let config = HashicorpVaultConfig::builder()
    ///     .signing_key_name("my-key")
    ///     .jwt_kid_transformer(transformer)
    ///     // ... other config ...
    ///     .build();
    ///
    /// // JWT kid will be "#my-key-1" instead of "my-key-1"
    /// ```
    pub jwt_kid_transformer: Option<JwtKidTransformer>,
    #[builder(default = default_clock())]
    pub(crate) clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for HashicorpVaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_config_debug = match &self.auth_config {
            VaultAuthConfig::OAuth2 { client_id, token_url, role, .. } => {
                format!("OAuth2 {{ client_id: {}, client_secret: ***, token_url: {}, role: {:?} }}",
                    client_id, token_url, role)
            }
            VaultAuthConfig::KubernetesServiceAccount { token_file_path } => {
                format!("KubernetesServiceAccount {{ token_file_path: {:?} }}",
                    token_file_path)
            }
        };

        f.debug_struct("HashicorpVaultConfig")
            .field("vault_url", &self.vault_url)
            .field("auth_config", &auth_config_debug)
            .field("mount_path", &self.mount_path)
            .field("soft_delete", &self.soft_delete)
            .field(
                "on_renewal_error",
                &self.on_renewal_error.as_ref().map(|_| "<callback>"),
            )
            .field("health_threshold", &self.health_threshold)
            .field("token_renewal_percentage", &self.token_renewal_percentage)
            .field("request_timeout", &self.request_timeout)
            .field("max_consecutive_failures", &self.max_consecutive_failures)
            .field("renewal_jitter", &self.renewal_jitter)
            .field("transit_mount_path", &self.transit_mount_path)
            .field("signing_key_name", &self.signing_key_name)
            .field("jwt_kid_transformer", &self.jwt_kid_transformer.as_ref().map(|_| "<transformer>"))
            .finish()
    }
}
