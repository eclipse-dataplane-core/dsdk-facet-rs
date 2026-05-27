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
use config::{Config, Environment, File};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

#[cfg(test)]
mod tests;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default port for the Siglet management API
pub const DEFAULT_SIGLET_API_PORT: u16 = 8080;

/// Default port for the DataPlane signaling API
pub const DEFAULT_SIGNALING_PORT: u16 = 8081;

/// Default port for the token refresh API
pub const DEFAULT_REFRESH_API_PORT: u16 = 8082;

/// Default bind address (0.0.0.0 - listen on all interfaces)
pub const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

/// Default name for the Vault transit signing key used for access tokens.
/// Derived from `{ACCESS_TOKEN_SIGNING_KEY_PREFIX}-{SIGLET_PC_ID}` = `"signing-siglet"`.
pub const DEFAULT_VAULT_SIGNING_KEY_NAME: &str = "signing-siglet";

/// Default JWKS cache TTL in seconds for the signaling-API JWT verifier.
pub const DEFAULT_JWKS_CACHE_TTL_SECONDS: u64 = 300;

/// Default expected audience for tokens accepted on the signaling API.
///
/// Tokens issued for this siglet must carry `aud = "siglet"` (or whatever
/// value the operator overrides this with). The IdP minting the JWT should
/// be configured to use the same value as the issued token's `aud`.
pub const DEFAULT_SIGNALING_AUDIENCE: &str = "siglet";

/// Default scope required on signaling-API JWTs.
///
/// Incoming tokens must carry this value as one of the space-delimited entries in
/// their `scope` claim. Operators can override it via `signaling_auth.required_scope`;
/// the default is the data-plane-signaling protocol scope.
pub const DEFAULT_SIGNALING_SCOPE: &str = "dplane-signaling";

/// Default TCP connect-phase timeout in seconds for the shared HTTP client.
pub const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default total per-request timeout in seconds for the shared HTTP client.
pub const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Minimum server secret length in bytes (128 bits)
pub const MIN_SERVER_SECRET_BYTES: usize = 16;

/// Minimum server secret length in hex characters (32 hex chars = 16 bytes)
pub const MIN_SERVER_SECRET_HEX_CHARS: usize = MIN_SERVER_SECRET_BYTES * 2;

/// Environment variable name for the configuration file path
pub const ENV_CONFIG_FILE: &str = "SIGLET_CONFIG_FILE";

// ============================================================================
// Type Definitions
// ============================================================================

/// Authentication configuration for the signaling API.
///
/// Tagged union: the `mode` field selects between disabled and enabled. The `jwks_url`
/// field is only present (and required) for the enabled variant — turning auth off
/// makes the URL inexpressible rather than merely optional.
///
/// TOML/YAML examples:
/// ```text
/// # Production: validate JWTs against the IdP's JWKS endpoint
/// [signaling_auth]
/// mode = "enabled"
/// jwks_url = "https://idp.example.com/.well-known/jwks.json"
///
/// # Development: skip JWT verification (still extracts participant_context_id from URL)
/// [signaling_auth]
/// mode = "disabled"
/// ```
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum SignalingAuthConfig {
    Disabled,
    Enabled {
        jwks_url: String,
        #[serde(default = "default_jwks_cache_ttl_seconds")]
        cache_ttl_seconds: u64,
        /// Expected JWT `aud` claim. The signaling-API verifier rejects tokens
        /// whose audience doesn't match this string — that's what binds a token
        /// minted for this siglet to *this* siglet, blocking cross-service
        /// replay of JWTs issued by the same IdP for other recipients.
        ///
        /// Defaults to `"siglet"`. In multi-siglet deployments, give each
        /// instance a distinct value (e.g. its public URL or DID).
        #[serde(default = "default_signaling_audience")]
        audience: String,
        /// Scope the signaling-API verifier requires in the JWT's `scope` claim.
        /// The claim is OAuth2 space-delimited (RFC 6749 §3.3): a token is accepted
        /// as long as this value is one of its whitespace-separated entries.
        ///
        /// Defaults to `"dplane-signaling"`, so it doesn't need to be set
        /// explicitly. Must be non-empty when auth is enabled.
        #[serde(default = "default_signaling_scope")]
        required_scope: String,
    },
}

impl Default for SignalingAuthConfig {
    /// Default is auth ON with an empty `jwks_url`, which fails validation. This
    /// forces every deployment to either supply a JWKS URL or explicitly opt out
    /// via `mode = "disabled"` — there is no silent "auth disabled" fallback.
    fn default() -> Self {
        Self::Enabled {
            jwks_url: String::new(),
            cache_ttl_seconds: DEFAULT_JWKS_CACHE_TTL_SECONDS,
            audience: DEFAULT_SIGNALING_AUDIENCE.to_string(),
            required_scope: DEFAULT_SIGNALING_SCOPE.to_string(),
        }
    }
}

/// Timeouts for the process-wide outbound HTTP client (used for JWKS fetching,
/// OAuth2 token refresh against upstream providers, etc.).
///
/// Both fields are in seconds and have to be > 0; zero values are caught by
/// `SigletConfig::validate`. The defaults are sized for small JSON payloads
/// over short-lived requests, which fits every current consumer.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct HttpClientConfig {
    #[serde(default = "default_http_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_http_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout_seconds: DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
            request_timeout_seconds: DEFAULT_HTTP_REQUEST_TIMEOUT_SECS,
        }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum StorageBackend {
    #[default]
    Memory,
    /// Vault for `TokenStore`; Postgres for `RenewableTokenStore` and `LockManager`.
    #[serde(rename = "postgres-vault")]
    PostgresVault { url: String },
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenSource {
    Client,
    Provider,
}

#[derive(Builder, Deserialize, Clone, Debug)]
pub struct TransferType {
    pub transfer_type: String,
    pub endpoint_type: String,
    pub endpoint: Option<String>,
    pub token_source: TokenSource,
    #[serde(default)]
    #[builder(default)]
    pub endpoint_mappings: Vec<EndpointMapping>,
}

#[derive(Builder, Deserialize, Clone, Debug)]
pub struct EndpointMapping {
    /// A key in `DataFlow.metadata` to match on.
    pub key: String,
    /// The expected string value of the metadata entry identified by `key`.
    pub value: String,
    pub endpoint: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct VaultConfig {
    pub url: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<String>,
    #[serde(default = "default_vault_signing_key_name")]
    pub signing_key_name: String,
    #[serde(default)]
    pub use_http_resolution: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            url: None,
            token: None,
            token_file: None,
            signing_key_name: DEFAULT_VAULT_SIGNING_KEY_NAME.to_string(),
            use_http_resolution: false,
        }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TokenConfig {
    pub issuer: Option<String>,
    pub refresh_endpoint: Option<String>,
    pub server_secret: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct SigletConfig {
    #[serde(default = "default_siglet_api_port")]
    pub siglet_api_port: u16,
    #[serde(default = "default_signaling_port")]
    pub signaling_port: u16,
    #[serde(default = "default_refresh_api_port")]
    pub refresh_api_port: u16,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default)]
    pub storage_backend: StorageBackend,
    #[serde(default)]
    pub transfer_types: Vec<TransferType>,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub token: TokenConfig,
    #[serde(default)]
    pub signaling_auth: SignalingAuthConfig,
    #[serde(default)]
    pub http_client: HttpClientConfig,
}

impl Default for SigletConfig {
    fn default() -> Self {
        Self {
            siglet_api_port: DEFAULT_SIGLET_API_PORT,
            signaling_port: DEFAULT_SIGNALING_PORT,
            refresh_api_port: DEFAULT_REFRESH_API_PORT,
            bind: DEFAULT_BIND_ADDRESS,
            storage_backend: StorageBackend::Memory,
            transfer_types: Vec::new(),
            vault: VaultConfig::default(),
            token: TokenConfig::default(),
            signaling_auth: SignalingAuthConfig::default(),
            http_client: HttpClientConfig::default(),
        }
    }
}

impl SigletConfig {
    /// Validates the configuration and returns detailed errors if invalid
    ///
    /// This should be called immediately after loading the config to fail fast
    /// before starting any services.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut errors = Vec::new();

        // Validate Vault URL is provided
        if self.vault.url.is_none() {
            errors.push("vault_url is required".to_string());
        }

        // Validate Vault URL format
        if let Some(url) = &self.vault.url
            && url.parse::<reqwest::Url>().is_err()
        {
            errors.push(format!("vault_url is not a valid URL: '{}'", url));
        }

        // Validate Vault authentication is provided
        if self.vault.token.is_none() && self.vault.token_file.is_none() {
            errors.push("Either vault_token or vault_token_file is required".to_string());
        }

        // Validate server secret format (if provided)
        if let Some(secret_hex) = &self.token.server_secret {
            if secret_hex.is_empty() {
                errors.push("token_server_secret cannot be empty".to_string());
            } else if let Ok(decoded) = hex::decode(secret_hex) {
                // Check length (should be at least MIN_SERVER_SECRET_BYTES for security)
                if decoded.len() < MIN_SERVER_SECRET_BYTES {
                    errors.push(format!(
                        "token_server_secret should be at least {} hex characters ({} bytes), got {} bytes",
                        MIN_SERVER_SECRET_HEX_CHARS,
                        MIN_SERVER_SECRET_BYTES,
                        decoded.len()
                    ));
                }
            } else {
                errors.push(format!(
                    "token_server_secret must be a valid hex-encoded string, got: '{}'",
                    secret_hex
                ));
            }
        }

        // Validate port numbers don't conflict
        if self.siglet_api_port == self.signaling_port {
            errors.push(format!(
                "siglet_api_port and signaling_port cannot be the same (both are {})",
                self.siglet_api_port
            ));
        }
        if self.refresh_api_port == self.siglet_api_port {
            errors.push(format!(
                "refresh_api_port and siglet_api_port cannot be the same (both are {})",
                self.refresh_api_port
            ));
        }
        if self.refresh_api_port == self.signaling_port {
            errors.push(format!(
                "refresh_api_port and signaling_port cannot be the same (both are {})",
                self.refresh_api_port
            ));
        }

        // Validate port numbers are not 0 (system-assigned)
        if self.siglet_api_port == 0 {
            errors.push("siglet_api_port cannot be 0".to_string());
        }
        if self.signaling_port == 0 {
            errors.push("signaling_port cannot be 0".to_string());
        }
        if self.refresh_api_port == 0 {
            errors.push("refresh_api_port cannot be 0".to_string());
        }

        // Validate transfer types
        for (idx, tt) in self.transfer_types.iter().enumerate() {
            if tt.transfer_type.is_empty() {
                errors.push(format!("transfer_types[{}]: transfer_type cannot be empty", idx));
            }
            if tt.endpoint_type.is_empty() {
                errors.push(format!("transfer_types[{}]: endpoint_type cannot be empty", idx));
            }

            if tt.endpoint_mappings.is_empty() {
                // No mappings: static endpoint is required
                match &tt.endpoint {
                    None => errors.push(format!(
                        "transfer_types[{}]: endpoint is required when no endpoint_mappings are configured",
                        idx
                    )),
                    Some(e) if e.is_empty() => {
                        errors.push(format!("transfer_types[{}]: endpoint cannot be empty", idx))
                    }
                    _ => {}
                }
            } else {
                // Validate each mapping entry
                for (midx, mapping) in tt.endpoint_mappings.iter().enumerate() {
                    if mapping.key.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: key cannot be empty",
                            idx, midx
                        ));
                    }
                    if mapping.value.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: value cannot be empty",
                            idx, midx
                        ));
                    }
                    if mapping.endpoint.is_empty() {
                        errors.push(format!(
                            "transfer_types[{}].endpoint_mappings[{}]: endpoint cannot be empty",
                            idx, midx
                        ));
                    }
                }
            }
        }

        // Validate vault signing key name
        if self.vault.signing_key_name.is_empty() {
            errors.push("vault_signing_key_name cannot be empty".to_string());
        }

        // Validate HTTP client timeouts. Zero would disable the timeout entirely
        // in reqwest, which is almost certainly not what the operator meant.
        if self.http_client.connect_timeout_seconds == 0 {
            errors.push("http_client.connect_timeout_seconds must be greater than 0".to_string());
        }
        if self.http_client.request_timeout_seconds == 0 {
            errors.push("http_client.request_timeout_seconds must be greater than 0".to_string());
        }

        // Validate signaling auth config
        if let SignalingAuthConfig::Enabled {
            jwks_url,
            cache_ttl_seconds,
            audience,
            required_scope,
        } = &self.signaling_auth
        {
            if jwks_url.is_empty() {
                errors.push(
                    "signaling_auth.jwks_url is required when signaling_auth.mode = \"enabled\" \
                     (set signaling_auth.mode = \"disabled\" to skip JWT verification in dev)"
                        .to_string(),
                );
            } else if jwks_url.parse::<reqwest::Url>().is_err() {
                errors.push(format!("signaling_auth.jwks_url is not a valid URL: '{}'", jwks_url));
            }
            if *cache_ttl_seconds == 0 {
                errors.push("signaling_auth.cache_ttl_seconds must be greater than 0".to_string());
            }
            if audience.is_empty() {
                errors.push("signaling_auth.audience cannot be empty".to_string());
            }
            // A blank required_scope can't be satisfied by any token (scope entries
            // are non-empty), so it would fail every request closed. Reject it at
            // startup with a clear message rather than letting it silently lock out
            // all callers. `serde` already supplies the default for a *missing* key.
            if required_scope.trim().is_empty() {
                errors.push("signaling_auth.required_scope cannot be empty".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::Multiple(errors))
        }
    }
}

const fn default_siglet_api_port() -> u16 {
    DEFAULT_SIGLET_API_PORT
}

const fn default_signaling_port() -> u16 {
    DEFAULT_SIGNALING_PORT
}

const fn default_refresh_api_port() -> u16 {
    DEFAULT_REFRESH_API_PORT
}

fn default_bind() -> IpAddr {
    DEFAULT_BIND_ADDRESS
}

fn default_vault_signing_key_name() -> String {
    DEFAULT_VAULT_SIGNING_KEY_NAME.to_string()
}

const fn default_jwks_cache_ttl_seconds() -> u64 {
    DEFAULT_JWKS_CACHE_TTL_SECONDS
}

fn default_signaling_audience() -> String {
    DEFAULT_SIGNALING_AUDIENCE.to_string()
}

fn default_signaling_scope() -> String {
    DEFAULT_SIGNALING_SCOPE.to_string()
}

const fn default_http_connect_timeout_seconds() -> u64 {
    DEFAULT_HTTP_CONNECT_TIMEOUT_SECS
}

const fn default_http_request_timeout_seconds() -> u64 {
    DEFAULT_HTTP_REQUEST_TIMEOUT_SECS
}

pub fn load_config() -> anyhow::Result<SigletConfig> {
    let path = std::env::args().nth(1);
    let config_file = std::env::var(ENV_CONFIG_FILE)
        .map(PathBuf::from)
        .ok()
        .or_else(|| path.map(PathBuf::from));

    let mut config_builder = Config::builder();
    if let Some(path) = config_file {
        config_builder = config_builder.add_source(File::from(path.clone()));
    }

    config_builder
        .add_source(Environment::with_prefix("SIGLET").separator("__"))
        .build()?
        .try_deserialize()
        .map_err(Into::into)
}

/// Error type for configuration validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Single(String),
    Multiple(Vec<String>),
}

impl ValidationError {
    /// Creates a single validation error
    pub fn single(msg: impl Into<String>) -> Self {
        ValidationError::Single(msg.into())
    }

    /// Returns the number of validation errors
    pub fn error_count(&self) -> usize {
        match self {
            ValidationError::Single(_) => 1,
            ValidationError::Multiple(errors) => errors.len(),
        }
    }

    /// Returns all error messages
    pub fn messages(&self) -> Vec<&str> {
        match self {
            ValidationError::Single(msg) => vec![msg.as_str()],
            ValidationError::Multiple(errors) => errors.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Single(msg) => write!(f, "Configuration validation failed: {}", msg),
            ValidationError::Multiple(errors) => {
                writeln!(f, "Configuration validation failed with {} error(s):", errors.len())?;
                for (i, error) in errors.iter().enumerate() {
                    writeln!(f, "  {}. {}", i + 1, error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}
