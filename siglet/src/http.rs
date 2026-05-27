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

//! Shared HTTP client used by Siglet's outbound subsystems.
//!
//! A single `reqwest::Client` per process shares the connection pool and provides
//! a single configuration source.
use crate::config::HttpClientConfig;
use reqwest::Client;
use std::time::Duration;

/// Builds the shared HTTP client used by every Siglet outbound caller.
///
/// The caller-supplied `HttpClientConfig` is expected to have already passed
/// `SigletConfig::validate` (which rejects zero-valued timeouts). We don't
/// re-validate here; this function is infallible by design so the runtime
/// can construct the client at startup without an extra error path.
pub fn build_http_client(cfg: &HttpClientConfig) -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(cfg.connect_timeout_seconds))
        .timeout(Duration::from_secs(cfg.request_timeout_seconds))
        .build()
        .expect("reqwest::Client build with default TLS should not fail")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::config::{DEFAULT_HTTP_CONNECT_TIMEOUT_SECS, DEFAULT_HTTP_REQUEST_TIMEOUT_SECS};

    #[test]
    fn build_http_client_with_default_config() {
        // The defaults supplied by HttpClientConfig::default() must produce a
        // working Client. reqwest doesn't expose the configured timeouts on
        // Client publicly, so the assertion here is essentially "does not panic"
        // — combined with the deserialization tests below, that's enough to pin
        // the config → client wiring.
        let _client = build_http_client(&HttpClientConfig::default());
    }

    #[test]
    fn build_http_client_with_custom_timeouts() {
        let cfg = HttpClientConfig {
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
        };
        let _client = build_http_client(&cfg);
    }

    #[test]
    fn http_client_config_default_matches_constants() {
        // Pins the default values so an accidental drift between the constants
        // and the Default impl is caught at compile/test time rather than in
        // production. If you intentionally change either constant, update this
        // test too.
        let cfg = HttpClientConfig::default();
        assert_eq!(cfg.connect_timeout_seconds, DEFAULT_HTTP_CONNECT_TIMEOUT_SECS);
        assert_eq!(cfg.request_timeout_seconds, DEFAULT_HTTP_REQUEST_TIMEOUT_SECS);
    }

    #[test]
    fn http_client_config_deserialize_empty_uses_defaults() {
        // An operator who supplies the [http_client] table with no keys gets
        // the same configuration as if they omitted the table entirely.
        let parsed: HttpClientConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, HttpClientConfig::default());
    }

    #[test]
    fn http_client_config_deserialize_partial_fills_defaults() {
        // Specifying one field but not the other should leave the unspecified
        // field at its default. This is the load-bearing property of the
        // per-field `#[serde(default = ...)]` annotations.
        let parsed: HttpClientConfig = serde_json::from_str(r#"{"connect_timeout_seconds": 5}"#).unwrap();
        assert_eq!(parsed.connect_timeout_seconds, 5);
        assert_eq!(parsed.request_timeout_seconds, DEFAULT_HTTP_REQUEST_TIMEOUT_SECS);
    }

    #[test]
    fn http_client_config_deserialize_both_fields() {
        let parsed: HttpClientConfig =
            serde_json::from_str(r#"{"connect_timeout_seconds": 5, "request_timeout_seconds": 120}"#).unwrap();
        assert_eq!(parsed.connect_timeout_seconds, 5);
        assert_eq!(parsed.request_timeout_seconds, 120);
    }
}
