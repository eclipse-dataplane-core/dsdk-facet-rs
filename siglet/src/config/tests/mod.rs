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

#![allow(clippy::unwrap_used)]

use crate::config::{
    ClaimMapping, EndpointMapping, ManagementApiAuthConfig, SigletConfig, SignalingAuthConfig, StorageBackend,
    TokenApiAuthConfig, TokenConfig, TokenSource, TransferType, ValidationError, VaultAuth, VaultConfig,
};
use std::net::{IpAddr, Ipv4Addr};

/// Helper function to create a valid minimal configuration.
///
/// Signaling auth is explicitly disabled here so existing assertions about
/// "minimal valid config" don't have to also configure a JWKS URL.
fn create_valid_config() -> SigletConfig {
    SigletConfig {
        vault: VaultConfig {
            url: Some("https://vault.example.com".to_string()),
            token: Some("test-token".to_string()),
            ..Default::default()
        },
        signaling_auth: SignalingAuthConfig::Disabled,
        token_api_auth: TokenApiAuthConfig::Disabled,
        management_api_auth: ManagementApiAuthConfig::Disabled,
        ..Default::default()
    }
}

/// Helper function to create a valid config with vault token file instead of token
fn create_valid_config_with_token_file() -> SigletConfig {
    SigletConfig {
        vault: VaultConfig {
            url: Some("https://vault.example.com".to_string()),
            token_file: Some("/var/run/secrets/vault-token".to_string()),
            ..Default::default()
        },
        signaling_auth: SignalingAuthConfig::Disabled,
        token_api_auth: TokenApiAuthConfig::Disabled,
        management_api_auth: ManagementApiAuthConfig::Disabled,
        ..Default::default()
    }
}

// ============================================================================
// Valid Configuration Tests
// ============================================================================

#[test]
fn test_valid_minimal_config() {
    let config = create_valid_config();
    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_with_all_fields() {
    let config = SigletConfig {
        siglet_api_port: 8080,
        signaling_port: 8081,
        refresh_api_port: 8082,
        management_api_port: 8083,
        bind: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        storage_backend: StorageBackend::Memory,
        transfer_types: vec![
            TransferType::builder()
                .transfer_type("http-pull".to_string())
                .endpoint_type("HTTP".to_string())
                .endpoint("https://pull.example.com".to_string())
                .token_source(TokenSource::Provider)
                .build(),
        ],
        vault: VaultConfig {
            url: Some("https://vault.example.com:8200".to_string()),
            token: Some("hvs.test-token-12345".to_string()),
            signing_key_name: "my-signing-key".to_string(),
            ..Default::default()
        },
        token: TokenConfig {
            issuer: Some("my-issuer".to_string()),
            refresh_endpoint: Some("https://api.example.com/refresh".to_string()),
            server_secret: Some("0123456789abcdef0123456789abcdef".to_string()), // 16 bytes
        },
        signaling_auth: SignalingAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "https://siglet.example.com".to_string(),
            required_scope: "dplane-signaling".to_string(),
        },
        token_api_auth: TokenApiAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "https://siglet.example.com".to_string(),
            required_scope: "siglet-token-api".to_string(),
        },
        management_api_auth: ManagementApiAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "https://siglet.example.com".to_string(),
        },
        http_client: crate::config::HttpClientConfig {
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
        },
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_with_token_file() {
    let config = create_valid_config_with_token_file();
    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_with_both_token_and_token_file() {
    let mut config = create_valid_config();
    config.vault.token_file = Some("/var/run/secrets/vault-token".to_string());

    // Both provided is valid (implementation will choose one)
    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_different_ports() {
    let mut config = create_valid_config();
    config.siglet_api_port = 9000;
    config.signaling_port = 9001;
    config.refresh_api_port = 9002;

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_with_multiple_transfer_types() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .build(),
        TransferType::builder()
            .transfer_type("http-push".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://push.example.com".to_string())
            .token_source(TokenSource::Client)
            .build(),
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("S3".to_string())
            .endpoint("https://s3.example.com".to_string())
            .token_source(TokenSource::Client)
            .build(),
    ];

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_config_with_long_hex_secret() {
    let mut config = create_valid_config();
    // 64 hex chars = 32 bytes
    config.token.server_secret = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    assert!(config.validate().is_ok());
}

// ============================================================================
// Vault URL Validation Tests
// ============================================================================

#[test]
fn test_missing_vault_url() {
    let mut config = create_valid_config();
    config.vault.url = None;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.error_count(), 1);
    assert!(err.messages().contains(&"vault_url is required"));
}

#[test]
fn test_invalid_vault_url_format() {
    let mut config = create_valid_config();
    config.vault.url = Some("not-a-valid-url".to_string());

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("vault_url is not a valid URL")));
}

#[test]
fn test_invalid_vault_url_missing_scheme() {
    let mut config = create_valid_config();
    config.vault.url = Some("vault.example.com".to_string());

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("vault_url is not a valid URL")));
}

#[test]
fn test_valid_vault_url_with_port() {
    let mut config = create_valid_config();
    config.vault.url = Some("https://vault.example.com:8200".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_vault_url_with_path() {
    let mut config = create_valid_config();
    config.vault.url = Some("https://vault.example.com/v1".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_vault_url_http() {
    let mut config = create_valid_config();
    config.vault.url = Some("http://localhost:8200".to_string());

    // HTTP is valid (though not recommended for production)
    assert!(config.validate().is_ok());
}

// ============================================================================
// Vault Authentication Validation Tests
// ============================================================================

#[test]
fn test_missing_vault_authentication() {
    let mut config = create_valid_config();
    config.vault.token = None;
    config.vault.token_file = None;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"Either vault_token or vault_token_file is required"));
}

#[test]
fn test_vault_token_provided() {
    let mut config = create_valid_config();
    config.vault.token = Some("test-token".to_string());
    config.vault.token_file = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_vault_token_file_provided() {
    let config = create_valid_config_with_token_file();
    assert!(config.validate().is_ok());
}

#[test]
fn test_resolved_auth_falls_back_to_legacy_fields() {
    let mut config = create_valid_config();
    config.vault.auth = None;
    config.vault.token = Some("legacy-token".to_string());
    config.vault.token_file = None;

    match config.vault.resolved_auth() {
        VaultAuth::KubernetesServiceAccount { token, token_file } => {
            assert_eq!(token, Some("legacy-token".to_string()));
            assert_eq!(token_file, None);
        }
        other => panic!("expected KubernetesServiceAccount from legacy fields, got {:?}", other),
    }
}

#[test]
fn test_resolved_auth_prefers_explicit_enum_over_legacy() {
    let mut config = create_valid_config();
    // Legacy fields set, but the explicit enum should win.
    config.vault.token = Some("legacy-token".to_string());
    config.vault.auth = Some(VaultAuth::TokenExchange {
        exchange_url: "https://sts.example.com/token".to_string(),
        subject_token_file: "/var/run/secrets/token".to_string(),
        audience: "vault".to_string(),
        scope: "vault-access".to_string(),
        role: None,
    });

    assert!(matches!(config.vault.resolved_auth(), VaultAuth::TokenExchange { .. }));
}

#[test]
fn test_token_exchange_auth_passes_validation_without_legacy_token() {
    let mut config = create_valid_config();
    // No legacy token/token_file, but token-exchange auth is fully specified.
    config.vault.token = None;
    config.vault.token_file = None;
    config.vault.auth = Some(VaultAuth::TokenExchange {
        exchange_url: "https://sts.example.com/token".to_string(),
        subject_token_file: "/var/run/secrets/token".to_string(),
        audience: "vault".to_string(),
        scope: "vault-access".to_string(),
        role: None,
    });

    assert!(config.validate().is_ok());
}

#[test]
fn test_kubernetes_auth_enum_without_token_fails_validation() {
    let mut config = create_valid_config();
    config.vault.token = None;
    config.vault.token_file = None;
    config.vault.auth = Some(VaultAuth::KubernetesServiceAccount {
        token: None,
        token_file: None,
    });

    let err = config.validate().unwrap_err();
    assert!(
        err.messages()
            .contains(&"Either vault_token or vault_token_file is required")
    );
}

// ============================================================================
// Server Secret Validation Tests
// ============================================================================

#[test]
fn test_valid_hex_server_secret() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("0123456789abcdef0123456789abcdef".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_invalid_hex_server_secret() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("not-valid-hex".to_string());

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("token_server_secret must be a valid hex-encoded string"))
    );
}

#[test]
fn test_empty_server_secret() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("".to_string());

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"token_server_secret cannot be empty"));
}

#[test]
fn test_server_secret_too_short() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("0123456789abcdef".to_string()); // 8 bytes, less than 16

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("should be at least 32 hex characters"))
    );
}

#[test]
fn test_server_secret_exact_minimum() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("0123456789abcdef0123456789abcdef".to_string()); // Exactly 16 bytes

    assert!(config.validate().is_ok());
}

#[test]
fn test_server_secret_uppercase_hex() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("0123456789ABCDEF0123456789ABCDEF".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_server_secret_mixed_case_hex() {
    let mut config = create_valid_config();
    config.token.server_secret = Some("0123456789AbCdEf0123456789aBcDeF".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_no_server_secret_is_valid() {
    let mut config = create_valid_config();
    config.token.server_secret = None;

    // None is valid (will generate random secret)
    assert!(config.validate().is_ok());
}

// ============================================================================
// Port Validation Tests
// ============================================================================

#[test]
fn test_port_conflict() {
    let mut config = create_valid_config();
    config.siglet_api_port = 8080;
    config.signaling_port = 8080;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("siglet_api_port and signaling_port cannot be the same"))
    );
}

#[test]
fn test_siglet_api_port_zero() {
    let mut config = create_valid_config();
    config.siglet_api_port = 0;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"siglet_api_port cannot be 0"));
}

#[test]
fn test_signaling_port_zero() {
    let mut config = create_valid_config();
    config.signaling_port = 0;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"signaling_port cannot be 0"));
}

#[test]
fn test_both_ports_zero() {
    let mut config = create_valid_config();
    config.siglet_api_port = 0;
    config.signaling_port = 0;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    // Should have 2 errors (one for each port being 0)
    // Note: won't have "same port" error because both are 0
    assert!(err.error_count() >= 2);
}

#[test]
fn test_refresh_api_port_conflicts_with_siglet_api_port() {
    let mut config = create_valid_config();
    config.refresh_api_port = config.siglet_api_port;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("refresh_api_port and siglet_api_port cannot be the same"))
    );
}

#[test]
fn test_refresh_api_port_conflicts_with_signaling_port() {
    let mut config = create_valid_config();
    config.refresh_api_port = config.signaling_port;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("refresh_api_port and signaling_port cannot be the same"))
    );
}

#[test]
fn test_refresh_api_port_zero() {
    let mut config = create_valid_config();
    config.refresh_api_port = 0;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"refresh_api_port cannot be 0"));
}

#[test]
fn test_high_port_numbers_valid() {
    let mut config = create_valid_config();
    config.siglet_api_port = 65535;
    config.signaling_port = 65534;
    config.refresh_api_port = 65533;

    assert!(config.validate().is_ok());
}

// ============================================================================
// Transfer Types Validation Tests
// ============================================================================

#[test]
fn test_empty_transfer_type() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("".to_string())
            .endpoint("https://pull.example.com".to_string())
            .endpoint_type("HTTP".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("transfer_type cannot be empty")));
}

#[test]
fn test_empty_endpoint_type() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint("https://pull.example.com".to_string())
            .endpoint_type("".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("endpoint_type cannot be empty")));
}

#[test]
fn test_empty_endpoint() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint("".to_string())
            .endpoint_type("HTTP".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("endpoint cannot be empty")));
}

#[test]
fn test_multiple_transfer_types_with_one_invalid() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .build(),
        TransferType::builder()
            .transfer_type("".to_string())
            .endpoint_type("S3".to_string())
            .endpoint("https://s3.example.com".to_string())
            .token_source(TokenSource::Client)
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.iter().any(|msg| msg.contains("transfer_types[1]")));
}

#[test]
fn test_empty_transfer_types_list_is_valid() {
    let mut config = create_valid_config();
    config.transfer_types = vec![];

    assert!(config.validate().is_ok());
}

// ============================================================================
// Storage Backend Validation Tests
// ============================================================================

#[test]
fn test_memory_storage_backend_valid() {
    let mut config = create_valid_config();
    config.storage_backend = StorageBackend::Memory;

    assert!(config.validate().is_ok());
}

// ============================================================================
// Vault Signing Key Name Validation Tests
// ============================================================================

#[test]
fn test_empty_vault_signing_key_name() {
    let mut config = create_valid_config();
    config.vault.signing_key_name = "".to_string();

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(messages.contains(&"vault_signing_key_name cannot be empty"));
}

#[test]
fn test_valid_vault_signing_key_name() {
    let mut config = create_valid_config();
    config.vault.signing_key_name = "my-custom-key".to_string();

    assert!(config.validate().is_ok());
}

#[test]
fn test_empty_vault_mount_path() {
    let mut config = create_valid_config();
    config.vault.mount_path = Some("   ".to_string());

    let result = config.validate();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .messages()
            .contains(&"vault.mount_path cannot be empty when set")
    );
}

#[test]
fn test_valid_vault_mount_path() {
    let mut config = create_valid_config();
    config.vault.mount_path = Some("kv".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_none_vault_mount_path_is_valid() {
    let mut config = create_valid_config();
    config.vault.mount_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_empty_vault_token_subpath() {
    let mut config = create_valid_config();
    config.vault.token_subpath = Some("".to_string());

    let result = config.validate();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .messages()
            .contains(&"vault.token_subpath cannot be empty when set")
    );
}

#[test]
fn test_valid_vault_token_subpath() {
    let mut config = create_valid_config();
    config.vault.token_subpath = Some("destination".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_none_vault_token_subpath_is_valid() {
    let mut config = create_valid_config();
    config.vault.token_subpath = None;

    assert!(config.validate().is_ok());
}

// ============================================================================
// Multiple Errors Tests
// ============================================================================

#[test]
fn test_multiple_validation_errors() {
    let mut config = SigletConfig::default();
    config.vault.url = None; // Error 1
    config.vault.token = None; // Error 2 (combined with vault_token_file)
    config.vault.token_file = None;
    config.siglet_api_port = 8080;
    config.signaling_port = 8080; // Error 3

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.error_count() >= 3);

    let messages = err.messages();
    assert!(messages.contains(&"vault_url is required"));
    assert!(messages.contains(&"Either vault_token or vault_token_file is required"));
    assert!(messages.iter().any(|msg| msg.contains("cannot be the same")));
}

#[test]
fn test_all_possible_errors() {
    let config = SigletConfig {
        siglet_api_port: 0,     // Error 1
        signaling_port: 0,      // Error 2
        refresh_api_port: 0,    // Error 3
        management_api_port: 0, // Error 3b
        bind: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        storage_backend: StorageBackend::Memory,
        transfer_types: vec![
            TransferType::builder()
                .transfer_type("".to_string()) // Error 4
                .endpoint_type("".to_string()) // Error 5
                .endpoint("".to_string())
                .token_source(TokenSource::Provider)
                .build(),
        ],
        vault: VaultConfig {
            url: None,   // Error 6
            token: None, // Error 7 (combined)
            token_file: None,
            signing_key_name: "".to_string(), // Error 8
            mount_path: None,
            token_subpath: None,
            use_http_resolution: false,
            auth: None,
        },
        token: TokenConfig {
            server_secret: Some("invalid-hex".to_string()), // Error 9
            ..Default::default()
        },
        signaling_auth: SignalingAuthConfig::Enabled {
            jwks_url: String::new(),       // Error 10: empty URL
            cache_ttl_seconds: 0,          // Error 11: zero TTL
            audience: String::new(),       // Error 12: empty audience
            required_scope: String::new(), // Error 13: empty required scope
        },
        token_api_auth: TokenApiAuthConfig::Disabled,
        management_api_auth: ManagementApiAuthConfig::Disabled,
        http_client: crate::config::HttpClientConfig {
            connect_timeout_seconds: 0, // Error 12: zero connect timeout
            request_timeout_seconds: 0, // Error 13: zero request timeout
        },
    };

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.error_count() >= 8);
}

// ============================================================================
// ValidationError Type Tests
// ============================================================================

#[test]
fn test_validation_error_single() {
    let err = ValidationError::single("test error");
    assert_eq!(err.error_count(), 1);
    assert_eq!(err.messages(), vec!["test error"]);
}

#[test]
fn test_validation_error_multiple() {
    let err = ValidationError::Multiple(vec![
        "error 1".to_string(),
        "error 2".to_string(),
        "error 3".to_string(),
    ]);
    assert_eq!(err.error_count(), 3);
    assert_eq!(err.messages(), vec!["error 1", "error 2", "error 3"]);
}

#[test]
fn test_validation_error_display_single() {
    let err = ValidationError::single("test error");
    let display = format!("{}", err);
    assert!(display.contains("Configuration validation failed: test error"));
}

#[test]
fn test_validation_error_display_multiple() {
    let err = ValidationError::Multiple(vec!["error 1".to_string(), "error 2".to_string()]);
    let display = format!("{}", err);
    assert!(display.contains("Configuration validation failed with 2 error(s)"));
    assert!(display.contains("1. error 1"));
    assert!(display.contains("2. error 2"));
}

#[test]
fn test_validation_error_clone() {
    let err = ValidationError::single("test error");
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_vault_url_with_query_params() {
    let mut config = create_valid_config();
    config.vault.url = Some("https://vault.example.com?namespace=admin".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_vault_url_localhost() {
    let mut config = create_valid_config();
    config.vault.url = Some("http://localhost:8200".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_vault_url_ip_address() {
    let mut config = create_valid_config();
    config.vault.url = Some("https://192.168.1.100:8200".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_default_config_validation_fails() {
    let config = SigletConfig::default();

    // Default config should fail validation (missing vault_url and auth)
    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn test_config_with_whitespace_in_vault_url() {
    let mut config = create_valid_config();
    config.vault.url = Some(" https://vault.example.com ".to_string());

    // URL parser accepts and trims whitespace, so this is valid
    // (The URL will be trimmed when parsed)
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_vault_signing_key_with_special_characters() {
    let mut config = create_valid_config();
    config.vault.signing_key_name = "my-key_2024.v1".to_string();

    assert!(config.validate().is_ok());
}

// ============================================================================
// Endpoint Mappings Validation Tests
// ============================================================================

fn make_mapping(key: &str, value: &str, endpoint: &str) -> EndpointMapping {
    EndpointMapping::builder()
        .key(key.to_string())
        .value(value.to_string())
        .endpoint(endpoint.to_string())
        .build()
}

#[test]
fn test_valid_transfer_type_with_endpoint_mappings_no_static_endpoint() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("app", "app1", "https://s3.example.com/climate")])
            .build(),
    ];

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_transfer_type_with_endpoint_mappings_and_static_endpoint() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .endpoint("https://s3.example.com/default".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("app", "app1", "https://s3.example.com/climate")])
            .build(),
    ];

    // Both static endpoint and mappings is valid
    assert!(config.validate().is_ok());
}

#[test]
fn test_transfer_type_missing_endpoint_without_mappings() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("endpoint is required when no endpoint_mappings are configured"))
    );
}

#[test]
fn test_transfer_type_endpoint_mapping_empty_key() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("", "app1", "https://s3.example.com/bucket")])
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("endpoint_mappings[0]") && msg.contains("key cannot be empty"))
    );
}

#[test]
fn test_transfer_type_endpoint_mapping_empty_value() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("app", "", "https://s3.example.com/bucket")])
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("endpoint_mappings[0]") && msg.contains("value cannot be empty"))
    );
}

#[test]
fn test_transfer_type_endpoint_mapping_empty_endpoint() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("app", "app1", "")])
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("endpoint_mappings[0]") && msg.contains("endpoint cannot be empty"))
    );
}

#[test]
fn test_transfer_type_multiple_mapping_errors_reported() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping("", "", "")])
            .build(),
    ];

    let result = config.validate();
    assert!(result.is_err());

    // Empty key + empty value + empty endpoint = 3 errors from the one mapping
    let err = result.unwrap_err();
    assert!(err.error_count() >= 3);
}

#[test]
fn test_valid_transfer_type_with_arbitrary_metadata_key() {
    // Any metadata key name is valid — not restricted to a fixed allowlist
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![make_mapping(
                "customMetaField",
                "some-value",
                "https://s3.example.com/bucket",
            )])
            .build(),
    ];

    assert!(config.validate().is_ok());
}

#[test]
fn test_valid_transfer_type_with_multiple_mappings() {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![
                make_mapping("app", "app1", "https://s3.example.com/climate"),
                make_mapping("app", "app2", "https://s3.example.com/finance"),
            ])
            .build(),
    ];

    assert!(config.validate().is_ok());
}

// ============================================================================
// Signaling Auth Config Validation Tests
// ============================================================================

#[test]
fn test_signaling_auth_default_is_enabled_with_empty_url() {
    // Pins the "default is on" contract: a SignalingAuthConfig with no field set
    // defaults to Enabled. The empty URL is a deliberate forcing function — it
    // makes validation fail unless the operator either supplies a JWKS URL or
    // explicitly switches to Disabled. There is no silent "auth off" fallback.
    let default = SignalingAuthConfig::default();
    match default {
        SignalingAuthConfig::Enabled { jwks_url, .. } => assert!(jwks_url.is_empty()),
        SignalingAuthConfig::Disabled => panic!("default must be Enabled"),
    }
}

#[test]
fn test_signaling_auth_enabled_requires_jwks_url() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: String::new(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "dplane-signaling".to_string(),
    };

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("signaling_auth.jwks_url is required"))
    );
}

#[test]
fn test_signaling_auth_enabled_rejects_invalid_jwks_url() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: "not-a-url".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "dplane-signaling".to_string(),
    };

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("signaling_auth.jwks_url is not a valid URL"))
    );
}

#[test]
fn test_signaling_auth_enabled_with_valid_jwks_url_passes() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "dplane-signaling".to_string(),
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_signaling_auth_disabled_passes_without_url() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Disabled;

    // Disabled needs no URL — the type makes the URL inexpressible.
    assert!(config.validate().is_ok());
}

#[test]
fn test_signaling_auth_rejects_zero_cache_ttl() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 0,
        audience: "siglet".to_string(),
        required_scope: "dplane-signaling".to_string(),
    };

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    let messages = err.messages();
    assert!(
        messages
            .iter()
            .any(|msg| msg.contains("signaling_auth.cache_ttl_seconds"))
    );
}

#[test]
fn test_management_api_auth_default_is_enabled_with_empty_url() {
    // Strict default: must be explicitly configured or disabled.
    assert!(matches!(
        ManagementApiAuthConfig::default(),
        ManagementApiAuthConfig::Enabled { jwks_url, .. } if jwks_url.is_empty()
    ));
}

#[test]
fn test_management_api_auth_enabled_requires_jwks_url() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Enabled {
        jwks_url: String::new(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("management_api_auth.jwks_url is required"));
}

#[test]
fn test_management_api_auth_enabled_rejects_invalid_jwks_url() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Enabled {
        jwks_url: "not-a-url".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("management_api_auth.jwks_url is not a valid URL"));
}

#[test]
fn test_management_api_auth_rejects_zero_cache_ttl() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 0,
        audience: "siglet".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("management_api_auth.cache_ttl_seconds"));
}

#[test]
fn test_management_api_auth_rejects_empty_audience() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: String::new(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("management_api_auth.audience cannot be empty"));
}

#[test]
fn test_management_api_auth_enabled_with_valid_jwks_url_passes() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_management_api_auth_disabled_passes_without_url() {
    let mut config = create_valid_config();
    config.management_api_auth = ManagementApiAuthConfig::Disabled;

    assert!(config.validate().is_ok());
}

#[test]
fn test_management_api_auth_deserialize_enabled_defaults_audience() {
    let json = r#"{"mode": "enabled", "jwks_url": "https://idp.example.com/jwks.json"}"#;
    let parsed: ManagementApiAuthConfig = serde_json::from_str(json).expect("enabled variant should parse");
    assert_eq!(
        parsed,
        ManagementApiAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "siglet".to_string(),
        }
    );
}

#[test]
fn test_signaling_auth_deserialize_disabled() {
    let json = r#"{"mode": "disabled"}"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).expect("disabled variant should parse");
    assert_eq!(parsed, SignalingAuthConfig::Disabled);
}

#[test]
fn test_signaling_auth_deserialize_enabled() {
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json"
    }"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).expect("enabled variant should parse");
    // cache_ttl_seconds, audience, and required_scope all fall back to their
    // defaults — pin all three.
    assert_eq!(
        parsed,
        SignalingAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "siglet".to_string(),
            required_scope: "dplane-signaling".to_string(),
        }
    );
}

#[test]
fn test_signaling_auth_audience_defaults_to_siglet() {
    // Pins the user-visible default: omitting `audience` from the [signaling_auth]
    // table gives you `"siglet"`. Production deployments should override this with
    // an instance-specific identifier, but the out-of-the-box default must match
    // jwtlet's documented `token.audience` value used in dev/example configs.
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json"
    }"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).unwrap();
    match parsed {
        SignalingAuthConfig::Enabled { audience, .. } => {
            assert_eq!(audience, "siglet");
        }
        SignalingAuthConfig::Disabled => panic!("expected Enabled variant"),
    }
}

#[test]
fn test_signaling_auth_audience_round_trip() {
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json",
        "audience": "https://siglet.example.com"
    }"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).unwrap();
    match parsed {
        SignalingAuthConfig::Enabled { audience, .. } => {
            assert_eq!(audience, "https://siglet.example.com");
        }
        SignalingAuthConfig::Disabled => panic!("expected Enabled variant"),
    }
}

#[test]
fn test_signaling_auth_rejects_empty_audience() {
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: String::new(),
        required_scope: "dplane-signaling".to_string(),
    };

    let err = config.validate().expect_err("empty audience must fail");
    assert!(
        err.messages()
            .iter()
            .any(|msg| msg.contains("signaling_auth.audience cannot be empty"))
    );
}

#[test]
fn test_signaling_auth_required_scope_defaults_to_dplane_signaling() {
    // Pins the user-visible default: omitting `required_scope` from the
    // [signaling_auth] table yields `"dplane-signaling"`, so existing configs that
    // predate this option keep working without edits.
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json"
    }"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).unwrap();
    match parsed {
        SignalingAuthConfig::Enabled { required_scope, .. } => {
            assert_eq!(required_scope, "dplane-signaling");
        }
        SignalingAuthConfig::Disabled => panic!("expected Enabled variant"),
    }
}

#[test]
fn test_signaling_auth_required_scope_round_trip() {
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json",
        "required_scope": "custom:signaling"
    }"#;
    let parsed: SignalingAuthConfig = serde_json::from_str(json).unwrap();
    match parsed {
        SignalingAuthConfig::Enabled { required_scope, .. } => {
            assert_eq!(required_scope, "custom:signaling");
        }
        SignalingAuthConfig::Disabled => panic!("expected Enabled variant"),
    }
}

#[test]
fn test_signaling_auth_rejects_empty_required_scope() {
    // An explicitly blank required_scope can't be satisfied by any token, so it
    // must fail validation rather than silently locking out every caller. A
    // whitespace-only value is treated the same.
    let mut config = create_valid_config();
    config.signaling_auth = SignalingAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "   ".to_string(),
    };

    let err = config.validate().expect_err("empty required_scope must fail");
    assert!(
        err.messages()
            .iter()
            .any(|msg| msg.contains("signaling_auth.required_scope cannot be empty"))
    );
}

// ============================================================================
// Token API Auth Config Validation Tests
// ============================================================================

#[test]
fn test_token_api_auth_default_is_enabled_with_empty_url() {
    // Same "default is on" contract as signaling and management auth: the empty URL
    // is a forcing function that fails validation until the operator either supplies
    // a JWKS URL or explicitly switches to Disabled.
    assert!(matches!(
        TokenApiAuthConfig::default(),
        TokenApiAuthConfig::Enabled { jwks_url, .. } if jwks_url.is_empty()
    ));
}

#[test]
fn test_token_api_auth_enabled_requires_jwks_url() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: String::new(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "siglet-token-api".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("token_api_auth.jwks_url is required"));
}

#[test]
fn test_token_api_auth_enabled_rejects_invalid_jwks_url() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: "not-a-url".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "siglet-token-api".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("token_api_auth.jwks_url is not a valid URL"));
}

#[test]
fn test_token_api_auth_enabled_with_valid_jwks_url_passes() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "siglet-token-api".to_string(),
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_token_api_auth_disabled_passes_without_url() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Disabled;

    assert!(config.validate().is_ok());
}

#[test]
fn test_token_api_auth_rejects_zero_cache_ttl() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 0,
        audience: "siglet".to_string(),
        required_scope: "siglet-token-api".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("token_api_auth.cache_ttl_seconds"));
}

#[test]
fn test_token_api_auth_rejects_empty_audience() {
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: String::new(),
        required_scope: "siglet-token-api".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("token_api_auth.audience cannot be empty"));
}

#[test]
fn test_token_api_auth_rejects_empty_required_scope() {
    // A blank required_scope can't be satisfied by any token; a whitespace-only
    // value is treated the same. Mirrors the signaling-auth rule.
    let mut config = create_valid_config();
    config.token_api_auth = TokenApiAuthConfig::Enabled {
        jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
        cache_ttl_seconds: 300,
        audience: "siglet".to_string(),
        required_scope: "   ".to_string(),
    };

    let messages = config.validate().unwrap_err().messages().join("\n");
    assert!(messages.contains("token_api_auth.required_scope cannot be empty"));
}

#[test]
fn test_token_api_auth_deserialize_disabled() {
    let json = r#"{"mode": "disabled"}"#;
    let parsed: TokenApiAuthConfig = serde_json::from_str(json).expect("disabled variant should parse");
    assert_eq!(parsed, TokenApiAuthConfig::Disabled);
}

#[test]
fn test_token_api_auth_deserialize_enabled_uses_defaults() {
    // Pins the user-visible defaults: a [token_api_auth] table carrying only a
    // jwks_url yields the same TTL/audience/scope the token API used when it was
    // still driven by [signaling_auth], so behaviour is unchanged for operators
    // who just move the URL into the new block.
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json"
    }"#;
    let parsed: TokenApiAuthConfig = serde_json::from_str(json).expect("enabled variant should parse");
    assert_eq!(
        parsed,
        TokenApiAuthConfig::Enabled {
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            cache_ttl_seconds: 300,
            audience: "siglet".to_string(),
            required_scope: "siglet-token-api".to_string(),
        }
    );
}

#[test]
fn test_token_api_auth_audience_and_scope_round_trip() {
    let json = r#"{
        "mode": "enabled",
        "jwks_url": "https://idp.example.com/.well-known/jwks.json",
        "audience": "https://siglet.example.com",
        "required_scope": "custom:token-api"
    }"#;
    let parsed: TokenApiAuthConfig = serde_json::from_str(json).unwrap();
    match parsed {
        TokenApiAuthConfig::Enabled {
            audience,
            required_scope,
            ..
        } => {
            assert_eq!(audience, "https://siglet.example.com");
            assert_eq!(required_scope, "custom:token-api");
        }
        TokenApiAuthConfig::Disabled => panic!("expected Enabled variant"),
    }
}

// ============================================================================
// HTTP Client Config Validation Tests
// ============================================================================

#[test]
fn test_http_client_defaults_pass_validation() {
    // The default values must produce a valid config — operators who never
    // touch [http_client] should not have their deployment refuse to start.
    let config = create_valid_config();
    assert_eq!(config.http_client, crate::config::HttpClientConfig::default());
    assert!(config.validate().is_ok());
}

#[test]
fn test_http_client_rejects_zero_connect_timeout() {
    let mut config = create_valid_config();
    config.http_client.connect_timeout_seconds = 0;

    let err = config.validate().expect_err("zero connect_timeout must fail");
    assert!(
        err.messages()
            .iter()
            .any(|msg| msg.contains("http_client.connect_timeout_seconds")),
        "validation error must mention the offending field, got: {:?}",
        err.messages()
    );
}

#[test]
fn test_http_client_rejects_zero_request_timeout() {
    let mut config = create_valid_config();
    config.http_client.request_timeout_seconds = 0;

    let err = config.validate().expect_err("zero request_timeout must fail");
    assert!(
        err.messages()
            .iter()
            .any(|msg| msg.contains("http_client.request_timeout_seconds"))
    );
}

#[test]
fn test_http_client_accepts_custom_timeouts() {
    let mut config = create_valid_config();
    config.http_client = crate::config::HttpClientConfig {
        connect_timeout_seconds: 1,
        request_timeout_seconds: 600,
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_http_client_deserialize_partial_fills_defaults() {
    use crate::config::{DEFAULT_HTTP_CONNECT_TIMEOUT_SECS, HttpClientConfig};
    // Specifying request_timeout but not connect_timeout — the unspecified
    // field must fall back to the constant default, not to zero.
    let parsed: HttpClientConfig = serde_json::from_str(r#"{"request_timeout_seconds": 120}"#).unwrap();
    assert_eq!(parsed.connect_timeout_seconds, DEFAULT_HTTP_CONNECT_TIMEOUT_SECS);
    assert_eq!(parsed.request_timeout_seconds, 120);
}

// ============================================================================
// TransferType serde: camelCase canonical, snake_case config compatibility
// ============================================================================

#[test]
fn test_transfer_type_serializes_camel_case() {
    let tt = TransferType::builder()
        .transfer_type("HttpData-PULL".to_string())
        .endpoint_type("HTTP".to_string())
        .endpoint("https://data.example.com".to_string())
        .token_source(TokenSource::Provider)
        .tx_renewal_support(true)
        .build();

    let v = serde_json::to_value(&tt).unwrap();
    // Canonical wire form is camelCase.
    assert_eq!(v["transferType"], "HttpData-PULL");
    assert_eq!(v["endpointType"], "HTTP");
    assert_eq!(v["tokenSource"], "provider");
    assert_eq!(v["txRenewalSupport"], true);
    // The snake_case keys must NOT appear in the output.
    assert!(v.get("transfer_type").is_none());
    assert!(v.get("token_source").is_none());
}

#[test]
fn test_transfer_type_deserializes_camel_case() {
    let json = r#"{
        "transferType": "HttpData-PULL",
        "endpointType": "HTTP",
        "endpoint": "https://data.example.com/assets",
        "tokenSource": "provider",
        "txRenewalSupport": true
    }"#;
    let tt: TransferType = serde_json::from_str(json).unwrap();
    assert_eq!(tt.transfer_type, "HttpData-PULL");
    assert_eq!(tt.endpoint_type, "HTTP");
    assert_eq!(tt.token_source, TokenSource::Provider);
    assert!(tt.tx_renewal_support);
}

#[test]
fn test_transfer_type_deserializes_snake_case_from_toml_config() {
    use config::{Config, File, FileFormat};

    // Regression guard: existing snake_case TOML config files must keep loading through the
    // `config` crate even though the canonical serde form is now camelCase (via serde aliases).
    let toml = r#"
        [[transfer_types]]
        transfer_type = "HttpData-PULL"
        endpoint_type = "HTTP"
        token_source = "provider"
        endpoint = "https://data.provider.example.com/assets"
        tx_renewal_support = true

        [[transfer_types.endpoint_mappings]]
        key = "region"
        value = "eu-west-1"
        endpoint = "https://eu-west-1.data.example.com"
    "#;

    let cfg: SigletConfig = Config::builder()
        .add_source(File::from_str(toml, FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();

    assert_eq!(cfg.transfer_types.len(), 1);
    let tt = &cfg.transfer_types[0];
    assert_eq!(tt.transfer_type, "HttpData-PULL");
    assert_eq!(tt.endpoint_type, "HTTP");
    assert_eq!(tt.token_source, TokenSource::Provider);
    assert!(tt.tx_renewal_support);
    assert_eq!(tt.endpoint_mappings.len(), 1);
    assert_eq!(tt.endpoint_mappings[0].key, "region");
    assert_eq!(tt.endpoint_mappings[0].value, "eu-west-1");
    assert_eq!(tt.endpoint_mappings[0].endpoint, "https://eu-west-1.data.example.com");
}

// ============================================================================
// Claim Mappings Validation Tests
// ============================================================================

fn make_claim_mapping(from: &str, to: &str) -> ClaimMapping {
    ClaimMapping::builder().from(from).to(to).build()
}

/// Builds a config whose single transfer type carries the given root claim mappings.
fn config_with_claim_mappings(claim_mappings: Vec<ClaimMapping>) -> SigletConfig {
    let mut config = create_valid_config();
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("http-pull".to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://data.example.com".to_string())
            .token_source(TokenSource::Provider)
            .claim_mappings(claim_mappings)
            .build(),
    ];
    config
}

fn validation_messages(config: &SigletConfig) -> Vec<String> {
    match config.validate() {
        Ok(()) => vec![],
        Err(ValidationError::Multiple(errors)) => errors,
        Err(e) => vec![e.to_string()],
    }
}

#[test]
fn test_valid_claim_mappings_pass_validation() {
    let config = config_with_claim_mappings(vec![
        make_claim_mapping("flow.agreementId", "agreement"),
        make_claim_mapping("'urn:asset:' + flow.datasetId", "assetUrn"),
        make_claim_mapping(
            r#"flow.claims.vc.filter(c, "MembershipCredential" in c.type).map(c, c.issuer)"#,
            "issuers",
        ),
    ]);
    assert!(config.validate().is_ok(), "{:?}", validation_messages(&config));
}

#[test]
fn test_claim_mapping_with_empty_to_is_rejected() {
    let config = config_with_claim_mappings(vec![make_claim_mapping("flow.agreementId", "  ")]);
    let errors = validation_messages(&config);
    assert!(
        errors.iter().any(|e| e.contains("to cannot be empty")),
        "expected an empty-`to` error, got {errors:?}"
    );
}

#[test]
fn test_claim_mapping_with_empty_from_is_rejected() {
    let config = config_with_claim_mappings(vec![make_claim_mapping("", "claim")]);
    let errors = validation_messages(&config);
    assert!(
        errors.iter().any(|e| e.contains("from cannot be empty")),
        "expected an empty-`from` error, got {errors:?}"
    );
}

#[test]
fn test_claim_mapping_with_reserved_claim_name_is_rejected() {
    for reserved in ["sub", "exp", "iss", "aud", "iat", "nbf", "jti"] {
        let config = config_with_claim_mappings(vec![make_claim_mapping("'x'", reserved)]);
        let errors = validation_messages(&config);
        assert!(
            errors.iter().any(|e| e.contains("reserved JWT claim")),
            "expected '{reserved}' to be rejected, got {errors:?}"
        );
    }
}

#[test]
fn test_claim_mapping_with_invalid_expression_is_rejected() {
    let config = config_with_claim_mappings(vec![make_claim_mapping("flow.", "broken")]);
    let errors = validation_messages(&config);
    assert!(
        errors.iter().any(|e| e.contains("invalid expression")),
        "expected an invalid-expression error, got {errors:?}"
    );
}

#[test]
fn test_duplicate_claim_key_is_rejected() {
    let config = config_with_claim_mappings(vec![
        make_claim_mapping("flow.agreementId", "same"),
        make_claim_mapping("flow.datasetId", "same"),
    ]);
    let errors = validation_messages(&config);
    assert!(
        errors.iter().any(|e| e.contains("duplicate claim key 'same'")),
        "expected a duplicate-key error, got {errors:?}"
    );
}

#[test]
fn test_claim_mapping_errors_accumulate_rather_than_short_circuiting() {
    let config = config_with_claim_mappings(vec![
        make_claim_mapping("flow.", "broken"),
        make_claim_mapping("'x'", "sub"),
        make_claim_mapping("", ""),
    ]);
    let errors = validation_messages(&config);
    assert!(errors.len() >= 4, "every problem should be reported, got {errors:?}");
    assert!(errors.iter().any(|e| e.contains("invalid expression")));
    assert!(errors.iter().any(|e| e.contains("reserved JWT claim")));
    assert!(errors.iter().any(|e| e.contains("to cannot be empty")));
    assert!(errors.iter().any(|e| e.contains("from cannot be empty")));
}

#[test]
fn test_endpoint_mapping_claim_mappings_are_validated() {
    let mut config = create_valid_config();
    let mut mapping = make_mapping("app", "app1", "https://s3.example.com/climate");
    mapping.claim_mappings = vec![make_claim_mapping("flow.", "broken")];
    config.transfer_types = vec![
        TransferType::builder()
            .transfer_type("s3-pull".to_string())
            .endpoint_type("AmazonS3".to_string())
            .token_source(TokenSource::Provider)
            .endpoint_mappings(vec![mapping])
            .build(),
    ];

    let errors = validation_messages(&config);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("endpoint_mappings[0].claim_mappings[0]") && e.contains("invalid expression")),
        "expected the error to point at the endpoint mapping's claim mapping, got {errors:?}"
    );
}

// ============================================================================
// Claim Mappings serde
// ============================================================================

#[test]
fn test_transfer_type_serializes_claim_mappings_camel_case() {
    let tt = TransferType::builder()
        .transfer_type("HttpData-PULL".to_string())
        .endpoint_type("HTTP".to_string())
        .endpoint("https://data.example.com".to_string())
        .token_source(TokenSource::Provider)
        .claim_mappings(vec![make_claim_mapping("flow.datasetId", "assetId")])
        .build();

    let v = serde_json::to_value(&tt).unwrap();
    assert_eq!(v["claimMappings"][0]["from"], "flow.datasetId");
    assert_eq!(v["claimMappings"][0]["to"], "assetId");
    assert_eq!(v["claimMappings"][0]["optional"], false);
    assert!(v.get("claim_mappings").is_none());
}

#[test]
fn test_endpoint_mapping_serializes_claim_mappings_camel_case() {
    let mut mapping = make_mapping("app", "app1", "https://s3.example.com/climate");
    mapping.claim_mappings = vec![make_claim_mapping("'us-east-1'", "zone")];

    let v = serde_json::to_value(&mapping).unwrap();
    // The three pre-existing fields are single words, so camelCase leaves them unchanged.
    assert_eq!(v["key"], "app");
    assert_eq!(v["value"], "app1");
    assert_eq!(v["endpoint"], "https://s3.example.com/climate");
    assert_eq!(v["claimMappings"][0]["to"], "zone");
    assert!(v.get("claim_mappings").is_none());
}

#[test]
fn test_transfer_type_without_claim_mappings_deserializes() {
    // Back-compat guard for rows already stored in the transfer_type_mappings JSONB column,
    // which predate the claimMappings field.
    let json = r#"{
        "transferType": "HttpData-PULL",
        "endpointType": "HTTP",
        "endpoint": "https://data.example.com",
        "tokenSource": "provider",
        "endpointMappings": [{"key": "app", "value": "app1", "endpoint": "https://a.example.com"}]
    }"#;
    let tt: TransferType = serde_json::from_str(json).unwrap();
    assert!(tt.claim_mappings.is_empty());
    assert!(tt.endpoint_mappings[0].claim_mappings.is_empty());
}

#[test]
fn test_claim_mappings_deserialize_snake_case_from_toml_config() {
    use config::{Config, File, FileFormat};

    let toml = r#"
        [[transfer_types]]
        transfer_type = "HttpData-PULL"
        endpoint_type = "HTTP"
        token_source = "provider"

        [[transfer_types.claim_mappings]]
        from = "flow.metadata.region"
        to = "region"

        [[transfer_types.endpoint_mappings]]
        key = "region"
        value = "eu-west-1"
        endpoint = "https://eu-west-1.data.example.com"

        [[transfer_types.endpoint_mappings.claim_mappings]]
        from = "'eu-west-1'"
        to = "zone"
        optional = true
    "#;

    let cfg: SigletConfig = Config::builder()
        .add_source(File::from_str(toml, FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();

    let tt = &cfg.transfer_types[0];
    assert_eq!(tt.claim_mappings.len(), 1);
    assert_eq!(tt.claim_mappings[0].from, "flow.metadata.region");
    assert_eq!(tt.claim_mappings[0].to, "region");
    assert!(!tt.claim_mappings[0].optional, "optional defaults to false");

    let endpoint_mappings = &tt.endpoint_mappings[0].claim_mappings;
    assert_eq!(endpoint_mappings.len(), 1);
    assert_eq!(endpoint_mappings[0].to, "zone");
    assert!(endpoint_mappings[0].optional);
}

#[test]
fn test_documented_claim_mapping_toml_parses_and_validates() {
    use config::{Config, File, FileFormat};

    // Mirrors the claim-mapping block in docs/siglet.md's configuration reference. Keeping it
    // here means a documented example that stops parsing — or stops validating — fails the build.
    let toml = r#"
        [vault]
        url = "https://vault.example.com"
        token = "test-token"

        [[transfer_types]]
        transfer_type = "HttpData-PULL"
        endpoint_type = "HTTP"
        token_source = "provider"

        [[transfer_types.claim_mappings]]
        from = "flow.metadata.region"
        to = "region"

        [[transfer_types.claim_mappings]]
        from = '"urn:asset:" + flow.datasetId'
        to = "assetUrn"

        [[transfer_types.claim_mappings]]
        from = 'flow.claims.vc.filter(c, "MembershipCredential" in c.type)[0].credentialSubject.holderIdentifier'
        to = "holderIdentifier"
        optional = true

        [[transfer_types.endpoint_mappings]]
        key = "region"
        value = "us-east-1"
        endpoint = "https://us-east-1.data.example.com"

        [[transfer_types.endpoint_mappings.claim_mappings]]
        from = '"us-east-1"'
        to = "region"
    "#;

    let mut cfg: SigletConfig = Config::builder()
        .add_source(File::from_str(toml, FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    cfg.signaling_auth = SignalingAuthConfig::Disabled;
    cfg.token_api_auth = TokenApiAuthConfig::Disabled;
    cfg.management_api_auth = ManagementApiAuthConfig::Disabled;

    let tt = &cfg.transfer_types[0];
    assert_eq!(tt.claim_mappings.len(), 3);
    assert_eq!(tt.claim_mappings[1].from, r#""urn:asset:" + flow.datasetId"#);
    assert!(tt.claim_mappings[2].optional);
    assert_eq!(tt.endpoint_mappings[0].claim_mappings[0].from, r#""us-east-1""#);

    // Every documented expression must compile.
    assert!(cfg.validate().is_ok(), "{:?}", validation_messages(&cfg));
}
