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

//! Tests to verify internal error details are NOT leaked to clients.
//!
//! This test suite creates failing mock implementations with detailed internal
//! error messages and verifies that clients only see generic error responses.
//!
//! Note: Pingora does NOT send internal error context strings to clients - they
//! are only logged. This is verified per https://github.com/cloudflare/pingora/issues/457

#![allow(clippy::unwrap_used)]
mod common;

use crate::common::{
    DefaultOperationParser, DetailedFailureJwtVerifier, FailingAuthEvaluator, FailingCredentialResolver,
    FailingOperationParser, PassthroughCredentialsResolver, PermissiveAuthEvaluator, ProxyConfig,
    SuspiciousCredentialResolver, TestJwtVerifier, get_available_port, launch_s3proxy,
};

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use dsdk_facet_proxy::s3::S3Credentials;
use dsdk_facet_testcontainers::s3::{TEST_BUCKET, TEST_KEY};
use std::sync::Arc;

// ============================================================================
// Tests - Internal Error Details Are NOT Leaked to Clients
// ============================================================================

#[tokio::test]
async fn test_credential_resolver_failure_does_not_leak_details() {
    let proxy_port = get_available_port();

    // Launch proxy with failing credential resolver that has detailed internal error
    let internal_host = "creds-db.internal.example.com:5432";
    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        Arc::new(FailingCredentialResolver {
            internal_detail: internal_host.to_string(),
        }),
        Arc::new(PermissiveAuthEvaluator),
        Arc::new(TestJwtVerifier {
            scope: TEST_BUCKET.to_string(),
        }),
        Arc::new(DefaultOperationParser),
    ))
    .await;

    // Configure client
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    // Make request - will fail during credential resolution
    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    assert!(result.is_err(), "Request should fail due to credential resolver error");

    let err = result.unwrap_err();
    let err_str = format!("{:?} {}", err, err);

    // Assert that sensitive internal details are NOT leaked to client
    assert!(
        !err_str.contains("creds-db.internal.example.com"),
        "Leaked internal hostname: {}",
        err_str
    );
    assert!(!err_str.contains("5432"), "Leaked internal port: {}", err_str);
}

#[tokio::test]
async fn test_authorization_evaluator_failure_does_not_leak_details() {
    let proxy_port = get_available_port();

    // Launch proxy with failing auth evaluator that has detailed internal error
    let internal_service = "policy-svc-1.prod.internal:8080";
    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: "test-key".to_string(),
                secret_key: "test-secret".to_string(),
                region: "us-east-1".to_string(),
            },
        }),
        Arc::new(FailingAuthEvaluator {
            internal_detail: internal_service.to_string(),
        }),
        Arc::new(TestJwtVerifier {
            scope: TEST_BUCKET.to_string(),
        }),
        Arc::new(DefaultOperationParser),
    ))
    .await;

    // Configure client
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    // Make request - will fail during authorization evaluation
    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    assert!(
        result.is_err(),
        "Request should fail due to authorization evaluator error"
    );

    let err = result.unwrap_err();
    let err_str = format!("{:?} {}", err, err);

    // Assert that sensitive internal details are NOT leaked to client
    assert!(
        !err_str.contains("policy-svc-1.prod.internal"),
        "Leaked internal hostname: {}",
        err_str
    );
    assert!(!err_str.contains("8080"), "Leaked internal port: {}", err_str);
}

#[tokio::test]
async fn test_operation_parser_failure_does_not_leak_details() {
    let proxy_port = get_available_port();

    // Launch proxy with failing operation parser that has detailed internal error
    let internal_detail = "index 42";
    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: "test-key".to_string(),
                secret_key: "test-secret".to_string(),
                region: "us-east-1".to_string(),
            },
        }),
        Arc::new(PermissiveAuthEvaluator),
        Arc::new(TestJwtVerifier {
            scope: TEST_BUCKET.to_string(),
        }),
        Arc::new(FailingOperationParser {
            internal_detail: internal_detail.to_string(),
        }),
    ))
    .await;

    // Configure client
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    // Make request - will fail during operation parsing
    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    assert!(result.is_err(), "Request should fail due to operation parser error");

    let err = result.unwrap_err();
    let err_str = format!("{:?} {}", err, err);

    // Assert that sensitive internal details are NOT leaked to client
    assert!(!err_str.contains("index 42"), "Leaked internal detail: {}", err_str);
    assert!(
        !err_str.contains("0x7fff5fbff000"),
        "Leaked memory address: {}",
        err_str
    );
}

#[tokio::test]
async fn test_aws_signing_with_suspicious_credentials_does_not_leak() {
    let proxy_port = get_available_port();

    // Launch proxy with credential resolver that returns suspicious internal values
    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        Arc::new(SuspiciousCredentialResolver),
        Arc::new(PermissiveAuthEvaluator),
        Arc::new(TestJwtVerifier {
            scope: TEST_BUCKET.to_string(),
        }),
        Arc::new(DefaultOperationParser),
    ))
    .await;

    // Configure client
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    // Make request - may fail at various points (signing, upstream connection, etc.)
    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    // Whether it succeeds or fails, internal credential details should not be exposed
    if let Err(err) = result {
        let err_str = format!("{:?} {}", err, err);

        // Assert that sensitive credential details are NOT leaked to client
        assert!(
            !err_str.contains("AKIA_INTERNAL_USE_ONLY"),
            "Leaked access key: {}",
            err_str
        );
        assert!(!err_str.contains("secret_key_prod"), "Leaked secret key: {}", err_str);
        assert!(
            !err_str.contains("us-east-1-internal-vpc"),
            "Leaked internal region: {}",
            err_str
        );
    }
    // If it succeeds, that's fine - we're just checking no leakage occurs
}

#[tokio::test]
async fn test_jwt_verification_failure_message_is_generic() {
    let proxy_port = get_available_port();

    // Launch proxy with JWT verifier that fails with detailed internal error
    let internal_service = "keys.auth-service.internal:9000";
    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: "test-key".to_string(),
                secret_key: "test-secret".to_string(),
                region: "us-east-1".to_string(),
            },
        }),
        Arc::new(PermissiveAuthEvaluator),
        Arc::new(DetailedFailureJwtVerifier {
            internal_detail: internal_service.to_string(),
        }),
        Arc::new(DefaultOperationParser),
    ))
    .await;

    // Configure client
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    // Make request - will fail during JWT verification
    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    assert!(result.is_err(), "Request should fail due to JWT verification error");

    let err = result.unwrap_err();
    let err_str = format!("{:?} {}", err, err);

    // Assert that sensitive internal details are NOT leaked to client
    assert!(
        !err_str.contains("keys.auth-service.internal"),
        "Leaked internal hostname: {}",
        err_str
    );
    assert!(!err_str.contains("9000"), "Leaked internal port: {}", err_str);
    assert!(
        !err_str.contains("req-abc-123-def"),
        "Leaked correlation ID: {}",
        err_str
    );
    assert!(!err_str.contains("xyz-789"), "Leaked trace ID: {}", err_str);
}

#[tokio::test]
async fn test_internal_failures_use_generic_messages() {
    let credential_resolver = Arc::new(FailingCredentialResolver {
        internal_detail: "db-primary-01.us-west-2.rds.amazonaws.com:5432".to_string(),
    });

    let proxy_port = get_available_port();

    launch_s3proxy(ProxyConfig::for_error_testing(
        proxy_port,
        credential_resolver,
        Arc::new(PermissiveAuthEvaluator),
        Arc::new(TestJwtVerifier {
            scope: TEST_BUCKET.to_string(),
        }),
        Arc::new(DefaultOperationParser),
    ))
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("", "", Some("test-token".to_string()), None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url)
        .load()
        .await;

    let client = Client::new(&config);

    let result = client.get_object().bucket(TEST_BUCKET).key(TEST_KEY).send().await;

    assert!(result.is_err(), "Request should fail");

    let err = result.unwrap_err();
    let err_str = format!("{:?} {}", err, err);

    // Assert that internal details are NOT leaked to client
    assert!(!err_str.contains("db-primary-01"), "Leaked hostname: {}", err_str);
    assert!(
        !err_str.contains("us-west-2.rds.amazonaws.com"),
        "Leaked hostname: {}",
        err_str
    );
    assert!(!err_str.contains("5432"), "Leaked port: {}", err_str);
}
