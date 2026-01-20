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

mod common;

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::Client;
use facet_common::proxy::s3::UpstreamStyle;
use crate::common::{
    get_available_port, launch_s3proxy, MinioInstance, ProxyConfig,
    MINIO_ACCESS_KEY, MINIO_SECRET_KEY, TEST_BUCKET, TEST_KEY,
};

const TEST_CONTENT: &str = "Hello from Pingora proxy test!";
const VALID_SESSION_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const INVALID_SESSION_TOKEN: &str = "invalid-token";

#[tokio::test]
async fn test_s3_proxy_with_token_validation() {
    // Start MinIO container
    let minio = MinioInstance::launch().await;
    minio.setup_bucket_with_file(TEST_BUCKET, TEST_KEY, TEST_CONTENT.as_bytes()).await;

    // Get an available port for the proxy
    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_token_testing(
        proxy_port,
        minio.host.clone(),
        UpstreamStyle::PathStyle,
        None,
        VALID_SESSION_TOKEN.to_string(),
        "test-scope".to_string(),
    ).await);

    // Configure SDK to use the proxy as a reverse proxy endpoint
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    // Test Case 1: Valid token succeeds
    let valid_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            "",
            "",
            Some(VALID_SESSION_TOKEN.to_string()), // Valid token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let valid_client = Client::new(&valid_config);

    let result = valid_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await
        .expect("Request with valid token should succeed");

    let body = result.body.collect().await.expect("Failed to read body");
    let content = String::from_utf8(body.to_vec()).expect("Invalid UTF-8");

    assert_eq!(content, TEST_CONTENT, "Content should match");

    // Test Case 2: Invalid token fails
    let invalid_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
            Some(INVALID_SESSION_TOKEN.to_string()), // Invalid token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let invalid_client = Client::new(&invalid_config);

    let result = invalid_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(result.is_err(), "Request with invalid token should fail");

    // Test Case 3: Missing token fails
    let no_token_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
            None, // No token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let no_token_client = Client::new(&no_token_config);

    let result = no_token_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(result.is_err(), "Request without token should fail");
}
