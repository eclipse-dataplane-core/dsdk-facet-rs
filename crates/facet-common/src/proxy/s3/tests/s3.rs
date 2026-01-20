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

use super::super::*;
use crate::context::ParticipantContext;
use std::sync::Arc;
use crate::auth::TrueAuthorizationEvaluator;

#[test]
fn test_try_parse_path_style_with_key() {
    let parsed = S3Proxy::try_parse_path_style("/my-bucket/path/to/object.txt");
    assert!(parsed.is_some());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.bucket, "my-bucket");
    assert_eq!(parsed.key, "path/to/object.txt");
}

#[test]
fn test_try_parse_path_style_bucket_only() {
    let parsed = S3Proxy::try_parse_path_style("/my-bucket");
    assert!(parsed.is_some());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.bucket, "my-bucket");
    assert_eq!(parsed.key, "");
}

#[test]
fn test_try_parse_path_style_bucket_with_trailing_slash() {
    let parsed = S3Proxy::try_parse_path_style("/my-bucket/");
    assert!(parsed.is_some());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.bucket, "my-bucket");
    assert_eq!(parsed.key, "");
}

#[test]
fn test_try_parse_path_style_empty() {
    let parsed = S3Proxy::try_parse_path_style("/");
    assert!(parsed.is_none());
}

#[test]
fn test_try_parse_path_style_no_leading_slash() {
    let parsed = S3Proxy::try_parse_path_style("my-bucket/key");
    assert!(parsed.is_some());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.bucket, "my-bucket");
    assert_eq!(parsed.key, "key");
}

#[test]
fn test_extract_bucket_from_host_with_subdomain() {
    let bucket = S3Proxy::extract_bucket_from_host("my-bucket.proxy.com", "proxy.com");
    assert_eq!(bucket, Some("my-bucket".to_string()));
}

#[test]
fn test_extract_bucket_from_host_with_port() {
    let bucket = S3Proxy::extract_bucket_from_host("my-bucket.proxy.com:8080", "proxy.com");
    assert_eq!(bucket, Some("my-bucket".to_string()));
}

#[test]
fn test_extract_bucket_from_host_exact_match() {
    let bucket = S3Proxy::extract_bucket_from_host("proxy.com", "proxy.com");
    assert_eq!(bucket, None);
}

#[test]
fn test_extract_bucket_from_host_no_match() {
    let bucket = S3Proxy::extract_bucket_from_host("other.com", "proxy.com");
    assert_eq!(bucket, None);
}

#[test]
fn test_extract_bucket_from_host_nested_subdomain() {
    let bucket = S3Proxy::extract_bucket_from_host("bucket.sub.proxy.com", "proxy.com");
    assert_eq!(bucket, Some("bucket.sub".to_string()));
}

#[test]
fn test_parse_incoming_path_style() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let parsed = proxy
        .parse_incoming_request("proxy.com:6000", "/test-bucket/file.txt")
        .unwrap();
    assert_eq!(parsed.bucket, "test-bucket");
    assert_eq!(parsed.key, "file.txt");
}

#[test]
fn test_parse_incoming_path_style_bucket_only() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let parsed = proxy
        .parse_incoming_request("proxy.com:6000", "/test-bucket")
        .unwrap();
    assert_eq!(parsed.bucket, "test-bucket");
    assert_eq!(parsed.key, "");
}

#[test]
fn test_parse_incoming_virtual_hosted_with_proxy_domain() {
    let proxy = create_test_proxy(
        UpstreamStyle::PathStyle,
        Some("proxy.com".to_string()),
    );
    let parsed = proxy
        .parse_incoming_request("test-bucket.proxy.com:6000", "/file.txt")
        .unwrap();
    assert_eq!(parsed.bucket, "test-bucket");
    assert_eq!(parsed.key, "file.txt");
}

#[test]
fn test_parse_incoming_virtual_hosted_root_object() {
    let proxy = create_test_proxy(
        UpstreamStyle::PathStyle,
        Some("proxy.com".to_string()),
    );
    let parsed = proxy
        .parse_incoming_request("test-bucket.proxy.com", "/")
        .unwrap();
    assert_eq!(parsed.bucket, "test-bucket");
    assert_eq!(parsed.key, "");
}

#[test]
fn test_parse_incoming_virtual_hosted_no_leading_slash() {
    let proxy = create_test_proxy(
        UpstreamStyle::PathStyle,
        Some("proxy.com".to_string()),
    );
    let parsed = proxy
        .parse_incoming_request("test-bucket.proxy.com", "file.txt")
        .unwrap();
    assert_eq!(parsed.bucket, "test-bucket");
    assert_eq!(parsed.key, "file.txt");
}

#[test]
fn test_parse_incoming_fallback_to_path_style() {
    let proxy = create_test_proxy(
        UpstreamStyle::PathStyle,
        Some("proxy.com".to_string()),
    );
    // Host doesn't match proxy domain, should fall back to path-style
    let parsed = proxy
        .parse_incoming_request("other.com", "/bucket/key.txt")
        .unwrap();
    assert_eq!(parsed.bucket, "bucket");
    assert_eq!(parsed.key, "key.txt");
}

#[test]
fn test_parse_endpoint_with_port() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let (host, port) = proxy.parse_endpoint("example.com:9000").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 9000);
}

#[test]
fn test_parse_endpoint_without_port() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let (host, port) = proxy.parse_endpoint("example.com").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80); // default_port for non-TLS
}

#[test]
fn test_parse_endpoint_with_tls() {
    let proxy = S3Proxy::builder()
        .use_tls(true)
        .upstream_endpoint("example.com".to_string())
        .credential_resolver(Arc::new(StaticCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: "test".to_string(),
                secret_key: "test".to_string(),
                region: "us-east-1".to_string(),
            },
        }))
        .participant_context_resolver(Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext::builder()
                .identifier("test")
                .audience("test")
                .build(),
        }))
        .auth_evaluator(Arc::new(TrueAuthorizationEvaluator::new()))
        .build();

    let (host, port) = proxy.parse_endpoint("example.com").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 443); // default_port for TLS
}

#[test]
fn test_upstream_style_variants() {
    // Test that both variants exist and are different
    assert_ne!(UpstreamStyle::PathStyle, UpstreamStyle::VirtualHosted);
}

// Tests for Phase 5: New helper methods and improved error handling

#[test]
fn test_parse_endpoint_invalid_port() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let result = proxy.parse_endpoint("example.com:invalid");
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("Invalid port"));
}

#[test]
fn test_parse_endpoint_port_out_of_range() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let result = proxy.parse_endpoint("example.com:99999");
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("Invalid port"));
}

#[test]
fn test_parse_endpoint_ipv6_with_port() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    // IPv6 addresses should work with rsplit_once since it splits from the right
    let (host, port) = proxy.parse_endpoint("[::1]:8080").unwrap();
    assert_eq!(host, "[::1]");
    assert_eq!(port, 8080);
}

#[test]
fn test_build_upstream_host_path_style() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "my-key".to_string(),
    };
    let (host, port) = proxy.build_upstream_host(&parsed).unwrap();
    assert_eq!(host, "minio");
    assert_eq!(port, 9000);
}

#[test]
fn test_build_upstream_host_virtual_hosted() {
    let proxy = create_test_proxy(UpstreamStyle::VirtualHosted, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "my-key".to_string(),
    };
    let (host, port) = proxy.build_upstream_host(&parsed).unwrap();
    assert_eq!(host, "my-bucket.minio");
    assert_eq!(port, 9000);
}

#[test]
fn test_build_upstream_uri_and_host_path_style() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "path/to/file.txt".to_string(),
    };
    let (uri, host) = proxy.build_upstream_uri_and_host(&parsed);
    assert_eq!(uri, "/my-bucket/path/to/file.txt");
    assert_eq!(host, "minio:9000");
}

#[test]
fn test_build_upstream_uri_and_host_path_style_empty_key() {
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "".to_string(),
    };
    let (uri, host) = proxy.build_upstream_uri_and_host(&parsed);
    assert_eq!(uri, "/my-bucket");
    assert_eq!(host, "minio:9000");
}

#[test]
fn test_build_upstream_uri_and_host_virtual_hosted() {
    let proxy = create_test_proxy(UpstreamStyle::VirtualHosted, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "path/to/file.txt".to_string(),
    };
    let (uri, host) = proxy.build_upstream_uri_and_host(&parsed);
    assert_eq!(uri, "/path/to/file.txt");
    assert_eq!(host, "my-bucket.minio:9000");
}

#[test]
fn test_build_upstream_uri_and_host_virtual_hosted_empty_key() {
    let proxy = create_test_proxy(UpstreamStyle::VirtualHosted, None);
    let parsed = ParsedS3Request {
        bucket: "my-bucket".to_string(),
        key: "".to_string(),
    };
    let (uri, host) = proxy.build_upstream_uri_and_host(&parsed);
    assert_eq!(uri, "/");
    assert_eq!(host, "my-bucket.minio:9000");
}

fn create_test_proxy(upstream_style: UpstreamStyle, proxy_domain: Option<String>) -> S3Proxy {
    S3Proxy::builder()
        .use_tls(false)
        .upstream_endpoint("minio:9000".to_string())
        .upstream_style(upstream_style)
        .maybe_proxy_domain(proxy_domain)
        .credential_resolver(Arc::new(StaticCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: "test".to_string(),
                secret_key: "test".to_string(),
                region: "us-east-1".to_string(),
            },
        }))
        .participant_context_resolver(Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext::builder()
                .identifier("test")
                .audience("test")
                .build(),
        }))
        .auth_evaluator(Arc::new(TrueAuthorizationEvaluator::new()))
        .build()
}

#[test]
fn test_context_caching() {
    // Create proxy
    let proxy = create_test_proxy(UpstreamStyle::PathStyle, None);

    // Create context using new_ctx
    let mut ctx = proxy.new_ctx();

    // Verify initial state
    assert!(ctx.parsed_request.is_none(), "Initially parsed_request should be None");
    assert_eq!(ctx.participant_context.identifier, "anonymous");
    assert_eq!(ctx.participant_context.audience, "anonymous");

    // Simulate parsing and caching (what upstream_peer does)
    let parsed = ParsedS3Request {
        bucket: "test-bucket".to_string(),
        key: "test-key.txt".to_string(),
    };
    ctx.parsed_request = Some(parsed.clone());

    // Verify cached data
    assert!(ctx.parsed_request.is_some(), "After caching, parsed_request should be Some");
    assert_eq!(ctx.parsed_request.as_ref().unwrap().bucket, "test-bucket");
    assert_eq!(ctx.parsed_request.as_ref().unwrap().key, "test-key.txt");

    // Verify we can retrieve it (what upstream_request_filter does)
    let retrieved = ctx.parsed_request.as_ref().unwrap();
    assert_eq!(retrieved.bucket, "test-bucket");
    assert_eq!(retrieved.key, "test-key.txt");
}

