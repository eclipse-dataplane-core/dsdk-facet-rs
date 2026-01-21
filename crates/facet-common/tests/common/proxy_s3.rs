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

use super::mocks::{PassthroughCredentialsResolver, TestJwtVerifier, TokenMatchingJwtVerifier};
use super::{MINIO_ACCESS_KEY, MINIO_SECRET_KEY};
use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use facet_common::auth::{AuthorizationEvaluator, MemoryAuthorizationEvaluator, RuleStore};
use facet_common::context::ParticipantContext;
use facet_common::jwt::JwtVerifier;
use facet_common::proxy::s3::{
    DefaultS3OperationParser, ParticipantContextResolver, S3CredentialResolver, S3Credentials, S3OperationParser,
    S3Proxy, StaticParticipantContextResolver, UpstreamStyle,
};
use pingora::server::Server;
use pingora::server::configuration::Opt;
use pingora_proxy::http_proxy_service;
use std::sync::Arc;

/// Create a test S3 client configured to use the proxy
pub async fn create_test_client(proxy_url: &str, token: Option<String>) -> Client {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            "",
            "",
            token.or(Some("test-token".to_string())),
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(proxy_url)
        .load()
        .await;

    Client::new(&config)
}

/// Configuration for launching an S3 proxy
pub struct ProxyConfig {
    pub port: u16,
    pub upstream_endpoint: String,
    pub upstream_style: UpstreamStyle,
    pub proxy_domain: Option<String>,
    pub credential_resolver: Arc<dyn S3CredentialResolver>,
    pub participant_context_resolver: Arc<dyn ParticipantContextResolver>,
    pub token_verifier: Arc<dyn JwtVerifier>,
    pub auth_evaluator: Arc<dyn AuthorizationEvaluator>,
    pub operation_parser: Option<Arc<dyn S3OperationParser>>,
}

impl ProxyConfig {
    /// Create configuration for authorization testing
    pub fn for_auth_testing(
        port: u16,
        upstream_endpoint: String,
        auth_evaluator: Arc<MemoryAuthorizationEvaluator>,
        participant_id: &str,
        scope: &str,
    ) -> Self {
        let credential_resolver = Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_key: MINIO_SECRET_KEY.to_string(),
                region: "us-east-1".to_string(),
            },
        });

        let participant_context_resolver = Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext::builder()
                .id(participant_id)
                .audience("s3-proxy")
                .build(),
        });

        let token_verifier = Arc::new(TestJwtVerifier {
            scope: scope.to_string(),
        });

        Self {
            port,
            upstream_endpoint,
            upstream_style: UpstreamStyle::PathStyle,
            proxy_domain: None,
            credential_resolver,
            participant_context_resolver,
            token_verifier,
            auth_evaluator,
            operation_parser: None, // Use default
        }
    }

    /// Create configuration for token validation testing
    pub async fn for_token_testing(
        port: u16,
        upstream_endpoint: String,
        upstream_style: UpstreamStyle,
        proxy_domain: Option<String>,
        valid_token: String,
        scope: String,
    ) -> Self {
        let credential_resolver = Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_key: MINIO_SECRET_KEY.to_string(),
                region: "us-east-1".to_string(),
            },
        });

        let participant_context_resolver = Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext::builder()
                .id("proxy")
                .audience("s3-proxy")
                .build(),
        });

        let token_verifier = Arc::new(TokenMatchingJwtVerifier {
            valid_token,
            scope: scope.clone(),
        });

        let auth_evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
        let rule = facet_common::auth::Rule::new(scope, vec!["s3:GetObject".to_string()], ".*".to_string())
            .expect("Failed to create authorization rule");
        let ctx = &ParticipantContext::builder()
            .id("proxy")
            .audience("test-audience")
            .build();

        auth_evaluator.save_rule(ctx, rule).await.unwrap();

        Self {
            port,
            upstream_endpoint,
            upstream_style,
            proxy_domain,
            credential_resolver,
            participant_context_resolver,
            token_verifier,
            auth_evaluator,
            operation_parser: None, // Use default
        }
    }

    /// Create configuration for error propagation testing
    pub fn for_error_testing(
        port: u16,
        credential_resolver: Arc<dyn S3CredentialResolver>,
        auth_evaluator: Arc<dyn AuthorizationEvaluator>,
        token_verifier: Arc<dyn JwtVerifier>,
        operation_parser: Arc<dyn S3OperationParser>,
    ) -> Self {
        let participant_context_resolver = Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext::builder()
                .id("test-user")
                .audience("test-audience")
                .build(),
        });

        Self {
            port,
            upstream_endpoint: "127.0.0.1:9000".to_string(),
            upstream_style: UpstreamStyle::PathStyle,
            proxy_domain: None,
            credential_resolver,
            participant_context_resolver,
            token_verifier,
            auth_evaluator,
            operation_parser: Some(operation_parser),
        }
    }
}

/// Launch S3 proxy with the given configuration
pub async fn launch_s3proxy(config: ProxyConfig) {
    let port = config.port;

    std::thread::spawn(move || {
        let operation_parser = config
            .operation_parser
            .unwrap_or_else(|| Arc::new(DefaultS3OperationParser::new()));

        let proxy = S3Proxy::builder()
            .use_tls(false)
            .credential_resolver(config.credential_resolver)
            .participant_context_resolver(config.participant_context_resolver)
            .token_verifier(config.token_verifier)
            .upstream_endpoint(config.upstream_endpoint)
            .upstream_style(config.upstream_style)
            .maybe_proxy_domain(config.proxy_domain)
            .auth_evaluator(config.auth_evaluator)
            .operation_parser(operation_parser)
            .build();

        let mut server = Server::new(Some(Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }))
        .unwrap();

        server.bootstrap();

        let mut proxy_service = http_proxy_service(&server.configuration, proxy);
        proxy_service.add_tcp(&format!("0.0.0.0:{}", port));

        server.add_service(proxy_service);
        server.run_forever();
    });

    // Wait for proxy to be ready with 5-second timeout
    let wait_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        async {
            loop {
                if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    ).await;

    if wait_result.is_err() {
        panic!("Proxy failed to start within 5 seconds on port {}", port);
    }
}

/// Add an authorization rule to an evaluator.
pub async fn add_auth_rule(
    evaluator: &Arc<MemoryAuthorizationEvaluator>,
    participant_id: &str,
    scope: &str,
    actions: Vec<&str>,
    resource_pattern: &str,
) {
    let rule = facet_common::auth::Rule::new(
        scope.to_string(),
        actions.into_iter().map(String::from).collect(),
        resource_pattern.to_string(),
    )
    .unwrap();

    let ctx = &ParticipantContext::builder()
        .id(participant_id)
        .audience("test-audience")
        .build();

    evaluator.save_rule(ctx, rule).await.unwrap();
}
