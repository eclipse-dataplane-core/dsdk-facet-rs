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

use common::{
    create_test_client, get_available_port, launch_s3proxy, setup_postgres_container,
    MinioInstance, PassthroughCredentialsResolver, ProxyConfig, TestJwtVerifier,
    MINIO_ACCESS_KEY, MINIO_SECRET_KEY, TEST_BUCKET,
};
use facet_common::auth::{AuthorizationEvaluator, Operation, PostgresAuthorizationEvaluator, Rule, RuleStore};
use facet_common::context::ParticipantContext;
use facet_common::proxy::s3::{
    DefaultS3OperationParser, S3Credentials, StaticParticipantContextResolver, UpstreamStyle,
};
use std::sync::Arc;

#[tokio::test]
async fn test_s3_proxy_end_to_end_with_postgres() {
    // Launch Postgres container and initialize auth evaluator
    let (pool, _pg_container) = setup_postgres_container().await;
    let auth_evaluator = Arc::new(PostgresAuthorizationEvaluator::new(pool));
    auth_evaluator.initialize().await.unwrap();

    // Launch MinIO container as upstream S3 server
    let minio = MinioInstance::launch().await;
    minio.setup_bucket_with_file(TEST_BUCKET, "test-file.txt", b"Hello from MinIO!").await;
    minio.setup_bucket_with_file(TEST_BUCKET, "data/document.pdf", b"PDF content here").await;

    let participant_id = "user123";
    let scope = "agreement-456";
    let participant_context = ParticipantContext::builder()
        .id(participant_id)
        .audience("s3-proxy")
        .build();

    // Create authorization rules in Postgres
    // Rule 1: Allow GetObject on all objects in test-bucket (note: URL path includes leading slash)
    let get_rule = Rule::new(
        scope.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();

    // Rule 2: Allow PutObject in test-bucket/uploads/ path (note: URL path includes leading slash)
    let put_rule = Rule::new(
        scope.to_string(),
        vec!["s3:PutObject".to_string()],
        format!("^/{}/uploads/.*", TEST_BUCKET),
    )
    .unwrap();

    auth_evaluator.save_rule(&participant_context, get_rule).await.unwrap();
    auth_evaluator.save_rule(&participant_context, put_rule).await.unwrap();

    // Verify rules are stored
    let rules = auth_evaluator.get_rules(&participant_context).await.unwrap();
    assert_eq!(rules.len(), 2);

    // Configure and launch S3 proxy with Postgres auth
    let proxy_port = get_available_port();
    let proxy_config = ProxyConfig {
        port: proxy_port,
        upstream_endpoint: minio.host.clone(),
        upstream_style: UpstreamStyle::PathStyle,
        proxy_domain: None,
        credential_resolver: Arc::new(PassthroughCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_key: MINIO_SECRET_KEY.to_string(),
                region: "us-east-1".to_string(),
            },
        }),
        participant_context_resolver: Arc::new(StaticParticipantContextResolver {
            participant_context: participant_context.clone(),
        }),
        token_verifier: Arc::new(TestJwtVerifier {
            scope: scope.to_string(),
        }),
        auth_evaluator: auth_evaluator.clone(),
        operation_parser: Some(Arc::new(DefaultS3OperationParser::new())),
    };

    launch_s3proxy(proxy_config).await;

    // Test 1: GET request - should succeed (authorized by get_rule)
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let client = create_test_client(&proxy_url, Some("test-token".to_string())).await;

    let get_response = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(get_response.is_ok(), "GetObject should succeed with valid authorization. Error: {:?}", get_response.as_ref().err());
    let body = get_response.unwrap().body.collect().await.unwrap();
    assert_eq!(body.to_vec(), b"Hello from MinIO!");

    // Test 2: GET another file - should succeed (authorized by get_rule)
    let get_response2 = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("data/document.pdf")
        .send()
        .await;

    assert!(get_response2.is_ok(), "GetObject should succeed for nested path");
    let body2 = get_response2.unwrap().body.collect().await.unwrap();
    assert_eq!(body2.to_vec(), b"PDF content here");

    // Test 3: PUT request to uploads/ - should succeed (authorized by put_rule)
    let put_response = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("uploads/new-file.txt")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b"New content uploaded through proxy"))
        .send()
        .await;

    assert!(put_response.is_ok(), "PutObject should succeed in uploads/ path");

    assert!(
        minio.verify_object_content(TEST_BUCKET, "uploads/new-file.txt", b"New content uploaded through proxy").await,
        "Uploaded file should exist in MinIO with correct content"
    );

    // Test 5: Verify authorization decisions are persisted in Postgres
    // Check that we can evaluate operations directly using the AuthorizationEvaluator trait
    let get_operation = Operation::builder()
        .scope(scope)
        .action("s3:GetObject")
        .resource(format!("/{}/test-file.txt", TEST_BUCKET))
        .build();

    let authorized = <PostgresAuthorizationEvaluator as AuthorizationEvaluator>::evaluate(
        &*auth_evaluator,
        &participant_context,
        get_operation,
    )
    .await
    .unwrap();
    assert!(authorized, "GetObject operation should be authorized");

    let put_operation = Operation::builder()
        .scope(scope)
        .action("s3:PutObject")
        .resource(format!("/{}/uploads/new-file.txt", TEST_BUCKET))
        .build();

    let authorized_put = <PostgresAuthorizationEvaluator as AuthorizationEvaluator>::evaluate(
        &*auth_evaluator,
        &participant_context,
        put_operation,
    )
    .await
    .unwrap();
    assert!(authorized_put, "PutObject operation should be authorized for uploads/ path");

    // Test 6: Verify unauthorized operation would be denied
    let delete_operation = Operation::builder()
        .scope(scope)
        .action("s3:DeleteObject")
        .resource(format!("/{}/test-file.txt", TEST_BUCKET))
        .build();

    let unauthorized = <PostgresAuthorizationEvaluator as AuthorizationEvaluator>::evaluate(
        &*auth_evaluator,
        &participant_context,
        delete_operation,
    )
    .await
    .unwrap();
    assert!(!unauthorized, "DeleteObject should not be authorized");
}
