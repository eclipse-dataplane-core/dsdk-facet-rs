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
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use facet_common::auth::MemoryAuthorizationEvaluator;
use std::sync::Arc;
use crate::common::{
    create_test_client, get_available_port, add_auth_rule, MinioInstance,
    ProxyConfig, launch_s3proxy, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, TEST_BUCKET,
};


// ==================== Object GET Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_get_object() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/test-file.txt$", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: GET through proxy should succeed
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow GetObject with correct permissions");

    // Verify: Check content matches what's in MinIO
    let body = result.unwrap().body.collect().await.unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(content, "test content", "Content should match MinIO data");

    // Verify: File exists in MinIO
    assert!(minio.verify_object_exists(TEST_BUCKET, "test-file.txt").await, "File should exist in MinIO");
}

#[tokio::test]
async fn test_e2e_allow_get_object_with_wildcard() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: GET through proxy should succeed
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow GetObject with wildcard pattern");

    // Verify: File content matches MinIO
    let body = result.unwrap().body.collect().await.unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(content, "test content");
}

#[tokio::test]
async fn test_e2e_allow_head_object() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: HEAD through proxy should succeed
    let result = client
        .head_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "HEAD should use same permission as GET");

    // Verify: Object exists in MinIO
    assert!(minio.verify_object_exists(TEST_BUCKET, "test-file.txt").await, "Object should exist in MinIO");
}

// ==================== Object PUT Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_put_object() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:PutObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: PUT through proxy should succeed
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .body(ByteStream::from_static(b"new content"))
        .send()
        .await;

    assert!(result.is_ok(), "Should allow PutObject with correct permissions");

    // Verify: Object was created in MinIO with correct content
    assert!(minio.verify_object_content(TEST_BUCKET, "new-file.txt", b"new content").await, "Object should exist with correct content");
}

// ==================== Object DELETE Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_delete_object() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:DeleteObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: DELETE through proxy should succeed
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow DeleteObject with correct permissions");

    // Verify: Object was deleted from MinIO
    assert!(minio.verify_object_deleted(TEST_BUCKET, "test-file.txt").await, "Object should not exist after deletion");
}

// ==================== Bucket Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_list_bucket() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:ListBucket"], &format!("^/{}/?$", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: LIST through proxy should succeed
    let result = client.list_objects_v2().bucket(TEST_BUCKET).send().await;

    assert!(result.is_ok(), "Should allow ListBucket with correct permissions");
    assert!(result.unwrap().contents().len() > 0, "Should have objects in bucket");
}

// ==================== Deny Scenarios ====================

#[tokio::test]
async fn test_e2e_deny_wrong_action() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    // Only allow GetObject
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to PUT (not allowed)
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("unauthorized.txt")
        .body(ByteStream::from_static(b"content"))
        .send()
        .await;

    assert!(result.is_err(), "Should deny PutObject without permission");

    // Verify: Object was NOT created in MinIO
    assert!(minio.verify_object_deleted(TEST_BUCKET, "unauthorized.txt").await, "Unauthorized object should not exist");
}

#[tokio::test]
async fn test_e2e_deny_wrong_resource_pattern() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    // Only allow access to /public/* path
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/public/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to access file not in /public/
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_err(), "Should deny access to files outside allowed pattern");

    // Verify: Original file still exists in MinIO (access was denied, not deleted)
    assert!(minio.verify_object_exists(TEST_BUCKET, "test-file.txt").await, "Original file should still exist");
}

#[tokio::test]
async fn test_e2e_deny_read_only_user_trying_to_write() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    // Read-only permissions
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "readonly_user", TEST_BUCKET, vec!["s3:GetObject", "s3:ListBucket"], &format!("^/{}.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "readonly_user", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to delete (not allowed)
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_err(), "Read-only user should not be able to delete");

    // Verify: File still exists in MinIO
    assert!(minio.verify_object_exists(TEST_BUCKET, "test-file.txt").await, "File should still exist after failed delete");
}

// ==================== Multiple Actions ====================

#[tokio::test]
async fn test_e2e_multiple_actions_in_single_rule() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user1", TEST_BUCKET, vec!["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], &format!("^/{}/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user1", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test GET
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow GET");

    // Test PUT
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .body(ByteStream::from_static(b"content"))
        .send()
        .await;
    assert!(result.is_ok(), "Should allow PUT");

    // Test DELETE
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow DELETE");

    // Verify: All operations succeeded in MinIO
    assert!(minio.verify_object_exists(TEST_BUCKET, "new-file.txt").await, "PUT file should exist");
    assert!(minio.verify_object_deleted(TEST_BUCKET, "test-file.txt").await, "Deleted file should not exist");
}

// ==================== General Scenarios ====================

#[tokio::test]
async fn test_e2e_readonly_access_to_entire_bucket() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "analyst", TEST_BUCKET, vec!["s3:GetObject"], &format!("^/{}/.*", TEST_BUCKET)).await;
    add_auth_rule(&evaluator, "analyst", TEST_BUCKET, vec!["s3:ListBucket"], &format!("^/{}/?$", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "analyst", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can list bucket
    let result = client.list_objects_v2().bucket(TEST_BUCKET).send().await;
    assert!(result.is_ok(), "Should allow list");

    // Can read objects
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow read");

    // Cannot write
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new.txt")
        .body(ByteStream::from_static(b"data"))
        .send()
        .await;
    assert!(result.is_err(), "Should deny write");

    // Cannot delete
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_err(), "Should deny delete");
}

#[tokio::test]
async fn test_e2e_folder_specific_access() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    // Upload files to different folders using a direct client
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&minio.endpoint)
        .load()
        .await;
    let setup_client = Client::new(&config);

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("users/user123/file.txt")
        .body(ByteStream::from_static(b"user123 data"))
        .send()
        .await
        .unwrap();

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("users/user456/file.txt")
        .body(ByteStream::from_static(b"user456 data"))
        .send()
        .await
        .unwrap();

    // User can only access their own folder
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "user123", TEST_BUCKET, vec!["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], &format!("^/{}/users/user123/.*", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "user123", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can access own folder
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("users/user123/file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should access own folder");

    // Cannot access another user's folder
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("users/user456/file.txt")
        .send()
        .await;
    assert!(result.is_err(), "Should not access other user's folder");
}

#[tokio::test]
async fn test_e2e_regex_pattern_with_file_extension() {
    let minio = MinioInstance::launch().await;
    minio.setup_default_bucket().await;

    // Upload files with different extensions using a direct client
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&minio.endpoint)
        .load()
        .await;
    let setup_client = Client::new(&config);

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("image.jpg")
        .body(ByteStream::from_static(b"image data"))
        .send()
        .await
        .unwrap();

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("document.pdf")
        .body(ByteStream::from_static(b"pdf data"))
        .send()
        .await
        .unwrap();

    // Only allow access to image files
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    add_auth_rule(&evaluator, "image-processor", TEST_BUCKET, vec!["s3:GetObject"], &format!(r"^/{}/.*\.(jpg|jpeg|png|gif)$", TEST_BUCKET)).await;

    let proxy_port = get_available_port();
    launch_s3proxy(ProxyConfig::for_auth_testing(proxy_port, minio.host.clone(), evaluator.clone(), "image-processor", TEST_BUCKET));

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can access image files
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("image.jpg")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow access to image files");

    // Cannot access non-image files
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("document.pdf")
        .send()
        .await;
    assert!(result.is_err(), "Should deny access to non-image files");
}
