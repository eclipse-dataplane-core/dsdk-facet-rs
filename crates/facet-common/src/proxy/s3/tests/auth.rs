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

use crate::auth::{AuthorizationEvaluator, MemoryAuthorizationEvaluator, Rule, RuleStore};
use crate::context::ParticipantContext;
use crate::proxy::s3::opparser::DefaultS3OperationParser;
use crate::proxy::s3::{S3OperationParser, S3Resources};
use pingora_http::RequestHeader;

/// Helper function to create a RequestHeader for testing
fn create_request(method: &str, uri: &str) -> RequestHeader {
    let mut req = RequestHeader::build(method, uri.as_bytes(), None).unwrap();
    req.insert_header("Host", "test-bucket.s3.amazonaws.com").unwrap();
    req
}

/// Helper function to create a test participant context
fn create_participant(identifier: &str) -> ParticipantContext {
    ParticipantContext::builder()
        .id(identifier)
        .build()
}

/// Helper function to set up rules for a participant
async fn setup_rules(evaluator: &MemoryAuthorizationEvaluator, participant_id: &str, rules: Vec<Rule>) {
    let ctx = &ParticipantContext::builder()
        .id(participant_id)
        .build();
    for rule in rules {
        evaluator.save_rule(ctx, rule).await.unwrap();
    }
}

// ==================== Object GET Operations - Allow ====================

#[tokio::test]
async fn test_allow_get_object() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Allow GetObject on specific resource
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            "^/bucket1/file.txt$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_get_object_with_wildcard() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Allow GetObject on all objects in bucket
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/path/to/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_get_object_acl() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObjectAcl".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/file.txt?acl");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_get_object_tagging() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObjectTagging".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/file.txt?tagging");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_head_object() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // HEAD uses same permission as GET
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("HEAD", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_get_object_version() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObjectVersion".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/file.txt?versionId=abc123");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

// ==================== Object PUT Operations - Allow ====================

#[tokio::test]
async fn test_allow_put_object() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:PutObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("PUT", "/bucket1/new-file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_put_object_acl() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:PutObjectAcl".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("PUT", "/bucket1/file.txt?acl");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_put_object_tagging() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:PutObjectTagging".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("PUT", "/bucket1/file.txt?tagging");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

// ==================== Object DELETE Operations - Allow ====================

#[tokio::test]
async fn test_allow_delete_object() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:DeleteObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("DELETE", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_post_delete_batch() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:DeleteObject".to_string()],
            "^/bucket1.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("POST", "/bucket1?delete");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

// ==================== Bucket Operations - Allow ====================

#[tokio::test]
async fn test_allow_list_bucket() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:ListBucket".to_string()],
            S3Resources::exact_match("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1?list-type=2");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_list_bucket_versions() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:ListBucketVersions".to_string()],
            S3Resources::exact_match("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1?versions");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_list_bucket_multipart_uploads() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:ListBucketMultipartUploads".to_string()],
            S3Resources::exact_match("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1?uploads");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

#[tokio::test]
async fn test_allow_get_bucket_location() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetBucketLocation".to_string()],
            S3Resources::exact_match("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1?location");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(result);
}

// ==================== Deny Scenarios ====================

#[tokio::test]
async fn test_deny_no_rules_for_participant() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("unknown_user");

    let req = create_request("GET", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

#[tokio::test]
async fn test_deny_wrong_scope() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Request to bucket2, but rules are for bucket1 scope
    let req = create_request("GET", "/bucket2/file.txt");
    let operation = parser.parse_operation("bucket2", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

#[tokio::test]
async fn test_deny_wrong_action() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Only allow GetObject
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Try to PutObject
    let req = create_request("PUT", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

#[tokio::test]
async fn test_deny_wrong_resource_pattern() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Only allow access to /bucket1/public/*
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            "^/bucket1/public/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Try to access /bucket1/private/file.txt
    let req = create_request("GET", "/bucket1/private/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

#[tokio::test]
async fn test_deny_read_only_user_trying_to_write() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("readonly_user");

    // Read-only permissions
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string(), "s3:ListBucket".to_string()],
            "^/bucket1.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "readonly_user", rules).await;

    // Try to delete
    let req = create_request("DELETE", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

#[tokio::test]
async fn test_deny_get_acl_without_permission() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Only allow GetObject, not GetObjectAcl
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    let req = create_request("GET", "/bucket1/file.txt?acl");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    let result = evaluator.evaluate(&participant, operation).await.unwrap();

    assert!(!result);
}

// ==================== Multiple Actions ====================

#[tokio::test]
async fn test_multiple_actions_in_single_rule() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Allow multiple actions
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
                "s3:DeleteObject".to_string(),
            ],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Test GET
    let req = create_request("GET", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Test PUT
    let req = create_request("PUT", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Test DELETE
    let req = create_request("DELETE", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());
}

// ==================== Multiple Rules ====================

#[tokio::test]
async fn test_multiple_rules_different_resources() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Different permissions for different paths
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            "^/bucket1/public/.*".to_string(),
        )
        .unwrap(),
        Rule::new(
            "bucket1".to_string(),
            vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
                "s3:DeleteObject".to_string(),
            ],
            "^/bucket1/uploads/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Can read from public
    let req = create_request("GET", "/bucket1/public/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot write to public
    let req = create_request("PUT", "/bucket1/public/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());

    // Can write to uploads
    let req = create_request("PUT", "/bucket1/uploads/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());
}

#[tokio::test]
async fn test_multiple_rules_different_scopes() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user1");

    // Access to multiple buckets
    let rules = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
        Rule::new(
            "bucket2".to_string(),
            vec!["s3:PutObject".to_string()],
            "^/bucket2/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules).await;

    // Can read from bucket1
    let req = create_request("GET", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot write to bucket1
    let req = create_request("PUT", "/bucket1/file.txt");
    let operation = parser.parse_operation("bucket1", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());

    // Can write to bucket2
    let req = create_request("PUT", "/bucket2/file.txt");
    let operation = parser.parse_operation("bucket2", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot read from bucket2
    let req = create_request("GET", "/bucket2/file.txt");
    let operation = parser.parse_operation("bucket2", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());
}

// ==================== Real-world Scenarios ====================

#[tokio::test]
async fn test_readonly_access_to_entire_bucket() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("analyst");

    let rules = vec![
        Rule::new(
            "data-bucket".to_string(),
            vec!["s3:GetObject".to_string()],
            "^/data-bucket/.*".to_string(),
        )
        .unwrap(),
        Rule::new(
            "data-bucket".to_string(),
            vec!["s3:ListBucket".to_string()],
            "^/data-bucket$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "analyst", rules).await;

    // Can list bucket
    let req = create_request("GET", "/data-bucket?list-type=2");
    let operation = parser.parse_operation("data-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Can read objects
    let req = create_request("GET", "/data-bucket/reports/2024/q1.csv");
    let operation = parser.parse_operation("data-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot delete
    let req = create_request("DELETE", "/data-bucket/reports/2024/q1.csv");
    let operation = parser.parse_operation("data-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot write
    let req = create_request("PUT", "/data-bucket/reports/2024/q2.csv");
    let operation = parser.parse_operation("data-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());
}

#[tokio::test]
async fn test_folder_specific_access() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("user123");

    // User can only access their own folder
    let rules = vec![
        Rule::new(
            "shared-bucket".to_string(),
            vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
                "s3:DeleteObject".to_string(),
            ],
            "^/shared-bucket/users/user123/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user123", rules).await;

    // Can access own folder
    let req = create_request("GET", "/shared-bucket/users/user123/documents/file.pdf");
    let operation = parser.parse_operation("shared-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot access another user's folder
    let req = create_request("GET", "/shared-bucket/users/user456/documents/file.pdf");
    let operation = parser.parse_operation("shared-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());
}

#[tokio::test]
async fn test_temporary_upload_access() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("upload-service");

    // Service can only write to temp uploads folder
    let rules = vec![
        Rule::new(
            "storage-bucket".to_string(),
            vec!["s3:PutObject".to_string()],
            "^/storage-bucket/temp-uploads/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "upload-service", rules).await;

    // Can upload to temp
    let req = create_request("PUT", "/storage-bucket/temp-uploads/file-abc123.tmp");
    let operation = parser.parse_operation("storage-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot read
    let req = create_request("GET", "/storage-bucket/temp-uploads/file-abc123.tmp");
    let operation = parser.parse_operation("storage-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot upload to permanent storage
    let req = create_request("PUT", "/storage-bucket/permanent/file.dat");
    let operation = parser.parse_operation("storage-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());
}

#[tokio::test]
async fn test_versioned_bucket_access() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("backup-service");

    let rules = vec![
        Rule::new(
            "versioned-bucket".to_string(),
            vec!["s3:GetObjectVersion".to_string(), "s3:ListBucketVersions".to_string()],
            "^/versioned-bucket.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "backup-service", rules).await;

    // Can list versions
    let req = create_request("GET", "/versioned-bucket?versions");
    let operation = parser.parse_operation("versioned-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Can get specific version
    let req = create_request("GET", "/versioned-bucket/file.txt?versionId=v123");
    let operation = parser.parse_operation("versioned-bucket", &req).unwrap();
    assert!(evaluator.evaluate(&participant, operation).await.unwrap());

    // Cannot get current version (no GetObject permission)
    let req = create_request("GET", "/versioned-bucket/file.txt");
    let operation = parser.parse_operation("versioned-bucket", &req).unwrap();
    assert!(!evaluator.evaluate(&participant, operation).await.unwrap());
}

#[tokio::test]
async fn test_admin_full_access() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("admin");

    // Admin has all permissions
    let rules = vec![
        Rule::new(
            "admin-bucket".to_string(),
            vec![
                "s3:GetObject".to_string(),
                "s3:GetObjectAcl".to_string(),
                "s3:GetObjectTagging".to_string(),
                "s3:PutObject".to_string(),
                "s3:PutObjectAcl".to_string(),
                "s3:PutObjectTagging".to_string(),
                "s3:DeleteObject".to_string(),
                "s3:ListBucket".to_string(),
                "s3:ListBucketVersions".to_string(),
            ],
            "^/admin-bucket.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "admin", rules).await;

    // Test various operations
    let operations = vec![
        ("GET", "/admin-bucket/file.txt"),
        ("GET", "/admin-bucket/file.txt?acl"),
        ("GET", "/admin-bucket/file.txt?tagging"),
        ("PUT", "/admin-bucket/file.txt"),
        ("PUT", "/admin-bucket/file.txt?acl"),
        ("DELETE", "/admin-bucket/file.txt"),
        ("GET", "/admin-bucket?list-type=2"),
        ("GET", "/admin-bucket?versions"),
    ];

    for (method, uri) in operations {
        let req = create_request(method, uri);
        let operation = parser.parse_operation("admin-bucket", &req).unwrap();
        assert!(
            evaluator.evaluate(&participant, operation).await.unwrap(),
            "Admin should have access to {} {}",
            method,
            uri
        );
    }
}

// ==================== Multiple Participants ====================

#[tokio::test]
async fn test_different_participants_different_permissions() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();

    // Setup rules for user1
    let rules_user1 = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:GetObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user1", rules_user1).await;

    // Setup rules for user2
    let rules_user2 = vec![
        Rule::new(
            "bucket1".to_string(),
            vec!["s3:PutObject".to_string()],
            S3Resources::all_objects_in_bucket("bucket1"),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "user2", rules_user2).await;

    let req_get = create_request("GET", "/bucket1/file.txt");
    let req_put = create_request("PUT", "/bucket1/file.txt");

    // user1 can read
    let operation = parser.parse_operation("bucket1", &req_get).unwrap();
    let participant1 = create_participant("user1");
    assert!(evaluator.evaluate(&participant1, operation).await.unwrap());

    // user1 cannot write
    let operation = parser.parse_operation("bucket1", &req_put).unwrap();
    assert!(!evaluator.evaluate(&participant1, operation).await.unwrap());

    // user2 can write
    let operation = parser.parse_operation("bucket1", &req_put).unwrap();
    let participant2 = create_participant("user2");
    assert!(evaluator.evaluate(&participant2, operation).await.unwrap());

    // user2 cannot read
    let operation = parser.parse_operation("bucket1", &req_get).unwrap();
    assert!(!evaluator.evaluate(&participant2, operation).await.unwrap());
}

// ==================== Complex Resource Patterns ====================

#[tokio::test]
async fn test_regex_pattern_with_specific_file_extension() {
    let parser = DefaultS3OperationParser::new();
    let evaluator = MemoryAuthorizationEvaluator::new();
    let participant = create_participant("image-processor");

    // Only allow access to image files
    let rules = vec![
        Rule::new(
            "media-bucket".to_string(),
            vec!["s3:GetObject".to_string()],
            r"^/media-bucket/.*\.(jpg|jpeg|png|gif)$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "image-processor", rules).await;

    // Can access image files
    let image_files = vec![
        "/media-bucket/photos/vacation.jpg",
        "/media-bucket/profile.png",
        "/media-bucket/logo.gif",
    ];
    for uri in image_files {
        let req = create_request("GET", uri);
        let operation = parser.parse_operation("media-bucket", &req).unwrap();
        assert!(
            evaluator.evaluate(&participant, operation).await.unwrap(),
            "Should allow access to {}",
            uri
        );
    }

    // Cannot access non-image files
    let non_image_files = vec![
        "/media-bucket/document.pdf",
        "/media-bucket/video.mp4",
        "/media-bucket/data.json",
    ];
    for uri in non_image_files {
        let req = create_request("GET", uri);
        let operation = parser.parse_operation("media-bucket", &req).unwrap();
        assert!(
            !evaluator.evaluate(&participant, operation).await.unwrap(),
            "Should deny access to {}",
            uri
        );
    }
}
