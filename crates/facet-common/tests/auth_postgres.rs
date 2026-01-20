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

use crate::common::setup_postgres_container;
use facet_common::auth::{
    AuthorizationError, AuthorizationEvaluator, Operation, PostgresAuthorizationEvaluator, Rule,
    RuleStore,
};
use facet_common::context::ParticipantContext;
use std::sync::Arc;

#[tokio::test]
async fn test_postgres_auth_initialize_idempotent() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);

    // Initialize multiple times - should not fail
    evaluator.initialize().await.unwrap();
    evaluator.initialize().await.unwrap();

    // Should be able to use the evaluator
    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();
}

#[tokio::test]
async fn test_postgres_auth_save_and_get_single_rule() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string(), "write".to_string()],
        "^resource.*$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();

    let retrieved_rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(retrieved_rules.len(), 1);
    assert_eq!(retrieved_rules[0].scope, rule.scope);
    assert_eq!(retrieved_rules[0].actions, rule.actions);
    assert_eq!(retrieved_rules[0].resource, rule.resource);
}

#[tokio::test]
async fn test_postgres_auth_save_multiple_rules_same_participant() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let rule2 = Rule::new(
        "scope2".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();

    let rule3 = Rule::new(
        "scope1".to_string(),
        vec!["delete".to_string()],
        "^resource3$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();
    evaluator.save_rule(&ctx, rule3).await.unwrap();

    let retrieved_rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(retrieved_rules.len(), 3);
}

#[tokio::test]
async fn test_postgres_auth_save_rules_different_participants() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx1 = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let ctx2 = ParticipantContext::builder()
        .identifier("participant2")
        .audience("test-audience")
        .build();

    let rule1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let rule2 = Rule::new(
        "scope1".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx1, rule1).await.unwrap();
    evaluator.save_rule(&ctx2, rule2).await.unwrap();

    let rules1 = evaluator.get_rules(&ctx1).await.unwrap();
    let rules2 = evaluator.get_rules(&ctx2).await.unwrap();

    assert_eq!(rules1.len(), 1);
    assert_eq!(rules2.len(), 1);
    assert_eq!(rules1[0].actions[0], "read");
    assert_eq!(rules2[0].actions[0], "write");
}

#[tokio::test]
async fn test_postgres_auth_get_rules_no_rules() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("nonexistent")
        .audience("test-audience")
        .build();

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_postgres_auth_remove_rule() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 1);

    evaluator.remove_rule(&ctx, rule).await.unwrap();

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_postgres_auth_remove_rule_nonexistent() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    // Removing a non-existent rule should succeed (no-op)
    let result = evaluator.remove_rule(&ctx, rule).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_postgres_auth_remove_specific_rule_multiple_exist() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let rule2 = Rule::new(
        "scope1".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();

    evaluator.remove_rule(&ctx, rule1).await.unwrap();

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].actions[0], "write");
}

#[tokio::test]
async fn test_postgres_auth_evaluate_authorized_exact_match() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_postgres_auth_evaluate_no_rules_for_participant() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_postgres_auth_evaluate_wrong_scope() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let operation = Operation::builder()
        .scope("scope2")
        .action("read")
        .resource("resource1")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_postgres_auth_evaluate_wrong_action() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("write")
        .resource("resource1")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_postgres_auth_evaluate_wrong_resource() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource2")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_postgres_auth_evaluate_regex_pattern() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^bucket/folder/.*\\.txt$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    // Should match
    let operation1 = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("bucket/folder/file1.txt")
        .build();
    assert!(evaluator.evaluate(&ctx, operation1).await.unwrap());

    let operation2 = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("bucket/folder/subfolder/file2.txt")
        .build();
    assert!(evaluator.evaluate(&ctx, operation2).await.unwrap());

    // Should not match
    let operation3 = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("bucket/folder/file.pdf")
        .build();
    assert!(!evaluator.evaluate(&ctx, operation3).await.unwrap());
}

#[tokio::test]
async fn test_postgres_auth_evaluate_multiple_actions() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string(), "write".to_string(), "delete".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    // All three actions should be authorized
    let op_read = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();
    assert!(evaluator.evaluate(&ctx, op_read).await.unwrap());

    let op_write = Operation::builder()
        .scope("test_scope")
        .action("write")
        .resource("resource1")
        .build();
    assert!(evaluator.evaluate(&ctx, op_write).await.unwrap());

    let op_delete = Operation::builder()
        .scope("test_scope")
        .action("delete")
        .resource("resource1")
        .build();
    assert!(evaluator.evaluate(&ctx, op_delete).await.unwrap());

    // But not an unauthorized action
    let op_admin = Operation::builder()
        .scope("test_scope")
        .action("admin")
        .resource("resource1")
        .build();
    assert!(!evaluator.evaluate(&ctx, op_admin).await.unwrap());
}

#[tokio::test]
async fn test_postgres_auth_evaluate_multiple_rules() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule1 = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let rule2 = Rule::new(
        "test_scope".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();

    // Read resource1 should be authorized
    let op1 = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();
    assert!(evaluator.evaluate(&ctx, op1).await.unwrap());

    // Write resource2 should be authorized
    let op2 = Operation::builder()
        .scope("test_scope")
        .action("write")
        .resource("resource2")
        .build();
    assert!(evaluator.evaluate(&ctx, op2).await.unwrap());

    // Write resource1 should not be authorized
    let op3 = Operation::builder()
        .scope("test_scope")
        .action("write")
        .resource("resource1")
        .build();
    assert!(!evaluator.evaluate(&ctx, op3).await.unwrap());
}

#[tokio::test]
async fn test_postgres_auth_update_existing_rule() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    // Save initial rule with only "read" action
    let rule1 = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1).await.unwrap();

    // Update the same rule (same scope and resource) with different actions
    let rule2 = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string(), "write".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule2).await.unwrap();

    // Should have only one rule (updated)
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].actions.len(), 2);
    assert!(rules[0].actions.contains(&"read".to_string()));
    assert!(rules[0].actions.contains(&"write".to_string()));
}

#[tokio::test]
async fn test_postgres_auth_concurrent_save_rules() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = Arc::new(PostgresAuthorizationEvaluator::new(pool));
    evaluator.initialize().await.unwrap();

    let mut handles = vec![];

    // Spawn 10 concurrent tasks saving rules
    for i in 0..10 {
        let evaluator_clone = evaluator.clone();
        let handle = tokio::spawn(async move {
            let ctx = ParticipantContext::builder()
                .identifier(format!("participant{}", i))
                .audience("test-audience")
                .build();

            let rule = Rule::new(
                format!("scope{}", i),
                vec!["read".to_string()],
                format!("^resource{}$", i),
            )
            .unwrap();

            evaluator_clone.save_rule(&ctx, rule).await
        });
        handles.push(handle);
    }

    // All saves should succeed
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }

    // Verify all rules were saved
    for i in 0..10 {
        let ctx = ParticipantContext::builder()
            .identifier(format!("participant{}", i))
            .audience("test-audience")
            .build();
        let rules = evaluator.get_rules(&ctx).await.unwrap();
        assert_eq!(rules.len(), 1);
    }
}

#[tokio::test]
async fn test_postgres_auth_concurrent_evaluations() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = Arc::new(PostgresAuthorizationEvaluator::new(pool));
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource.*$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let mut handles = vec![];

    // Spawn 4 concurrent evaluation tasks
    for i in 0..4 {
        let evaluator_clone = evaluator.clone();
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            let operation = Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource(format!("resource{}", i))
                .build();
            evaluator_clone.evaluate(&ctx_clone, operation).await
        });
        handles.push(handle);
    }

    // All evaluations should succeed and return true
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}


#[tokio::test]
async fn test_postgres_auth_with_long_identifiers() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let long_identifier = "a".repeat(255);
    let long_scope = "b".repeat(255);

    let ctx = ParticipantContext::builder()
        .identifier(&long_identifier)
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        long_scope.clone(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    let operation = Operation::builder()
        .scope(long_scope)
        .action("read")
        .resource("resource1")
        .build();

    let result = evaluator.evaluate(&ctx, operation).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_postgres_auth_different_participants_isolated() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx1 = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let ctx2 = ParticipantContext::builder()
        .identifier("participant2")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx1, rule).await.unwrap();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();

    // Participant1 should be authorized
    assert!(evaluator.evaluate(&ctx1, operation.clone()).await.unwrap());

    // Participant2 should not be authorized
    assert!(!evaluator.evaluate(&ctx2, operation).await.unwrap());
}

#[tokio::test]
async fn test_postgres_auth_actions_persisted_as_csv() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool.clone());
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec![
            "action1".to_string(),
            "action2".to_string(),
            "action3".to_string(),
        ],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    // Verify by querying database directly
    let row: (String,) = sqlx::query_as("SELECT actions FROM authorization_rules WHERE participant_identifier = $1")
        .bind("participant1")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(row.0, "action1,action2,action3");

    // Verify retrieval correctly splits the CSV
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules[0].actions.len(), 3);
    assert_eq!(rules[0].actions, vec!["action1", "action2", "action3"]);
}

#[tokio::test]
async fn test_postgres_auth_regex_compilation_on_retrieval() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource.*$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule).await.unwrap();

    // Get rules - regex should be compiled during retrieval
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert!(rules[0].compiled_regex.is_some());

    // Verify the regex works
    assert!(rules[0].matches_resource("resource123"));
    assert!(!rules[0].matches_resource("other123"));
}

#[tokio::test]
async fn test_postgres_auth_invalid_regex_error() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool.clone());
    evaluator.initialize().await.unwrap();

    let ctx = ParticipantContext::builder()
        .identifier("participant1")
        .audience("test-audience")
        .build();

    // Manually insert an invalid regex into the database
    sqlx::query(
        "INSERT INTO authorization_rules (participant_identifier, scope, resource, actions) VALUES ($1, $2, $3, $4)",
    )
    .bind("participant1")
    .bind("test_scope")
    .bind("[invalid-regex")
    .bind("read")
    .execute(&pool)
    .await
    .unwrap();

    // Getting rules should fail due to invalid regex
    let result = evaluator.get_rules(&ctx).await;
    assert!(result.is_err());
    if let Err(AuthorizationError::StoreError(msg)) = result {
        assert!(msg.contains("Failed to compile regex"));
    } else {
        panic!("Expected InvalidRegex error");
    }
}

#[tokio::test]
async fn test_postgres_auth_complex_real_world_scenario() {
    let (pool, _container) = setup_postgres_container().await;
    let evaluator = PostgresAuthorizationEvaluator::new(pool);
    evaluator.initialize().await.unwrap();

    // Scenario: Multi-tenant S3-like access control
    // User1 has read access to bucket1/folder1/*
    // User1 has write access to bucket1/folder1/uploads/*
    // User2 has admin access to bucket2/*

    let user1 = ParticipantContext::builder()
        .identifier("user1@example.com")
        .audience("s3-api")
        .build();

    let user2 = ParticipantContext::builder()
        .identifier("user2@example.com")
        .audience("s3-api")
        .build();

    // User1 rules
    let rule1 = Rule::new(
        "agreement123".to_string(),
        vec!["s3:GetObject".to_string()],
        "^bucket1/folder1/.*$".to_string(),
    )
    .unwrap();

    let rule2 = Rule::new(
        "agreement123".to_string(),
        vec!["s3:PutObject".to_string()],
        "^bucket1/folder1/uploads/.*$".to_string(),
    )
    .unwrap();

    // User2 rules
    let rule3 = Rule::new(
        "agreement456".to_string(),
        vec![
            "s3:GetObject".to_string(),
            "s3:PutObject".to_string(),
            "s3:DeleteObject".to_string(),
        ],
        "^bucket2/.*$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&user1, rule1).await.unwrap();
    evaluator.save_rule(&user1, rule2).await.unwrap();
    evaluator.save_rule(&user2, rule3).await.unwrap();

    // Test User1 permissions
    assert!(
        evaluator
            .evaluate(
                &user1,
                Operation::builder()
                    .scope("agreement123")
                    .action("s3:GetObject")
                    .resource("bucket1/folder1/file.txt")
                    .build()
            )
            .await
            .unwrap()
    );

    assert!(
        evaluator
            .evaluate(
                &user1,
                Operation::builder()
                    .scope("agreement123")
                    .action("s3:PutObject")
                    .resource("bucket1/folder1/uploads/newfile.txt")
                    .build()
            )
            .await
            .unwrap()
    );

    assert!(
        !evaluator
            .evaluate(
                &user1,
                Operation::builder()
                    .scope("agreement123")
                    .action("s3:DeleteObject")
                    .resource("bucket1/folder1/file.txt")
                    .build()
            )
            .await
            .unwrap()
    );

    // Test User2 permissions
    assert!(
        evaluator
            .evaluate(
                &user2,
                Operation::builder()
                    .scope("agreement456")
                    .action("s3:GetObject")
                    .resource("bucket2/any/path/file.txt")
                    .build()
            )
            .await
            .unwrap()
    );

    assert!(
        evaluator
            .evaluate(
                &user2,
                Operation::builder()
                    .scope("agreement456")
                    .action("s3:DeleteObject")
                    .resource("bucket2/file.txt")
                    .build()
            )
            .await
            .unwrap()
    );

    // Test cross-user isolation
    assert!(
        !evaluator
            .evaluate(
                &user1,
                Operation::builder()
                    .scope("agreement456")
                    .action("s3:GetObject")
                    .resource("bucket2/file.txt")
                    .build()
            )
            .await
            .unwrap()
    );
}
