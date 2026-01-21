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

use crate::auth::{
    AuthorizationError, AuthorizationEvaluator, MemoryAuthorizationEvaluator, Operation, Rule, RuleStore,
};
use crate::context::ParticipantContext;

fn create_test_evaluator() -> MemoryAuthorizationEvaluator {
    MemoryAuthorizationEvaluator::new()
}

async fn setup_rules(evaluator: &MemoryAuthorizationEvaluator, participant_id: &str, rules: Vec<Rule>) {
    let ctx = &ParticipantContext::builder().id(participant_id).build();

    for rule in rules {
        evaluator.save_rule(ctx, rule).await.unwrap();
    }
}

#[tokio::test]
async fn test_evaluate_authorized_exact_match() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("resource1")
                .build(),
        )
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_evaluate_no_rules_for_participant() {
    let evaluator = create_test_evaluator();

    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("unknown_participant").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("resource1")
                .build(),
        )
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_evaluate_no_rules_for_scope() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("scope2")
                .action("read")
                .resource("resource1")
                .build(),
        )
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_evaluate_action_not_authorized() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("write")
                .resource("resource1")
                .build(),
        )
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_evaluate_resource_not_matching() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("resource2")
                .build(),
        )
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_evaluate_regex_pattern_matching() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^/api/users/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    // Should match the pattern
    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("/api/users/123")
                .build(),
        )
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should not match the pattern
    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("/api/posts/123")
                .build(),
        )
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[tokio::test]
async fn test_evaluate_multiple_actions_in_rule() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string(), "write".to_string(), "delete".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    // All three actions should be authorized
    for action in &["read", "write", "delete"] {
        let result = evaluator
            .evaluate(
                &ParticipantContext::builder().id("participant1").build(),
                Operation::builder()
                    .scope("test_scope")
                    .action(*action)
                    .resource("resource1")
                    .build(),
            )
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "Action {} should be authorized", action);
    }
}

#[tokio::test]
async fn test_evaluate_multiple_rules() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^/api/users/.*".to_string(),
        )
        .unwrap(),
        Rule::new(
            "test_scope".to_string(),
            vec!["write".to_string()],
            "^/api/posts/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    // First rule should match
    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("read")
                .resource("/api/users/456")
                .build(),
        )
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Second rule should match
    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("write")
                .resource("/api/posts/789")
                .build(),
        )
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // No rule should match (wrong action for resource)
    let result = evaluator
        .evaluate(
            &ParticipantContext::builder().id("participant1").build(),
            Operation::builder()
                .scope("test_scope")
                .action("write")
                .resource("/api/users/456")
                .build(),
        )
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_rule_invalid_regex() {
    let result = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "[invalid(".to_string(),
    );

    assert!(result.is_err());
    match result {
        Err(AuthorizationError::InvalidRegex(_)) => {}
        _ => panic!("Expected InvalidRegex error"),
    }
}

#[test]
fn test_rule_matches_resource() {
    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^/api/.*".to_string(),
    )
    .unwrap();

    assert!(rule.matches_resource("/api/users"));
    assert!(rule.matches_resource("/api/posts/123"));
    assert!(!rule.matches_resource("/v2/api/users"));
    assert!(!rule.matches_resource("api/users"));
}

#[tokio::test]
async fn test_get_rules_no_rules() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let result = evaluator.get_rules(&ctx).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_rules_single_rule() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();

    let result = evaluator.get_rules(&ctx).await;
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].scope, "scope1");
    assert_eq!(rules[0].actions, vec!["read"]);
}

#[tokio::test]
async fn test_get_rules_multiple_scopes() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let rules = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope2".to_string(),
            vec!["write".to_string()],
            "^resource2$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator.get_rules(&ctx).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_rules_same_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let rules = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope1".to_string(),
            vec!["write".to_string()],
            "^resource2$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules).await;

    let result = evaluator.get_rules(&ctx).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[tokio::test]
async fn test_save_rule() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.save_rule(&ctx, rule).await;
    assert!(result.is_ok());

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 1);
}

#[tokio::test]
async fn test_save_multiple_rules_same_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

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

    evaluator.save_rule(&ctx, rule1).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 2);
}

#[tokio::test]
async fn test_save_rules_different_participants() {
    let evaluator = create_test_evaluator();
    let ctx1 = ParticipantContext::builder().id("participant1").build();
    let ctx2 = ParticipantContext::builder().id("participant2").build();

    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx1, rule.clone()).await.unwrap();
    evaluator.save_rule(&ctx2, rule).await.unwrap();

    assert_eq!(evaluator.get_rules(&ctx1).await.unwrap().len(), 1);
    assert_eq!(evaluator.get_rules(&ctx2).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_remove_rule_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 1);

    let result = evaluator.remove_rule(&ctx, rule).await;
    assert!(result.is_ok());
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_remove_rule_not_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.remove_rule(&ctx, rule).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_remove_rule_participant_not_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("unknown").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.remove_rule(&ctx, rule).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_remove_rule_multiple_in_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

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
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 2);

    evaluator.remove_rule(&ctx, rule1).await.unwrap();
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_remove_last_rule_cleans_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

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

    evaluator.save_rule(&ctx, rule1.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();

    // Verify both scopes exist in internal map
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert!(evaluator.has_scope("participant1", "scope2"));
    assert_eq!(evaluator.scope_count("participant1"), Some(2));

    evaluator.remove_rule(&ctx, rule1).await.unwrap();

    // Verify scope1 is removed from internal map but scope2 remains
    assert!(!evaluator.has_scope("participant1", "scope1"));
    assert!(evaluator.has_scope("participant1", "scope2"));
    assert_eq!(evaluator.scope_count("participant1"), Some(1));

    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].scope, "scope2");
}

#[tokio::test]
async fn test_remove_last_rule_cleans_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();

    // Verify participant exists in internal map
    assert!(evaluator.has_participant("participant1"));
    assert_eq!(evaluator.participant_count(), 1);

    evaluator.remove_rule(&ctx, rule).await.unwrap();

    // Verify participant is completely removed from internal map
    assert!(!evaluator.has_participant("participant1"));
    assert_eq!(evaluator.participant_count(), 0);
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_remove_rules_single_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add multiple rules across different scopes
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

    let rule3 = Rule::new(
        "scope2".to_string(),
        vec!["delete".to_string()],
        "^resource3$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();
    evaluator.save_rule(&ctx, rule3).await.unwrap();

    // Verify rules exist
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 3);

    // Remove all rules
    evaluator.remove_rules(&ctx).await.unwrap();

    // Verify all rules are removed
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_remove_rules_no_rules() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Remove rules when no rules exist - should be a no-op
    let result = evaluator.remove_rules(&ctx).await;
    assert!(result.is_ok());

    // Verify still no rules
    let rules = evaluator.get_rules(&ctx).await.unwrap();
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_remove_rules_isolation() {
    let evaluator = create_test_evaluator();
    let ctx1 = ParticipantContext::builder().id("participant1").build();

    let ctx2 = ParticipantContext::builder().id("participant2").build();

    // Add rules for both participants
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

    // Verify both have rules
    assert_eq!(evaluator.get_rules(&ctx1).await.unwrap().len(), 1);
    assert_eq!(evaluator.get_rules(&ctx2).await.unwrap().len(), 1);

    // Remove rules for participant1
    evaluator.remove_rules(&ctx1).await.unwrap();

    // Verify participant1 has no rules but participant2 still has rules
    assert_eq!(evaluator.get_rules(&ctx1).await.unwrap().len(), 0);
    assert_eq!(evaluator.get_rules(&ctx2).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_remove_rules_then_read() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    // Add rule
    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 1);

    // Remove all rules
    evaluator.remove_rules(&ctx).await.unwrap();
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 0);

    // Re-add same rule - should work
    evaluator.save_rule(&ctx, rule).await.unwrap();
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_remove_rules_affects_authorization() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let operation = Operation::builder()
        .scope("test_scope")
        .action("read")
        .resource("resource1")
        .build();

    // Add rule and verify authorization succeeds
    evaluator.save_rule(&ctx, rule).await.unwrap();
    assert!(evaluator.evaluate(&ctx, operation.clone()).await.unwrap());

    // Remove all rules
    evaluator.remove_rules(&ctx).await.unwrap();

    // Verify authorization now fails
    assert!(!evaluator.evaluate(&ctx, operation).await.unwrap());
}

#[tokio::test]
async fn test_remove_rules_multiple_scopes() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add rules in multiple scopes
    let rules = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope2".to_string(),
            vec!["write".to_string()],
            "^resource2$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope3".to_string(),
            vec!["delete".to_string()],
            "^resource3$".to_string(),
        )
        .unwrap(),
    ];

    for rule in rules {
        evaluator.save_rule(&ctx, rule).await.unwrap();
    }

    // Verify all rules exist
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 3);

    // Remove all rules
    evaluator.remove_rules(&ctx).await.unwrap();

    // Verify all rules from all scopes are removed
    assert_eq!(evaluator.get_rules(&ctx).await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_remove_rule_incremental_cleanup() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add 3 rules to the same scope
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
    let rule3 = Rule::new(
        "scope1".to_string(),
        vec!["delete".to_string()],
        "^resource3$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule2.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule3.clone()).await.unwrap();

    // Verify initial state
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(3));

    // Remove first rule - scope and participant should remain
    evaluator.remove_rule(&ctx, rule1).await.unwrap();
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(2));

    // Remove second rule - scope and participant should remain
    evaluator.remove_rule(&ctx, rule2).await.unwrap();
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(1));

    // Remove last rule - scope and participant should be cleaned up
    evaluator.remove_rule(&ctx, rule3).await.unwrap();
    assert!(!evaluator.has_participant("participant1"));
    assert!(!evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), None);
    assert_eq!(evaluator.participant_count(), 0);
}

#[tokio::test]
async fn test_remove_rule_keeps_other_scopes() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add rules to multiple scopes
    let rule1_scope1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();
    let rule2_scope1 = Rule::new(
        "scope1".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();
    let rule_scope2 = Rule::new(
        "scope2".to_string(),
        vec!["delete".to_string()],
        "^resource3$".to_string(),
    )
    .unwrap();
    let rule_scope3 = Rule::new(
        "scope3".to_string(),
        vec!["admin".to_string()],
        "^resource4$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1_scope1.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule2_scope1.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule_scope2.clone()).await.unwrap();
    evaluator.save_rule(&ctx, rule_scope3.clone()).await.unwrap();

    // Verify initial state
    assert_eq!(evaluator.scope_count("participant1"), Some(3));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(2));
    assert_eq!(evaluator.rule_count("participant1", "scope2"), Some(1));
    assert_eq!(evaluator.rule_count("participant1", "scope3"), Some(1));

    // Remove all rules from scope1
    evaluator.remove_rule(&ctx, rule1_scope1).await.unwrap();
    evaluator.remove_rule(&ctx, rule2_scope1).await.unwrap();

    // Verify scope1 is removed but other scopes remain
    assert!(evaluator.has_participant("participant1"));
    assert!(!evaluator.has_scope("participant1", "scope1"));
    assert!(evaluator.has_scope("participant1", "scope2"));
    assert!(evaluator.has_scope("participant1", "scope3"));
    assert_eq!(evaluator.scope_count("participant1"), Some(2));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), None);
}

#[tokio::test]
async fn test_remove_rules_cleans_all_internal_state() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add multiple rules across multiple scopes
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
        "scope3".to_string(),
        vec!["delete".to_string()],
        "^resource3$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule1).await.unwrap();
    evaluator.save_rule(&ctx, rule2).await.unwrap();
    evaluator.save_rule(&ctx, rule3).await.unwrap();

    // Verify participant and scopes exist
    assert!(evaluator.has_participant("participant1"));
    assert_eq!(evaluator.scope_count("participant1"), Some(3));
    assert_eq!(evaluator.participant_count(), 1);

    // Remove all rules at once
    evaluator.remove_rules(&ctx).await.unwrap();

    // Verify complete cleanup
    assert!(!evaluator.has_participant("participant1"));
    assert_eq!(evaluator.scope_count("participant1"), None);
    assert_eq!(evaluator.participant_count(), 0);
}

#[tokio::test]
async fn test_multiple_participants_isolation() {
    let evaluator = create_test_evaluator();
    let ctx1 = ParticipantContext::builder().id("participant1").build();
    let ctx2 = ParticipantContext::builder().id("participant2").build();

    // Add rules for both participants
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

    evaluator.save_rule(&ctx1, rule1.clone()).await.unwrap();
    evaluator.save_rule(&ctx2, rule2).await.unwrap();

    // Verify both participants exist
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_participant("participant2"));
    assert_eq!(evaluator.participant_count(), 2);

    // Remove participant1's rule
    evaluator.remove_rule(&ctx1, rule1).await.unwrap();

    // Verify participant1 is cleaned up but participant2 remains
    assert!(!evaluator.has_participant("participant1"));
    assert!(evaluator.has_participant("participant2"));
    assert_eq!(evaluator.participant_count(), 1);
}

#[tokio::test]
async fn test_remove_nonexistent_rule_no_impact() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add one rule
    let rule1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();
    evaluator.save_rule(&ctx, rule1).await.unwrap();

    // Try to remove a rule that doesn't exist
    let nonexistent_rule = Rule::new(
        "scope1".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();
    evaluator.remove_rule(&ctx, nonexistent_rule).await.unwrap();

    // Verify the existing rule is not affected
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(1));
}

#[tokio::test]
async fn test_remove_rule_from_nonexistent_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("nonexistent_participant").build();

    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    // Should not error, just no-op
    evaluator.remove_rule(&ctx, rule).await.unwrap();

    // Verify still no participant
    assert!(!evaluator.has_participant("nonexistent_participant"));
    assert_eq!(evaluator.participant_count(), 0);
}

#[tokio::test]
async fn test_remove_rule_from_nonexistent_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add a rule in scope1
    let rule1 = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();
    evaluator.save_rule(&ctx, rule1).await.unwrap();

    // Try to remove a rule from scope2 (doesn't exist)
    let rule2 = Rule::new(
        "scope2".to_string(),
        vec!["write".to_string()],
        "^resource2$".to_string(),
    )
    .unwrap();
    evaluator.remove_rule(&ctx, rule2).await.unwrap();

    // Verify scope1 is unaffected
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert!(!evaluator.has_scope("participant1", "scope2"));
    assert_eq!(evaluator.scope_count("participant1"), Some(1));
}

#[tokio::test]
async fn test_remove_rules_from_nonexistent_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("nonexistent_participant").build();

    // Should not error, just no-op
    evaluator.remove_rules(&ctx).await.unwrap();

    // Verify still no participant
    assert!(!evaluator.has_participant("nonexistent_participant"));
    assert_eq!(evaluator.participant_count(), 0);
}

#[tokio::test]
async fn test_readd_after_cleanup() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    // Add, remove, and add again
    evaluator.save_rule(&ctx, rule.clone()).await.unwrap();
    assert!(evaluator.has_participant("participant1"));

    evaluator.remove_rule(&ctx, rule.clone()).await.unwrap();
    assert!(!evaluator.has_participant("participant1"));

    evaluator.save_rule(&ctx, rule).await.unwrap();
    assert!(evaluator.has_participant("participant1"));
    assert!(evaluator.has_scope("participant1", "scope1"));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(1));
}

#[tokio::test]
async fn test_complex_multi_scope_multi_rule_cleanup() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext::builder().id("participant1").build();

    // Add multiple rules across multiple scopes
    let rules_scope1 = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope1".to_string(),
            vec!["write".to_string()],
            "^resource2$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope1".to_string(),
            vec!["delete".to_string()],
            "^resource3$".to_string(),
        )
        .unwrap(),
    ];
    let rules_scope2 = vec![
        Rule::new(
            "scope2".to_string(),
            vec!["read".to_string()],
            "^resource4$".to_string(),
        )
        .unwrap(),
        Rule::new(
            "scope2".to_string(),
            vec!["write".to_string()],
            "^resource5$".to_string(),
        )
        .unwrap(),
    ];

    for rule in &rules_scope1 {
        evaluator.save_rule(&ctx, rule.clone()).await.unwrap();
    }
    for rule in &rules_scope2 {
        evaluator.save_rule(&ctx, rule.clone()).await.unwrap();
    }

    // Verify initial state
    assert_eq!(evaluator.scope_count("participant1"), Some(2));
    assert_eq!(evaluator.rule_count("participant1", "scope1"), Some(3));
    assert_eq!(evaluator.rule_count("participant1", "scope2"), Some(2));

    // Remove all rules from scope1
    for rule in &rules_scope1 {
        evaluator.remove_rule(&ctx, rule.clone()).await.unwrap();
    }

    // Verify scope1 is cleaned up but participant and scope2 remain
    assert!(evaluator.has_participant("participant1"));
    assert!(!evaluator.has_scope("participant1", "scope1"));
    assert!(evaluator.has_scope("participant1", "scope2"));
    assert_eq!(evaluator.scope_count("participant1"), Some(1));
    assert_eq!(evaluator.rule_count("participant1", "scope2"), Some(2));

    // Remove all rules from scope2
    for rule in &rules_scope2 {
        evaluator.remove_rule(&ctx, rule.clone()).await.unwrap();
    }

    // Verify complete cleanup
    assert!(!evaluator.has_participant("participant1"));
    assert_eq!(evaluator.participant_count(), 0);
}
