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

use crate::auth::{AuthorizationError, AuthorizationEvaluator, Operation, Rule, RuleStore};
use crate::context::ParticipantContext;
use std::collections::HashMap;
use std::sync::RwLock;

/// A thread-safe, in-memory implementation of an authorization evaluator.
pub struct MemoryAuthorizationEvaluator {
    rules: RwLock<HashMap<String, HashMap<String, Vec<Rule>>>>,
}

impl MemoryAuthorizationEvaluator {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl AuthorizationEvaluator for MemoryAuthorizationEvaluator {
    async fn evaluate(
        &self,
        participant_context: &ParticipantContext,
        operation: Operation,
    ) -> Result<bool, AuthorizationError> {
        let rules = self
            .rules
            .read()
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to acquire lock: {}", e)))?;

        // Check if rules exist for this participant
        let Some(participant_rules) = rules.get(&participant_context.identifier) else {
            // No grant rules defined for this participant, not authorized
            return Ok(false);
        };
        let Some(scope_rules) = participant_rules.get(&operation.scope) else {
            // No grant rules defined for this participant and scope, not authorized
            return Ok(false);
        };

        for rule in scope_rules {
            if rule.actions.contains(&operation.action) && rule.matches_resource(&operation.resource) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait::async_trait]
impl RuleStore for MemoryAuthorizationEvaluator {
    async fn get_rules(&self, participant_context: &ParticipantContext) -> Result<Vec<Rule>, AuthorizationError> {
        let rules = self
            .rules
            .read()
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to acquire lock: {}", e)))?;

        let Some(participant_rules) = rules.get(&participant_context.identifier) else {
            return Ok(Vec::new());
        };

        let all_rules: Vec<Rule> = participant_rules
            .values()
            .flat_map(|scope_rules| scope_rules.iter().cloned())
            .collect();

        Ok(all_rules)
    }

    async fn save_rule(&self, participant_context: &ParticipantContext, rule: Rule) -> Result<(), AuthorizationError> {
        let mut rules = self
            .rules
            .write()
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to acquire lock: {}", e)))?;

        rules
            .entry(participant_context.identifier.clone())
            .or_insert_with(HashMap::new)
            .entry(rule.scope.clone())
            .or_insert_with(Vec::new)
            .push(rule);

        Ok(())
    }

    async fn remove_rule(
        &self,
        participant_context: &ParticipantContext,
        rule: Rule,
    ) -> Result<(), AuthorizationError> {
        let mut rules = self
            .rules
            .write()
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to acquire lock: {}", e)))?;

        let Some(participant_rules) = rules.get_mut(&participant_context.identifier) else {
            return Ok(());
        };

        let Some(scope_rules) = participant_rules.get_mut(&rule.scope) else {
            return Ok(());
        };

        scope_rules.retain(|r| !(r.scope == rule.scope && r.actions == rule.actions && r.resource == rule.resource));

        if scope_rules.is_empty() {
            participant_rules.remove(&rule.scope);
        }

        if participant_rules.is_empty() {
            rules.remove(&participant_context.identifier);
        }

        Ok(())
    }

    async fn remove_rules(&self, participant_context: &ParticipantContext) -> Result<(), AuthorizationError> {
        let mut rules = self
            .rules
            .write()
            .map_err(|e| AuthorizationError::StoreError(format!("Failed to acquire lock: {}", e)))?; 
        rules.remove(&participant_context.identifier);
        Ok(())
    }
}

#[cfg(test)]
impl MemoryAuthorizationEvaluator {
    /// Check if a participant exists in the internal rules map
    pub(crate) fn has_participant(&self, participant_id: &str) -> bool {
        self.rules
            .read()
            .map(|rules| rules.contains_key(participant_id))
            .unwrap_or(false)
    }

    /// Check if a scope exists for a participant in the internal rules map
    pub(crate) fn has_scope(&self, participant_id: &str, scope: &str) -> bool {
        self.rules
            .read()
            .map(|rules| {
                rules
                    .get(participant_id)
                    .map(|participant_rules| participant_rules.contains_key(scope))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Get the number of scopes for a participant
    pub(crate) fn scope_count(&self, participant_id: &str) -> Option<usize> {
        self.rules
            .read()
            .ok()
            .and_then(|rules| rules.get(participant_id).map(|p| p.len()))
    }

    /// Get the number of rules in a specific scope for a participant
    pub(crate) fn rule_count(&self, participant_id: &str, scope: &str) -> Option<usize> {
        self.rules
            .read()
            .ok()
            .and_then(|rules| {
                rules
                    .get(participant_id)
                    .and_then(|participant_rules| participant_rules.get(scope).map(|r| r.len()))
            })
    }

    /// Get the total number of participants in the map
    pub(crate) fn participant_count(&self) -> usize {
        self.rules
            .read()
            .map(|rules| rules.len())
            .unwrap_or(0)
    }
}
