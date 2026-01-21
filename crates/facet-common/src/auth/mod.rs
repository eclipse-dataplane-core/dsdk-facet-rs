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

#[cfg(test)]
mod tests;

mod mem;
mod postgres;

use bon::Builder;
use crate::context::ParticipantContext;
use regex::Regex;
use thiserror::Error;

pub use mem::MemoryAuthorizationEvaluator;
pub use postgres::PostgresAuthorizationEvaluator;

/// Represents an operation with specific attributes that describe its scope, action, and resource.
///
/// # Fields
///
/// * `scope` - The scope or domain of the operation, for example, a contract agreement.
/// * `action` - The specific action to be performed, such as "protocol::read", "write", or "protocol::delete".
/// * `resource` - The resource on which the action will be performed.
#[derive(Builder, Debug, Clone)]
pub struct Operation {
    #[builder(into)]
    pub scope: String,
    #[builder(into)]
    pub action: String,
    #[builder(into)]
    pub resource: String,
}

/// Represents a rule that defines access or operational constraints on a resource.
///
/// # Fields
///
/// * `scope` - The scope or domain of the operation, for example, a contract agreement.
/// * `action` - The specific action to be performed, such as "protocol::read", "write", or "protocol::delete".
/// * `resource` - The resource on which the action will be performed.
#[derive(Debug, Clone)]
pub struct Rule {
    pub scope: String,
    pub actions: Vec<String>,
    pub resource: String,
    pub compiled_regex: Option<Regex>,
}

impl Rule {
    pub fn new(scope: String, actions: Vec<String>, resource: String) -> Result<Self, AuthorizationError> {
        let compiled_regex = Regex::new(&resource)
            .map(Some)
            .map_err(|e| AuthorizationError::InvalidRegex(format!("Failed to compile regex '{}': {}", resource, e)))?;

        Ok(Self {
            scope,
            actions,
            resource,
            compiled_regex,
        })
    }

    pub fn matches_resource(&self, resource: &str) -> bool {
        match &self.compiled_regex {
            Some(regex) => regex.is_match(resource),
            None => resource == self.resource,
        }
    }
}

/// Evaluates whether an operation is authorized for a participant based on the configured rules.
#[async_trait::async_trait]
pub trait AuthorizationEvaluator: Sync + Send {
    async fn evaluate(
        &self,
        participant_context: &ParticipantContext,
        operation: Operation,
    ) -> Result<bool, AuthorizationError>;
}

/// Stores rules for a participant.
#[async_trait::async_trait]
pub trait RuleStore: Send + Sync {
    async fn get_rules(&self, participant_context: &ParticipantContext) -> Result<Vec<Rule>, AuthorizationError>;
    async fn save_rule(&self, participant_context: &ParticipantContext, rule: Rule) -> Result<(), AuthorizationError>;
    async fn remove_rule(&self, participant_context: &ParticipantContext, rule: Rule) -> Result<(), AuthorizationError>;
    async fn remove_rules(&self, participant_context: &ParticipantContext) -> Result<(), AuthorizationError>;
}

pub struct TrueAuthorizationEvaluator {}

impl TrueAuthorizationEvaluator {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl AuthorizationEvaluator for TrueAuthorizationEvaluator {
    async fn evaluate(&self, _: &ParticipantContext, _: Operation) -> Result<bool, AuthorizationError> {
        Ok(true)
    }
}

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Store error: {0}")]
    StoreError(String),
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
}
