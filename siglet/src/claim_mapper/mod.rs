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
//! Maps properties of a [`DataFlow`] into the claims of a generated JWT.
//!
//! A [`ClaimMapping`] binds the result of an expression (`from`) to a JWT claim key (`to`).
//! Mappings are configured per transfer type — statically in `SigletConfig` and at runtime through
//! the management API — so operators can shape token claims without a code change.
//!
//! The expression dialect is CEL; see [`CelClaimMapper`]. [`ClaimMapper`] is the extension point
//! for adding another dialect later.

mod cel_mapper;
mod credential_functions;
mod projection;

#[cfg(test)]
mod tests;

pub use cel_mapper::CelClaimMapper;
pub(crate) use projection::unwrap_json_value;

use bon::Builder;
use dataplane_sdk::core::model::data_flow::DataFlow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;
use thiserror::Error;

/// A single expression-to-claim binding.
///
/// All three field names are single words, so the camelCase wire form and the snake_case
/// configuration form coincide — unlike [`crate::config::TransferType`], no `serde(alias)` is
/// needed here.
#[derive(Builder, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
#[builder(on(String, into))]
pub struct ClaimMapping {
    /// Source expression, evaluated against the `flow` root variable.
    pub from: String,
    /// Target JWT claim key. Must not collide with a reserved JWT claim.
    pub to: String,
    /// When true, the mapping is skipped if its expression fails to evaluate or yields null.
    /// When false (the default) an evaluation failure fails the whole flow.
    #[serde(default)]
    #[builder(default)]
    pub optional: bool,
}

/// Failures arising while compiling or evaluating claim mappings.
///
/// Every variant carries owned `String` data rather than a borrowed engine type, so the error is
/// `'static + Send + Sync` and converts cleanly into a `HandlerError`.
#[derive(Debug, Error, PartialEq)]
pub enum ClaimMapperError {
    #[error("invalid expression '{expression}': {message}")]
    Compile { expression: String, message: String },

    #[error("failed to evaluate expression '{expression}' for claim '{claim}': {message}")]
    Evaluate {
        expression: String,
        claim: String,
        message: String,
    },

    #[error(
        "expression '{expression}' for claim '{claim}' produced a value that cannot be represented as JSON: {message}"
    )]
    Convert {
        expression: String,
        claim: String,
        message: String,
    },

    #[error("failed to project data flow '{flow_id}' for evaluation: {message}")]
    Projection { flow_id: String, message: String },

    #[error("failed to bind the 'flow' variable for data flow '{flow_id}': {message}")]
    Binding { flow_id: String, message: String },
}

/// Evaluates configured expressions against a [`DataFlow`] to produce JWT claims.
///
/// The whole mapping list is passed in a single call so implementations can build their evaluation
/// context — the flow projection, the interpreter environment — once per token rather than once
/// per mapping.
///
/// Deliberately synchronous: expression evaluation is bounded CPU work, so pushing it through
/// `async_trait` would add boxing to the token-generation path for no benefit.
pub trait ClaimMapper: Send + Sync {
    /// Dialect name, for error messages and diagnostics.
    fn dialect(&self) -> &'static str;

    /// Checks that `expression` parses.
    ///
    /// Used by configuration validation and by the management API so that a bad expression is
    /// rejected when it is written rather than when a flow runs.
    fn validate(&self, expression: &str) -> Result<(), ClaimMapperError>;

    /// Evaluates `mappings` in order and returns the resulting claims.
    ///
    /// Later entries override earlier ones on the same `to`. A mapping with `optional` set is
    /// skipped when its expression fails or yields null; otherwise a failure is returned as an
    /// error, while a null result is bound as a JSON `null`.
    fn map_claims(
        &self,
        mappings: &[ClaimMapping],
        flow: &DataFlow,
    ) -> Result<HashMap<String, Value>, ClaimMapperError>;
}

/// The process-wide mapper used for validating expressions outside a request.
///
/// Configuration validation and the management API both need to compile an expression without
/// having a handler at hand. Sharing one instance also shares its compiled-program cache with
/// nothing else, which is fine: validation compiles each expression once.
fn validation_mapper() -> &'static CelClaimMapper {
    static MAPPER: OnceLock<CelClaimMapper> = OnceLock::new();
    MAPPER.get_or_init(CelClaimMapper::new)
}

/// Checks that a claim-mapping expression compiles, using the same engine used at flow time.
///
/// Routing validation through the runtime compiler is what guarantees a configuration cannot pass
/// validation and then fail to compile when a flow arrives.
pub fn validate_expression(expression: &str) -> Result<(), ClaimMapperError> {
    validation_mapper().validate(expression)
}

/// Merges a transfer type's root claim mappings with those of the endpoint mapping that matched.
///
/// Root mappings form the base and keep their configured order. An entry from the matched endpoint
/// mapping whose `to` matches a root entry replaces it **in place**, preserving position; entries
/// with a new `to` are appended. When no endpoint mapping matched — including the static-endpoint
/// case, where a transfer type has no endpoint mappings at all — only the root mappings apply.
///
/// Replacing in place rather than appending keeps evaluation order stable, which matters because a
/// non-optional failure aborts the flow: the same configuration should always report the same
/// mapping as the culprit.
pub fn merge_claim_mappings(root: &[ClaimMapping], endpoint: Option<&[ClaimMapping]>) -> Vec<ClaimMapping> {
    let Some(endpoint) = endpoint.filter(|e| !e.is_empty()) else {
        return root.to_vec();
    };

    let mut merged = root.to_vec();
    for mapping in endpoint {
        match merged.iter_mut().find(|existing| existing.to == mapping.to) {
            Some(existing) => *existing = mapping.clone(),
            None => merged.push(mapping.clone()),
        }
    }
    merged
}
