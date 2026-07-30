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
//! A [`ClaimMapper`] backed by the Common Expression Language.

use super::projection::flow_to_value;
use super::{ClaimMapper, ClaimMapperError, ClaimMapping};
use cel::{Context, Program};
use dataplane_sdk::core::model::data_flow::DataFlow;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Upper bound on retained compiled programs.
///
/// Expressions come from operator configuration, so the real working set is a handful. The cap
/// exists only so a pathological management-API workload cannot grow the cache without limit.
const PROGRAM_CACHE_CAPACITY: usize = 512;

/// Evaluates CEL expressions against a [`DataFlow`] projection.
///
/// Compiled programs are cached by expression source. Pre-compiling at configuration load would
/// not be sufficient: transfer types are read per request and can be replaced at any time through
/// the management API, so a table built at startup would miss every runtime-configured mapping.
/// Keying the cache on the source text means a changed expression is simply a different key, so
/// there is no invalidation to get wrong.
pub struct CelClaimMapper {
    programs: RwLock<HashMap<String, Arc<Program>>>,
}

impl CelClaimMapper {
    pub fn new() -> Self {
        Self {
            programs: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the compiled program for `expression`, compiling and caching it on first use.
    ///
    /// Compilation happens outside the lock so a slow parse never blocks other requests; the cost
    /// is that a race may compile the same expression twice, which is harmless. A poisoned lock
    /// degrades to an uncached compile rather than propagating a panic.
    fn program_for(&self, expression: &str) -> Result<Arc<Program>, ClaimMapperError> {
        if let Ok(cache) = self.programs.read()
            && let Some(program) = cache.get(expression)
        {
            return Ok(Arc::clone(program));
        }

        let program = Arc::new(Self::compile(expression)?);

        if let Ok(mut cache) = self.programs.write()
            && cache.len() < PROGRAM_CACHE_CAPACITY
        {
            cache.insert(expression.to_string(), Arc::clone(&program));
        }

        Ok(program)
    }

    fn compile(expression: &str) -> Result<Program, ClaimMapperError> {
        Program::compile(expression).map_err(|e| ClaimMapperError::Compile {
            expression: expression.to_string(),
            message: e.to_string(),
        })
    }
}

impl Default for CelClaimMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimMapper for CelClaimMapper {
    fn dialect(&self) -> &'static str {
        "cel"
    }

    fn validate(&self, expression: &str) -> Result<(), ClaimMapperError> {
        self.program_for(expression).map(|_| ())
    }

    fn map_claims(
        &self,
        mappings: &[ClaimMapping],
        flow: &DataFlow,
    ) -> Result<HashMap<String, Value>, ClaimMapperError> {
        if mappings.is_empty() {
            return Ok(HashMap::new());
        }

        // Project the flow and build the evaluation context once for the whole batch.
        let projection = flow_to_value(flow)?;
        let mut context = Context::default();
        super::credential_functions::register(&mut context);
        context
            .add_variable("flow", projection)
            .map_err(|e| ClaimMapperError::Binding {
                flow_id: flow.id.clone(),
                message: e.to_string(),
            })?;

        let mut claims = HashMap::with_capacity(mappings.len());
        for mapping in mappings {
            let program = match self.program_for(&mapping.from) {
                Ok(program) => program,
                Err(_) if mapping.optional => {
                    tracing::debug!(
                        claim = %mapping.to,
                        expression = %mapping.from,
                        "skipping optional claim mapping: expression failed to compile"
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };

            let value = match program.execute(&context) {
                Ok(value) => value,
                Err(_) if mapping.optional => {
                    tracing::debug!(
                        claim = %mapping.to,
                        expression = %mapping.from,
                        "skipping optional claim mapping: expression failed to evaluate"
                    );
                    continue;
                }
                Err(e) => {
                    return Err(ClaimMapperError::Evaluate {
                        expression: mapping.from.clone(),
                        claim: mapping.to.clone(),
                        message: e.to_string(),
                    });
                }
            };

            // A null result is only special for optional mappings; a required mapping binds it as
            // a JSON null. `value` is held in a local because the conversion error borrows it.
            if mapping.optional && matches!(value, cel::objects::Value::Null) {
                tracing::debug!(
                    claim = %mapping.to,
                    expression = %mapping.from,
                    "skipping optional claim mapping: expression evaluated to null"
                );
                continue;
            }

            let json = value.json().map_err(|e| ClaimMapperError::Convert {
                expression: mapping.from.clone(),
                claim: mapping.to.clone(),
                message: e.to_string(),
            })?;

            claims.insert(mapping.to.clone(), json);
        }

        Ok(claims)
    }
}
