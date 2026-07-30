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
//! Projects a [`DataFlow`] into the JSON document that claim-mapping expressions are evaluated
//! against.

use super::ClaimMapperError;
use dataplane_sdk::core::model::data_flow::DataFlow;
use serde_json::{Map, Value};

/// Unwraps a value that is itself a JSON-encoded string.
///
/// `"\"hello\""` becomes `"hello"`, `"[1,2]"` becomes `[1,2]` and `"null"` becomes `null`. Strings
/// that are not valid JSON, and values that are not strings, are returned unchanged. Only the top
/// level is unwrapped: members of a parsed object or array are not re-parsed in turn.
///
/// Control planes vary in whether they send structured metadata as real JSON or as a JSON-encoded
/// string, so normalizing here is what lets a single expression work against both.
///
/// The recursion terminates because the JSON encoding of a string is strictly longer than the
/// string itself, so a value cannot encode itself.
pub(crate) fn unwrap_json_value(value: &Value) -> Value {
    match value {
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(parsed) => unwrap_json_value(&parsed),
            Err(_) => value.clone(),
        },
        _ => value.clone(),
    }
}

/// Normalizes a metadata/claims map, unwrapping any JSON-encoded string values.
fn unwrap_map(source: &std::collections::HashMap<String, Value>) -> Value {
    Value::Object(
        source
            .iter()
            .map(|(k, v)| (k.clone(), unwrap_json_value(v)))
            .collect::<Map<String, Value>>(),
    )
}

/// Serializes a value, mapping any failure onto [`ClaimMapperError::Projection`].
///
/// `serde_json::to_value` only fails for types whose `Serialize` impl errors, which none of the
/// projected fields do — but the workspace denies `unwrap`, and a surfaced error beats a panic.
fn project_field<T: serde::Serialize>(flow_id: &str, field: &str, value: &T) -> Result<Value, ClaimMapperError> {
    serde_json::to_value(value).map_err(|e| ClaimMapperError::Projection {
        flow_id: flow_id.to_string(),
        message: format!("field '{}': {}", field, e),
    })
}

/// Projects a [`DataFlow`] into the JSON document bound to the expression root variable `flow`.
///
/// `DataFlow` does not derive `Serialize`, so the projection is built by hand. Field names use the
/// camelCase wire form of the data plane signaling model, so an expression reads the same as the
/// JSON an operator sees on the signaling API.
///
/// Notable shape decisions:
/// - `Option` fields are emitted as an explicit `null` rather than omitted, so `== null` works
///   without a `has()` guard.
/// - `labels`, `metadata` and `claims` are always present (possibly empty), so a missing key is a
///   clean "no such key" error rather than an undeclared-reference error.
/// - `metadata` and `claims` values are passed through [`unwrap_json_value`].
/// - Timestamps are RFC3339 strings, because the bridge into the expression engine is
///   `serde_json::Value`, which has no timestamp type. Use `timestamp(flow.createdAt)` to get a
///   real timestamp inside an expression.
pub(crate) fn flow_to_value(flow: &DataFlow) -> Result<Value, ClaimMapperError> {
    let mut out = Map::new();

    out.insert("id".to_string(), Value::String(flow.id.clone()));
    out.insert("state".to_string(), project_field(&flow.id, "state", &flow.state)?);
    out.insert("profile".to_string(), Value::String(flow.profile.clone()));
    out.insert("kind".to_string(), project_field(&flow.id, "kind", &flow.kind)?);
    out.insert("agreementId".to_string(), Value::String(flow.agreement_id.clone()));
    out.insert("datasetId".to_string(), Value::String(flow.dataset_id.clone()));
    out.insert(
        "dataspaceContext".to_string(),
        Value::String(flow.dataspace_context.clone()),
    );
    out.insert("participantId".to_string(), Value::String(flow.participant_id.clone()));
    out.insert(
        "counterPartyId".to_string(),
        Value::String(flow.counter_party_id.clone()),
    );
    out.insert(
        "controlPlaneId".to_string(),
        Value::String(flow.control_plane_id.clone()),
    );
    out.insert(
        "participantContextId".to_string(),
        Value::String(flow.participant_context_id.clone()),
    );
    out.insert(
        "suspensionReason".to_string(),
        flow.suspension_reason.clone().map_or(Value::Null, Value::String),
    );
    out.insert(
        "terminationReason".to_string(),
        flow.termination_reason.clone().map_or(Value::Null, Value::String),
    );
    out.insert(
        "labels".to_string(),
        Value::Array(flow.labels.iter().cloned().map(Value::String).collect()),
    );
    out.insert("metadata".to_string(), unwrap_map(&flow.metadata));
    out.insert("claims".to_string(), unwrap_map(&flow.claims));
    out.insert(
        "dataAddress".to_string(),
        match flow.data_address.as_ref() {
            Some(address) => project_field(&flow.id, "dataAddress", address)?,
            None => Value::Null,
        },
    );
    out.insert("createdAt".to_string(), Value::String(flow.created_at.to_rfc3339()));
    out.insert("updatedAt".to_string(), Value::String(flow.updated_at.to_rfc3339()));

    Ok(Value::Object(out))
}
