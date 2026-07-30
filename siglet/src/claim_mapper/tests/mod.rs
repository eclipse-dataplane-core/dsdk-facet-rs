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
#![allow(clippy::unwrap_used)]

use super::projection::{flow_to_value, unwrap_json_value};
use super::{CelClaimMapper, ClaimMapper, ClaimMapperError, ClaimMapping, merge_claim_mappings, validate_expression};
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::model::data_flow::{DataFlow, DataFlowType};
use serde_json::{Value, json};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_flow() -> DataFlow {
    DataFlow::builder()
        .id("flow-1")
        .participant_id("participant-1")
        .profile("http-pull")
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .dataspace_context("dataspace-1")
        .counter_party_id("counter-party-1")
        .control_plane_id("control-plane-1")
        .participant_context_id("context-1")
        .kind(DataFlowType::Provider)
        .build()
}

fn flow_with_metadata(metadata: HashMap<String, Value>) -> DataFlow {
    let mut flow = test_flow();
    flow.metadata = metadata;
    flow
}

fn metadata(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn mapping(from: &str, to: &str) -> ClaimMapping {
    ClaimMapping::builder().from(from).to(to).build()
}

fn optional_mapping(from: &str, to: &str) -> ClaimMapping {
    ClaimMapping::builder().from(from).to(to).optional(true).build()
}

/// Evaluates a single expression against `flow` and returns the resulting claim value.
fn eval(flow: &DataFlow, expression: &str) -> Result<Option<Value>, ClaimMapperError> {
    let mapper = CelClaimMapper::new();
    mapper
        .map_claims(&[mapping(expression, "result")], flow)
        .map(|claims| claims.get("result").cloned())
}

// ---------------------------------------------------------------------------
// unwrap_json_value
// ---------------------------------------------------------------------------

#[test]
fn test_unwrap_json_value_leaves_non_strings_unchanged() {
    for value in [json!(null), json!(true), json!(42), json!(-1), json!(1.5)] {
        assert_eq!(unwrap_json_value(&value), value);
    }
    assert_eq!(unwrap_json_value(&json!([1, 2])), json!([1, 2]));
    assert_eq!(unwrap_json_value(&json!({"a": 1})), json!({"a": 1}));
}

#[test]
fn test_unwrap_json_value_leaves_plain_strings_unchanged() {
    assert_eq!(unwrap_json_value(&json!("hello")), json!("hello"));
    assert_eq!(unwrap_json_value(&json!("")), json!(""));
    assert_eq!(unwrap_json_value(&json!("not json {")), json!("not json {"));
}

#[test]
fn test_unwrap_json_value_unwraps_encoded_values() {
    assert_eq!(unwrap_json_value(&json!("\"hello\"")), json!("hello"));
    assert_eq!(unwrap_json_value(&json!("null")), json!(null));
    assert_eq!(unwrap_json_value(&json!("true")), json!(true));
    assert_eq!(unwrap_json_value(&json!("123")), json!(123));
    assert_eq!(unwrap_json_value(&json!("[1,2]")), json!([1, 2]));
    assert_eq!(unwrap_json_value(&json!("{\"a\":1}")), json!({"a": 1}));
}

#[test]
fn test_unwrap_json_value_unwraps_double_encoded_strings() {
    // A doubly-encoded string peels all the way down.
    assert_eq!(unwrap_json_value(&json!("\"\\\"hello\\\"\"")), json!("hello"));
}

#[test]
fn test_unwrap_json_value_does_not_recurse_into_members() {
    // The outer string is parsed, but the encoded member inside it is left alone.
    let value = json!("{\"a\": \"\\\"inner\\\"\"}");
    assert_eq!(unwrap_json_value(&value), json!({"a": "\"inner\""}));
}

// ---------------------------------------------------------------------------
// flow_to_value
// ---------------------------------------------------------------------------

#[test]
fn test_flow_to_value_projects_scalar_fields_in_camel_case() {
    let projected = flow_to_value(&test_flow()).unwrap();

    assert_eq!(projected["id"], json!("flow-1"));
    assert_eq!(projected["profile"], json!("http-pull"));
    assert_eq!(projected["agreementId"], json!("agreement-1"));
    assert_eq!(projected["datasetId"], json!("dataset-1"));
    assert_eq!(projected["dataspaceContext"], json!("dataspace-1"));
    assert_eq!(projected["participantId"], json!("participant-1"));
    assert_eq!(projected["counterPartyId"], json!("counter-party-1"));
    assert_eq!(projected["controlPlaneId"], json!("control-plane-1"));
    assert_eq!(projected["participantContextId"], json!("context-1"));
}

#[test]
fn test_flow_to_value_projects_enums_as_screaming_snake_case() {
    let projected = flow_to_value(&test_flow()).unwrap();
    assert_eq!(projected["kind"], json!("PROVIDER"));
    assert_eq!(projected["state"], json!("INITIATING"));
}

#[test]
fn test_flow_to_value_emits_null_for_absent_options() {
    let projected = flow_to_value(&test_flow()).unwrap();
    assert_eq!(projected["suspensionReason"], Value::Null);
    assert_eq!(projected["terminationReason"], Value::Null);
    assert_eq!(projected["dataAddress"], Value::Null);
}

#[test]
fn test_flow_to_value_emits_empty_collections_not_null() {
    let projected = flow_to_value(&test_flow()).unwrap();
    assert_eq!(projected["labels"], json!([]));
    assert_eq!(projected["metadata"], json!({}));
    assert_eq!(projected["claims"], json!({}));
}

#[test]
fn test_flow_to_value_projects_data_address() {
    let mut flow = test_flow();
    flow.data_address = Some(
        DataAddress::builder()
            .endpoint("https://example.com")
            .endpoint_type("HTTP")
            .endpoint_properties(vec![
                EndpointProperty::builder().name("authType").value("bearer").build(),
            ])
            .build(),
    );

    let projected = flow_to_value(&flow).unwrap();
    assert_eq!(projected["dataAddress"]["endpoint"], json!("https://example.com"));
    assert_eq!(projected["dataAddress"]["endpointType"], json!("HTTP"));
    assert_eq!(projected["dataAddress"]["@type"], json!("DataAddress"));
    assert_eq!(
        projected["dataAddress"]["endpointProperties"][0]["name"],
        json!("authType")
    );
}

#[test]
fn test_flow_to_value_unwraps_json_encoded_metadata_and_claims() {
    let mut flow = flow_with_metadata(metadata(&[("encoded", json!("[1,2]")), ("plain", json!("x"))]));
    flow.claims = metadata(&[("wrapped", json!("{\"a\":1}"))]);

    let projected = flow_to_value(&flow).unwrap();
    assert_eq!(projected["metadata"]["encoded"], json!([1, 2]));
    assert_eq!(projected["metadata"]["plain"], json!("x"));
    assert_eq!(projected["claims"]["wrapped"], json!({"a": 1}));
}

#[test]
fn test_flow_to_value_emits_rfc3339_timestamps() {
    let projected = flow_to_value(&test_flow()).unwrap();
    let created = projected["createdAt"].as_str().unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(created).is_ok(),
        "createdAt should be RFC3339, got {created}"
    );
    assert!(projected["updatedAt"].is_string());
}

// ---------------------------------------------------------------------------
// map_claims — basics and type preservation
// ---------------------------------------------------------------------------

#[test]
fn test_map_claims_empty_slice_yields_no_claims() {
    let mapper = CelClaimMapper::new();
    let claims = mapper.map_claims(&[], &test_flow()).unwrap();
    assert!(claims.is_empty());
}

#[test]
fn test_map_claims_evaluates_literals_and_field_access() {
    let flow = test_flow();
    assert_eq!(eval(&flow, "'static-value'").unwrap(), Some(json!("static-value")));
    assert_eq!(eval(&flow, "flow.agreementId").unwrap(), Some(json!("agreement-1")));
    assert_eq!(
        eval(&flow, "'urn:asset:' + flow.datasetId").unwrap(),
        Some(json!("urn:asset:dataset-1"))
    );
}

#[test]
fn test_map_claims_preserves_json_types() {
    let flow = flow_with_metadata(metadata(&[
        ("count", json!(7)),
        ("ratio", json!(1.5)),
        ("enabled", json!(true)),
        ("list", json!([1, 2])),
        ("obj", json!({"a": 1})),
    ]));

    assert_eq!(eval(&flow, "flow.metadata.count").unwrap(), Some(json!(7)));
    assert_eq!(eval(&flow, "flow.metadata.ratio").unwrap(), Some(json!(1.5)));
    assert_eq!(eval(&flow, "flow.metadata.enabled").unwrap(), Some(json!(true)));
    assert_eq!(eval(&flow, "flow.metadata.list").unwrap(), Some(json!([1, 2])));
    assert_eq!(eval(&flow, "flow.metadata.obj").unwrap(), Some(json!({"a": 1})));
    assert_eq!(eval(&flow, "size(flow.metadata.list) > 1").unwrap(), Some(json!(true)));
}

#[test]
fn test_map_claims_reads_namespaced_metadata_keys() {
    let key = "https://w3id.org/edc/v0.0.1/ns/region";
    let flow = flow_with_metadata(metadata(&[(key, json!("eu-west-1"))]));

    assert_eq!(
        eval(&flow, &format!("flow.metadata[\"{key}\"]")).unwrap(),
        Some(json!("eu-west-1"))
    );
    // `has()` rejects index syntax, so membership is the guard idiom for namespaced keys.
    assert_eq!(
        eval(&flow, &format!("\"{key}\" in flow.metadata")).unwrap(),
        Some(json!(true))
    );
    assert_eq!(
        eval(
            &flow,
            r#""absent" in flow.metadata ? flow.metadata["absent"] : "fallback""#
        )
        .unwrap(),
        Some(json!("fallback"))
    );
}

#[test]
fn test_map_claims_supports_has_guard_for_identifier_keys() {
    let flow = flow_with_metadata(metadata(&[("tier", json!("gold"))]));
    assert_eq!(
        eval(&flow, "has(flow.metadata.tier) ? flow.metadata.tier : 'basic'").unwrap(),
        Some(json!("gold"))
    );
    assert_eq!(
        eval(&flow, "has(flow.metadata.absent) ? flow.metadata.absent : 'basic'").unwrap(),
        Some(json!("basic"))
    );
}

#[test]
fn test_map_claims_later_mapping_overrides_earlier_on_same_key() {
    let mapper = CelClaimMapper::new();
    let claims = mapper
        .map_claims(
            &[mapping("'first'", "claim"), mapping("'second'", "claim")],
            &test_flow(),
        )
        .unwrap();
    assert_eq!(claims.get("claim"), Some(&json!("second")));
}

// ---------------------------------------------------------------------------
// map_claims — the verifiable-credential case
// ---------------------------------------------------------------------------

#[test]
fn test_map_claims_filters_verifiable_credentials() {
    // The credential list arrives as a JSON-encoded string, exercising unwrapping, the filter/map
    // macros and list-to-JSON conversion in a single path.
    let encoded = r#"[{"type":["VerifiableCredential","MembershipCredential"],
                       "credentialSubject":{"holderIdentifier":"BPNL0001"}},
                      {"type":["VerifiableCredential","DismantlerCredential"],
                       "credentialSubject":{"holderIdentifier":"BPNL0002"}}]"#;
    let mut flow = test_flow();
    flow.claims = metadata(&[("vc", json!(encoded))]);

    assert_eq!(
        eval(
            &flow,
            r#"flow.claims.vc.filter(c, "MembershipCredential" in c.type).map(c, c.credentialSubject.holderIdentifier)"#
        )
        .unwrap(),
        Some(json!(["BPNL0001"]))
    );

    // Plucking a single scalar out of the matched credential.
    assert_eq!(
        eval(
            &flow,
            r#"flow.claims.vc.filter(c, "MembershipCredential" in c.type)[0].credentialSubject.holderIdentifier"#
        )
        .unwrap(),
        Some(json!("BPNL0001"))
    );

    // The three-argument map form filters and projects in one pass.
    assert_eq!(
        eval(
            &flow,
            r#"flow.claims.vc.map(c, "DismantlerCredential" in c.type, c.credentialSubject.holderIdentifier)"#
        )
        .unwrap(),
        Some(json!(["BPNL0002"]))
    );

    assert_eq!(
        eval(&flow, r#"flow.claims.vc.exists(c, "MembershipCredential" in c.type)"#).unwrap(),
        Some(json!(true))
    );
}

#[test]
fn test_map_claims_indexing_an_empty_filter_result_is_an_error() {
    let mut flow = test_flow();
    flow.claims = metadata(&[("vc", json!("[{\"type\":[\"Other\"]}]"))]);

    let result = eval(
        &flow,
        r#"flow.claims.vc.filter(c, "MembershipCredential" in c.type)[0].credentialSubject.holderIdentifier"#,
    );
    assert!(matches!(result, Err(ClaimMapperError::Evaluate { .. })));
}

// ---------------------------------------------------------------------------
// map_claims — credential helper functions
//
// withType / hasType / hasCredential / hasClaim / claim / claims, mirroring the EDC
// decentralized-claims-cel extension. The point of these is that the array/scalar variance of the
// W3C VC data model (`type` string-or-list, `credentialSubject` object-or-array) is normalized, so
// the same expression works regardless of shape.
// ---------------------------------------------------------------------------

fn flow_with_vc(vc: Value) -> DataFlow {
    let mut flow = test_flow();
    flow.claims = metadata(&[("vc", vc)]);
    flow
}

/// Two credentials whose `credentialSubject` is a single **object** (JSON-LD compacted form).
fn vc_object_subject() -> Value {
    json!([
        {"type": ["VerifiableCredential", "MembershipCredential"],
         "credentialSubject": {"holderIdentifier": "BPNL0001", "status": "active"}},
        {"type": ["VerifiableCredential", "DismantlerCredential"],
         "credentialSubject": {"allowedBrands": ["BMW", "Audi"]}}
    ])
}

/// The same credentials whose `credentialSubject` is an **array** of subjects — the shape that made
/// the naive `credentialSubject.holderIdentifier` expression fail.
fn vc_array_subject() -> Value {
    json!([
        {"type": ["VerifiableCredential", "MembershipCredential"],
         "credentialSubject": [{"holderIdentifier": "BPNL0001", "status": "active"}]},
        {"type": ["VerifiableCredential", "DismantlerCredential"],
         "credentialSubject": [{"allowedBrands": ["BMW", "Audi"]}]}
    ])
}

#[test]
fn test_helpers_normalize_object_and_array_subject() {
    // The regression that motivated the helpers: identical results whether credentialSubject is an
    // object or an array.
    for vc in [vc_object_subject(), vc_array_subject()] {
        let flow = flow_with_vc(vc);
        assert_eq!(
            eval(
                &flow,
                "flow.claims.vc.withType('MembershipCredential').claim('holderIdentifier')"
            )
            .unwrap(),
            Some(json!("BPNL0001"))
        );
    }
}

#[test]
fn test_withtype_normalizes_scalar_type() {
    let flow = flow_with_vc(json!([
        {"type": "MembershipCredential", "credentialSubject": [{"holderIdentifier": "BPNL0001"}]}
    ]));
    assert_eq!(
        eval(
            &flow,
            "flow.claims.vc.withType('MembershipCredential').claim('holderIdentifier')"
        )
        .unwrap(),
        Some(json!("BPNL0001"))
    );
}

#[test]
fn test_withtype_falls_back_to_jsonld_type_key() {
    let flow = flow_with_vc(json!([
        {"@type": ["MembershipCredential"], "credentialSubject": [{"holderIdentifier": "BPNL0001"}]}
    ]));
    assert_eq!(
        eval(
            &flow,
            "flow.claims.vc.withType('MembershipCredential').claim('holderIdentifier')"
        )
        .unwrap(),
        Some(json!("BPNL0001"))
    );
}

#[test]
fn test_has_credential_and_has_type() {
    let flow = flow_with_vc(vc_array_subject());
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasCredential('MembershipCredential')").unwrap(),
        Some(json!(true))
    );
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasCredential('UnknownCredential')").unwrap(),
        Some(json!(false))
    );
    // Single-credential form, composed with the exists() macro.
    assert_eq!(
        eval(&flow, "flow.claims.vc.exists(c, c.hasType('DismantlerCredential'))").unwrap(),
        Some(json!(true))
    );
}

#[test]
fn test_has_claim_one_and_two_argument_forms() {
    let flow = flow_with_vc(vc_array_subject());
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasClaim('status')").unwrap(),
        Some(json!(true))
    );
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasClaim('absent')").unwrap(),
        Some(json!(false))
    );
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasClaim('status', 'active')").unwrap(),
        Some(json!(true))
    );
    assert_eq!(
        eval(&flow, "flow.claims.vc.hasClaim('status', 'revoked')").unwrap(),
        Some(json!(false))
    );
    // Scoped to the matching credential.
    assert_eq!(
        eval(
            &flow,
            "flow.claims.vc.withType('MembershipCredential').hasClaim('status', 'active')"
        )
        .unwrap(),
        Some(json!(true))
    );
}

#[test]
fn test_claim_returns_first_and_claims_returns_all() {
    let flow = flow_with_vc(json!([
        {"type": ["MembershipCredential"], "credentialSubject": [{"holderIdentifier": "BPNL0001"}]},
        {"type": ["MembershipCredential"], "credentialSubject": [{"holderIdentifier": "BPNL0002"}]}
    ]));
    assert_eq!(
        eval(&flow, "flow.claims.vc.claim('holderIdentifier')").unwrap(),
        Some(json!("BPNL0001"))
    );
    assert_eq!(
        eval(&flow, "flow.claims.vc.claims('holderIdentifier')").unwrap(),
        Some(json!(["BPNL0001", "BPNL0002"]))
    );
    // An absent claim yields null; for a required mapping that binds a JSON null.
    assert_eq!(
        eval(&flow, "flow.claims.vc.claim('absent')").unwrap(),
        Some(json!(null))
    );
}

#[test]
fn test_claim_supports_dot_paths() {
    let flow = flow_with_vc(json!([
        {"type": ["DegreeCredential"], "credentialSubject": [{"degree": {"type": "BachelorDegree"}}]}
    ]));
    assert_eq!(
        eval(
            &flow,
            "flow.claims.vc.withType('DegreeCredential').claim('degree.type')"
        )
        .unwrap(),
        Some(json!("BachelorDegree"))
    );
}

#[test]
fn test_helpers_work_on_json_encoded_credential_list() {
    // The list arrives as a JSON-encoded string; unwrapping and the helpers compose.
    let encoded = r#"[{"type":["MembershipCredential"],"credentialSubject":[{"holderIdentifier":"BPNL0001"}]}]"#;
    let flow = flow_with_vc(json!(encoded));
    assert_eq!(
        eval(
            &flow,
            "flow.claims.vc.withType('MembershipCredential').claim('holderIdentifier')"
        )
        .unwrap(),
        Some(json!("BPNL0001"))
    );
}

#[test]
fn test_helpers_are_lenient_on_non_credential_input() {
    // A string is not credential-shaped; helpers degrade to empty/null/false rather than erroring.
    let flow = flow_with_metadata(metadata(&[("s", json!("hello"))]));
    assert_eq!(eval(&flow, "flow.metadata.s.withType('X')").unwrap(), Some(json!([])));
    assert_eq!(eval(&flow, "flow.metadata.s.claim('x')").unwrap(), Some(json!(null)));
    assert_eq!(eval(&flow, "flow.metadata.s.claims('x')").unwrap(), Some(json!([])));
    assert_eq!(
        eval(&flow, "flow.metadata.s.hasCredential('X')").unwrap(),
        Some(json!(false))
    );
    assert_eq!(
        eval(&flow, "flow.metadata.s.hasClaim('x')").unwrap(),
        Some(json!(false))
    );
}

// ---------------------------------------------------------------------------
// map_claims — failure and optionality
// ---------------------------------------------------------------------------

#[test]
fn test_map_claims_required_failure_is_an_error() {
    let flow = test_flow();
    let err = eval(&flow, "flow.metadata.absent").unwrap_err();
    match err {
        ClaimMapperError::Evaluate { claim, expression, .. } => {
            assert_eq!(claim, "result");
            assert_eq!(expression, "flow.metadata.absent");
        }
        other => panic!("expected an Evaluate error, got {other:?}"),
    }
}

#[test]
fn test_map_claims_optional_failure_is_skipped_and_others_survive() {
    let mapper = CelClaimMapper::new();
    let claims = mapper
        .map_claims(
            &[
                optional_mapping("flow.metadata.absent", "skipped"),
                mapping("flow.agreementId", "kept"),
            ],
            &test_flow(),
        )
        .unwrap();

    assert!(!claims.contains_key("skipped"));
    assert_eq!(claims.get("kept"), Some(&json!("agreement-1")));
}

#[test]
fn test_map_claims_optional_null_is_skipped() {
    let mapper = CelClaimMapper::new();
    let claims = mapper
        .map_claims(&[optional_mapping("null", "nothing")], &test_flow())
        .unwrap();
    assert!(!claims.contains_key("nothing"));
}

#[test]
fn test_map_claims_required_null_is_bound_as_json_null() {
    // A null result is not a failure: only errors hard-fail. A required mapping binds the null.
    let mapper = CelClaimMapper::new();
    let claims = mapper.map_claims(&[mapping("null", "explicit")], &test_flow()).unwrap();
    assert_eq!(claims.get("explicit"), Some(&Value::Null));
}

#[test]
fn test_map_claims_optional_compile_failure_is_skipped() {
    let mapper = CelClaimMapper::new();
    let claims = mapper
        .map_claims(
            &[optional_mapping("flow.", "broken"), mapping("'ok'", "fine")],
            &test_flow(),
        )
        .unwrap();
    assert!(!claims.contains_key("broken"));
    assert_eq!(claims.get("fine"), Some(&json!("ok")));
}

#[test]
fn test_map_claims_required_compile_failure_is_an_error() {
    let mapper = CelClaimMapper::new();
    let err = mapper
        .map_claims(&[mapping("flow.", "broken")], &test_flow())
        .unwrap_err();
    assert!(matches!(err, ClaimMapperError::Compile { .. }));
}

// ---------------------------------------------------------------------------
// Caching and validation
// ---------------------------------------------------------------------------

#[test]
fn test_repeated_evaluation_of_the_same_expression_is_consistent() {
    let mapper = CelClaimMapper::new();
    let flow = test_flow();
    let first = mapper.map_claims(&[mapping("flow.datasetId", "d")], &flow).unwrap();
    let second = mapper.map_claims(&[mapping("flow.datasetId", "d")], &flow).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.get("d"), Some(&json!("dataset-1")));
}

#[test]
fn test_dialect_is_cel() {
    assert_eq!(CelClaimMapper::new().dialect(), "cel");
}

#[test]
fn test_validate_expression_accepts_valid_and_rejects_invalid() {
    assert!(validate_expression("flow.agreementId").is_ok());
    assert!(validate_expression("'literal'").is_ok());

    let err = validate_expression("flow.").unwrap_err();
    match err {
        ClaimMapperError::Compile { expression, .. } => assert_eq!(expression, "flow."),
        other => panic!("expected a Compile error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// merge_claim_mappings
// ---------------------------------------------------------------------------

#[test]
fn test_merge_returns_root_when_no_endpoint_mappings() {
    let root = vec![mapping("flow.profile", "profile")];
    assert_eq!(merge_claim_mappings(&root, None), root);
    assert_eq!(merge_claim_mappings(&root, Some(&[])), root);
}

#[test]
fn test_merge_returns_endpoint_when_root_is_empty() {
    let endpoint = vec![mapping("'us-east-1'", "zone")];
    assert_eq!(merge_claim_mappings(&[], Some(&endpoint)), endpoint);
}

#[test]
fn test_merge_endpoint_overrides_root_in_place() {
    let root = vec![mapping("flow.profile", "profile"), mapping("'eu'", "zone")];
    let endpoint = vec![mapping("'us-east-1'", "zone")];

    let merged = merge_claim_mappings(&root, Some(&endpoint));

    // The overriding entry keeps the root's position, so evaluation order stays stable.
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].to, "profile");
    assert_eq!(merged[1].to, "zone");
    assert_eq!(merged[1].from, "'us-east-1'");
}

#[test]
fn test_merge_appends_new_endpoint_keys() {
    let root = vec![mapping("flow.profile", "profile")];
    let endpoint = vec![mapping("'extra'", "added")];

    let merged = merge_claim_mappings(&root, Some(&endpoint));
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].to, "profile");
    assert_eq!(merged[1].to, "added");
}

#[test]
fn test_merge_of_two_empty_lists_is_empty() {
    assert!(merge_claim_mappings(&[], None).is_empty());
    assert!(merge_claim_mappings(&[], Some(&[])).is_empty());
}

// ---------------------------------------------------------------------------
// Serde
// ---------------------------------------------------------------------------

#[test]
fn test_claim_mapping_serializes_camel_case_and_defaults_optional() {
    let parsed: ClaimMapping = serde_json::from_str(r#"{"from":"flow.datasetId","to":"assetId"}"#).unwrap();
    assert_eq!(parsed.from, "flow.datasetId");
    assert_eq!(parsed.to, "assetId");
    assert!(!parsed.optional, "optional should default to false");

    let round_tripped: ClaimMapping = serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(round_tripped, parsed);
}
