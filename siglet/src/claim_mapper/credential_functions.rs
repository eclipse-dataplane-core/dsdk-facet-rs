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
//! Credential-aware CEL functions that hide the array/scalar variance of the W3C Verifiable
//! Credential data model.
//!
//! `type` and `@context` may be a string or a list, and `credentialSubject` may be a single object
//! or an array of subjects. Navigating that by hand in raw CEL is verbose and error-prone — reading
//! `credentialSubject.holderIdentifier` when `credentialSubject` is an array fails with a cryptic
//! `Unexpected type: got 'string', want 'int|uint'`. These functions normalize the shape internally
//! so an operator can write, for example:
//!
//! ```text
//! flow.claims.vc.withType('MembershipCredential').claim('holderIdentifier')
//! ```
//!
//! The names and semantics mirror the Eclipse EDC `decentralized-claims-cel` extension, so
//! expressions are portable between the EDC control plane and siglet.
//!
//! Every function is **lenient**: a target that is not credential-shaped yields an empty list,
//! `null`, or `false` rather than an error. This is what keeps the pitfall hidden; a required
//! mapping that yields `null` binds a JSON `null`, consistent with the rest of the mapper.
//!
//! All functions are registered as methods and are meant to be called method-style
//! (`target.fn(args)`); `This` refers to the target, which may be a credential list or a single
//! credential object — both are accepted.

use cel::extractors::{Arguments, This};
use cel::objects::{Key, Map};
use cel::{Context, ExecutionError, Value};
use std::sync::Arc;

/// Property names that may carry a credential's type set, in lookup order (`@type` is the
/// JSON-LD form).
const TYPE_KEYS: [&str; 2] = ["type", "@type"];
/// Property name holding a credential's subject(s).
const SUBJECT_KEY: &str = "credentialSubject";

/// Every function returns `Ok`; the `Result` return only exists because it is the return type the
/// engine's `IntoResolveResult` is guaranteed to accept.
type FnResult = Result<Value, ExecutionError>;

fn as_map(value: &Value) -> Option<&Map> {
    match value {
        Value::Map(map) => Some(map),
        _ => None,
    }
}

/// Looks up a string key in a map value, returning `None` for non-maps or absent keys.
fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    as_map(value)?.get(&Key::from(key))
}

fn as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

fn is_present(value: &Value) -> bool {
    !matches!(value, Value::Null)
}

/// Normalizes the target into a list of credential objects: a list stays a list, a single
/// credential object becomes a one-element list, anything else is empty.
fn credentials(target: &Value) -> Vec<&Value> {
    match target {
        Value::List(list) => list.iter().collect(),
        Value::Map(_) => vec![target],
        _ => Vec::new(),
    }
}

/// Normalizes a credential's `credentialSubject` (object *or* array) into a list of subjects.
///
/// This is the core of the pitfall fix: callers never have to know whether the subject was serialized
/// as a single object or a set.
fn subjects(credential: &Value) -> Vec<&Value> {
    match field(credential, SUBJECT_KEY) {
        Some(Value::List(list)) => list.iter().collect(),
        Some(subject @ Value::Map(_)) => vec![subject],
        _ => Vec::new(),
    }
}

/// True when the credential's type set (`type`, falling back to `@type`) contains `wanted`. A scalar
/// `type` counts as a one-element set.
fn credential_has_type(credential: &Value, wanted: &str) -> bool {
    TYPE_KEYS.iter().any(|key| match field(credential, key) {
        Some(Value::String(s)) => s.as_str() == wanted,
        Some(Value::List(list)) => list.iter().filter_map(as_str).any(|t| t == wanted),
        _ => false,
    })
}

/// Resolves a dotted claim path (`degree.type`) against a subject, walking nested maps.
fn navigate<'a>(subject: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = subject;
    for segment in path.split('.') {
        current = field(current, segment)?;
    }
    Some(current)
}

/// Iterates the non-null values of subject claim `name` across every credential/subject, in order.
fn claim_values<'a>(target: &'a Value, name: &'a str) -> impl Iterator<Item = &'a Value> {
    credentials(target)
        .into_iter()
        .flat_map(subjects)
        .filter_map(move |subject| navigate(subject, name))
        .filter(|value| is_present(value))
}

/// `list.withType(t)` — the sublist of credentials whose type set contains `t`.
pub fn with_type(This(this): This<Value>, wanted: Arc<String>) -> FnResult {
    let matched: Vec<Value> = credentials(&this)
        .into_iter()
        .filter(|credential| credential_has_type(credential, wanted.as_str()))
        .cloned()
        .collect();
    Ok(Value::List(Arc::new(matched)))
}

/// `credential.hasType(t)` — whether the credential has type `t`. Meant for the single-credential
/// form inside a macro (`exists(c, c.hasType('MembershipCredential'))`), but a list target is also
/// accepted and treated as "any".
pub fn has_type(This(this): This<Value>, wanted: Arc<String>) -> FnResult {
    let matched = credentials(&this)
        .iter()
        .any(|credential| credential_has_type(credential, wanted.as_str()));
    Ok(Value::Bool(matched))
}

/// `list.hasCredential(t)` — whether any credential in the list has type `t`.
pub fn has_credential(This(this): This<Value>, wanted: Arc<String>) -> FnResult {
    has_type(This(this), wanted)
}

/// `list.hasClaim(name)` / `list.hasClaim(name, value)` — whether any subject carries claim `name`
/// (equal to `value`, when the second argument is given). The claim value must be non-null.
pub fn has_claim(This(this): This<Value>, Arguments(args): Arguments) -> FnResult {
    let Some(name) = args.first().and_then(as_str) else {
        return Ok(Value::Bool(false));
    };
    let expected = args.get(1);
    let found = claim_values(&this, name).any(|value| expected.is_none_or(|want| value == want));
    Ok(Value::Bool(found))
}

/// `list.claim(name)` — the first non-null value of subject claim `name`, or `null`. `name` may be a
/// dotted path (`degree.type`).
pub fn claim(This(this): This<Value>, name: Arc<String>) -> FnResult {
    Ok(claim_values(&this, name.as_str())
        .next()
        .cloned()
        .unwrap_or(Value::Null))
}

/// `list.claims(name)` — all non-null values of subject claim `name` across every credential/subject.
pub fn claims(This(this): This<Value>, name: Arc<String>) -> FnResult {
    let values: Vec<Value> = claim_values(&this, name.as_str()).cloned().collect();
    Ok(Value::List(Arc::new(values)))
}

/// Registers the credential helpers on `context` under their EDC-compatible names.
///
/// Called once per evaluation, after `Context::default()`. Functions resolve at execute-time, so
/// this never affects the compiled-program cache or expression validation.
pub(crate) fn register(context: &mut Context) {
    context.add_function("withType", with_type);
    context.add_function("hasType", has_type);
    context.add_function("hasCredential", has_credential);
    context.add_function("hasClaim", has_claim);
    context.add_function("claim", claim);
    context.add_function("claims", claims);
}
