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

//! Tests for SigningKeyRecord serialization

use crate::jwt::jwtutils::SigningKeyRecord;
use crate::jwt::KeyFormat;

#[test]
fn test_signing_key_record_serialization() {
    // Create a SigningKeyRecord
    let record = SigningKeyRecord::builder()
        .private_key("test-private-key-content")
        .kid("did:web:example.com#key-123")
        .key_format(KeyFormat::PEM)
        .build();

    // Serialize to JSON
    let json = serde_json::to_string(&record).expect("Failed to serialize");

    // Verify JSON contains expected fields
    assert!(json.contains("private_key"));
    assert!(json.contains("test-private-key-content"));
    assert!(json.contains("kid"));
    assert!(json.contains("did:web:example.com#key-123"));
    assert!(json.contains("key_format"));
    assert!(json.contains("PEM"));

    // Deserialize back
    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify fields match
    assert_eq!(deserialized.private_key, "test-private-key-content");
    assert_eq!(deserialized.kid, "did:web:example.com#key-123");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_round_trip() {
    // Test with a real-looking PEM key
    let pem_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n-----END PRIVATE KEY-----";

    let original = SigningKeyRecord::builder()
        .private_key(pem_key)
        .kid("did:web:example.org#signing-key-1")
        .key_format(KeyFormat::DER)
        .build();

    // Serialize and deserialize
    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let roundtrip: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify exact match
    assert_eq!(original.private_key, roundtrip.private_key);
    assert_eq!(original.kid, roundtrip.kid);
    assert_eq!(original.key_format, roundtrip.key_format);
}

#[test]
fn test_signing_key_record_pretty_json() {
    let record = SigningKeyRecord::builder()
        .private_key("my-private-key")
        .kid("my-kid")
        .key_format(KeyFormat::PEM)
        .build();

    // Test pretty JSON formatting
    let pretty_json = serde_json::to_string_pretty(&record).expect("Failed to serialize");

    // Should be multi-line
    assert!(pretty_json.contains('\n'));

    // Should deserialize correctly
    let deserialized: SigningKeyRecord = serde_json::from_str(&pretty_json).expect("Failed to deserialize");
    assert_eq!(deserialized.private_key, "my-private-key");
    assert_eq!(deserialized.kid, "my-kid");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_default_key_format() {
    // Test that key_format defaults to PEM when not specified
    let record = SigningKeyRecord::builder()
        .private_key("test-key")
        .kid("test-kid")
        .build();

    assert_eq!(record.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_with_der_format() {
    // Test with DER format
    let record = SigningKeyRecord::builder()
        .private_key("der-key-content")
        .kid("did:web:test.com#key-der")
        .key_format(KeyFormat::DER)
        .build();

    let json = serde_json::to_string(&record).expect("Failed to serialize");
    assert!(json.contains("DER"));

    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.key_format, KeyFormat::DER);
    assert_eq!(deserialized.private_key, "der-key-content");
}
