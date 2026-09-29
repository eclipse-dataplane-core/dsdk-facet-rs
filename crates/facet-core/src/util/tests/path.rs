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

use crate::util::path::{validate_path, validate_path_segment};

#[test]
fn accepts_typical_identifiers() {
    for value in [
        "flow-1",
        "3f1c2b7e-8a9d-4c1e-9f00-1234567890ab",
        "did:web:provider.example.com",
        "urn:connector:provider",
        "participant_A.v2~x@y",
    ] {
        assert!(validate_path_segment(value).is_ok(), "{value}");
    }
}

#[test]
fn rejects_traversal_and_separators() {
    for value in [
        "",
        ".",
        "..",
        "../other/flow",
        "a/b",
        "a\\b",
        "..%2Fother",
        "flow?x=1",
        "flow#frag",
        "flow id",
        "flow\n",
        "flöw",
    ] {
        assert!(validate_path_segment(value).is_err(), "{value:?}");
    }
}

#[test]
fn rejects_overlong_segment() {
    assert!(validate_path_segment(&"a".repeat(256)).is_ok());
    assert!(validate_path_segment(&"a".repeat(257)).is_err());
}

#[test]
fn validate_path_checks_every_segment() {
    assert!(validate_path("tokens/flow-1").is_ok());
    assert!(validate_path("tokens/../flow-1").is_err());
    assert!(validate_path("tokens//flow-1").is_err());
    assert!(validate_path("/flow-1").is_err());
}
