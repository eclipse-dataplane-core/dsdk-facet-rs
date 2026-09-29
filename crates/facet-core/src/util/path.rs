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

//! Validation for identifiers that end up as segments of a storage path or URL.
//!
//! Participant context ids, token identifiers (flow ids) and Vault key names are interpolated into
//! Vault paths such as `/v1/secret/data/{participant_context_id}/{identifier}`. An identifier that
//! carries `/`, `..` or a percent-escape could therefore address another participant context's
//! secrets, so every such value must pass [`validate_path_segment`] before it is used.

use thiserror::Error;

/// Upper bound on a path segment's length, generous for UUIDs, DIDs and URNs.
pub const MAX_PATH_SEGMENT_LEN: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid identifier '{value}': {reason}")]
pub struct InvalidPathSegment {
    pub value: String,
    pub reason: &'static str,
}

/// Checks that `value` is safe to use as a single path segment.
///
/// Accepts non-empty values of at most [`MAX_PATH_SEGMENT_LEN`] characters drawn from
/// `[A-Za-z0-9._:@~-]`, except `.` and `..`. Everything else is rejected — notably `/` and `\`
/// (segment separators), `%` (an escape the server on the other end may decode into a separator),
/// `?` and `#` (they end the path), whitespace and control characters.
pub fn validate_path_segment(value: &str) -> Result<(), InvalidPathSegment> {
    let invalid = |reason| {
        Err(InvalidPathSegment {
            value: value.chars().take(MAX_PATH_SEGMENT_LEN).collect(),
            reason,
        })
    };
    if value.is_empty() {
        return invalid("must not be empty");
    }
    if value.len() > MAX_PATH_SEGMENT_LEN {
        return invalid("too long");
    }
    if value == "." || value == ".." {
        return invalid("must not be a relative path segment");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '@' | '~' | '-'))
    {
        return invalid("contains a character outside [A-Za-z0-9._:@~-]");
    }
    Ok(())
}

/// Checks every `/`-separated segment of `path` with [`validate_path_segment`], for values that are
/// legitimately multi-segment (e.g. an operator-configured `subpath/identifier`).
pub fn validate_path(path: &str) -> Result<(), InvalidPathSegment> {
    path.split('/').try_for_each(validate_path_segment)
}
