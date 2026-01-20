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

//! S3 Operation Parser implementations
//!
//! This module provides parsers that map HTTP requests to S3 IAM actions
//! following AWS S3's operation model.

use super::S3OperationParser;
use crate::auth::Operation;
use pingora_core::Result;
use pingora_http::RequestHeader;
use url::Url;

use super::internal_error;

/// Default S3 operation parser that maps HTTP methods and query parameters to S3 IAM actions.
///
/// This parser follows AWS S3's operation model where the action is determined by:
/// - HTTP Method (GET, PUT, POST, DELETE, HEAD)
/// - Query parameters (e.g., `?acl`, `?tagging`, `?list-type=2`)
/// - Request path (bucket-only vs. bucket+key)
///
/// # Examples
///
/// - `GET /bucket/key` → `s3:GetObject`
/// - `GET /bucket/key?acl` → `s3:GetObjectAcl`
/// - `GET /bucket?list-type=2` → `s3:ListBucket`
/// - `PUT /bucket/key` → `s3:PutObject`
/// - `DELETE /bucket/key` → `s3:DeleteObject`
pub struct DefaultS3OperationParser;

impl DefaultS3OperationParser {
    pub fn new() -> Self {
        Self
    }

    /// Determines if the request is a bucket-level operation based on query parameters
    fn is_bucket_operation(query_pairs: &[(String, String)]) -> bool {
        query_pairs.iter().any(|(key, _)| {
            matches!(
                key.as_str(),
                "list-type" | "versions" | "delete" | "uploads" | "location"
            )
        })
    }

    /// Parses the S3 action from HTTP method and query parameters
    fn parse_action(method: &str, query_pairs: &[(String, String)], is_bucket_op: bool) -> String {
        // Check for query parameter-based operations first
        for (key, _value) in query_pairs {
            match (method, key.as_str()) {
                // Object-level operations with query parameters
                ("GET", "acl") => return "s3:GetObjectAcl".to_string(),
                ("GET", "tagging") => return "s3:GetObjectTagging".to_string(),
                ("GET", "torrent") => return "s3:GetObjectTorrent".to_string(),
                ("GET", "legal-hold") => return "s3:GetObjectLegalHold".to_string(),
                ("GET", "retention") => return "s3:GetObjectRetention".to_string(),
                ("GET", "versionId") => return "s3:GetObjectVersion".to_string(),
                ("PUT", "acl") => return "s3:PutObjectAcl".to_string(),
                ("PUT", "tagging") => return "s3:PutObjectTagging".to_string(),
                ("PUT", "legal-hold") => return "s3:PutObjectLegalHold".to_string(),
                ("PUT", "retention") => return "s3:PutObjectRetention".to_string(),
                ("PUT", "restore") => return "s3:RestoreObject".to_string(),
                // Bucket-level operations
                ("GET", "list-type") => return "s3:ListBucket".to_string(),
                ("GET", "versions") => return "s3:ListBucketVersions".to_string(),
                ("GET", "uploads") => return "s3:ListBucketMultipartUploads".to_string(),
                ("GET", "location") => return "s3:GetBucketLocation".to_string(),
                ("POST", "delete") => return "s3:DeleteObject".to_string(),
                _ => {}
            }
        }

        // Default operations based on method alone
        match method {
            "GET" if is_bucket_op => "s3:ListBucket".to_string(),
            "GET" => "s3:GetObject".to_string(),
            "HEAD" => "s3:GetObject".to_string(), // HEAD uses same permission as GET
            "PUT" => "s3:PutObject".to_string(),
            "POST" => "s3:PutObject".to_string(), // Form-based upload
            "DELETE" => "s3:DeleteObject".to_string(),
            _ => format!("s3:{}Object", method.to_lowercase()), // Fallback
        }
    }
}

impl S3OperationParser for DefaultS3OperationParser {
    fn parse_operation(&self, scope: &str, request: &RequestHeader) -> Result<Operation> {
        let method = request.method.as_str();
        let uri = request.uri.to_string();

        // Parse URL to extract query parameters
        let url = if uri.starts_with("http://") || uri.starts_with("https://") {
            Url::parse(&uri)
                .map_err(|e| internal_error(format!("Failed to parse operation URI '{}' (method={}): {}", uri, method, e)))?
        } else {
            Url::parse(&format!("http://dummy{}", uri))
                .map_err(|e| internal_error(format!("Failed to parse relative URI '{}' (method={}): {}", uri, method, e)))?
        };

        // Collect query parameters
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        // Determine if this is a bucket-level operation
        let is_bucket_op = Self::is_bucket_operation(&query_pairs);

        // Parse the action
        let action = Self::parse_action(method, &query_pairs, is_bucket_op);

        // Extract resource (the path)
        let resource = url.path().to_string();

        Ok(Operation::builder()
            .scope(scope)
            .action(action)
            .resource(resource)
            .build())
    }
}
