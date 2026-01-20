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

use facet_common::auth::{AuthorizationError, AuthorizationEvaluator, Operation};
use facet_common::context::ParticipantContext;
use facet_common::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use facet_common::proxy::s3::{S3CredentialResolver, S3Credentials, S3OperationParser};
use pingora_core::Result;
use pingora_http::RequestHeader;
use serde_json::{Map, Value};

// ============================================================================
// Passing Mock Implementations
// ============================================================================

/// Passthrough credential resolver with configurable credentials
pub struct PassthroughCredentialsResolver {
    pub credentials: S3Credentials,
}

impl S3CredentialResolver for PassthroughCredentialsResolver {
    fn resolve_credentials(&self, _context: &ParticipantContext) -> Result<S3Credentials> {
        Ok(self.credentials.clone())
    }
}

/// Always-permissive authorization evaluator (allows all operations)
pub struct PermissiveAuthEvaluator;

#[async_trait::async_trait]
impl AuthorizationEvaluator for PermissiveAuthEvaluator {
    async fn evaluate(
        &self,
        _participant_context: &ParticipantContext,
        _operation: Operation,
    ) -> std::result::Result<bool, AuthorizationError> {
        Ok(true)
    }
}

/// Default operation parser (simple implementation)
pub struct DefaultOperationParser;

impl S3OperationParser for DefaultOperationParser {
    fn parse_operation(&self, scope: &str, request: &RequestHeader) -> Result<Operation> {
        Ok(Operation::builder()
            .scope(scope)
            .action(format!("s3:{}", request.method.as_str()))
            .resource(request.uri.path())
            .build())
    }
}

/// Test JWT verifier that accepts any token with a configurable scope
pub struct TestJwtVerifier {
    pub scope: String,
}

impl JwtVerifier for TestJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        _token: &str,
    ) -> std::result::Result<TokenClaims, JwtVerificationError> {
        let mut custom = Map::new();
        custom.insert("scope".to_string(), Value::String(self.scope.clone()));
        Ok(TokenClaims {
            sub: "test-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: "s3-proxy".to_string(),
            iat: 0,
            exp: 9999999999,
            nbf: None,
            custom,
        })
    }
}

/// Mock JWT verifier that validates against a specific token string
pub struct TokenMatchingJwtVerifier {
    pub valid_token: String,
    pub scope: String,
}

impl JwtVerifier for TokenMatchingJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        token: &str,
    ) -> std::result::Result<TokenClaims, JwtVerificationError> {
        let mut custom = Map::new();
        custom.insert("scope".to_string(), Value::String(self.scope.clone()));

        if token == self.valid_token {
            Ok(TokenClaims {
                sub: "test-user".to_string(),
                iss: "test-issuer".to_string(),
                aud: "s3-proxy".to_string(),
                iat: 0,
                exp: 9999999999,
                nbf: None,
                custom,
            })
        } else {
            Err(JwtVerificationError::InvalidSignature)
        }
    }
}

// ============================================================================
// Failing Mock Implementations (for error testing)
// ============================================================================

/// Credential resolver that fails with a detailed internal error message
pub struct FailingCredentialResolver {
    pub internal_detail: String,
}

impl S3CredentialResolver for FailingCredentialResolver {
    fn resolve_credentials(&self, _context: &ParticipantContext) -> Result<S3Credentials> {
        Err(facet_common::proxy::s3::internal_error(format!(
            "Database connection to {} failed: timeout after 30s, last error: connection refused",
            self.internal_detail
        )))
    }
}

/// Authorization evaluator that fails with a detailed internal error
pub struct FailingAuthEvaluator {
    pub internal_detail: String,
}

#[async_trait::async_trait]
impl AuthorizationEvaluator for FailingAuthEvaluator {
    async fn evaluate(
        &self,
        _participant_context: &ParticipantContext,
        _operation: Operation,
    ) -> std::result::Result<bool, AuthorizationError> {
        Err(AuthorizationError::InternalError(format!(
            "Policy engine at {} unreachable: connection refused (exit code 111)",
            self.internal_detail
        )))
    }
}

/// Operation parser that fails with a detailed internal error
pub struct FailingOperationParser {
    pub internal_detail: String,
}

impl S3OperationParser for FailingOperationParser {
    fn parse_operation(&self, _scope: &str, _request: &RequestHeader) -> Result<Operation> {
        Err(facet_common::proxy::s3::internal_error(format!(
            "Parser cache corrupted at {}, memory address 0x7fff5fbff000, stack trace: [parser.rs:123]",
            self.internal_detail
        )))
    }
}

/// Credential resolver that returns suspicious/internal credential values
pub struct SuspiciousCredentialResolver;

impl S3CredentialResolver for SuspiciousCredentialResolver {
    fn resolve_credentials(&self, _context: &ParticipantContext) -> Result<S3Credentials> {
        Ok(S3Credentials {
            access_key_id: "AKIA_INTERNAL_USE_ONLY".to_string(),
            secret_key: "secret_key_prod_abc123def456".to_string(),
            region: "us-east-1-internal-vpc-endpoint".to_string(),
        })
    }
}

/// JWT verifier that fails with a detailed internal error message
pub struct DetailedFailureJwtVerifier {
    pub internal_detail: String,
}

impl JwtVerifier for DetailedFailureJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        _token: &str,
    ) -> std::result::Result<TokenClaims, JwtVerificationError> {
        Err(JwtVerificationError::VerificationFailed(format!(
            "Key server at {} returned 500: Internal Server Error, correlation-id: {}, trace-id: xyz-789",
            self.internal_detail, "req-abc-123-def"
        )))
    }
}