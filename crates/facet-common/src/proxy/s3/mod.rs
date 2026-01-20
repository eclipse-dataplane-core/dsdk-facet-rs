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

//! S3 Proxy implementation based on Pingora
//!
//! This module implements a reverse proxy for S3-compatible storage services.
//! It handles:
//! - Request parsing (path-style and virtual-hosted-style addressing)
//! - JWT token validation via `x-amz-security-token` header
//! - AWS SigV4 request signing for upstream
//! - Support for multiple upstream addressing styles
//!
//! # Architecture
//!
//! The proxy intercepts S3 requests, validates JWT tokens, and signs requests
//! with AWS credentials before forwarding to the upstream S3 service.
//!
//! ## Request Flow
//!
//! 1. **Parse incoming request**: Extract bucket and key from either:
//!    - Path-style: `/bucket/key` (e.g., `/my-bucket/path/to/file.txt`)
//!    - Virtual-hosted-style: `bucket.proxy.com/key`
//!    - **Note**: Parsing happens once in `upstream_peer` and is cached in the session context
//!
//! 2. **Validate JWT token**: Check `x-amz-security-token` header
//!
//! 3. **Sign request**: Generate AWS SigV4 signature using resolved credentials
//!
//! 4. **Forward to upstream**: Transform request for upstream S3 service based on:
//!    - `UpstreamStyle::PathStyle`: Send as `/bucket/key` to fixed endpoint
//!    - `UpstreamStyle::VirtualHosted`: Send as `/key` to `bucket.endpoint`
//!
//! # Examples
//!
//! ```ignore
//! use facet_common::proxy::s3::{S3Proxy, UpstreamStyle};
//!
//! let proxy = S3Proxy::builder()
//!     .use_tls(true)
//!     .upstream_endpoint("s3.amazonaws.com".to_string())
//!     .upstream_style(UpstreamStyle::VirtualHosted)
//!     .proxy_domain(Some("proxy.example.com".to_string()))
//!     .credential_resolver(Arc::new(my_credential_resolver))
//!     .participant_context_resolver(Arc::new(my_context_resolver))
//!     .build();
//! ```

pub mod opparser;

#[cfg(test)]
mod tests;

use crate::auth::{AuthorizationEvaluator, Operation};
use crate::context::ParticipantContext;
use crate::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use bon::Builder;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::SystemTime;

pub use opparser::DefaultS3OperationParser;

const SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";
const HOST: &str = "host";

/// Creates S3 resource expressions.
pub struct S3Resources {}

impl S3Resources {
    pub fn exact_match(file: &str) -> String {
        format!("^/{}$", file)
    }

    pub fn all_objects_in_bucket(bucket: &str) -> String {
        format!("^/{}/.*", bucket)
    }
}

/// S3 addressing style for upstream requests
#[derive(Clone, Debug, PartialEq)]
pub enum UpstreamStyle {
    /// Path-style: http://endpoint/bucket/key
    PathStyle,
    /// Virtual-hosted-style: http://bucket.endpoint/key
    VirtualHosted,
}

/// Parsed S3 request with bucket and key extracted
#[derive(Clone, Debug)]
pub struct ParsedS3Request {
    pub bucket: String,
    pub key: String, // Can be empty for bucket-level operations
}

/// Session context that caches parsed S3 request data to avoid duplicate parsing
#[derive(Clone, Debug)]
pub struct S3ProxyContext {
    /// Participant context for authorization
    pub participant_context: ParticipantContext,
    /// Cached parsed S3 request (bucket and key)
    pub parsed_request: Option<ParsedS3Request>,
}

/// Resolves credentials for a given participant context.
pub trait S3CredentialResolver: Sync + Send {
    fn resolve_credentials(&self, context: &ParticipantContext) -> Result<S3Credentials>;
}

/// Resolves the participant context for a given request URL.
pub trait ParticipantContextResolver: Sync + Send {
    fn resolve(&self, url: &str) -> Result<ParticipantContext>;
}

pub trait S3OperationParser: Sync + Send {
    fn parse_operation(&self, scope: &str, request: &RequestHeader) -> Result<Operation>;
}

#[derive(Clone)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_key: String,
    pub region: String,
}

#[derive(Builder)]
pub struct S3Proxy {
    use_tls: bool,
    #[builder(default = (if use_tls { 443u16 } else { 80u16 }))]
    default_port: u16,
    participant_context_resolver: Arc<dyn ParticipantContextResolver>,
    credential_resolver: Arc<dyn S3CredentialResolver>,
    #[builder(default =  Arc::new(NoOpJwtVerifier))]
    token_verifier: Arc<dyn JwtVerifier>,
    auth_evaluator: Arc<dyn AuthorizationEvaluator>,
    #[builder(default = Arc::new(DefaultS3OperationParser::new()))]
    operation_parser: Arc<dyn S3OperationParser>,
    upstream_endpoint: String, // S3 service endpoint
    /// How to format requests to the upstream S3 service
    #[builder(default = UpstreamStyle::PathStyle)]
    upstream_style: UpstreamStyle,
    /// Optional proxy domain for extracting bucket from virtual-hosted requests
    /// Example: "proxy.example.com" - strips this from "bucket.proxy.example.com"
    /// If None, assumes incoming path-style requests
    proxy_domain: Option<String>,
}

impl S3Proxy {
    /// Parse incoming request to extract bucket and key
    pub(crate) fn parse_incoming_request(&self, host: &str, path: &str) -> Result<ParsedS3Request> {
        // Try virtual-hosted-style first if proxy_domain is set
        if let Some(ref proxy_domain) = self.proxy_domain
            && let Some(bucket) = Self::extract_bucket_from_host(host, proxy_domain)
        {
            return Ok(ParsedS3Request {
                bucket,
                key: path.trim_start_matches('/').to_string(),
            });
        }

        // Try path-style: /bucket/key or /bucket
        if let Some(parsed) = Self::try_parse_path_style(path) {
            return Ok(parsed);
        }

        // Fallback error
        Err(client_error(400, format!("Invalid path format: {}", path)))
    }

    pub(crate) fn try_parse_path_style(path: &str) -> Option<ParsedS3Request> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return None;
        }

        let mut parts = path.splitn(2, '/');
        let bucket = parts.next()?.to_string();
        let key = parts.next().unwrap_or("").to_string();

        Some(ParsedS3Request { bucket, key })
    }

    pub(crate) fn extract_bucket_from_host(host: &str, proxy_domain: &str) -> Option<String> {
        // Remove port if present
        let host_without_port = host.split(':').next()?;

        // Check if host ends with .proxy_domain
        if let Some(bucket) = host_without_port.strip_suffix(&format!(".{}", proxy_domain))
            && !bucket.is_empty()
        {
            return Some(bucket.to_string());
        }

        // Check if host exactly matches proxy_domain (no bucket, root operations)
        if host_without_port == proxy_domain {
            return None; // No bucket in host
        }

        None
    }

    pub(crate) fn parse_endpoint(&self, endpoint: &str) -> Result<(String, u16)> {
        match endpoint.rsplit_once(':') {
            Some((hostname, port_str)) => {
                let port = port_str.parse::<u16>().map_err(|e| {
                    internal_error(format!("Invalid port '{}' in endpoint '{}': {}", port_str, endpoint, e))
                })?;
                Ok((hostname.to_string(), port))
            }
            None => Ok((endpoint.to_string(), self.default_port)),
        }
    }

    /// Extract host and path from the request header
    pub(crate) fn extract_request_components<'a>(&self, req_header: &'a RequestHeader) -> Result<(&'a str, &'a str)> {
        let path = req_header.uri.path();
        let host = req_header
            .headers
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| client_error(400, "Missing Host header"))?;
        Ok((host, path))
    }

    /// Build upstream host and port based on addressing style
    pub(crate) fn build_upstream_host(&self, parsed: &ParsedS3Request) -> Result<(String, u16)> {
        match &self.upstream_style {
            UpstreamStyle::PathStyle => {
                // Path-style: just use upstream_endpoint as-is
                self.parse_endpoint(&self.upstream_endpoint)
            }
            UpstreamStyle::VirtualHosted => {
                // Virtual-hosted-style: prepend bucket to upstream_endpoint
                let virtual_host = format!("{}.{}", parsed.bucket, self.upstream_endpoint);
                self.parse_endpoint(&virtual_host)
            }
        }
    }

    /// Build upstream URI and Host header based on addressing style
    pub(crate) fn build_upstream_uri_and_host(&self, parsed: &ParsedS3Request) -> (String, String) {
        match &self.upstream_style {
            UpstreamStyle::PathStyle => {
                // Path-style: /bucket/key
                let uri = if parsed.key.is_empty() {
                    format!("/{}", parsed.bucket)
                } else {
                    format!("/{}/{}", parsed.bucket, parsed.key)
                };
                (uri, self.upstream_endpoint.to_string())
            }
            UpstreamStyle::VirtualHosted => {
                // Virtual-hosted-style: /key with bucket.endpoint as Host
                let uri = format!("/{}", parsed.key);
                let host = format!("{}.{}", parsed.bucket, self.upstream_endpoint);
                (uri, host)
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for S3Proxy {
    type CTX = S3ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        S3ProxyContext {
            participant_context: ParticipantContext {
                identifier: "anonymous".to_string(),
                audience: "anonymous".to_string(),
            },
            parsed_request: None,
        }
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let req_header = session.req_header();
        let (host, path) = self.extract_request_components(req_header)?;

        // Resolve participant context
        ctx.participant_context = self.participant_context_resolver.resolve(path)?;

        // Parse incoming request to extract bucket and key (PARSE ONCE)
        let parsed = self.parse_incoming_request(host, path)?;

        // Construct upstream peer based on style
        let (upstream_host, port) = self.build_upstream_host(&parsed)?;

        // Cache parsed request for later use in upstream_request_filter
        ctx.parsed_request = Some(parsed);

        let addr = format!("{}:{}", upstream_host, port);
        let peer = Box::new(HttpPeer::new(addr.as_str(), self.use_tls, upstream_host.clone()));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Retrieve cached parsed request (already parsed in upstream_peer)
        let parsed = ctx
            .parsed_request
            .as_ref()
            .ok_or_else(|| internal_error("BUG: Parsed request not cached in context (programming error)"))?;

        // Reconstruct URI and Host based on upstream_style
        let (new_uri, new_host) = self.build_upstream_uri_and_host(parsed);

        // Update the request URI
        let uri: http::Uri = new_uri
            .parse()
            .map_err(|e| internal_error(format!("Failed to parse URI: {}", e)))?;
        upstream_request.set_uri(uri);

        // Update Host header
        upstream_request.remove_header(HOST);
        upstream_request
            .insert_header(HOST, new_host.as_str())
            .map_err(|e| internal_error(format!("Failed to insert host header: {}", e)))?;

        // Extract x-amz-security-token header and validate the token
        let token = session
            .req_header()
            .headers
            .get(SECURITY_TOKEN_HEADER)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| client_error(400, "Missing x-amz-security-token header"))?;

        // Verify token (remove from request if valid)
        let claims = self
            .token_verifier
            .verify_token(&ctx.participant_context, token)
            .map_err(|e| client_error_because(403, "JWT token verification failed", e))?;

        let scope = claims
            .custom
            .get("scope")
            .and_then(|v| v.as_str())
            .ok_or_else(|| client_error(403, "Missing scope in token claims"))?
            .to_string();

        // Parse operation from request
        let req_header = session.req_header();
        let operation = self.operation_parser.parse_operation(&scope, req_header)?;

        let is_authorized = self
            .auth_evaluator
            .evaluate(&ctx.participant_context, operation)
            .await
            .map_err(|e| {
                internal_error(format!(
                    "Authorization evaluation failed for participant {}: {}",
                    ctx.participant_context.identifier, e
                ))
            })?;

        if !is_authorized {
            return Err(client_error(403, "Unauthorized operation"));
        }

        upstream_request.remove_header(SECURITY_TOKEN_HEADER);

        // Extract request components for signing (use new URI and Host)
        let method = upstream_request.method.as_str();
        let uri = upstream_request.uri.to_string();

        // Build signing params
        let creds = self
            .credential_resolver
            .resolve_credentials(&ctx.participant_context)
            .map_err(|e| e.into_in())?; // Ensure the error is treated as an internal source

        let aws_creds = Credentials::new(&creds.access_key_id, &creds.secret_key, None, None, "facet-proxy");

        let identity: Identity = aws_creds.into();

        // Create signing settings
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = aws_sigv4::http_request::PayloadChecksumKind::XAmzSha256;

        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&creds.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|e| {
                internal_error(format!(
                    "Failed to build signing params for region '{}': {}",
                    creds.region, e
                ))
            })?
            .into();

        // Convert Pingora RequestHeader to http::Request for signing
        let mut http_request = http::Request::builder().method(method).uri(&uri);

        // Copy headers (including the host header we set earlier)
        for (name, value) in &upstream_request.headers {
            http_request = http_request.header(name, value);
        }

        let http_request = http_request.body("").map_err(|e| {
            internal_error(format!(
                "Failed to build HTTP request for signing (method={}, uri={}): {}",
                method, uri, e
            ))
        })?;

        // Sign the request
        let headers_vec: Vec<(String, String)> = http_request
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v_str| (k.as_str().to_string(), v_str.to_string())))
            .collect();

        let signable_request = SignableRequest::new(
            http_request.method().as_str(),
            http_request.uri().to_string(),
            headers_vec.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            SignableBody::UnsignedPayload,
        )
        .map_err(|e| internal_error(format!("Failed to create signable request: {}", e)))?;

        let (signing_instructions, _) = sign(signable_request, &signing_params)
            .map_err(|e| internal_error(format!("Failed to sign request: {}", e)))?
            .into_parts();

        // Apply signing headers to upstream request
        let headers_to_add: Vec<(String, String)> = signing_instructions
            .headers()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        for (name, value) in headers_to_add {
            upstream_request
                .insert_header(name, value.as_bytes())
                .map_err(|e| internal_error(format!("Failed to insert signing header: {}", e)))?;
        }
        Ok(())
    }
}

/// Helper to create internal errors with explanation.
/// Internal errors are logged but never sent to clients, so detailed messages are encouraged.
/// Sets the error source to Internal.
#[inline]
pub fn internal_error(msg: impl Into<String>) -> Box<Error> {
    Error::explain(ErrorType::InternalError, msg.into()).into_in()
}

/// Helper to create client-facing HTTP status errors.
/// These become HTTP responses, so messages should be generic.
/// Sets the error source to Downstream.
#[inline]
pub(crate) fn client_error(status: u16, msg: impl Into<String>) -> Box<Error> {
    Error::explain(ErrorType::HTTPStatus(status), msg.into()).into_down()
}

/// Helper to create client-facing HTTP status errors that wrap an underlying cause.
/// Sets the error source to Downstream.
#[inline]
pub(crate) fn client_error_because<E: std::error::Error + Send + Sync + 'static>(
    status: u16,
    msg: impl Into<String>,
    cause: E,
) -> Box<Error> {
    Error::because(
        ErrorType::HTTPStatus(status),
        msg.into(),
        Box::new(cause) as Box<dyn std::error::Error + Send + Sync>,
    )
    .into_down()
}

/// Default no-op JWT verifier that accepts all tokens (for testing and pass-through mode)
struct NoOpJwtVerifier;

impl JwtVerifier for NoOpJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        _token: &str,
    ) -> Result<TokenClaims, JwtVerificationError> {
        let mut custom = Map::new();
        custom.insert("scope".to_string(), Value::String("test-scope".to_string()));
        Ok(TokenClaims {
            sub: "noop".to_string(),
            iss: "noop".to_string(),
            aud: "noop".to_string(),
            iat: 0,
            exp: 9999999999,
            nbf: None,
            custom,
        })
    }
}

pub struct StaticCredentialsResolver {
    pub credentials: S3Credentials,
}

impl S3CredentialResolver for StaticCredentialsResolver {
    fn resolve_credentials(&self, _context: &ParticipantContext) -> Result<S3Credentials> {
        Ok(self.credentials.clone())
    }
}

pub struct StaticParticipantContextResolver {
    pub participant_context: ParticipantContext,
}

impl ParticipantContextResolver for StaticParticipantContextResolver {
    fn resolve(&self, _url: &str) -> Result<ParticipantContext> {
        Ok(self.participant_context.clone())
    }
}
