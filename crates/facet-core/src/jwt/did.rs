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

use crate::jwt::{JwtVerificationError, KeyFormat, KeyMaterial, VerificationKeyResolver};
use async_trait::async_trait;
use bon::Builder;
use serde::Deserialize;
use serde_json::Value;

/// DID document structure for parsing verification methods.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DidDocument {
    pub(crate) verification_method: Option<Vec<VerificationMethod>>,
}

/// Verification method in a DID document.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerificationMethod {
    pub(crate) id: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub(crate) verification_type: String,
    #[allow(dead_code)]
    pub(crate) controller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_key_jwk: Option<Value>,
}

/// Resolves verification keys from DID Web documents.
///
/// This resolver fetches DID documents via HTTPS and extracts verification methods
/// following the W3C DID Core specification. It supports `did:web` identifiers and
/// can resolve keys encoded as `publicKeyMultibase` or `publicKeyJwk`.
///
/// # Example DID URL
/// ```text
/// did:web:example.com#key-1
/// ```
/// This resolves to `https://example.com/.well-known/did.json` and extracts
/// the verification method with id ending in `#key-1`.
#[derive(Builder)]
pub struct DidWebVerificationKeyResolver {
    #[builder(default)]
    http_client: reqwest::Client,

    /// Whether to use HTTPS (true) or HTTP (false). Defaults to HTTPS.
    #[builder(default = true)]
    use_https: bool,
}

impl DidWebVerificationKeyResolver {
    /// Converts a did:web identifier to an HTTP(S) URL.
    pub(crate) fn did_web_to_url(&self, did: &str) -> Result<String, JwtVerificationError> {
        // Remove "did:web:" prefix
        let method_specific_id = did
            .strip_prefix("did:web:")
            .ok_or_else(|| JwtVerificationError::VerificationFailed(format!("Invalid did:web format: {}", did)))?;

        // Split by colon to get domain and path segments
        let parts: Vec<&str> = method_specific_id.split(':').collect();
        if parts.is_empty() {
            return Err(JwtVerificationError::VerificationFailed(
                "Empty did:web identifier".to_string(),
            ));
        }

        // First part is the domain (may contain percent-encoded port)
        let domain = parts[0].replace("%3A", ":").replace("%3a", ":");

        // Build the URL with configured protocol
        let protocol = if self.use_https { "https" } else { "http" };
        let mut url = format!("{}://{}", protocol, domain);

        if parts.len() > 1 {
            // Has path segments
            for segment in &parts[1..] {
                url.push('/');
                url.push_str(segment);
            }
            url.push_str("/did.json");
        } else {
            // No path, use .well-known
            url.push_str("/.well-known/did.json");
        }

        Ok(url)
    }

    /// Fetches and parses a DID document from the given URL.
    pub(crate) async fn fetch_did_document(&self, url: &str) -> Result<DidDocument, JwtVerificationError> {
        let response =
            self.http_client.get(url).send().await.map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to fetch DID document: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(JwtVerificationError::VerificationFailed(format!(
                "DID document fetch returned status: {}",
                response.status()
            )));
        }

        response
            .json::<DidDocument>()
            .await
            .map_err(|e| JwtVerificationError::VerificationFailed(format!("Failed to parse DID document: {}", e)))
    }

    /// Extracts a verification method by ID from a DID document.
    pub(crate) fn find_verification_method<'a>(
        doc: &'a DidDocument,
        fragment: &str,
    ) -> Result<&'a VerificationMethod, JwtVerificationError> {
        let methods = doc.verification_method.as_ref().ok_or_else(|| {
            JwtVerificationError::VerificationFailed("DID document has no verification methods".to_string())
        })?;

        // Match by full ID or by fragment suffix
        methods
            .iter()
            .find(|vm| vm.id.ends_with(&format!("#{}", fragment)) || vm.id == fragment)
            .ok_or_else(|| {
                JwtVerificationError::VerificationFailed(format!("Verification method {} not found", fragment))
            })
    }

    /// Converts a verification method to key material.
    pub(crate) fn verification_method_to_key_material(
        vm: &VerificationMethod,
        kid: &str,
    ) -> Result<KeyMaterial, JwtVerificationError> {
        // Try publicKeyMultibase first (preferred for Ed25519)
        if let Some(multibase_key) = &vm.public_key_multibase {
            let key_bytes = crate::util::crypto::validate_multibase_ed25519(multibase_key).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to decode publicKeyMultibase: {}", e))
            })?;

            // jsonwebtoken v10's DecodingKey::from_ed_der expects the raw 32-byte Ed25519
            // public key, NOT a SubjectPublicKeyInfo DER wrapper. This matches how
            // StaticVerificationKeyResolver passes keys in unit tests.
            return Ok(KeyMaterial::builder()
                .key(key_bytes)
                .key_format(KeyFormat::DER)
                .kid(kid)
                .build());
        }

        // Try publicKeyJwk: serialize the JWK back to JSON bytes so the verifier
        // can hand them to jsonwebtoken::DecodingKey::from_jwk, which dispatches
        // on the JWK's own `kty` (OKP/RSA/EC).
        if let Some(jwk) = &vm.public_key_jwk {
            let jwk_bytes = serde_json::to_vec(jwk).map_err(|e| {
                JwtVerificationError::VerificationFailed(format!("Failed to serialize publicKeyJwk: {}", e))
            })?;
            return Ok(KeyMaterial::builder()
                .key(jwk_bytes)
                .key_format(KeyFormat::Jwk)
                .kid(kid)
                .build());
        }

        Err(JwtVerificationError::VerificationFailed(
            "No supported public key format found in verification method".to_string(),
        ))
    }
}

#[async_trait]
impl VerificationKeyResolver for DidWebVerificationKeyResolver {
    async fn resolve_key(&self, iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        // iss is the JWT issuer (DID of the signer); kid may be a full DID URL or fragment.
        // We construct the full DID URL from iss + kid to locate the verification method.
        let did_url = if kid.starts_with("did:") {
            kid.to_string()
        } else if kid.starts_with('#') {
            format!("{}{}", iss, kid)
        } else {
            format!("{}#{}", iss, kid)
        };

        // Parse the DID URL to extract base DID and fragment
        let (base_did, fragment) = if let Some(hash_pos) = did_url.find('#') {
            let (base, frag) = did_url.split_at(hash_pos);
            (base.to_string(), frag[1..].to_string()) // Skip the '#'
        } else {
            return Err(JwtVerificationError::VerificationFailed(
                "kid must include fragment identifier".to_string(),
            ));
        };

        // Convert did:web to HTTP(S) URL
        let url = self.did_web_to_url(&base_did)?;

        // Fetch the DID document
        let doc = self.fetch_did_document(&url).await?;

        // Find the verification method
        let vm = Self::find_verification_method(&doc, &fragment)?;

        // Convert to KeyMaterial
        Self::verification_method_to_key_material(vm, kid)
    }
}
