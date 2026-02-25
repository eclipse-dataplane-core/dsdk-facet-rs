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

use crate::context::ParticipantContext;
use crate::jwt::{KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use crate::test_fixtures::{StaticSigningKeyResolver, StaticVerificationKeyResolver};
use crate::vault::{KeyMetadata, PublicKeyFormat, VaultError, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use std::sync::Arc;

/// Helper function to create a JWT generator for testing
pub fn create_test_generator(
    private_key: Vec<u8>,
    iss: &str,
    kid: &str,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
) -> LocalJwtGenerator {
    let signing_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(private_key)
            .iss(iss)
            .kid(kid)
            .key_format(key_format)
            .build(),
    );

    LocalJwtGenerator::builder()
        .signing_key_resolver(signing_resolver)
        .signing_algorithm(signing_algorithm)
        .build()
}

/// Helper function to create a JWT verifier for testing
pub fn create_test_verifier(
    public_key: Vec<u8>,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
) -> LocalJwtVerifier {
    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(public_key)
            .key_format(key_format)
            .build(),
    );

    LocalJwtVerifier::builder()
        .verification_key_resolver(verification_resolver)
        .signing_algorithm(signing_algorithm)
        .build()
}

/// Helper function to create a JWT verifier with leeway for testing
pub fn create_test_verifier_with_leeway(
    public_key: Vec<u8>,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
    leeway_seconds: u64,
) -> LocalJwtVerifier {
    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(public_key)
            .key_format(key_format)
            .build(),
    );

    LocalJwtVerifier::builder()
        .verification_key_resolver(verification_resolver)
        .signing_algorithm(signing_algorithm)
        .leeway_seconds(leeway_seconds)
        .build()
}

/// Simple mock VaultSigningClient that returns canned values
pub struct MockVaultSigningClient {
    pub key_name: String,
    pub current_version: usize,
    pub signature_bytes: Vec<u8>,
}

impl MockVaultSigningClient {
    pub fn new(key_name: &str) -> Self {
        // Create a simple mock Ed25519 signature (raw bytes)
        // Ed25519 signatures are 64 bytes
        let mock_signature_bytes = vec![0u8; 64];

        Self {
            key_name: key_name.to_string(),
            current_version: 1,
            signature_bytes: mock_signature_bytes,
        }
    }
}

#[async_trait]
impl VaultSigningClient for MockVaultSigningClient {
    async fn get_key_metadata(
        &self,
        _participant_context: &ParticipantContext,
        format: PublicKeyFormat,
    ) -> Result<KeyMetadata, VaultError> {
        // Generate a mock Ed25519 public key (32 bytes)
        // Using a deterministic value for testing consistency
        let mock_ed25519_pubkey = [
            0x1d, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50,
            0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
        ];

        let key = match format {
            PublicKeyFormat::Multibase => {
                // Encode as multibase: multicodec prefix (0xed01) + key, then base58btc with 'z' prefix
                let mut prefixed = vec![0xed, 0x01];
                prefixed.extend_from_slice(&mock_ed25519_pubkey);
                format!("z{}", bs58::encode(&prefixed).into_string())
            }
            PublicKeyFormat::Base64Url => {
                // Encode raw Ed25519 key (32 bytes) as base64url
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mock_ed25519_pubkey)
            }
        };

        Ok(KeyMetadata {
            key_name: self.key_name.clone(),
            keys: vec![key],
            current_version: self.current_version,
        })
    }

    async fn sign_content(
        &self,
        _participant_context: &ParticipantContext,
        _content: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        Ok(self.signature_bytes.clone())
    }
}
