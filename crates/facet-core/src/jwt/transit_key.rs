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

//! Resolves the Vault transit key (and optional `kid`) used to sign a participant context's
//! proof JWTs.
//!
//! [`VaultJwtGenerator`] delegates key selection to a [`TransitKeyResolver`] so the same
//! generator can serve two scenarios:
//! - [`PrefixTransitKeyResolver`] — siglet access-token minting / pull: the key name is derived
//!   from a static prefix and the participant context id, and the `kid` is derived from the
//!   Vault key version (`kid: None`).
//! - [`MappingTransitKeyResolver`] — consumer-side token renewal: the key name and `kid` come
//!   from a per-participant-context database mapping ([`SigningKeyMapping`]).
//!
//! [`VaultJwtGenerator`]: crate::jwt::VaultJwtGenerator

use crate::context::ParticipantContext;
use crate::jwt::JwtGenerationError;
use crate::jwt::mapping::{SigningKeyMappingError, SigningKeyMappingRepository};
use async_trait::async_trait;
use bon::Builder;
use std::sync::Arc;

/// The transit key a JWT should be signed with, plus the `kid` to advertise in the header.
///
/// When `kid` is `None`, the generator derives it from the Vault key metadata (`{key_name}-{version}`).
/// When `Some`, the value is used verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitKeyRef {
    pub key_name: String,
    pub kid: Option<String>,
}

/// Resolves the transit key reference for a participant context.
#[async_trait]
pub trait TransitKeyResolver: Send + Sync {
    async fn resolve(&self, participant_context: &ParticipantContext) -> Result<TransitKeyRef, JwtGenerationError>;
}

/// Derives the transit key name as `{prefix}-{pc.id}` and leaves the `kid` to be derived from
/// the Vault key version. This preserves the historical behavior used for siglet access-token
/// minting and the pull scenario.
#[derive(Builder)]
pub struct PrefixTransitKeyResolver {
    #[builder(into)]
    prefix: String,
}

#[async_trait]
impl TransitKeyResolver for PrefixTransitKeyResolver {
    async fn resolve(&self, participant_context: &ParticipantContext) -> Result<TransitKeyRef, JwtGenerationError> {
        Ok(TransitKeyRef {
            key_name: format!("{}-{}", self.prefix, participant_context.id),
            kid: None,
        })
    }
}

/// Resolves the transit key name and `kid` from a per-participant-context database mapping.
///
/// Used by the consumer-side token renewal flow. A missing mapping is a hard error
/// ([`JwtGenerationError::KeyResolution`]); the operator must configure the mapping via the
/// management API before renewal can mint a proof JWT.
#[derive(Builder)]
pub struct MappingTransitKeyResolver {
    repo: Arc<dyn SigningKeyMappingRepository>,
}

#[async_trait]
impl TransitKeyResolver for MappingTransitKeyResolver {
    async fn resolve(&self, participant_context: &ParticipantContext) -> Result<TransitKeyRef, JwtGenerationError> {
        match self.repo.find(&participant_context.id).await {
            Ok(mapping) => Ok(TransitKeyRef {
                key_name: mapping.key_name,
                kid: Some(mapping.kid),
            }),
            Err(SigningKeyMappingError::NotFound { .. }) => Err(JwtGenerationError::KeyResolution(format!(
                "no signing key mapping for participant context '{}'",
                participant_context.id
            ))),
            Err(e) => Err(JwtGenerationError::GenerationError(format!(
                "failed to resolve signing key mapping for participant context '{}': {}",
                participant_context.id, e
            ))),
        }
    }
}
