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
use crate::jwt::transit_key::{TransitKeyRef, TransitKeyResolver};
use crate::jwt::{JwtGenerationError, JwtGenerator, KeyType, TokenClaims};
use crate::util::clock::{Clock, default_clock};
use crate::vault::{PublicKeyFormat, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use bon::Builder;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// JWT generator that delegates signing to a participant-context Vault transit key.
///
/// The transit key name and the header `kid` are supplied by a [`TransitKeyResolver`]: the
/// prefix resolver derives `{prefix}-{pc.id}` (kid from the Vault key version), while the
/// mapping resolver reads both from a per-PC database association. The provisioner is
/// responsible for creating the transit key and publishing the corresponding public key so
/// verifiers can resolve it.
///
/// The JWS `alg` follows the transit key's type (Ed25519 → EdDSA, ECDSA P-256 → ES256,
/// P-384 → ES384, RSA → RS256 by default), unless the resolver pins a compatible algorithm.
/// The key type is read from Vault and cached per key name for [`DEFAULT_KEY_TYPE_CACHE_TTL`]
/// (configurable via `key_type_cache_ttl`). A transit key's type cannot change in place, but a key
/// can be deleted and re-created under the same name with another type, so entries expire, expired
/// entries are swept, and an entry is evicted as soon as signing with it fails.
#[derive(Builder)]
pub struct VaultJwtGenerator {
    signing_client: Arc<dyn VaultSigningClient>,

    /// Resolves the transit key name and (optional) `kid` for a participant context.
    key_resolver: Arc<dyn TransitKeyResolver>,

    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,

    /// How long a transit key's type is cached before it is read from Vault again.
    #[builder(default = DEFAULT_KEY_TYPE_CACHE_TTL)]
    key_type_cache_ttl: TimeDelta,

    #[builder(skip)]
    key_types: RwLock<HashMap<String, CachedKeyType>>,
}

/// Default lifetime of a cached transit key type.
pub const DEFAULT_KEY_TYPE_CACHE_TTL: TimeDelta = TimeDelta::minutes(10);

#[derive(Clone, Copy)]
struct CachedKeyType {
    key_type: KeyType,
    expires_at: DateTime<Utc>,
}

impl VaultJwtGenerator {
    /// Returns the cached key type, unless it has expired.
    fn cached_key_type(&self, key_name: &str) -> Option<KeyType> {
        let now = self.clock.now();
        self.key_types
            .read()
            .ok()
            .and_then(|cache| cache.get(key_name).copied())
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.key_type)
    }

    /// Caches a key type and sweeps expired entries, so the cache only holds keys used within the
    /// last TTL instead of growing with every key name ever seen.
    fn cache_key_type(&self, key_name: &str, key_type: KeyType) {
        let now = self.clock.now();
        if let Ok(mut cache) = self.key_types.write() {
            cache.retain(|_, entry| entry.expires_at > now);
            cache.insert(
                key_name.to_string(),
                CachedKeyType {
                    key_type,
                    expires_at: now + self.key_type_cache_ttl,
                },
            );
        }
    }

    fn evict_key_type(&self, key_name: &str) {
        if let Ok(mut cache) = self.key_types.write() {
            cache.remove(key_name);
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_key_count(&self) -> usize {
        self.key_types.read().map(|cache| cache.len()).unwrap_or(0)
    }
}

#[async_trait]
impl JwtGenerator for VaultJwtGenerator {
    async fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        mut claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        let TransitKeyRef {
            key_name,
            kid,
            algorithm,
        } = self.key_resolver.resolve(participant_context).await?;

        // Metadata is needed to derive the kid from the current key version, and to learn the
        // key type the first time a key is used. Base64Url works for every key type (Multibase
        // is Ed25519-only), and the key bytes themselves are not needed here.
        let cached_key_type = self.cached_key_type(&key_name);
        let (kid, key_type) = match (kid, cached_key_type) {
            (Some(kid), Some(key_type)) => (kid, key_type),
            (kid, _) => {
                let metadata = self
                    .signing_client
                    .get_key_metadata(participant_context, &key_name, PublicKeyFormat::Base64Url)
                    .await?;
                self.cache_key_type(&key_name, metadata.key_type);
                let kid = kid.unwrap_or_else(|| format!("{}-{}", metadata.key_name, metadata.current_version));
                (kid, metadata.key_type)
            }
        };

        // An incompatible pinned algorithm may mean the cached type is stale (key re-created with
        // another type), so evict and let the next call re-read it.
        let algorithm = key_type.resolve_algorithm(algorithm).map_err(|e| {
            self.evict_key_type(&key_name);
            JwtGenerationError::KeyResolution(format!("transit key '{}': {}", key_name, e))
        })?;

        claims.iat = self.clock.now().timestamp();

        let payload_bytes = serde_json::to_vec(&claims)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize claims: {}", e)))?;

        let header = serde_json::json!({ "alg": algorithm.as_str(), "typ": "JWT", "kid": kid });
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| JwtGenerationError::GenerationError(format!("Failed to serialize header: {}", e)))?;

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_bytes);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // A signing failure may come from a stale key type (wrong Vault sign parameters), so evict
        // it; the next call re-reads the metadata. Costs at most one extra read on other failures.
        let signature_bytes = self
            .signing_client
            .sign_content(participant_context, &key_name, algorithm, signing_input.as_bytes())
            .await
            .inspect_err(|_| self.evict_key_type(&key_name))?;
        let signature_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

        Ok(format!("{}.{}", signing_input, signature_b64url))
    }
}
