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
use crate::jwt::keys::public_key_to_jwk;
use crate::jwt::{
    Jwk, JwkSet, JwkSetProvider, JwtVerificationError, KeyFamily, KeyFormat, KeyMaterial, KeyType, SigningAlgorithm,
    VerificationKeyResolver,
};
use crate::util::task::TaskHandle;
use crate::vault::{PublicKeyFormat, VaultSigningClient};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use log::error;
use std::collections::HashMap;
use std::sync;
use std::sync::Arc;
use std::time::Duration;
use sync::Mutex;
use tokio::sync::watch;

/// Inner state shared between the resolver and the background refresh task.
struct VaultKeyResolverState {
    pub(super) vault_client: Arc<dyn VaultSigningClient>,
    /// Participant context used to scope the Vault access token when loading the signing key.
    /// This resolver loads the issuer's own key, so it is the issuer's participant context.
    signing_context: ParticipantContext,
    /// Algorithm the issuer signs with. Advertised as the JWK `alg`; `None` means the key type's
    /// default (see [`KeyType::default_algorithm`]).
    algorithm: Option<SigningAlgorithm>,
    public_keys: sync::RwLock<HashMap<String, CachedPublicKey>>,
}

impl VaultKeyResolverState {
    fn new(
        vault_client: Arc<dyn VaultSigningClient>,
        signing_context: ParticipantContext,
        algorithm: Option<SigningAlgorithm>,
    ) -> Self {
        Self {
            vault_client,
            signing_context,
            algorithm,
            public_keys: sync::RwLock::new(HashMap::new()),
        }
    }

    fn lookup(&self, kid: &str) -> Option<CachedPublicKey> {
        self.public_keys.read().ok()?.get(kid).cloned()
    }

    fn all_keys(&self) -> Vec<CachedPublicKey> {
        self.public_keys
            .read()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default()
    }

    async fn load_keys(&self) -> Result<(), JwtVerificationError> {
        let key_name = self
            .vault_client
            .signing_key_name()
            .ok_or_else(|| JwtVerificationError::GeneralError("signing_key_name not configured".to_string()))?;
        let metadata = self
            .vault_client
            .get_key_metadata(&self.signing_context, key_name, PublicKeyFormat::Base64Url)
            .await
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to get key metadata: {}", e)))?;

        let key_type = metadata.key_type;
        let algorithm = key_type
            .resolve_algorithm(self.algorithm)
            .map_err(|e| JwtVerificationError::GeneralError(format!("Signing key '{}': {}", key_name, e)))?;

        let cached_keys = metadata
            .keys
            .iter()
            .enumerate()
            .map(|(i, key_b64)| {
                let kid = format!("{}-{}", metadata.key_name, i + 1);
                let key_bytes = URL_SAFE_NO_PAD
                    .decode(key_b64)
                    .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to decode public key: {}", e)))?;
                let jwk = public_key_to_jwk(key_type, &key_bytes, &kid, algorithm)
                    .map_err(|e| JwtVerificationError::GeneralError(format!("Invalid public key '{}': {}", kid, e)))?;
                Ok(CachedPublicKey {
                    kid,
                    key_type,
                    key: key_bytes,
                    jwk,
                })
            })
            .collect::<Result<Vec<_>, JwtVerificationError>>()?;

        self.public_keys
            .write()
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to acquire write lock: {}", e)))?
            .extend(cached_keys.into_iter().map(|key| (key.kid.clone(), key)));
        Ok(())
    }
}

pub struct VaultVerificationKeyResolver {
    state: Arc<VaultKeyResolverState>,
    refresh_interval: Duration,
    refresh_handle: Mutex<Option<TaskHandle>>,
}

#[bon::bon]
impl VaultVerificationKeyResolver {
    #[builder(finish_fn = build)]
    pub fn new(
        vault_client: Arc<dyn VaultSigningClient>,
        /// Participant context used to scope the Vault access token when loading the signing key
        /// (the issuer's own participant context).
        signing_context: ParticipantContext,
        /// Algorithm the issuer signs with, advertised as the published JWK `alg`. Only needed to
        /// pick a non-default RSA variant (e.g. PS256); otherwise derived from the Vault key type.
        algorithm: Option<SigningAlgorithm>,
        #[builder(default = Duration::from_secs(300))] refresh_interval: Duration,
    ) -> Self {
        Self {
            state: Arc::new(VaultKeyResolverState::new(vault_client, signing_context, algorithm)),
            refresh_interval,
            refresh_handle: Mutex::new(None),
        }
    }

    pub async fn initialize(&self) -> Result<(), JwtVerificationError> {
        self.state.load_keys().await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = Arc::clone(&self.state);
        let interval = self.refresh_interval;
        let task_handle = tokio::spawn(async move {
            Self::refresh_loop(state, shutdown_rx, interval).await;
        });
        let mut handle_lock = self
            .refresh_handle
            .lock()
            .map_err(|e| JwtVerificationError::GeneralError(format!("Failed to acquire lock: {}", e)))?;
        *handle_lock = Some(TaskHandle::new(shutdown_tx, task_handle));

        Ok(())
    }

    async fn refresh_loop(
        state: Arc<VaultKeyResolverState>,
        mut shutdown_rx: watch::Receiver<bool>,
        interval: Duration,
    ) {
        let mut interval_timer = tokio::time::interval(interval);
        // Skip the first tick since keys were loaded during initialization
        interval_timer.tick().await;

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    if let Err(e) = state.load_keys().await {
                        error!("Failed to refresh Vault verification keys: {}", e);
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl VerificationKeyResolver for VaultVerificationKeyResolver {
    async fn resolve_key(&self, _iss: &str, kid: &str) -> Result<KeyMaterial, JwtVerificationError> {
        // 1. Check the cache first (populated by initialize() and the background refresh loop).
        if let Some(key) = self.state.lookup(kid) {
            return key.to_key_material();
        }

        // 2. Cache miss — the key may have been added by a recent rotation that the background
        //    refresh hasn't picked up yet. Repopulate the cache and try again.
        self.state
            .load_keys()
            .await
            .map_err(|e| JwtVerificationError::VerificationFailed(e.to_string()))?;

        // 3. Retry from the re-populated cache.
        self.state
            .lookup(kid)
            .ok_or_else(|| JwtVerificationError::VerificationFailed(format!("Key '{}' not found", kid)))?
            .to_key_material()
    }
}

#[async_trait]
impl JwkSetProvider for VaultVerificationKeyResolver {
    async fn jwk_set(&self) -> JwkSet {
        let keys = self.state.all_keys().into_iter().map(|key| key.jwk).collect();
        JwkSet { keys }
    }
}

/// A Vault public key version, with its JWK representation precomputed.
#[derive(Clone)]
struct CachedPublicKey {
    kid: String,
    key_type: KeyType,
    /// Raw Ed25519 key bytes, or DER `SubjectPublicKeyInfo` for RSA/EC.
    key: Vec<u8>,
    /// The JWK published in the JWKS (and used for RSA/EC verification).
    jwk: Jwk,
}

impl CachedPublicKey {
    /// Ed25519 keys are handed to the verifier as raw bytes (the format `DecodingKey::from_ed_der`
    /// expects); RSA and EC keys as their JWK, which carries the curve and parameters explicitly.
    fn to_key_material(&self) -> Result<KeyMaterial, JwtVerificationError> {
        let (key, key_format) = match self.key_type.family() {
            KeyFamily::Ed25519 => (self.key.clone(), KeyFormat::DER),
            KeyFamily::Rsa | KeyFamily::Ec => {
                let jwk_bytes = serde_json::to_vec(&self.jwk).map_err(|e| {
                    JwtVerificationError::GeneralError(format!("Failed to serialize JWK '{}': {}", self.kid, e))
                })?;
                (jwk_bytes, KeyFormat::Jwk)
            }
        };
        Ok(KeyMaterial::builder()
            .key(key)
            .key_format(key_format)
            .kid(self.kid.clone())
            .key_type(self.key_type)
            .build())
    }
}
