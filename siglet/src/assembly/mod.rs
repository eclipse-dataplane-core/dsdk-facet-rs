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

use crate::config::{SigletConfig, StorageBackend, TransferType};
use crate::error::SigletError;
use crate::handler::refresh::TokenRefreshHandler;
use crate::handler::{SigletDataFlowHandler, TokenApiHandler};
use dataplane_sdk::core::db::data_flow::memory::MemoryDataFlowRepo;
use dataplane_sdk::core::db::memory::MemoryContext;
use dataplane_sdk::sdk::DataPlaneSdk;
use dsdk_facet_core::jwt::{
    DidWebVerificationKeyResolver, JwkSetProvider, JwtGenerator, JwtVerifier, LocalJwtVerifier, SigningAlgorithm,
    VaultJwtGenerator, VaultVerificationKeyResolver,
};
use dsdk_facet_core::lock::{LockManager, MemoryLockManager};
use dsdk_facet_core::token::client::oauth::OAuth2TokenClient;
use dsdk_facet_core::token::client::{MemoryTokenStore, TokenClientApi, TokenStore};
use dsdk_facet_core::token::manager::{
    JwtTokenManager, MemoryRenewableTokenStore, RenewableTokenStore, TokenManager, ValidatedServerSecret,
};
use dsdk_facet_core::util::encryption::encryption_key;
use dsdk_facet_core::vault::VaultSigningClient;
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use dsdk_facet_postgres::lock::PostgresLockManager;
use dsdk_facet_postgres::renewable_token_store::PostgresRenewableTokenStore;
use dsdk_facet_postgres::token::PostgresTokenStore;
use rand::Rng;
use rand::thread_rng;
use reqwest::Client;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

#[cfg(test)]
mod tests;

// ============================================================================
// System Default Constants
// ============================================================================

/// Default JWT token issuer identifier
pub const DEFAULT_TOKEN_ISSUER: &str = "siglet";

/// Default data plane identifier
pub const DEFAULT_DATAPLANE_ID: &str = "dataplane-1";

/// Token refresh endpoint path
pub const TOKEN_REFRESH_PATH: &str = "/token/refresh";

/// Temporary file name for vault token (used in testing)
pub const VAULT_TOKEN_TEMP_FILE: &str = "siglet_vault_token";

/// Random server secret size in bytes (256 bits)
pub const RANDOM_SECRET_SIZE_BYTES: usize = 32;

/// Prefix for per-PC Vault transit keys used to sign proof JWTs.
/// The full key name is `{CLIENT_TRANSIT_KEY_PREFIX}-{pc.id}`.
pub const CLIENT_TRANSIT_KEY_PREFIX: &str = "client-signing";

/// Siglet's own participant context ID, used to derive the access-token signing key name.
/// The transit key is `{ACCESS_TOKEN_SIGNING_KEY_PREFIX}-{SIGLET_PC_ID}` = `"signing-siglet"`.
pub const SIGLET_PC_ID: &str = "siglet";

/// Prefix for Vault transit keys used to sign access tokens issued by Siglet.
pub const ACCESS_TOKEN_SIGNING_KEY_PREFIX: &str = "signing";

// ============================================================================
// Runtime
// ============================================================================

/// The fully assembled Siglet runtime, ready to be handed to the server.
pub struct SigletRuntime {
    pub sdk: DataPlaneSdk<MemoryContext>,
    pub refresh_handler: TokenRefreshHandler,
    pub token_api_handler: TokenApiHandler,
}

// ============================================================================
// Top-Level Assembly
// ============================================================================

/// Assembles the complete Siglet runtime from configuration.
///
/// Creates shared services (Vault client, JWT components, token manager) and
/// delegates store creation to the appropriate backend assembly function based
/// on `cfg.storage_backend`. The three component assembly functions
/// (`assemble_memory_sdk`, `assemble_refresh_api`, `assemble_token_api`) all
/// receive references to the same shared services.
pub async fn assemble(cfg: &SigletConfig) -> Result<SigletRuntime, SigletError> {
    let vault_client = create_vault_client(cfg).await?;
    let (jwt_generator, jwt_verifier) = create_jwt_components(vault_client.clone(), cfg.use_http_resolution);
    let server_secret = generate_server_secret(cfg)?;

    let (token_store, renewable_token_store, lock_manager) = match cfg.storage_backend {
        StorageBackend::Memory => assemble_memory_stores(),
        StorageBackend::Postgres => {
            let url = cfg.postgres_url.as_deref().ok_or_else(|| {
                SigletError::InvalidConfiguration("postgres_url is required for the Postgres backend".to_string())
            })?;
            let password = cfg.postgres_encryption_password.as_deref().ok_or_else(|| {
                SigletError::InvalidConfiguration(
                    "postgres_encryption_password is required for the Postgres backend".to_string(),
                )
            })?;
            let salt = cfg.postgres_encryption_salt.as_deref().ok_or_else(|| {
                SigletError::InvalidConfiguration(
                    "postgres_encryption_salt is required for the Postgres backend".to_string(),
                )
            })?;
            assemble_postgres_stores(url, password, salt).await?
        }
    };

    let vault_resolver = Arc::new(
        VaultVerificationKeyResolver::builder()
            .vault_client(vault_client.clone() as Arc<dyn VaultSigningClient>)
            .build(),
    );

    vault_resolver
        .initialize()
        .await
        .map_err(|e| SigletError::Vault(Box::new(e)))?;

    let vault_provider_verifier = create_vault_verifier(vault_resolver.clone());
    let token_manager = create_token_manager(
        cfg,
        server_secret,
        jwt_generator.clone(),
        jwt_verifier.clone(),
        vault_provider_verifier,
        renewable_token_store,
        vault_resolver,
        SIGLET_PC_ID,
    );

    let sdk = assemble_memory_sdk(cfg, token_store.clone(), token_manager.clone()).await?;
    let refresh_handler = assemble_refresh_api(token_manager.clone());
    let client = Client::new(); // TODO add client config options
    let token_api_handler = assemble_token_api(
        token_store,
        lock_manager,
        vault_client.clone() as Arc<dyn VaultSigningClient>,
        token_manager.clone(),
        client,
    );

    Ok(SigletRuntime {
        sdk,
        refresh_handler,
        token_api_handler,
    })
}

// ============================================================================
// Store Assembly
// ============================================================================

type StoreBundle = (Arc<dyn TokenStore>, Arc<dyn RenewableTokenStore>, Arc<dyn LockManager>);

/// Assembles in-memory implementations of all stores and the lock manager.
pub fn assemble_memory_stores() -> StoreBundle {
    let token_store = Arc::new(MemoryTokenStore::default()) as Arc<dyn TokenStore>;
    let renewable_token_store = Arc::new(MemoryRenewableTokenStore::default()) as Arc<dyn RenewableTokenStore>;
    let lock_manager = Arc::new(MemoryLockManager::new()) as Arc<dyn LockManager>;
    (token_store, renewable_token_store, lock_manager)
}

/// Assembles Postgres-backed implementations of all stores and the lock manager.
///
/// Connects to the database, creates and initializes tables, and returns Arc-wrapped
/// trait objects. The `encryption_password` and `encryption_salt` are used to derive
/// the key that encrypts tokens at rest.
pub async fn assemble_postgres_stores(
    url: &str,
    encryption_password: &str,
    encryption_salt: &str,
) -> Result<StoreBundle, SigletError> {
    let pool = PgPool::connect(url)
        .await
        .map_err(|e| SigletError::InvalidConfiguration(format!("Failed to connect to Postgres: {}", e)))?;

    let enc_key = encryption_key(encryption_password, encryption_salt)
        .map_err(|e| SigletError::InvalidConfiguration(format!("Invalid encryption key config: {}", e)))?;

    let token_store = Arc::new(
        PostgresTokenStore::builder()
            .pool(pool.clone())
            .encryption_key(enc_key)
            .build(),
    );
    token_store
        .initialize()
        .await
        .map_err(|e| SigletError::Token(Box::new(e)))?;

    let renewable_token_store = Arc::new(PostgresRenewableTokenStore::new(pool.clone()));
    renewable_token_store
        .initialize()
        .await
        .map_err(|e| SigletError::Token(Box::new(e)))?;

    let lock_manager = Arc::new(PostgresLockManager::builder().pool(pool).build());
    lock_manager
        .initialize()
        .await
        .map_err(|e| SigletError::Token(Box::new(e)))?;

    Ok((token_store, renewable_token_store, lock_manager))
}

// ============================================================================
// Component Assembly
// ============================================================================

/// Assembles a memory-based SDK for data plane operations using shared services.
pub async fn assemble_memory_sdk(
    cfg: &SigletConfig,
    token_store: Arc<dyn TokenStore>,
    token_manager: Arc<dyn TokenManager>,
) -> Result<DataPlaneSdk<MemoryContext>, SigletError> {
    let ctx = MemoryContext;
    let flow_repo = MemoryDataFlowRepo::default();
    let siglet_handler = create_siglet_handler(cfg, token_store, token_manager);

    DataPlaneSdk::builder(ctx)
        .with_repo(flow_repo)
        .with_handler(siglet_handler)
        .build()
        .map_err(|e| SigletError::DataPlane(anyhow::anyhow!(e)))
}

/// Assembles the token refresh handler backed by the given token manager.
pub fn assemble_refresh_api(token_manager: Arc<dyn TokenManager>) -> TokenRefreshHandler {
    TokenRefreshHandler::builder().token_manager(token_manager).build()
}

/// Assembles the token management API handler.
///
/// Uses a per-PC Vault transit key to sign proof JWTs in the token renewal flow.
/// Each PC's transit key is named `{CLIENT_TRANSIT_KEY_PREFIX}-{pc.id}` and must be
/// provisioned out-of-band. The corresponding public key must be published in the PC's
/// DID document so the server-side `DidWebVerificationKeyResolver` can verify the JWT.
pub fn assemble_token_api(
    token_store: Arc<dyn TokenStore>,
    lock_manager: Arc<dyn LockManager>,
    vault_client: Arc<dyn VaultSigningClient>,
    token_manager: Arc<dyn TokenManager>,
    http_client: Client,
) -> TokenApiHandler {
    let client_jwt_generator = Arc::new(
        VaultJwtGenerator::builder()
            .signing_client(vault_client)
            .key_name_prefix(CLIENT_TRANSIT_KEY_PREFIX)
            .build(),
    );
    let token_client = Arc::new(
        OAuth2TokenClient::builder()
            .jwt_generator(client_jwt_generator)
            .http_client(http_client)
            .expiration_seconds(3600)
            .build(),
    );
    let client_api = Arc::new(
        TokenClientApi::builder()
            .token_store(token_store)
            .token_client(token_client)
            .lock_manager(lock_manager)
            .build(),
    );
    TokenApiHandler::builder()
        .token_client_api(client_api)
        .token_manager(token_manager)
        .build()
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Creates a JWT verifier backed by the Vault signing key.
fn create_vault_verifier(resolver: Arc<VaultVerificationKeyResolver>) -> Arc<dyn JwtVerifier> {
    Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    )
}

/// Creates JWT generator and verifier components
fn create_jwt_components(
    vault_client: Arc<HashicorpVaultClient>,
    use_http_resolution: bool,
) -> (Arc<dyn JwtGenerator>, Arc<dyn JwtVerifier>) {
    let jwt_generator = Arc::new(
        VaultJwtGenerator::builder()
            .signing_client(vault_client.clone() as Arc<dyn VaultSigningClient>)
            .key_name_prefix(ACCESS_TOKEN_SIGNING_KEY_PREFIX)
            .build(),
    );

    if use_http_resolution {
        warn!("Enabled HTTP for DID Web key resolution - do not use for production");
    }
    let verification_key_resolver = Arc::new(
        DidWebVerificationKeyResolver::builder()
            .use_https(!use_http_resolution)
            .build(),
    );

    let jwt_verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(verification_key_resolver)
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );

    (jwt_generator, jwt_verifier)
}

/// Generates or decodes the server secret for token signing.
///
/// If no secret is provided in config, generates a random 256-bit (32 byte) secret.
/// This is acceptable for development/testing but NOT recommended for production.
fn generate_server_secret(cfg: &SigletConfig) -> Result<ValidatedServerSecret, SigletError> {
    let bytes = cfg.token_server_secret.as_ref().map_or_else(
        || {
            let mut secret = vec![0u8; RANDOM_SECRET_SIZE_BYTES];
            thread_rng().fill(&mut secret[..]);
            warn!("Generated random secret for token signing - Do not use in production");
            Ok(secret)
        },
        |secret_hex| {
            hex::decode(secret_hex)
                .map_err(|e| SigletError::InvalidConfiguration(format!("Invalid server secret hex: {}", e)))
        },
    )?;
    ValidatedServerSecret::try_from(bytes).map_err(|e| SigletError::InvalidConfiguration(e.to_string()))
}

/// Creates the token manager with all dependencies.
#[allow(clippy::too_many_arguments)]
fn create_token_manager(
    cfg: &SigletConfig,
    server_secret: ValidatedServerSecret,
    jwt_generator: Arc<dyn JwtGenerator>,
    client_verifier: Arc<dyn JwtVerifier>,
    provider_verifier: Arc<dyn JwtVerifier>,
    renewable_token_store: Arc<dyn RenewableTokenStore>,
    jwk_set_provider: Arc<dyn JwkSetProvider>,
    issuer_id: &str,
) -> Arc<dyn TokenManager> {
    let issuer = cfg
        .token_issuer
        .clone()
        .unwrap_or_else(|| DEFAULT_TOKEN_ISSUER.to_string());
    let refresh_endpoint = cfg
        .token_refresh_endpoint
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}{}", cfg.bind, cfg.refresh_api_port, TOKEN_REFRESH_PATH));

    Arc::new(
        JwtTokenManager::builder()
            .issuer(issuer)
            .issuer_id(issuer_id.to_string())
            .refresh_endpoint(refresh_endpoint)
            .server_secret(server_secret)
            .token_store(renewable_token_store)
            .token_generator(jwt_generator)
            .client_verifier(client_verifier)
            .provider_verifier(provider_verifier)
            .jwk_set_provider(jwk_set_provider)
            .build(),
    )
}

/// Builds the data flow handler with token management.
fn create_siglet_handler(
    cfg: &SigletConfig,
    token_store: Arc<dyn TokenStore>,
    token_manager: Arc<dyn TokenManager>,
) -> SigletDataFlowHandler {
    let transfer_type_mappings: HashMap<String, TransferType> = cfg
        .transfer_types
        .iter()
        .map(|tt| (tt.transfer_type.clone(), tt.clone()))
        .collect();

    SigletDataFlowHandler::builder()
        .token_store(token_store)
        .token_manager(token_manager)
        .dataplane_id(DEFAULT_DATAPLANE_ID)
        .transfer_type_mappings(transfer_type_mappings)
        .build()
}

/// Creates and initializes a Vault client for JWT signing.
async fn create_vault_client(cfg: &SigletConfig) -> Result<Arc<HashicorpVaultClient>, SigletError> {
    let vault_url = cfg
        .vault_url
        .as_ref()
        .ok_or_else(|| SigletError::InvalidConfiguration("vault_url is required".to_string()))?;

    let token_file = match (&cfg.vault_token_file, &cfg.vault_token) {
        (Some(token_file_path), _) => std::path::PathBuf::from(token_file_path),
        (None, Some(vault_token)) => {
            let token_file = std::env::temp_dir().join(VAULT_TOKEN_TEMP_FILE);
            std::fs::write(&token_file, vault_token)?;
            token_file
        }
        (None, None) => {
            return Err(SigletError::InvalidConfiguration(
                "Either vault_token or vault_token_file is required".to_string(),
            ));
        }
    };

    let vault_config = HashicorpVaultConfig::builder()
        .vault_url(vault_url)
        .auth_config(VaultAuthConfig::KubernetesServiceAccount {
            token_file_path: token_file,
        })
        .signing_key_name(cfg.vault_signing_key_name.clone())
        .build();

    let mut vault_client = HashicorpVaultClient::new(vault_config).map_err(|e| SigletError::Vault(Box::new(e)))?;

    vault_client
        .initialize()
        .await
        .map_err(|e| SigletError::Vault(Box::new(e)))?;

    Ok(Arc::new(vault_client))
}
