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

//! Container-gated tests for Postgres pool contention on the signaling start path.
//!
//! The SDK opens a transaction (one pooled connection) before calling `on_start`, and the handler
//! then reads transfer-type mappings and saves the renewable token through their own pools. When
//! all of that shares one pool, `max_connections` concurrent starts each hold one connection and
//! wait for a second, so every request stalls until `acquire_timeout`. These tests reproduce that
//! and check that giving the SDK its own pool (as `assemble_postgres` does) removes the stall.
//!
//! Requires a Docker-compatible runtime (via `dsdk-facet-testcontainers`).

#![allow(clippy::unwrap_used)]

use dataplane_sdk::core::db::tx::{Transaction, TransactionalContext};
use dataplane_sdk::core::model::messages::DataFlowStartMessage;
use dataplane_sdk::sdk::DataPlaneSdk;
use dataplane_sdk_postgres::{PgContext, PgControlPlaneRepo, PgDataFlowRepo};
use dsdk_facet_core::jwt::test_fixtures::{
    StaticSigningKeyResolver, StaticVerificationKeyResolver, generate_ed25519_keypair_pem,
};
use dsdk_facet_core::jwt::{JwkSet, JwkSetProvider, KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use dsdk_facet_core::token::client::MemoryTokenStore;
use dsdk_facet_core::token::manager::{JwtTokenManager, ValidatedServerSecret};
use dsdk_facet_postgres::renewable_token_store::PostgresRenewableTokenStore;
use dsdk_facet_testcontainers::postgres::setup_postgres_container;
use siglet::assembly::pg_pool_options;
use siglet::config::{PostgresPoolConfig, TokenSource, TransferType};
use siglet::handler::SigletDataFlowHandler;
use siglet::transfer_type::postgres::PostgresTransferTypeMappingStore;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ACQUIRE_TIMEOUT_SECS: u64 = 3;
const PROFILE: &str = "http-pull";

struct NoOpJwkSetProvider;

#[async_trait::async_trait]
impl JwkSetProvider for NoOpJwkSetProvider {
    async fn jwk_set(&self) -> JwkSet {
        JwkSet { keys: vec![] }
    }
}

/// A pool of two connections that gives up after `ACQUIRE_TIMEOUT_SECS`.
async fn small_pool(template: &PgPool) -> PgPool {
    let pool_cfg = PostgresPoolConfig {
        max_connections: 2,
        acquire_timeout_seconds: ACQUIRE_TIMEOUT_SECS,
        ..PostgresPoolConfig::default()
    };
    pg_pool_options(&pool_cfg)
        .connect_with((*template.connect_options()).clone())
        .await
        .unwrap()
}

/// Builds an SDK whose transactions run on `sdk_pool` and whose handler stores use `store_pool`.
async fn build_sdk(sdk_pool: PgPool, store_pool: PgPool) -> DataPlaneSdk<PgContext> {
    let ctx = PgContext::new(sdk_pool);
    let mut tx = ctx.begin().await.unwrap();
    PgDataFlowRepo.migrate(&mut tx).await.unwrap();
    PgControlPlaneRepo.migrate(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let renewable_store = Arc::new(PostgresRenewableTokenStore::new(store_pool.clone()));
    renewable_store.initialize().await.unwrap();
    let transfer_type_store = Arc::new(PostgresTransferTypeMappingStore::new(store_pool));
    transfer_type_store.initialize().await.unwrap();

    let keypair = generate_ed25519_keypair_pem().unwrap();
    let generator = Arc::new(
        LocalJwtGenerator::builder()
            .signing_key_resolver(Arc::new(
                StaticSigningKeyResolver::builder()
                    .key(keypair.private_key.clone())
                    .kid("test_kid_1")
                    .key_format(KeyFormat::PEM)
                    .build(),
            ))
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );
    let verifier = Arc::new(
        LocalJwtVerifier::builder()
            .verification_key_resolver(Arc::new(
                StaticVerificationKeyResolver::builder()
                    .key(keypair.public_key.clone())
                    .key_format(KeyFormat::PEM)
                    .build(),
            ))
            .signing_algorithm(SigningAlgorithm::EdDSA)
            .build(),
    );
    let token_manager = Arc::new(
        JwtTokenManager::builder()
            .issuer("did:web:issuer.com")
            .refresh_endpoint("http://localhost:8080/refresh")
            .server_secret(ValidatedServerSecret::try_from(b"this_is_exactly_32bytes_long!!!!".to_vec()).unwrap())
            .token_store(renewable_store)
            .token_generator(generator)
            .client_verifier(verifier.clone())
            .provider_verifier(verifier)
            .jwk_set_provider(Arc::new(NoOpJwkSetProvider))
            .build(),
    );

    let mut mappings = HashMap::new();
    mappings.insert(
        PROFILE.to_string(),
        TransferType::builder()
            .transfer_type(PROFILE.to_string())
            .endpoint_type("HTTP".to_string())
            .endpoint("https://pull.example.com".to_string())
            .token_source(TokenSource::Provider)
            .build(),
    );
    let handler = SigletDataFlowHandler::builder()
        .token_store(Arc::new(MemoryTokenStore::new()))
        .token_manager(token_manager)
        .dataplane_id("test-dataplane")
        .transfer_type_repo(transfer_type_store)
        .transfer_type_mappings(mappings)
        .build();

    DataPlaneSdk::builder(ctx)
        .with_repo(PgDataFlowRepo)
        .with_control_plane_repo(PgControlPlaneRepo)
        .with_handler(handler)
        .build()
        .unwrap()
}

fn start_message(flow_id: &str) -> DataFlowStartMessage {
    DataFlowStartMessage::builder()
        .message_id(format!("msg-{flow_id}"))
        .participant_id("participant-1")
        .counter_party_id("counter-party-1")
        .dataspace_context("dataspace-1")
        .data_flow_id(flow_id)
        .agreement_id("agreement-1")
        .dataset_id("dataset-1")
        .profile(PROFILE)
        .build()
}

/// Fires `count` concurrent starts and returns how many succeeded and how long they took.
async fn run_concurrent_starts(sdk: &DataPlaneSdk<PgContext>, count: usize) -> (usize, Duration) {
    let started = Instant::now();
    let handles: Vec<_> = (0..count)
        .map(|i| {
            let sdk = sdk.clone();
            tokio::spawn(async move { sdk.start("pc-1", "cp-1", start_message(&format!("flow-{i}"))).await })
        })
        .collect();

    let mut succeeded = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            succeeded += 1;
        }
    }
    (succeeded, started.elapsed())
}

#[tokio::test]
async fn test_shared_pool_stalls_concurrent_starts_until_acquire_timeout() {
    let (template, _container) = setup_postgres_container().await;
    let pool = small_pool(&template).await;
    let sdk = build_sdk(pool.clone(), pool).await;

    let (succeeded, elapsed) = run_concurrent_starts(&sdk, 4).await;

    assert!(
        elapsed >= Duration::from_secs(ACQUIRE_TIMEOUT_SECS),
        "starts should block on the pool until acquire_timeout, took {elapsed:?}"
    );
    assert!(
        succeeded < 4,
        "at least one start should time out acquiring a connection"
    );
}

#[tokio::test]
async fn test_separate_sdk_pool_does_not_stall_concurrent_starts() {
    let (template, _container) = setup_postgres_container().await;
    let sdk = build_sdk(small_pool(&template).await, small_pool(&template).await).await;

    let (succeeded, elapsed) = run_concurrent_starts(&sdk, 8).await;

    assert_eq!(succeeded, 8, "every start should succeed");
    assert!(
        elapsed < Duration::from_secs(ACQUIRE_TIMEOUT_SECS),
        "starts should not wait for acquire_timeout, took {elapsed:?}"
    );
}
