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

//! Unit tests for the token providers, focused on the token-exchange
//! ([`ExchangingTokenProvider`]) cache and refresh behavior.

use crate::config::{HashicorpVaultConfig, VaultAuthConfig};
use crate::provider::{ExchangingTokenProvider, VaultTokenProvider};
use chrono::{TimeDelta, Utc};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::util::clock::{Clock, MockClock};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use tempfile::NamedTempFile;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EXCHANGE_PATH: &str = "/token/exchange";
const JWT_LOGIN_PATH: &str = "/v1/auth/jwt/login";
const LEASE_DURATION: u64 = 3600;

/// Mounts a token-exchange endpoint returning a participant-bound JWT.
///
/// The provider appends `/token` to the configured `exchange_url`, so the mock matches that path.
async fn mount_exchange(server: &MockServer, expect: u64) {
    Mock::given(method("POST"))
        .and(path(format!("{}/token", EXCHANGE_PATH)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "participant-bound-jwt"
        })))
        .expect(expect)
        .mount(server)
        .await;
}

/// Mounts a Vault JWT-login endpoint returning a Vault client token.
async fn mount_jwt_login(server: &MockServer, expect: u64, token: &str) {
    Mock::given(method("POST"))
        .and(path(JWT_LOGIN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": token, "lease_duration": LEASE_DURATION }
        })))
        .expect(expect)
        .mount(server)
        .await;
}

/// Writes a subject token to a temp file and returns the file handle (kept alive by the caller).
fn subject_token_file() -> NamedTempFile {
    let file = NamedTempFile::new().expect("failed to create temp file");
    std::fs::write(file.path(), "k8s-service-account-token").expect("failed to write subject token");
    file
}

fn build_provider(
    server: &MockServer,
    subject_file: &NamedTempFile,
    clock: Arc<dyn Clock>,
) -> Arc<ExchangingTokenProvider> {
    let config = HashicorpVaultConfig::builder()
        .vault_url(server.uri())
        .auth_config(VaultAuthConfig::TokenExchange {
            subject_token_file_path: subject_file.path().to_path_buf(),
            exchange_url: format!("{}{}", server.uri(), EXCHANGE_PATH),
            audience: "vault".to_string(),
            scope: "vault-access".to_string(),
            role: None,
        })
        .clock(clock)
        .build();

    ExchangingTokenProvider::new(&config, Client::new(), config.clock.clone()).expect("failed to build provider")
}

fn ctx(id: &str) -> ParticipantContext {
    ParticipantContext::builder()
        .id(id)
        .identifier(format!("did:web:{}", id))
        .audience(format!("audience-{}", id))
        .build()
}

/// The exchange request binds `resource` to the participant context id and forwards the configured
/// `audience` and `scope`.
#[tokio::test]
async fn test_exchange_binds_resource_audience_and_scope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{}/token", EXCHANGE_PATH)))
        .and(body_string_contains("resource=participant-xyz"))
        .and(body_string_contains("audience=vault"))
        .and(body_string_contains("scope=vault-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "participant-bound-jwt"
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_jwt_login(&server, 1, "vault-token").await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock);

    provider
        .token(&ctx("participant-xyz"))
        .await
        .expect("token should be acquired");
    // The exchange mock only matches when resource/audience/scope are present; `.expect(1)` verifies it.
}

/// First call triggers exactly one exchange + one login and returns the Vault token.
#[tokio::test]
async fn test_token_exchange_acquires_token() {
    let server = MockServer::start().await;
    mount_exchange(&server, 1).await;
    mount_jwt_login(&server, 1, "vault-token-1").await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock);

    let token = provider
        .token(&ctx("participant-a"))
        .await
        .expect("token should be acquired");
    assert_eq!(token, "vault-token-1");
    // Expectations (exactly 1 exchange + 1 login) verified on server drop.
}

/// A second call within the cached TTL is served from cache without additional HTTP calls.
#[tokio::test]
async fn test_token_cached_within_ttl() {
    let server = MockServer::start().await;
    mount_exchange(&server, 1).await;
    mount_jwt_login(&server, 1, "vault-token-1").await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock);

    let c = ctx("participant-a");
    let first = provider.token(&c).await.expect("first token");
    let second = provider.token(&c).await.expect("second token");
    assert_eq!(first, second);
    // `.expect(1)` on both mocks asserts the second call did NOT hit the network.
}

/// After the cached token expires, the next call re-exchanges.
#[tokio::test]
async fn test_token_refreshed_after_expiry() {
    let server = MockServer::start().await;
    mount_exchange(&server, 2).await;
    // Two distinct tokens across the two acquisitions.
    Mock::given(method("POST"))
        .and(path(JWT_LOGIN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "vault-token-refreshed", "lease_duration": LEASE_DURATION }
        })))
        .expect(2)
        .mount(&server)
        .await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock.clone());

    let c = ctx("participant-a");
    provider.token(&c).await.expect("first token");

    // Advance past the cache validity window (0.8 * 3600 = 2880s).
    clock.advance(TimeDelta::seconds(3000));
    provider.token(&c).await.expect("token after expiry");
    // `.expect(2)` verifies a second exchange + login occurred.
}

/// Distinct participant contexts get independently-cached tokens.
#[tokio::test]
async fn test_tokens_are_per_participant_context() {
    let server = MockServer::start().await;
    mount_exchange(&server, 2).await;
    mount_jwt_login(&server, 2, "vault-token").await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock);

    provider.token(&ctx("participant-a")).await.expect("token a");
    provider.token(&ctx("participant-b")).await.expect("token b");
    // Two distinct contexts => two exchanges + two logins.
}

/// Concurrent calls for the same context do not trigger duplicate exchanges.
#[tokio::test]
async fn test_concurrent_calls_deduplicate_exchange() {
    let server = MockServer::start().await;
    mount_exchange(&server, 1).await;
    mount_jwt_login(&server, 1, "vault-token-1").await;

    let subject = subject_token_file();
    let clock = Arc::new(MockClock::new(Utc::now()));
    let provider = build_provider(&server, &subject, clock);

    let c = ctx("participant-a");
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let provider = Arc::clone(&provider);
            let c = c.clone();
            tokio::spawn(async move { provider.token(&c).await })
        })
        .collect();

    for handle in handles {
        let token = handle.await.expect("task join").expect("token");
        assert_eq!(token, "vault-token-1");
    }
    // `.expect(1)` verifies the double-checked write lock coalesced the 8 calls into 1 exchange.
}

/// A missing subject-token file surfaces a clear error and marks the provider unhealthy.
#[tokio::test]
async fn test_missing_subject_token_file_errors() {
    let server = MockServer::start().await;
    let clock = Arc::new(MockClock::new(Utc::now()));

    let config = HashicorpVaultConfig::builder()
        .vault_url(server.uri())
        .auth_config(VaultAuthConfig::TokenExchange {
            subject_token_file_path: "/nonexistent/subject/token".into(),
            exchange_url: format!("{}{}", server.uri(), EXCHANGE_PATH),
            audience: "vault".to_string(),
            scope: "vault-access".to_string(),
            role: None,
        })
        .clock(clock)
        .build();
    let provider = ExchangingTokenProvider::new(&config, Client::new(), config.clock.clone()).expect("build provider");

    let result = provider.token(&ctx("participant-a")).await;
    assert!(matches!(
        result,
        Err(dsdk_facet_core::vault::VaultError::TokenFileNotFound(_))
    ));
    assert_eq!(provider.consecutive_failures().await, 1);
    assert!(provider.last_error().await.is_some());
}
