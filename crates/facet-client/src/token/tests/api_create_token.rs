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

use crate::token::tests::mocks::{MockLockManager, MockTokenClient, MockTokenStore, create_dummy_lock_guard};
use crate::token::{TokenClientApi, TokenError};
use chrono::{TimeDelta, Utc};
use mockall::predicate::eq;
use std::sync::Arc;

#[tokio::test]
async fn test_create_token_success() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("test_identifier"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .once()
        .withf(|data| {
            data.identifier == "test_identifier"
                && data.token == "test_token"
                && data.refresh_token == "test_refresh_token"
        })
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let expires_at = Utc::now() + TimeDelta::hours(1);
    let result = token_api
        .save_token(
            "participant1",
            "test_identifier",
            "test_token",
            "test_refresh_token",
            "https://example.com/refresh",
            expires_at,
            "owner1",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_saves_correct_data() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let expected_expires_at = Utc::now() + TimeDelta::hours(2);

    token_store
        .expect_save_token()
        .once()
        .withf(move |data| {
            data.identifier == "service_a"
                && data.token == "access_token_123"
                && data.refresh_token == "refresh_token_456"
                && data.refresh_endpoint == "https://auth.example.com/token"
                && data.expires_at == expected_expires_at
        })
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "service_a",
            "access_token_123",
            "refresh_token_456",
            "https://auth.example.com/token",
            expected_expires_at,
            "admin",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_acquires_lock() {
    let mut lock_manager = MockLockManager::new();
    let _ = lock_manager
        .expect_lock()
        .once()
        .with(eq("critical_token"), eq("service_owner"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().once().returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "critical_token",
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "service_owner",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_lock_failure() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("test"), eq("owner1"))
        .returning(|_, _| {
            Err(crate::lock::LockError::lock_already_held(
                "test",
                "other_owner",
                "owner1",
            ))
        });

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().never();

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "test",
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner1",
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        TokenError::GeneralError(msg) => {
            assert!(msg.contains("Failed to acquire lock"));
        }
        _ => panic!("Expected GeneralError"),
    }
}

#[tokio::test]
async fn test_create_token_store_failure() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .once()
        .returning(|_| Err(TokenError::general_error("Storage unavailable")));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "test",
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner1",
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        TokenError::GeneralError(msg) => {
            assert!(msg.contains("Storage unavailable"));
        }
        _ => panic!("Expected GeneralError"),
    }
}

#[tokio::test]
async fn test_create_token_with_different_owners() {
    let mut lock_manager = MockLockManager::new();
    let mut seq = mockall::Sequence::new();

    lock_manager
        .expect_lock()
        .once()
        .in_sequence(&mut seq)
        .with(eq("token1"), eq("owner_a"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    lock_manager
        .expect_lock()
        .once()
        .in_sequence(&mut seq)
        .with(eq("token1"), eq("owner_b"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().times(2).returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let expires_at = Utc::now() + TimeDelta::hours(1);

    let result1 = token_api
        .save_token(
            "participant1",
            "token1",
            "token_a",
            "refresh_a",
            "https://example.com/refresh",
            expires_at,
            "owner_a",
        )
        .await;

    let result2 = token_api
        .save_token(
            "participant1",
            "token1",
            "token_b",
            "refresh_b",
            "https://example.com/refresh",
            expires_at,
            "owner_b",
        )
        .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_create_token_with_various_expiry_times() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .times(3)
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().times(3).returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    // Token expiring in 1 hour
    let result1 = token_api
        .save_token(
            "participant1",
            "token1",
            "t1",
            "r1",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    // Token expiring in 24 hours
    let result2 = token_api
        .save_token(
            "participant1",
            "token2",
            "t2",
            "r2",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::days(1),
            "owner",
        )
        .await;

    // Token expiring in 30 days
    let result3 = token_api
        .save_token(
            "participant1",
            "token3",
            "t3",
            "r3",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::days(30),
            "owner",
        )
        .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert!(result3.is_ok());
}

#[tokio::test]
async fn test_create_token_with_special_characters() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .once()
        .withf(|data| {
            data.identifier == "service:prod:api"
                && data.token.contains("eyJhbGc")
                && data.refresh_token.contains("eyJhbGc")
        })
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let jwt_like_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    let result = token_api
        .save_token(
            "participant1",
            "service:prod:api",
            jwt_like_token,
            jwt_like_token,
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_does_not_call_token_client() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().once().returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().never();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "test",
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_multiple_tokens_same_identifier() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .times(2)
        .with(eq("same_id"), eq("owner"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .times(2)
        .withf(|data| data.identifier == "same_id")
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let expires_at = Utc::now() + TimeDelta::hours(1);

    let result1 = token_api
        .save_token(
            "participant1",
            "same_id",
            "token_v1",
            "refresh_v1",
            "https://example.com/refresh",
            expires_at,
            "owner",
        )
        .await;

    let result2 = token_api
        .save_token(
            "participant1",
            "same_id",
            "token_v2",
            "refresh_v2",
            "https://example.com/refresh",
            expires_at,
            "owner",
        )
        .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_create_token_with_empty_refresh_endpoint() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .once()
        .withf(|data| data.refresh_endpoint == "")
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "test",
            "token",
            "refresh",
            "",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_with_long_identifier() {
    let long_identifier = "service.namespace.component.subcomponent.instance.prod.region.aws.us.east.1";

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq(long_identifier), eq("owner"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_save_token()
        .once()
        .withf(move |data| data.identifier == long_identifier)
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            long_identifier,
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_preserves_all_parameters() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let expected_expires_at = Utc::now() + TimeDelta::hours(3);
    let expected_endpoint = "https://custom.auth.example.com/token/refresh";

    token_store
        .expect_save_token()
        .once()
        .withf(move |data| {
            data.identifier == "api_key_123"
                && data.token == "access_super_secret_123"
                && data.refresh_token == "refresh_super_secret_456"
                && data.expires_at == expected_expires_at
                && data.refresh_endpoint == expected_endpoint
        })
        .returning(|_| Ok(()));

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "api_key_123",
            "access_super_secret_123",
            "refresh_super_secret_456",
            expected_endpoint,
            expected_expires_at,
            "system_admin",
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_token_lock_error_variations() {
    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .returning(|_, _| Err(crate::lock::LockError::store_error("Timeout waiting for lock")));

    let mut token_store = MockTokenStore::new();
    token_store.expect_save_token().never();

    let token_client = MockTokenClient::new();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api
        .save_token(
            "participant1",
            "test",
            "token",
            "refresh",
            "https://example.com/refresh",
            Utc::now() + TimeDelta::hours(1),
            "owner",
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        TokenError::GeneralError(msg) => {
            assert!(msg.contains("Failed to acquire lock"));
        }
        _ => panic!("Expected GeneralError"),
    }
}
