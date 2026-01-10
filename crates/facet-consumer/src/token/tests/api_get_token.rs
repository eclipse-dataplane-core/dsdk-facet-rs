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

use crate::token::tests::mocks::{create_dummy_lock_guard, MockLockManager, MockTokenClient, MockTokenStore};
use crate::token::{TokenClientApi, TokenData, TokenError};
use chrono::{TimeDelta, Utc};
use facet_common::util::MockClock;
use mockall::predicate::eq;
use std::sync::Arc;

#[tokio::test]
async fn test_get_token_not_expiring_does_not_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager.expect_lock().never();

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_get_token()
        .once()
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "active_token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(60),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().never();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock)
        .refresh_before_expiry_ms(5_000)
        .build();

    let result = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();
    assert_eq!(result, "active_token");
}

#[tokio::test]
async fn test_get_token_expiring_soon_triggers_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .times(2)
        .in_sequence(&mut seq)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "old_token".to_string(),
                refresh_token: "old_refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(10),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client
        .expect_refresh_token()
        .once()
        .with(
            eq("participant1"),
            eq("identifier1"),
            eq("old_refresh"),
            eq("https://example.com/refresh"),
        )
        .returning(|_, _, _, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "new_token".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    // Advance time so the token is within the 5s refresh threshold
    clock.advance(TimeDelta::seconds(6));

    let result = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();
    assert_eq!(result, "new_token");
}

#[tokio::test]
async fn test_get_token_expired_triggers_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .times(2)
        .in_sequence(&mut seq)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "expired_token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: Utc::now() - TimeDelta::seconds(10),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().once().returning(|_, _, _, _| {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "identifier1".to_string(),
            token: "refreshed_token".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(3600),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
    });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock)
        .build();

    let result = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();
    assert_eq!(result, "refreshed_token");
}

#[tokio::test]
async fn test_refresh_updates_stored_token() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .times(2)
        .in_sequence(&mut seq)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "old_token".to_string(),
                refresh_token: "old_refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .withf(|data| data.token == "refreshed_token" && data.refresh_token == "new_refresh_token")
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().once().returning(|_, _, _, _| {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "identifier1".to_string(),
            token: "refreshed_token".to_string(),
            refresh_token: "new_refresh_token".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(3600),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
    });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    clock.advance(TimeDelta::seconds(4));
    let _ = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_refresh_failure_returns_error() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_get_token()
        .times(2)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    let mut token_client = MockTokenClient::new();
    token_client
        .expect_refresh_token()
        .once()
        .returning(|_, _, _, _| Err(TokenError::network_error("Refresh endpoint unavailable")));

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    clock.advance(TimeDelta::seconds(4));
    let result = token_api.get_token("participant1", "identifier1", "owner1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_lock_acquired_during_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .times(2)
        .in_sequence(&mut seq)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().once().returning(|_, _, _, _| {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "identifier1".to_string(),
            token: "refreshed".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(3600),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
    });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    clock.advance(TimeDelta::seconds(4));

    // Trigger refresh which should acquire the lock
    let _ = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();

    // Verify that lock was called (it was expected above)
}

#[tokio::test]
async fn test_lock_prevents_concurrent_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|_, _| {
            Err(crate::lock::LockError::lock_already_held(
                "identifier1",
                "other_owner",
                "owner1",
            ))
        });

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_get_token()
        .once()
        .with(eq("participant1"), eq("identifier1"))
        .returning(move |_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: initial_time + TimeDelta::seconds(3),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().never();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    clock.advance(TimeDelta::seconds(4));

    // Attempt to get token should fail (cannot acquire lock)
    let result = token_api.get_token("participant1", "identifier1", "owner1").await;
    assert!(result.is_err(), "Should fail when lock is held by another owner");
}

#[tokio::test]
async fn test_token_not_found_error() {
    let mut lock_manager = MockLockManager::new();
    lock_manager.expect_lock().never();

    let mut token_store = MockTokenStore::new();
    token_store
        .expect_get_token()
        .once()
        .with(eq("participant1"), eq("nonexistent"))
        .returning(|_, id| Err(TokenError::token_not_found(id)));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().never();

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .build();

    let result = token_api.get_token("participant1", "nonexistent", "owner1").await;
    assert!(result.is_err());

    match result.unwrap_err() {
        TokenError::TokenNotFound { identifier } => {
            assert_eq!(identifier, "nonexistent");
        }
        _ => panic!("Expected TokenNotFound error"),
    }
}

#[tokio::test]
async fn test_refresh_with_custom_refresh_threshold() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("identifier1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .times(2)
        .in_sequence(&mut seq)
        .with(eq("participant1"), eq("identifier1"))
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "identifier1".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(20),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client.expect_refresh_token().once().returning(|_, _, _, _| {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "identifier1".to_string(),
            token: "refreshed".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(3600),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        })
    });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(10_000) // Refresh 10 seconds before expiry
        .build();

    clock.advance(TimeDelta::seconds(11));

    let result = token_api
        .get_token("participant1", "identifier1", "owner1")
        .await
        .unwrap();
    assert_eq!(result, "refreshed");
}

#[tokio::test]
async fn test_multiple_tokens_independent_refresh() {
    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let mut lock_manager = MockLockManager::new();
    lock_manager
        .expect_lock()
        .once()
        .with(eq("token1"), eq("owner1"))
        .returning(|identifier, owner| Ok(create_dummy_lock_guard(identifier, owner)));

    let mut token_store = MockTokenStore::new();
    let mut seq = mockall::Sequence::new();

    token_store
        .expect_get_token()
        .with(eq("participant1"), eq("token1"))
        .times(2)
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "token1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_get_token()
        .with(eq("participant1"), eq("token2"))
        .times(1)
        .returning(|_, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "token2".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(100),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    token_store
        .expect_update_token()
        .once()
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));

    let mut token_client = MockTokenClient::new();
    token_client
        .expect_refresh_token()
        .once()
        .with(
            eq("participant1"),
            eq("token1"),
            eq("refresh1"),
            eq("https://example.com/refresh"),
        )
        .returning(|_, _, _, _| {
            Ok(TokenData {
                participant_context: "participant1".to_string(),
                identifier: "token1".to_string(),
                token: "refreshed1".to_string(),
                refresh_token: "new_refresh1".to_string(),
                expires_at: Utc::now() + TimeDelta::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

    let token_api = TokenClientApi::builder()
        .lock_manager(Arc::new(lock_manager))
        .token_store(Arc::new(token_store))
        .token_client(Arc::new(token_client))
        .clock(clock.clone())
        .refresh_before_expiry_ms(5_000)
        .build();

    clock.advance(TimeDelta::seconds(4));

    // token1 should trigger refresh
    let result1 = token_api.get_token("participant1", "token1", "owner1").await.unwrap();
    assert_eq!(result1, "refreshed1");

    // token2 should not refresh
    let result2 = token_api.get_token("participant1", "token2", "owner1").await.unwrap();
    assert_eq!(result2, "token2");
}
