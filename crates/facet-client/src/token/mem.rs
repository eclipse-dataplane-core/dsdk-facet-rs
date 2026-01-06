
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

use crate::token::{TokenData, TokenError, TokenStore};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// In-memory token store for testing and development.
///
/// Maintains tokens in a thread-safe hashmap. Not suitable for production use.
///
/// # Example
///
/// ```
/// # use std::sync::Arc;
/// # use facet_client::token::{TokenStore, MemoryTokenStore, TokenData};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = Arc::new(MemoryTokenStore::new());
/// let token = TokenData {
///     identifier: "user123".into(),
///     token: "token_value".into(),
///     refresh_token: "refresh_value".into(),
///     expires_at: 1234567890,
///     refresh_endpoint: "https://example.com/refresh".into(),
/// };
/// store.save_token(token).await?;
/// # Ok(())
/// # }
/// ```
pub struct MemoryTokenStore {
    tokens: RwLock<HashMap<String, TokenRecord>>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Remove all tokens that were last accessed before the specified date
    /// (useful for cleaning up old tokens)
    ///
    /// # Arguments
    /// * `cutoff` - Remove tokens used before this date
    ///
    /// # Returns
    /// The number of tokens removed
    pub async fn remove_tokens_accessed_before(&self, cutoff: i64) -> Result<usize, TokenError> {
        let mut tokens = self.tokens.write().await;

        let initial_count = tokens.len();

        // Retain only tokens that were used after the cutoff date
        tokens.retain(|_, record| record.last_accessed > cutoff);

        let removed_count = initial_count - tokens.len();
        Ok(removed_count)
    }
}

impl Default for MemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenStore for MemoryTokenStore {
    async fn get_token(&self, identifier: &str) -> Result<TokenData, TokenError> {
        let tokens = self.tokens.read().await;
        tokens
            .get(identifier)
            .map(|record| TokenData {
                identifier: identifier.to_string(),
                token: record.token.clone(),
                refresh_token: record.refresh_token.clone(),
                expires_at: record.expires_at,
                refresh_endpoint: record.refresh_endpoint.clone(),
            })
            .ok_or_else(|| TokenError::token_not_found(identifier))
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        let record = TokenRecord {
            identifier: data.identifier.clone(),
            token: data.token,
            expires_at: data.expires_at,
            refresh_token: data.refresh_token,
            refresh_endpoint: data.refresh_endpoint,
            last_accessed: Utc::now().timestamp_millis(),
        };

        self.tokens.write().await.insert(data.identifier, record);
        Ok(())
    }

    async fn update_token(&self, data: TokenData) -> Result<(), TokenError> {
        let mut tokens = self.tokens.write().await;

        // Only update if the token exists
        if !tokens.contains_key(&data.identifier) {
            return Err(TokenError::cannot_update_non_existent(&data.identifier));
        }

        tokens.entry(data.identifier).and_modify(|record| {
            record.token = data.token.clone();
            record.refresh_token = data.refresh_token.clone();
            record.expires_at = data.expires_at;
            record.refresh_endpoint = data.refresh_endpoint;
            record.last_accessed = Utc::now().timestamp_millis();
        });

        Ok(())
    }

    async fn remove_token(&self, identifier: &str) -> Result<(), TokenError> {
        self.tokens.write().await.remove(identifier);
        Ok(())
    }

    async fn close(&self) {}
}

#[allow(dead_code)]
struct TokenRecord {
    identifier: String,
    token: String,
    refresh_token: String,
    refresh_endpoint: String,
    expires_at: i64,
    last_accessed: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn create_store_with_tokens() -> MemoryTokenStore {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;

        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
            .save_token(TokenData {
                identifier: "user2".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
            .save_token(TokenData {
                identifier: "user3".to_string(),
                token: "token3".to_string(),
                refresh_token: "refresh3".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
    }

    #[tokio::test]
    async fn test_new_store_is_empty() {
        let store = MemoryTokenStore::new();
        let data = store.get_token("nonexistent").await;
        assert!(data.is_err());
    }

    #[tokio::test]
    async fn test_save_token_success() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        let test_data = TokenData {
            identifier: "user1".to_string(),
            token: "token123".to_string(),
            refresh_token: "refresh123".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };

        let result = store.save_token(test_data.clone()).await;
        assert!(result.is_ok(), "save_token should return Ok");

        // Verify the saved token can be retrieved
        let retrieved = store.get_token("user1").await.expect("Failed to retrieve saved token");
        assert_eq!(retrieved.identifier, "user1", "Identifier should match");
        assert_eq!(retrieved.token, "token123", "Token should match");
        assert_eq!(retrieved.refresh_token, "refresh123", "Refresh token should match");
        assert_eq!(retrieved.expires_at, expiration, "Expiration should match");
        assert_eq!(
            retrieved.refresh_endpoint, "https://example.com/refresh",
            "Refresh endpoint should match"
        );
    }

    #[tokio::test]
    async fn test_save_token_updates_last_accessed_timestamp() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;

        // Set cutoff to the past, before we save any tokens
        let cutoff = Utc::now().timestamp_millis() - 1000; // 1 second in the past

        let token = TokenData {
            identifier: "user1".to_string(),
            token: "token123".to_string(),
            refresh_token: "refresh123".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };

        store.save_token(token).await.expect("Save failed");

        // Retrieve and verify it was stored
        let retrieved = store.get_token("user1").await.expect("Retrieve failed");
        assert_eq!(retrieved.token, "token123");

        // Wait a bit to ensure time has passed
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Remove tokens accessed before our cutoff (should not remove the newly saved token)
        let removed_count = store
            .remove_tokens_accessed_before(cutoff)
            .await
            .expect("Remove failed");
        assert_eq!(
            removed_count, 0,
            "New token should not be removed (accessed after cutoff)"
        );

        // Verify token still exists
        let still_exists = store.get_token("user1").await;
        assert!(still_exists.is_ok(), "Token should still exist after cleanup");
    }

    #[tokio::test]
    async fn test_save_multiple_tokens_retrieves_correct_one() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;

        // Save three different tokens
        let token1 = TokenData {
            identifier: "user1".to_string(),
            token: "token_a".to_string(),
            refresh_token: "refresh_a".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://service1.com/refresh".to_string(),
        };
        let token2 = TokenData {
            identifier: "user2".to_string(),
            token: "token_b".to_string(),
            refresh_token: "refresh_b".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://service2.com/refresh".to_string(),
        };
        let token3 = TokenData {
            identifier: "user3".to_string(),
            token: "token_c".to_string(),
            refresh_token: "refresh_c".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://service3.com/refresh".to_string(),
        };

        store.save_token(token1.clone()).await.expect("Save token1 failed");
        store.save_token(token2.clone()).await.expect("Save token2 failed");
        store.save_token(token3.clone()).await.expect("Save token3 failed");

        // Verify each token can be retrieved with correct data
        let retrieved1 = store.get_token("user1").await.expect("Get user1 failed");
        assert_eq!(retrieved1.token, "token_a");
        assert_eq!(retrieved1.refresh_token, "refresh_a");
        assert_eq!(retrieved1.refresh_endpoint, "https://service1.com/refresh");

        let retrieved2 = store.get_token("user2").await.expect("Get user2 failed");
        assert_eq!(retrieved2.token, "token_b");
        assert_eq!(retrieved2.refresh_token, "refresh_b");
        assert_eq!(retrieved2.refresh_endpoint, "https://service2.com/refresh");

        let retrieved3 = store.get_token("user3").await.expect("Get user3 failed");
        assert_eq!(retrieved3.token, "token_c");
        assert_eq!(retrieved3.refresh_token, "refresh_c");
        assert_eq!(retrieved3.refresh_endpoint, "https://service3.com/refresh");
    }

    #[tokio::test]
    async fn test_save_token_overwrites_with_different_values() {
        let store = MemoryTokenStore::new();
        let expiration1 = Utc::now().timestamp_millis() + 10000;
        let expiration2 = Utc::now().timestamp_millis() + 20000;

        let token1 = TokenData {
            identifier: "user1".to_string(),
            token: "old_token".to_string(),
            refresh_token: "old_refresh".to_string(),
            expires_at: expiration1,
            refresh_endpoint: "https://old.example.com/refresh".to_string(),
        };

        store.save_token(token1).await.expect("Save token1 failed");

        let token2 = TokenData {
            identifier: "user1".to_string(),
            token: "new_token".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: expiration2,
            refresh_endpoint: "https://new.example.com/refresh".to_string(),
        };

        store.save_token(token2).await.expect("Save token2 failed");

        // Verify the new token replaced the old one
        let retrieved = store.get_token("user1").await.expect("Get failed");
        assert_eq!(retrieved.token, "new_token", "Token should be updated");
        assert_eq!(
            retrieved.refresh_token, "new_refresh",
            "Refresh token should be updated"
        );
        assert_eq!(retrieved.expires_at, expiration2, "Expiration should be updated");
        assert_eq!(
            retrieved.refresh_endpoint, "https://new.example.com/refresh",
            "Endpoint should be updated"
        );
    }

    #[tokio::test]
    async fn test_save_token_with_edge_case_values() {
        let store = MemoryTokenStore::new();

        // Test with minimum valid values
        let min_token = TokenData {
            identifier: "x".to_string(),
            token: "t".to_string(),
            refresh_token: "r".to_string(),
            expires_at: 0,
            refresh_endpoint: "https://example.com".to_string(),
        };

        store.save_token(min_token).await.expect("Save min token failed");
        let retrieved = store.get_token("x").await.expect("Get min token failed");
        assert_eq!(retrieved.identifier, "x");
        assert_eq!(retrieved.token, "t");
        assert_eq!(retrieved.expires_at, 0);

        // Test with very long values
        let long_token = TokenData {
            identifier: "user_with_long_id".to_string(),
            token: "t".repeat(1000),
            refresh_token: "r".repeat(1000),
            expires_at: i64::MAX,
            refresh_endpoint: "https://very.long.domain.name.example.com/path/to/refresh/endpoint".to_string(),
        };

        store.save_token(long_token).await.expect("Save long token failed");
        let retrieved = store
            .get_token("user_with_long_id")
            .await
            .expect("Get long token failed");
        assert_eq!(retrieved.token.len(), 1000, "Long token should be preserved");
        assert_eq!(
            retrieved.refresh_token.len(),
            1000,
            "Long refresh token should be preserved"
        );
        assert_eq!(retrieved.expires_at, i64::MAX);
    }

    #[tokio::test]
    async fn test_save_token_with_empty_identifier() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        let result = store
            .save_token(TokenData {
                identifier: "".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_save_token_overwrites_existing() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("First save failed");
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Second save failed");

        let data = store.get_token("user1").await.expect("Failed to get token");
        assert_eq!(data.token, "token2");
    }

    #[tokio::test]
    async fn test_save_multiple_tokens() {
        let store = create_store_with_tokens().await;

        assert_eq!(store.get_token("user1").await.unwrap().token, "token1");
        assert_eq!(store.get_token("user2").await.unwrap().token, "token2");
        assert_eq!(store.get_token("user3").await.unwrap().token, "token3");
    }

    #[tokio::test]
    async fn test_get_token_success() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "mytoken".to_string(),
                refresh_token: "myrefresh".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");
        let data = store.get_token("user1").await.expect("Failed to get token");
        assert_eq!(data.token, "mytoken");
    }

    #[tokio::test]
    async fn test_get_token_not_found() {
        let store = MemoryTokenStore::new();
        let data = store.get_token("nonexistent").await;
        assert!(data.is_err());
        assert!(data.unwrap_err().to_string().contains("Token not found"));
    }

    #[tokio::test]
    async fn test_get_token_returns_clone() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        let token1 = store.get_token("user1").await.expect("Failed to get token");
        let token2 = store.get_token("user1").await.expect("Failed to get token");

        assert_eq!(token1, token2);
    }

    #[tokio::test]
    async fn test_update_token_success() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        store
            .update_token(TokenData {
                identifier: "user1".to_string(),
                token: "token_new".to_string(),
                refresh_token: "refresh_new".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to update");

        let data = store.get_token("user1").await.expect("Failed to get token");
        assert_eq!(data.token, "token_new");
    }

    #[tokio::test]
    async fn test_update_nonexistent_token() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        let result = store
            .update_token(TokenData {
                identifier: "nonexistent".to_string(),
                token: "token".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-existent"));
    }

    #[tokio::test]
    async fn test_update_token_updates_last_accessed() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;
        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        tokio::time::sleep(Duration::from_millis(10)).await;

        store
            .update_token(TokenData {
                identifier: "user1".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to update");

        let _ = store.get_token("user1").await.expect("Failed to get token");
    }

    #[tokio::test]
    async fn test_remove_token_success() {
        let store = create_store_with_tokens().await;
        let result = store.remove_token("user1").await;
        assert!(result.is_ok());

        let data = store.get_token("user1").await;
        assert!(data.is_err());
    }

    #[tokio::test]
    async fn test_remove_token_nonexistent() {
        let store = MemoryTokenStore::new();
        let result = store.remove_token("nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_token_does_not_affect_others() {
        let store = create_store_with_tokens().await;
        store.remove_token("user1").await.expect("Failed to remove");

        assert!(store.get_token("user2").await.is_ok());
        assert!(store.get_token("user3").await.is_ok());
    }

    #[tokio::test]
    async fn test_remove_multiple_tokens() {
        let store = create_store_with_tokens().await;
        store.remove_token("user1").await.expect("Failed to remove user1");
        store.remove_token("user2").await.expect("Failed to remove user2");

        assert!(store.get_token("user1").await.is_err());
        assert!(store.get_token("user2").await.is_err());
        assert!(store.get_token("user3").await.is_ok());
    }

    #[tokio::test]
    async fn test_remove_tokens_used_before_success() {
        let store = create_store_with_tokens().await;
        let cutoff = Utc::now().timestamp_millis() + 1000;

        let removed = store
            .remove_tokens_accessed_before(cutoff)
            .await
            .expect("Failed to remove tokens");

        assert_eq!(removed, 3);
        assert!(store.get_token("user1").await.is_err());
        assert!(store.get_token("user2").await.is_err());
        assert!(store.get_token("user3").await.is_err());
    }

    #[tokio::test]
    async fn test_remove_tokens_used_before_empty_store() {
        let store = MemoryTokenStore::new();
        let cutoff = Utc::now().timestamp_millis();

        let removed = store
            .remove_tokens_accessed_before(cutoff)
            .await
            .expect("Failed to remove tokens");

        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn test_remove_tokens_accessed_before_no_matches() {
        let store = create_store_with_tokens().await;
        let cutoff = Utc::now().timestamp_millis() - 86_400_000; // 1 day ago

        let removed = store
            .remove_tokens_accessed_before(cutoff)
            .await
            .expect("Failed to remove tokens");

        assert_eq!(removed, 0);
        assert!(store.get_token("user1").await.is_ok());
        assert!(store.get_token("user2").await.is_ok());
        assert!(store.get_token("user3").await.is_ok());
    }

    #[tokio::test]
    async fn test_close_does_not_panic() {
        let store = create_store_with_tokens().await;
        store.close().await;
    }

    #[tokio::test]
    async fn test_save_get_update_remove_flow() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now().timestamp_millis() + 10000;

        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        store
            .update_token(TokenData {
                identifier: "user1".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to update");

        store.remove_token("user1").await.expect("Failed to remove");
        assert!(store.get_token("user1").await.is_err());
    }

    #[tokio::test]
    async fn test_multiple_operations_concurrent_like() {
        let store = create_store_with_tokens().await;

        let _ = store.get_token("user1").await;
        store
            .update_token(TokenData {
                identifier: "user2".to_string(),
                token: "new_token".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now().timestamp_millis() + 10000,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to update");
        store.remove_token("user1").await.expect("Failed to remove");

        assert!(store.get_token("user1").await.is_err());
        assert!(store.get_token("user2").await.is_ok());
        assert!(store.get_token("user3").await.is_ok());
    }

    #[tokio::test]
    async fn test_token_with_special_characters() {
        let store = MemoryTokenStore::new();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let refresh = "refresh_token_!@#$%^&*()";

        let expiration = Utc::now().timestamp_millis() + 10000;

        store
            .save_token(TokenData {
                identifier: "user".to_string(),
                token: token.to_string(),
                refresh_token: refresh.to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        assert_eq!(store.get_token("user").await.unwrap().token, token);
    }
}