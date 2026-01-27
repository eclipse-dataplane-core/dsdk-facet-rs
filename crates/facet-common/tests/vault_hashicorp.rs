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

mod common;

use crate::common::{create_network, setup_keycloak_container, setup_vault_container};
use facet_common::context::ParticipantContext;
use facet_common::vault::hashicorp::{HashicorpVaultClient, HashicorpVaultConfig};
use facet_common::vault::VaultClient;

fn create_test_context() -> ParticipantContext {
    ParticipantContext {
        id: "test-id".to_string(),
        identifier: "test-identifier".to_string(),
        audience: "test-audience".to_string(),
    }
}

/// Integration tests for HashicorpVaultClient 
/// 
/// All scenarios are combined in a single test to amortize the expensive container
/// startup time (Vault + Keycloak).
///
/// Scenarios covered:
/// 1. CRUD operations with soft delete (default)
/// 2. Secret not found error handling
/// 3. CRUD operations with hard delete
/// 4. Health check functionality
/// 5. Initialization failure with invalid credentials
#[tokio::test]
async fn test_vault_client_integration() {
    // ============================================================================
    // SETUP: Start containers once for all scenarios
    // ============================================================================
    let network = create_network().await;

    let (keycloak_setup, _keycloak_container) = setup_keycloak_container(&network).await;

    let jwks_url = format!(
        "{}/realms/master/protocol/openid-connect/certs",
        keycloak_setup.keycloak_internal_url
    );
    let (vault_url, _root_token, _vault_container) = setup_vault_container(
        &network,
        &jwks_url,
        &keycloak_setup.keycloak_container_id,
    )
    .await;

    // ============================================================================
    // SCENARIO 1: CRUD Operations with Soft Delete (Default)
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id(&keycloak_setup.client_id)
            .client_secret(&keycloak_setup.client_secret)
            .token_url(&keycloak_setup.token_url)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Test: Store a secret
        client
            .store_secret(&ctx, "test/path", "my-secret-value")
            .await
            .expect("Failed to store secret");

        // Test: Resolve the secret
        let retrieved = client
            .resolve_secret(&ctx, "test/path")
            .await
            .expect("Failed to resolve secret");
        assert_eq!(retrieved, "my-secret-value");

        // Test: Update the secret
        client
            .store_secret(&ctx, "test/path", "updated-secret-value")
            .await
            .expect("Failed to update secret");

        let updated = client
            .resolve_secret(&ctx, "test/path")
            .await
            .expect("Failed to resolve updated secret");
        assert_eq!(updated, "updated-secret-value");

        // Test: Store another secret at a different path
        client
            .store_secret(&ctx, "test/another", "another-value")
            .await
            .expect("Failed to store another secret");

        let another = client
            .resolve_secret(&ctx, "test/another")
            .await
            .expect("Failed to resolve another secret");
        assert_eq!(another, "another-value");

        // Test: Remove a secret (soft delete)
        client
            .remove_secret(&ctx, "test/path")
            .await
            .expect("Failed to remove secret");

        // Test: Verify secret is gone
        let result = client.resolve_secret(&ctx, "test/path").await;
        assert!(result.is_err(), "Expected error when reading deleted secret");

        // Test: The other secret should still be accessible
        let still_there = client
            .resolve_secret(&ctx, "test/another")
            .await
            .expect("Other secret should still be accessible");
        assert_eq!(still_there, "another-value");

    }

    // ============================================================================
    // SCENARIO 2: Secret Not Found Error Handling
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id(&keycloak_setup.client_id)
            .client_secret(&keycloak_setup.client_secret)
            .token_url(&keycloak_setup.token_url)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Try to read a non-existent secret
        let result = client.resolve_secret(&ctx, "nonexistent/path").await;
        assert!(result.is_err(), "Expected error for non-existent secret");

        match result {
            Err(facet_common::vault::VaultError::SecretNotFound { identifier }) => {
                assert_eq!(identifier, "nonexistent/path");
            }
            _ => panic!("Expected SecretNotFound error"),
        }

    }

    // ============================================================================
    // SCENARIO 3: CRUD Operations with Hard Delete
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id(&keycloak_setup.client_id)
            .client_secret(&keycloak_setup.client_secret)
            .token_url(&keycloak_setup.token_url)
            .soft_delete(false)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Store a secret
        client
            .store_secret(&ctx, "test/hard-delete", "value")
            .await
            .expect("Failed to store secret");

        // Verify it exists
        let value = client.resolve_secret(&ctx, "test/hard-delete").await.unwrap();
        assert_eq!(value, "value");

        // Hard delete the secret
        client
            .remove_secret(&ctx, "test/hard-delete")
            .await
            .expect("Failed to remove secret");

        // Verify it is removed
        let result = client.resolve_secret(&ctx, "test/hard-delete").await;
        assert!(result.is_err(), "Expected error after hard delete");

    }

    // ============================================================================
    // SCENARIO 4: Health Check Functionality
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id(&keycloak_setup.client_id)
            .client_secret(&keycloak_setup.client_secret)
            .token_url(&keycloak_setup.token_url)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Client should be healthy immediately after initialization
        assert!(client.is_healthy().await, "Client should be healthy after initialization");

        // Last error should be None
        let last_error = client.last_error().await.expect("Should get last error");
        assert!(last_error.is_none(), "Last error should be None after successful initialization");

        // Consecutive failures should be 0
        let failures = client.consecutive_failures().await.expect("Should get consecutive failures");
        assert_eq!(failures, 0, "Consecutive failures should be 0 after successful initialization");

        // Verify client can perform operations while healthy
        client
            .store_secret(&ctx, "test/health", "healthy-value")
            .await
            .expect("Healthy client should be able to store secrets");

        let value = client.resolve_secret(&ctx, "test/health").await.expect("Should resolve secret");
        assert_eq!(value, "healthy-value");

    }

    // ============================================================================
    // SCENARIO 5: Initialization Failure with Invalid Credentials
    // ============================================================================
    {
        let ctx = create_test_context();
        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id("invalid-client-id")
            .client_secret("invalid-secret")
            .token_url(&keycloak_setup.token_url)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");

        // Initialization should fail due to invalid credentials
        let init_result = client.initialize().await;
        assert!(init_result.is_err(), "Initialization should fail with invalid credentials");

        // Client should not be usable after failed initialization
        let resolve_result = client.resolve_secret(&ctx, "test/any").await;
        assert!(resolve_result.is_err(), "Operations should fail on uninitialized client");

    }

    // ============================================================================
    // SCENARIO 6: Participant Context Isolation
    // ============================================================================
    {
        let ctx1 = ParticipantContext {
            id: "participant-1".to_string(),
            identifier: "participant-1-identifier".to_string(),
            audience: "participant-1-audience".to_string(),
        };

        let ctx2 = ParticipantContext {
            id: "participant-2".to_string(),
            identifier: "participant-2-identifier".to_string(),
            audience: "participant-2-audience".to_string(),
        };

        let config = HashicorpVaultConfig::builder()
            .vault_url(&vault_url)
            .client_id(&keycloak_setup.client_id)
            .client_secret(&keycloak_setup.client_secret)
            .token_url(&keycloak_setup.token_url)
            .build();

        let mut client = HashicorpVaultClient::new(config)
            .expect("Failed to create Vault client");
        client.initialize().await.expect("Failed to initialize Vault client");

        // Store secrets for both participants at the same path
        client
            .store_secret(&ctx1, "shared/path", "secret-for-participant-1")
            .await
            .expect("Failed to store secret for participant 1");

        client
            .store_secret(&ctx2, "shared/path", "secret-for-participant-2")
            .await
            .expect("Failed to store secret for participant 2");

        // Each participant should retrieve only their own secret
        let secret1 = client
            .resolve_secret(&ctx1, "shared/path")
            .await
            .expect("Failed to resolve secret for participant 1");
        assert_eq!(secret1, "secret-for-participant-1");

        let secret2 = client
            .resolve_secret(&ctx2, "shared/path")
            .await
            .expect("Failed to resolve secret for participant 2");
        assert_eq!(secret2, "secret-for-participant-2");

        // Remove secret for participant 1
        client
            .remove_secret(&ctx1, "shared/path")
            .await
            .expect("Failed to remove secret for participant 1");

        // Participant 1's secret should be gone
        let result = client.resolve_secret(&ctx1, "shared/path").await;
        assert!(result.is_err(), "Expected error when reading deleted secret for participant 1");

        // Participant 2's secret should still be accessible
        let secret2_after = client
            .resolve_secret(&ctx2, "shared/path")
            .await
            .expect("Participant 2's secret should still be accessible");
        assert_eq!(secret2_after, "secret-for-participant-2");

    }

}