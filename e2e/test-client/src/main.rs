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

//! E2E test client that runs inside Kubernetes pods to verify
//! HashicorpVaultClient with FileBasedVaultAuthClient

use anyhow::{Context, Result};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::vault::VaultClient;
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Get configuration from environment variables
    let vault_url = env::var("VAULT_URL").unwrap_or_else(|_| "http://vault:8200".to_string());
    let token_file_path = env::var("TOKEN_FILE_PATH")
        .unwrap_or_else(|_| "/vault/secrets/.vault-token".to_string());
    let test_mode = env::var("TEST_MODE").unwrap_or_else(|_| "crud".to_string());

    println!("=== Vault E2E Test Client ===");
    println!("Vault URL: {}", vault_url);
    println!("Token file: {}", token_file_path);
    println!("Test mode: {}", test_mode);
    println!();

    match test_mode.as_str() {
        "crud" => test_crud_operations(&vault_url, &token_file_path).await,
        "health" => test_health_check(&vault_url, &token_file_path).await,
        "token-read" => test_token_read(&token_file_path).await,
        _ => {
            eprintln!("Unknown test mode: {}", test_mode);
            std::process::exit(1);
        }
    }
}

/// Test basic CRUD operations
async fn test_crud_operations(vault_url: &str, token_file_path: &str) -> Result<()> {
    println!("[CRUD] Starting CRUD operations test");

    // Create context
    let ctx = ParticipantContext {
        id: "e2e-test-id".to_string(),
        identifier: "e2e-test-identifier".to_string(),
        audience: "e2e-test-audience".to_string(),
    };

    // Create Vault client with FileBasedVaultAuthClient
    let config = HashicorpVaultConfig::builder()
        .vault_url(vault_url)
        .auth_config(VaultAuthConfig::KubernetesServiceAccount {
            token_file_path: PathBuf::from(token_file_path),
        })
        .build();

    println!("[CRUD] Creating HashicorpVaultClient with FileBasedVaultAuthClient");
    let mut client = HashicorpVaultClient::new(config)
        .context("Failed to create Vault client")?;

    println!("[CRUD] Initializing client (reading token file and authenticating)");
    client
        .initialize()
        .await
        .context("Failed to initialize Vault client")?;

    println!("[CRUD] Client initialized successfully");

    // Test: Store a secret
    println!("[CRUD] Storing secret at e2e-test/rust-client-test");
    client
        .store_secret(&ctx, "e2e-test/rust-client-test", "test-value-from-rust-client")
        .await
        .context("Failed to store secret")?;
    println!("[CRUD] Secret stored");

    // Test: Resolve the secret
    println!("[CRUD] Resolving secret from e2e-test/rust-client-test");
    let value = client
        .resolve_secret(&ctx, "e2e-test/rust-client-test")
        .await
        .context("Failed to resolve secret")?;

    assert_eq!(
        value, "test-value-from-rust-client",
        "Retrieved value doesn't match stored value"
    );
    println!("[CRUD] Secret resolved: {}", value);

    // Test: Update the secret
    println!("[CRUD] Updating secret");
    client
        .store_secret(&ctx, "e2e-test/rust-client-test", "updated-value-from-rust-client")
        .await
        .context("Failed to update secret")?;
    println!("[CRUD] Secret updated");

    // Test: Resolve updated secret
    println!("[CRUD] Resolving updated secret");
    let updated_value = client
        .resolve_secret(&ctx, "e2e-test/rust-client-test")
        .await
        .context("Failed to resolve updated secret")?;

    assert_eq!(
        updated_value, "updated-value-from-rust-client",
        "Updated value doesn't match"
    );
    println!("[CRUD] Updated secret resolved: {}", updated_value);

    // Test: Remove the secret
    println!("[CRUD] Removing secret");
    client
        .remove_secret(&ctx, "e2e-test/rust-client-test")
        .await
        .context("Failed to remove secret")?;
    println!("[CRUD] Secret removed");

    // Test: Verify secret is gone
    println!("[CRUD] Verifying secret is removed");
    let result = client.resolve_secret(&ctx, "e2e-test/rust-client-test").await;
    assert!(result.is_err(), "Secret should not exist after removal");
    println!("[CRUD] Secret confirmed removed");

    println!();
    println!("[CRUD] All CRUD operations successful");

    Ok(())
}

/// Test health check functionality
async fn test_health_check(vault_url: &str, token_file_path: &str) -> Result<()> {
    println!("[HEALTH] Starting health check test");

    let config = HashicorpVaultConfig::builder()
        .vault_url(vault_url)
        .auth_config(VaultAuthConfig::KubernetesServiceAccount {
            token_file_path: PathBuf::from(token_file_path),
        })
        .build();

    println!("[HEALTH] Creating and initializing client");
    let mut client = HashicorpVaultClient::new(config)?;
    client.initialize().await?;

    println!("[HEALTH] Checking if client is healthy");
    let is_healthy = client.is_healthy().await;
    assert!(is_healthy, "Client should be healthy after initialization");
    println!("[HEALTH] Client is healthy: {}", is_healthy);

    println!("[HEALTH] Checking last error");
    let last_error = client.last_error().await?;
    assert!(
        last_error.is_none(),
        "Last error should be None after successful initialization"
    );
    println!("[HEALTH] Last error is None");

    println!("[HEALTH] Checking consecutive failures");
    let failures = client.consecutive_failures().await?;
    assert_eq!(
        failures, 0,
        "Consecutive failures should be 0 after successful initialization"
    );
    println!("[HEALTH] Consecutive failures: {}", failures);

    println!();
    println!("[HEALTH] Health check test successful");

    Ok(())
}

/// Test token file reading
async fn test_token_read(token_file_path: &str) -> Result<()> {
    println!("[TOKEN] Starting token read test");
    println!("[TOKEN] Token file path: {}", token_file_path);

    // Just verify we can read the token file
    let token = tokio::fs::read_to_string(token_file_path)
        .await
        .context("Failed to read token file")?;

    let token = token.trim();
    assert!(!token.is_empty(), "Token file should not be empty");
    assert!(
        token.starts_with("hvs.") || token.starts_with("s."),
        "Token should have valid Vault token format"
    );

    println!("[TOKEN] Token file read successfully");
    println!("[TOKEN] Token format valid: {}...", &token[..20.min(token.len())]);

    println!();
    println!("[TOKEN] Token read test successful");

    Ok(())
}
