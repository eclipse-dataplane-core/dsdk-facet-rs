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

//! Unit tests for authentication clients

use crate::auth::{FileBasedVaultAuthClient, VaultAuthClient};
use dsdk_facet_core::vault::VaultError;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::fs;

/// Test that FileBasedVaultAuthClient successfully reads a valid token file
#[tokio::test]
async fn test_file_based_auth_success() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Write a test token to the file
    fs::write(&file_path, "test-vault-token-12345")
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, ttl) = result.unwrap();
    assert_eq!(token, "test-vault-token-12345");
    assert_eq!(ttl, 3600); // Default TTL
}

/// Test that FileBasedVaultAuthClient uses custom estimated TTL
#[tokio::test]
async fn test_file_based_auth_custom_ttl() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    fs::write(&file_path, "test-token")
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .estimated_ttl(7200)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, ttl) = result.unwrap();
    assert_eq!(token, "test-token");
    assert_eq!(ttl, 7200);
}

/// Test that FileBasedVaultAuthClient trims whitespace from token
#[tokio::test]
async fn test_file_based_auth_trims_whitespace() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Write token with leading/trailing whitespace
    fs::write(&file_path, "  \n\t test-token-with-whitespace \t\n  ")
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, _) = result.unwrap();
    assert_eq!(token, "test-token-with-whitespace");
}

/// Test that FileBasedVaultAuthClient handles file not found error
#[tokio::test]
async fn test_file_based_auth_file_not_found() {
    let file_path = PathBuf::from("/tmp/nonexistent-vault-token-file-12345.token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path.clone())
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_err(), "Authentication should fail");

    match result.unwrap_err() {
        VaultError::TokenFileNotFound(msg) => {
            assert!(msg.contains("Token file not found"));
            assert!(msg.contains(&file_path.display().to_string()));
        }
        other => panic!("Expected TokenFileNotFound error, got: {:?}", other),
    }
}

/// Test that FileBasedVaultAuthClient handles an empty token file
#[tokio::test]
async fn test_file_based_auth_empty_file() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Write empty content
    fs::write(&file_path, "")
        .await
        .expect("Failed to write empty file");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_err(), "Authentication should fail");

    match result.unwrap_err() {
        VaultError::InvalidTokenFormat(msg) => {
            assert_eq!(msg, "Token file is empty");
        }
        other => panic!("Expected InvalidTokenFormat error, got: {:?}", other),
    }
}

/// Test that FileBasedVaultAuthClient handles a whitespace-only file
#[tokio::test]
async fn test_file_based_auth_whitespace_only() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Write only whitespace
    fs::write(&file_path, "   \n\t\t   \n  ")
        .await
        .expect("Failed to write whitespace");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_err(), "Authentication should fail");

    match result.unwrap_err() {
        VaultError::InvalidTokenFormat(msg) => {
            assert_eq!(msg, "Token file is empty");
        }
        other => panic!("Expected InvalidTokenFormat error, got: {:?}", other),
    }
}

/// Test that FileBasedVaultAuthClient can be called multiple times
#[tokio::test]
async fn test_file_based_auth_multiple_reads() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    fs::write(&file_path, "initial-token")
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path.clone())
        .build();

    // First read
    let result1 = auth_client.authenticate().await;
    assert!(result1.is_ok(), "First authentication should succeed");
    assert_eq!(result1.unwrap().0, "initial-token");

    // Update the token file
    fs::write(&file_path, "updated-token")
        .await
        .expect("Failed to update token");

    // Second read should get the new token
    let result2 = auth_client.authenticate().await;
    assert!(result2.is_ok(), "Second authentication should succeed");
    assert_eq!(result2.unwrap().0, "updated-token");
}

/// Test that FileBasedVaultAuthClient handles multiline content (should only use first line after trim)
#[tokio::test]
async fn test_file_based_auth_multiline_token() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Write multiline content - should read all of it
    let multiline_content = "first-line\nsecond-line\nthird-line";
    fs::write(&file_path, multiline_content)
        .await
        .expect("Failed to write multiline content");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, _) = result.unwrap();
    // The implementation reads the entire file and trims it
    assert_eq!(token, "first-line\nsecond-line\nthird-line");
}

/// Test that FileBasedVaultAuthClient handles token with special characters
#[tokio::test]
async fn test_file_based_auth_special_characters() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Vault tokens can contain various characters
    let token_with_special_chars = "hvs.CAESIAabc123-_XYZ.def456";
    fs::write(&file_path, token_with_special_chars)
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, _) = result.unwrap();
    assert_eq!(token, token_with_special_chars);
}

/// Test that FileBasedVaultAuthClient handles path with spaces
#[tokio::test]
async fn test_file_based_auth_path_with_spaces() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("token file with spaces.txt");

    fs::write(&file_path, "token-from-spaced-path")
        .await
        .expect("Failed to write token");

    let auth_client = FileBasedVaultAuthClient::builder()
        .token_file_path(file_path)
        .build();

    let result = auth_client.authenticate().await;
    assert!(result.is_ok(), "Authentication should succeed");

    let (token, _) = result.unwrap();
    assert_eq!(token, "token-from-spaced-path");
}
