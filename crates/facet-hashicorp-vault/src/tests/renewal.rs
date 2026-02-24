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

//! Unit tests for renewal triggers

use crate::renewal::{FileBasedRenewalTrigger, RenewalTrigger};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::timeout;

/// Test that FileBasedRenewalTrigger detects file modifications
#[tokio::test]
async fn test_file_based_trigger_detects_modification() {
    // Create a temporary file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Create the trigger
    let trigger = FileBasedRenewalTrigger::new(file_path.clone())
        .expect("Failed to create file based trigger");

    // Spawn a task that will modify the file after a short delay
    let file_path_clone = file_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::fs::write(&file_path_clone, "new-token-value")
            .await
            .expect("Failed to write to file");
    });

    // Wait for the trigger - should fire when file is modified
    let result = timeout(Duration::from_secs(5), trigger.wait_for_trigger(3600, 0)).await;

    assert!(result.is_ok(), "Trigger should fire within timeout");
    assert!(result.unwrap().is_ok(), "Trigger should succeed");
}

/// Test that FileBasedRenewalTrigger detects file creation
#[tokio::test]
async fn test_file_based_trigger_detects_creation() {
    // Create temp directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("token");

    // Create initial file so watcher can be set up
    tokio::fs::write(&file_path, "initial")
        .await
        .expect("Failed to create initial file");

    // Create the trigger
    let trigger = FileBasedRenewalTrigger::new(file_path.clone())
        .expect("Failed to create file based trigger");

    // Spawn a task that will recreate the file after a short delay
    let file_path_clone = file_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Remove and recreate (simulating rotation)
        tokio::fs::remove_file(&file_path_clone)
            .await
            .expect("Failed to remove file");
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::fs::write(&file_path_clone, "new-token")
            .await
            .expect("Failed to recreate file");
    });

    // Wait for the trigger - should fire when file is created
    let result = timeout(Duration::from_secs(5), trigger.wait_for_trigger(3600, 0)).await;

    assert!(result.is_ok(), "Trigger should fire within timeout");
    assert!(result.unwrap().is_ok(), "Trigger should succeed");
}

/// Test that FileBasedRenewalTrigger handles multiple rapid file changes
#[tokio::test]
async fn test_file_based_trigger_multiple_changes() {
    // Create a temporary file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Create the trigger
    let trigger = FileBasedRenewalTrigger::new(file_path.clone())
        .expect("Failed to create file based trigger");

    // Spawn a task that will modify the file multiple times
    let file_path_clone = file_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        for i in 0..5 {
            tokio::fs::write(&file_path_clone, format!("token-{}", i))
                .await
                .expect("Failed to write to file");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Wait for the trigger - should fire on first modification
    let result = timeout(Duration::from_secs(5), trigger.wait_for_trigger(3600, 0)).await;

    assert!(result.is_ok(), "Trigger should fire within timeout");
    assert!(result.unwrap().is_ok(), "Trigger should succeed");
}

/// Test that FileBasedRenewalTrigger fails gracefully with non-existent file
#[tokio::test]
async fn test_file_based_trigger_nonexistent_file() {
    let file_path = PathBuf::from("/tmp/nonexistent-file-that-should-not-exist-12345.token");

    // Creating trigger with non-existent file should fail
    let result = FileBasedRenewalTrigger::new(file_path);

    assert!(result.is_err(), "Creating trigger with non-existent file should fail");
}

/// Test that FileBasedRenewalTrigger can be reused after triggering
#[tokio::test]
async fn test_file_based_trigger_reuse() {
    // Create a temporary file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let file_path = temp_file.path().to_path_buf();

    // Create the trigger
    let trigger = FileBasedRenewalTrigger::new(file_path.clone())
        .expect("Failed to create file based trigger");

    // First trigger
    let file_path_clone = file_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::fs::write(&file_path_clone, "token-1")
            .await
            .expect("Failed to write to file");
    });

    let result = timeout(Duration::from_secs(5), trigger.wait_for_trigger(3600, 0)).await;
    assert!(result.is_ok() && result.unwrap().is_ok(), "First trigger should succeed");

    // Second trigger
    let file_path_clone = file_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::fs::write(&file_path_clone, "token-2")
            .await
            .expect("Failed to write to file");
    });

    let result = timeout(Duration::from_secs(5), trigger.wait_for_trigger(3600, 0)).await;
    assert!(result.is_ok() && result.unwrap().is_ok(), "Second trigger should succeed");
}
