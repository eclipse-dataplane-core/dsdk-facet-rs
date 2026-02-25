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

//! E2E tests for Kubernetes + Vault sidecar pattern
//!
//! These tests deploy actual pods in a Kind cluster with Vault Agent sidecars
//! and verify that the HashicorpVaultClient with FileBasedVaultAuthClient
//! correctly reads tokens and performs Vault operations.

use crate::utils::*;
use anyhow::{Context, Result};

/// Setup function to verify E2E environment is ready
async fn verify_e2e_setup() -> Result<()> {
    // Check Kind cluster exists
    if !kind_cluster_exists(KIND_CLUSTER_NAME)? {
        anyhow::bail!(
            "Kind cluster '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            KIND_CLUSTER_NAME
        );
    }

    // Check kubectl is configured
    if !kubectl_configured()? {
        anyhow::bail!("kubectl not configured or cluster not accessible");
    }

    // Check namespace exists
    if !namespace_exists(E2E_NAMESPACE)? {
        anyhow::bail!(
            "Namespace '{}' not found. Run 'cd e2e && ./scripts/setup.sh' first.",
            E2E_NAMESPACE
        );
    }

    // Check Vault deployment is ready
    wait_for_deployment_ready(E2E_NAMESPACE, "vault", 60)
        .await
        .context("Vault deployment not ready")?;

    Ok(())
}

/// Test that HashicorpVaultClient with FileBasedVaultAuthClient works in K8s
///
/// This test:
/// 1. Deploys a pod with Vault Agent sidecar and test container
/// 2. Waits for the sidecar to authenticate and write the token file
/// 3. Test container automatically runs vault-test binary (from Docker image)
/// 4. Waits for the test container to complete
/// 5. Retrieves logs and verifies CRUD operations succeeded
#[tokio::test]
#[ignore]
async fn test_hashicorp_vault_client_with_rust_binary() -> Result<()> {
    verify_e2e_setup().await?;

    // Clean up any leftover pods from previous runs
    let manifest_path = "manifests/test-pod.yaml";
    let _ = kubectl_delete(manifest_path);
    let _ = wait_for_pod_deleted(E2E_NAMESPACE, "test-app", 30).await;

    // Deploy test pod (with vault-test:local image)
    println!("Deploying test pod with vault-test container...");
    kubectl_apply(manifest_path)?;

    // Wait for vault-agent to be ready (not the test-runner, since it will complete and exit)
    println!("Waiting for vault-agent to be ready...");
    wait_for_pod_ready(E2E_NAMESPACE, "app=test-app", 120).await?;

    // Wait for the test-runner container to complete
    println!("Waiting for test-runner container to complete...");
    let exit_code = wait_for_container_completion(E2E_NAMESPACE, "test-app", "test-runner", 120)
        .await
        .context("Failed to wait for container completion")?;

    // Get the logs from the test-runner container
    println!("Retrieving logs from test-runner container...");
    let logs = get_pod_logs(E2E_NAMESPACE, "test-app", "test-runner")?;

    println!("Container logs:\n{}", logs);
    println!("Container exit code: {}", exit_code);

    // Verify the test succeeded
    assert_eq!(
        exit_code, 0,
        "Test container should exit with code 0, got {}",
        exit_code
    );

    // Verify success indicators in logs
    assert!(
        logs.contains("All CRUD operations successful"),
        "Logs should indicate CRUD operations succeeded"
    );
    assert!(
        logs.contains("Secret stored"),
        "Logs should show secret was stored"
    );
    assert!(
        logs.contains("Secret resolved"),
        "Logs should show secret was resolved"
    );
    assert!(
        logs.contains("Secret removed"),
        "Logs should show secret was removed"
    );

    // Cleanup
    kubectl_delete(manifest_path)?;

    Ok(())
}
