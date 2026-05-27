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

use crate::utils::*;
use anyhow::{Context, Result};
use dsdk_facet_testcontainers::utils::get_available_port;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

static SIGLET_DEPLOYMENT: OnceCell<Arc<SigletDeployment>> = OnceCell::const_new();

/// Information about the deployed Siglet instance.
pub struct SigletDeployment {
    pub pod_name: String,
    pub siglet_api_port: u16,
    pub signaling_port: u16,
    pub refresh_api_port: u16,
    // Keeps the kubectl port-forward processes alive for the lifetime of this handle.
    _port_forwards: Mutex<Vec<std::process::Child>>,
}

/// Deploys Siglet to K8S.
/// This function is idempotent and thread-safe — multiple tests can call it concurrently.
pub async fn ensure_siglet_deployed() -> Result<Arc<SigletDeployment>> {
    SIGLET_DEPLOYMENT
        .get_or_try_init(|| async {
            crate::utils::verify_e2e_setup().await?;

            // PostgreSQL must be running before Siglet starts (PostgresVault backend).
            crate::fixtures::postgres::ensure_postgres_deployed().await?;

            // The signaling API runs with JWT auth enabled; its HttpKeyProvider fetches
            // the JWKS from the signaling-jwks server, which must exist before Siglet
            // verifies any signaling request.
            crate::fixtures::signaling_jwks::ensure_signaling_jwks().await?;

            let config_manifest = "manifests/siglet-config.yaml";
            let deployment_manifest = "manifests/siglet-deployment.yaml";
            let service_manifest = "manifests/siglet-service.yaml";

            // Server-side apply is idempotent across concurrent callers (nextest runs each
            // test in a separate process with its own OnceCell). Both processes apply the
            // same static manifests; the second call is a no-op when nothing changed.
            // No deletion step — deleting and recreating causes a race where one process
            // kills the deployment the other just started.
            println!("Deploying Siglet with Vault Agent sidecar");
            for manifest in [config_manifest, deployment_manifest, service_manifest] {
                kubectl_apply_server_side(manifest)
                    .with_context(|| format!("Failed to apply {}", manifest))?;
            }

            println!("Waiting for Siglet to be ready");
            wait_for_rollout_complete(E2E_NAMESPACE, "siglet", 300).await?;

            // Get pod name — skip any pods with a deletionTimestamp (Terminating state)
            // so that a rollout restart doesn't cause us to target the old, shutting-down pod.
            let pod_name_output = std::process::Command::new("kubectl")
                .args([
                    "get",
                    "pods",
                    "-n",
                    E2E_NAMESPACE,
                    "-l",
                    "app=siglet",
                    "-o",
                    "go-template={{range .items}}{{if not .metadata.deletionTimestamp}}{{.metadata.name}}{{end}}{{end}}",
                ])
                .output()
                .context("Failed to get pod name")?;
            let pod_name = String::from_utf8_lossy(&pod_name_output.stdout).trim().to_string();

            println!("Siglet deployed: pod={}", pod_name);

            let (siglet_api_port, siglet_api_child) = setup_siglet_api_port_forward().await?;
            let (signaling_port, signaling_child) = setup_signaling_port_forward().await?;
            let (refresh_api_port, refresh_child) = setup_refresh_port_forward().await?;

            Ok(Arc::new(SigletDeployment {
                pod_name,
                siglet_api_port,
                signaling_port,
                refresh_api_port,
                _port_forwards: Mutex::new(vec![siglet_api_child, signaling_child, refresh_child]),
            }))
        })
        .await
        .map(|arc| arc.clone())
}

/// Sets up port forwarding for the Siglet management API (port 8080) and returns the local port
/// along with the child process handle (kept alive to maintain the forward).
async fn setup_siglet_api_port_forward() -> Result<(u16, std::process::Child)> {
    let local_port = get_available_port();

    let mut child = std::process::Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            E2E_NAMESPACE,
            "service/siglet",
            &format!("{}:8080", local_port),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start kubectl port-forward for siglet API")?;

    let client = Client::new();
    let start = std::time::Instant::now();
    let timeout_secs = 30;

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            let _ = child.kill();
            anyhow::bail!(
                "Failed to establish port-forward to siglet API (8080) on local port {} after {} seconds",
                local_port,
                timeout_secs
            );
        }

        match child
            .try_wait()
            .context("Failed to poll kubectl port-forward process")?
        {
            Some(status) => anyhow::bail!("kubectl port-forward (siglet API) exited unexpectedly: {}", status),
            None => {}
        }

        if client
            .get(format!("http://localhost:{}/health", local_port))
            .timeout(tokio::time::Duration::from_secs(1))
            .send()
            .await
            .is_ok()
        {
            return Ok((local_port, child));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

/// Sets up port forwarding for the Signaling API (port 8081) and returns the local port
/// along with the child process handle (kept alive to maintain the forward).
async fn setup_signaling_port_forward() -> Result<(u16, std::process::Child)> {
    let local_port = get_available_port();

    let mut child = std::process::Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            E2E_NAMESPACE,
            "service/siglet",
            &format!("{}:8081", local_port),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start kubectl port-forward for signaling API")?;

    let client = Client::new();
    let start = std::time::Instant::now();
    let timeout_secs = 30;

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            let _ = child.kill();
            anyhow::bail!(
                "Failed to establish port-forward to siglet signaling (8081) on local port {} after {} seconds",
                local_port,
                timeout_secs
            );
        }

        match child
            .try_wait()
            .context("Failed to poll kubectl port-forward process")?
        {
            Some(status) => anyhow::bail!("kubectl port-forward (signaling) exited unexpectedly: {}", status),
            None => {}
        }

        if client
            .get(format!("http://localhost:{}/api/v1/dataflows", local_port))
            .timeout(tokio::time::Duration::from_secs(1))
            .send()
            .await
            .is_ok()
        {
            return Ok((local_port, child));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

/// Sets up port forwarding for the Refresh API (port 8082) and returns the local port
/// along with the child process handle (kept alive to maintain the forward).
async fn setup_refresh_port_forward() -> Result<(u16, std::process::Child)> {
    let local_port = get_available_port();

    let mut child = std::process::Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            E2E_NAMESPACE,
            "service/siglet",
            &format!("{}:8082", local_port),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start kubectl port-forward for refresh API")?;

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    let timeout_secs = 30;

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            let _ = child.kill();
            anyhow::bail!(
                "Failed to establish port-forward to siglet refresh API (8082) on local port {} after {} seconds",
                local_port,
                timeout_secs
            );
        }

        match child
            .try_wait()
            .context("Failed to poll kubectl port-forward process")?
        {
            Some(status) => anyhow::bail!("kubectl port-forward (refresh) exited unexpectedly: {}", status),
            None => {}
        }

        // Probe with a GET to /token/refresh — expect 405 (Method Not Allowed) because
        // the endpoint only accepts POST; any HTTP response means the forward is up.
        if client
            .get(format!("http://localhost:{}/token/refresh", local_port))
            .timeout(tokio::time::Duration::from_secs(1))
            .send()
            .await
            .is_ok()
        {
            return Ok((local_port, child));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}
