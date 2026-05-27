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

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::process::Command;

/// Check if Kind cluster exists
pub fn kind_cluster_exists(cluster_name: &str) -> Result<bool> {
    let output = Command::new("kind")
        .args(["get", "clusters"])
        .output()
        .context("Failed to execute 'kind get clusters'. Is Kind installed?")?;

    if !output.status.success() {
        bail!("Failed to list Kind clusters");
    }

    let clusters = String::from_utf8_lossy(&output.stdout);
    Ok(clusters.lines().any(|line| line.trim() == cluster_name))
}

/// Check if kubectl is available and configured for the Kind cluster
pub fn kubectl_configured() -> Result<bool> {
    let output = Command::new("kubectl")
        .args(["cluster-info"])
        .output()
        .context("Failed to execute kubectl. Is kubectl installed?")?;

    Ok(output.status.success())
}

/// Check if namespace exists
pub fn namespace_exists(namespace: &str) -> Result<bool> {
    let output = Command::new("kubectl")
        .args(["get", "namespace", namespace])
        .output()
        .context("Failed to check namespace")?;

    Ok(output.status.success())
}

/// Execute a command inside a pod container
pub fn kubectl_exec(namespace: &str, pod_name: &str, container: &str, command: &[&str]) -> Result<String> {
    let mut args = vec!["exec", "-n", namespace, pod_name, "-c", container, "--"];
    args.extend_from_slice(command);

    let output = Command::new("kubectl")
        .args(&args)
        .output()
        .context("Failed to execute command in pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get logs from a pod container
pub fn get_pod_logs(namespace: &str, pod_name: &str, container: &str) -> Result<String> {
    let output = Command::new("kubectl")
        .args(["logs", "-n", namespace, pod_name, "-c", container])
        .output()
        .context("Failed to get pod logs")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Apply a manifest file using server-side apply with conflict override.
/// Safe to call concurrently from multiple processes — all callers succeed.
pub fn kubectl_apply_server_side(manifest_path: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args(["apply", "--server-side", "--force-conflicts", "-f", manifest_path])
        .output()
        .context("Failed to apply manifest (server-side)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to server-side apply manifest: {}", stderr);
    }

    Ok(())
}

/// Apply a Kubernetes manifest from a string (using stdin).
pub fn kubectl_apply_stdin(manifest_content: &str) -> Result<()> {
    kubectl_stdin_cmd(&["apply", "-f", "-"], manifest_content, "apply")
}

/// Apply a Kubernetes manifest from a string using server-side apply with conflict
/// override. Safe to call concurrently from multiple processes with identical
/// content — all callers succeed, mirroring [`kubectl_apply_server_side`].
pub fn kubectl_apply_server_side_stdin(manifest_content: &str) -> Result<()> {
    kubectl_stdin_cmd(
        &["apply", "--server-side", "--force-conflicts", "-f", "-"],
        manifest_content,
        "server-side apply",
    )
}

fn kubectl_stdin_cmd(args: &[&str], manifest_content: &str, op: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("kubectl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn kubectl {}", op))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(manifest_content.as_bytes())
            .context("Failed to write manifest to kubectl stdin")?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("Failed to wait for kubectl {}", op))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to {} manifest from stdin: {}", op, stderr);
    }

    Ok(())
}

/// Delete a pod by name (ignores not-found errors)
pub fn kubectl_delete_pod(namespace: &str, pod_name: &str) -> Result<()> {
    let output = Command::new("kubectl")
        .args(["delete", "pod", pod_name, "-n", namespace, "--ignore-not-found"])
        .output()
        .context("Failed to delete pod")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to delete pod {}: {}", pod_name, stderr);
    }

    Ok(())
}

/// Reads a binary field from a Kubernetes Secret.
///
/// Secret data is always base64-encoded in Kubernetes. This function retrieves
/// the field via jsonpath and decodes it once, returning the raw bytes.
pub fn read_secret_bytes(namespace: &str, secret_name: &str, field: &str) -> Result<Vec<u8>> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            &format!("jsonpath={{.data.{}}}", field),
        ])
        .output()
        .context("Failed to run kubectl get secret")?;

    if !output.status.success() || output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Secret '{}/{}' field '{}' not found: {}",
            namespace,
            secret_name,
            field,
            stderr
        );
    }

    let b64 = String::from_utf8(output.stdout).context("Non-UTF8 output from kubectl get secret")?;
    STANDARD
        .decode(b64.trim())
        .context("Failed to base64-decode secret field")
}
