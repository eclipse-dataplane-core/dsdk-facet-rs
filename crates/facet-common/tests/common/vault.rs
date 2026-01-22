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

use reqwest::Client;
use serde_json::json;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::hashicorp_vault::HashicorpVault;

/// Helper to create a HashiCorp Vault container with JWT auth configured using Keycloak JWKS
pub async fn setup_vault_container(
    network: &str,
    keycloak_jwks_url: &str,
    keycloak_container_id: &str,
) -> (String, String, testcontainers::ContainerAsync<HashicorpVault>) {
    setup_vault_container_with_ttl(network, keycloak_jwks_url, keycloak_container_id, "1h").await
}

/// Helper to create a HashiCorp Vault container with JWT auth configured using Keycloak JWKS
/// and a custom token TTL
pub async fn setup_vault_container_with_ttl(
    network: &str,
    keycloak_jwks_url: &str,
    keycloak_container_id: &str,
    token_ttl: &str,
) -> (String, String, testcontainers::ContainerAsync<HashicorpVault>) {
    use testcontainers::ImageExt;

    let container = HashicorpVault::default()
        .with_network(network)
        .start()
        .await.unwrap();

    let host_port = container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://127.0.0.1:{}", host_port);
    let root_token = "myroot";

    let client = Client::new();

    // Wait for Vault to be ready
    for _ in 0..30 {
        if client.get(&format!("{}/v1/sys/health", vault_url)).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Enable JWT auth method
    let enable_jwt = client
        .post(&format!("{}/v1/sys/auth/jwt", vault_url))
        .header("X-Vault-Token", root_token)
        .json(&json!({
            "type": "jwt"
        }))
        .send()
        .await
        .expect("Failed to enable JWT auth");

    assert!(
        enable_jwt.status().is_success(),
        "Failed to enable JWT auth: {}",
        enable_jwt.text().await.unwrap()
    );

    // Configure JWT auth with Keycloak JWKS URL
    let config_jwt = client
        .post(&format!("{}/v1/auth/jwt/config", vault_url))
        .header("X-Vault-Token", root_token)
        .json(&json!({
            "jwks_url": keycloak_jwks_url,
            "default_role": "provisioner"
        }))
        .send()
        .await
        .expect("Failed to configure JWT auth");

    assert!(
        config_jwt.status().is_success(),
        "Failed to configure JWT auth: {}",
        config_jwt.text().await.unwrap()
    );

    // Create a policy for secret access
    let create_policy = client
        .put(&format!("{}/v1/sys/policy/test-policy", vault_url))
        .header("X-Vault-Token", root_token)
        .json(&json!({
            "policy": "path \"secret/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}"
        }))
        .send()
        .await
        .expect("Failed to create policy");

    assert!(
        create_policy.status().is_success(),
        "Failed to create policy: {}",
        create_policy.text().await.unwrap()
    );

    // Create a role for JWT authentication matching Keycloak token structure
    let keycloak_issuer = format!("http://{}:8080/realms/master", keycloak_container_id);
    let create_role = client
        .post(&format!("{}/v1/auth/jwt/role/provisioner", vault_url))
        .header("X-Vault-Token", root_token)
        .json(&json!({
            "role_type": "jwt",
            "user_claim": "azp",
            "bound_issuer": keycloak_issuer,
            "bound_audiences": ["account"],
            "bound_claims": {
                "role": "provisioner"
            },
            "clock_skew_leeway": 60,
            "token_policies": ["test-policy"],
            "token_ttl": token_ttl,
            "token_max_ttl": "24h"
        }))
        .send()
        .await
        .expect("Failed to create JWT role");

    assert!(
        create_role.status().is_success(),
        "Failed to create JWT role: {}",
        create_role.text().await.unwrap()
    );

    // Enable KV v2 secrets engine (in dev mode, 'secret/' is already mounted as kv-v2)
    // So we don't need to create it again

    (vault_url, root_token.to_string(), container)
}