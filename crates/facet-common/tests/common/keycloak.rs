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
use serde::{Deserialize, Serialize};
use testcontainers::core::{ContainerPort, ExecCommand, WaitFor};
use testcontainers::{runners::AsyncRunner, GenericImage, ImageExt};

const KEYCLOAK_IMAGE: &str = "keycloak/keycloak";
const KEYCLOAK_TAG: &str = "latest";
const KEYCLOAK_ADMIN_USER: &str = "admin";
const KEYCLOAK_ADMIN_PASSWORD: &str = "admin";
const KEYCLOAK_PORT: u16 = 8080;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Serialize)]
struct ClientData {
    #[serde(rename = "clientId")]
    client_id: String,
    secret: String,
    enabled: bool,
    protocol: String,
    #[serde(rename = "publicClient")]
    public_client: bool,
    #[serde(rename = "serviceAccountsEnabled")]
    service_accounts_enabled: bool,
    #[serde(rename = "standardFlowEnabled")]
    standard_flow_enabled: bool,
    #[serde(rename = "directAccessGrantsEnabled")]
    direct_access_grants_enabled: bool,
    #[serde(rename = "fullScopeAllowed")]
    full_scope_allowed: bool,
    #[serde(rename = "protocolMappers")]
    protocol_mappers: Vec<ProtocolMapper>,
}

#[derive(Debug, Serialize)]
struct ProtocolMapper {
    name: String,
    protocol: String,
    #[serde(rename = "protocolMapper")]
    protocol_mapper: String,
    #[serde(rename = "consentRequired")]
    consent_required: bool,
    config: ProtocolMapperConfig,
}

#[derive(Debug, Serialize)]
struct ProtocolMapperConfig {
    #[serde(rename = "claim.name")]
    claim_name: String,
    #[serde(rename = "claim.value")]
    claim_value: String,
    #[serde(rename = "jsonType.label")]
    json_type_label: String,
    #[serde(rename = "access.token.claim")]
    access_token_claim: bool,
    #[serde(rename = "id.token.claim")]
    id_token_claim: bool,
    #[serde(rename = "userinfo.token.claim")]
    userinfo_token_claim: bool,
}

pub struct KeycloakSetup {
    pub keycloak_url: String,
    pub keycloak_internal_url: String,
    pub keycloak_container_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
}

/// Cleans up an existing Docker container by name if it exists
async fn cleanup_existing_container(container_name: &str) {
    use testcontainers::bollard::Docker;

    // Try to connect to Docker
    let docker = if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        Docker::connect_with_unix(&docker_host, 120, testcontainers::bollard::API_DEFAULT_VERSION)
            .ok()
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").expect("HOME env var not set");
        let socket_path = format!("{}/.docker/run/docker.sock", home);
        Docker::connect_with_unix(&socket_path, 120, testcontainers::bollard::API_DEFAULT_VERSION)
            .ok()
            .or_else(|| Docker::connect_with_local_defaults().ok())
    } else {
        Docker::connect_with_local_defaults().ok()
    };

    if let Some(docker) = docker {
        use testcontainers::bollard::query_parameters::RemoveContainerOptions;

        // Try to remove the container (best effort - ignore errors)
        let _ = docker.remove_container(
            container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            })
        ).await;
    }
}

/// Helper to create and configure a Keycloak container on a specific network
pub async fn setup_keycloak_container(network: &str) -> (
    KeycloakSetup,
    testcontainers::ContainerAsync<GenericImage>,
) {
    // Use a fixed hostname for predictable network communication
    let keycloak_hostname = "keycloak";

    // Clean up any existing Keycloak container with the same name
    cleanup_existing_container(keycloak_hostname).await;

    let container = GenericImage::new(KEYCLOAK_IMAGE, KEYCLOAK_TAG)
        .with_wait_for(WaitFor::message_on_stdout("Profile dev activated"))
        .with_exposed_port(ContainerPort::Tcp(KEYCLOAK_PORT))
        .with_env_var("KEYCLOAK_ADMIN", KEYCLOAK_ADMIN_USER)
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", KEYCLOAK_ADMIN_USER)
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", KEYCLOAK_ADMIN_PASSWORD)
        .with_env_var("KC_HEALTH_ENABLED", "true")
        .with_container_name(keycloak_hostname)
        .with_network(network)
        .with_cmd(vec!["start-dev", "--health-enabled=true"])
        .start()
        .await
        .unwrap();

    let host_port = container.get_host_port_ipv4(KEYCLOAK_PORT).await.unwrap();
    let keycloak_url = format!("http://127.0.0.1:{}", host_port);
    let keycloak_internal_url = format!("http://{}:{}", keycloak_hostname, KEYCLOAK_PORT);

    // Wait for Keycloak to be fully ready
    let client = Client::new();
    let ready = tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        async {
            loop {
                if client
                    .get(&format!("{}/realms/master", keycloak_url))
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    ).await;

    assert!(ready.is_ok(), "Keycloak failed to become ready within 30 seconds");

    // Disable SSL enforcement after Keycloak is ready
    let exec_result = container
        .exec(ExecCommand::new(vec![
            "/opt/keycloak/bin/kcadm.sh",
            "update",
            "realms/master",
            "-s",
            "sslRequired=NONE",
            "--server",
            &format!("http://localhost:{}", KEYCLOAK_PORT),
            "--realm",
            "master",
            "--user",
            KEYCLOAK_ADMIN_USER,
            "--password",
            KEYCLOAK_ADMIN_PASSWORD,
        ]))
        .await;

    if exec_result.is_err() {
        eprintln!("Warning: Failed to disable SSL in Keycloak, but continuing anyway");
    }

    // Note: get_admin_token below will retry with timeout if SSL config is still propagating
    let (client_id, client_secret) = create_keycloak_client(&keycloak_url).await;

    let token_url = format!("{}/realms/master/protocol/openid-connect/token", keycloak_url);

    (
        KeycloakSetup {
            keycloak_url,
            keycloak_internal_url,
            keycloak_container_id: keycloak_hostname.to_string(),
            client_id,
            client_secret,
            token_url,
        },
        container,
    )
}

async fn create_keycloak_client(keycloak_url: &str) -> (String, String) {
    let client = Client::new();

    // Get admin token
    let admin_token_url = format!("{}/realms/master/protocol/openid-connect/token", keycloak_url);
    let admin_token = get_admin_token(&client, &admin_token_url).await;

    // Create client
    let client_url = format!("{}/admin/realms/master/clients", keycloak_url);
    let client_id = "test-client";
    let client_secret = "test-secret";

    let client_data = ClientData {
        client_id: client_id.to_string(),
        secret: client_secret.to_string(),
        enabled: true,
        protocol: "openid-connect".to_string(),
        public_client: false,
        service_accounts_enabled: true,
        standard_flow_enabled: true,
        direct_access_grants_enabled: false,
        full_scope_allowed: true,
        protocol_mappers: vec![ProtocolMapper {
            name: "role".to_string(),
            protocol: "openid-connect".to_string(),
            protocol_mapper: "oidc-hardcoded-claim-mapper".to_string(),
            consent_required: false,
            config: ProtocolMapperConfig {
                claim_name: "role".to_string(),
                claim_value: "provisioner".to_string(),
                json_type_label: "String".to_string(),
                access_token_claim: true,
                id_token_claim: true,
                userinfo_token_claim: true,
            },
        }],
    };

    let response = client
        .post(&client_url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&client_data)
        .send()
        .await
        .expect("Failed to create Keycloak client");

    assert!(
        response.status().is_success(),
        "Failed to create Keycloak client: {}",
        response.text().await.unwrap()
    );

    (client_id.to_string(), client_secret.to_string())
}

async fn get_admin_token(client: &Client, admin_token_url: &str) -> String {
    let params = [
        ("username", KEYCLOAK_ADMIN_USER),
        ("password", KEYCLOAK_ADMIN_PASSWORD),
        ("client_id", "admin-cli"),
        ("grant_type", "password"),
    ];

    // Retry getting admin token with timeout (SSL configuration may still be propagating)
    let token_response = tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        async {
            loop {
                let response = client
                    .post(admin_token_url)
                    .form(&params)
                    .send()
                    .await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        return resp.json::<TokenResponse>().await
                            .expect("Failed to parse token response");
                    }
                    Ok(resp) => {
                        // Check if it's an SSL error that might resolve after config propagates
                        if let Ok(text) = resp.text().await {
                            if text.contains("HTTPS required") {
                                // SSL config still propagating, yield and retry
                                tokio::task::yield_now().await;
                                continue;
                            }
                            panic!("Failed to get admin token: {}", text);
                        }
                    }
                    Err(_) => {
                        // Network error, yield and retry
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    )
    .await
    .expect("Failed to get admin token within 15 seconds");

    token_response.access_token
}
