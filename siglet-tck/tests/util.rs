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

// Test-support code: unwrap/expect are acceptable here (failures should abort the test).
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{self, Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;
use regex::Regex;
use reqwest::Client;
use serde_json::json;
use siglet::assembly::assemble_postgres;
use siglet::config::{
    ManagementApiAuthConfig, SigletConfig, SignalingAuthConfig, StorageBackend, TokenConfig, TokenSource, TransferType,
    VaultConfig,
};
use siglet::http::build_http_client;
use siglet::server::{
    build_management_api_auth_layers, build_signaling_auth_layer, build_token_api_auth_layer, run_server,
};
use testcontainers::core::logs::LogFrame;
use testcontainers::core::logs::consumer::LogConsumer;
use testcontainers::core::{ContainerPort, Host, IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::hashicorp_vault::HashicorpVault;
use testcontainers_modules::postgres::Postgres;
use tracing::{error, info};

/// Vault transit signing key the siglet derives from `{prefix}-{SIGLET_PC_ID}` = `signing-siglet`.
/// It must exist in Vault before the siglet assembles, because the verification-key resolver
/// reads it during `assemble_memory`.
const SIGNING_KEY_NAME: &str = "signing-siglet";

/// Dev-mode Vault's root token (fixed by the `testcontainers-modules` HashiCorp Vault image).
const VAULT_ROOT_TOKEN: &str = "myroot";

/// Siglet API ports used for the in-process instance.
///
/// `SIGNALING_PORT` is what the TCK container targets (see `dps.tck.properties`). The other three
/// APIs must still bind (the server is fail-fast), so they get ports that avoid the TCK's own
/// host-mapped `8083`.
pub const SIGNALING_PORT: u16 = 8081;
const SIGLET_API_PORT: u16 = 28080;
const REFRESH_API_PORT: u16 = 28082;
const MANAGEMENT_API_PORT: u16 = 28083;

/// Starts a dev-mode Vault container and provisions it for the siglet:
/// enables the transit engine and creates the `signing-siglet` ed25519 key.
///
/// Returns the reachable Vault URL, the path to a file containing the Vault token (the siglet's
/// `KubernetesServiceAccount`/file-based auth reads the token verbatim from this file), and the
/// container handle (kept alive by the caller for the duration of the test).
pub async fn setup_vault() -> (String, PathBuf, ContainerAsync<HashicorpVault>) {
    let container = HashicorpVault::default()
        .start()
        .await
        .expect("failed to start Vault container");
    let host_port = container
        .get_host_port_ipv4(8200)
        .await
        .expect("failed to map Vault port");
    let vault_url = format!("http://127.0.0.1:{host_port}");

    let client = Client::new();

    // Wait for Vault to accept requests.
    for _ in 0..50 {
        if client.get(format!("{vault_url}/v1/sys/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Enable the transit secrets engine (dev mode does not mount it by default).
    let resp = client
        .post(format!("{vault_url}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", VAULT_ROOT_TOKEN)
        .json(&json!({ "type": "transit" }))
        .send()
        .await
        .expect("failed to enable transit engine");
    assert!(
        resp.status().is_success(),
        "enabling transit engine failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // Create the siglet's access-token signing key. EdDSA => ed25519.
    let resp = client
        .post(format!("{vault_url}/v1/transit/keys/{SIGNING_KEY_NAME}"))
        .header("X-Vault-Token", VAULT_ROOT_TOKEN)
        .json(&json!({ "type": "ed25519" }))
        .send()
        .await
        .expect("failed to create signing key");
    assert!(
        resp.status().is_success(),
        "creating signing key failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // The file-based Vault auth reads a token string directly from this file.
    let token_file = std::env::temp_dir().join("siglet_tck_vault_token");
    std::fs::write(&token_file, VAULT_ROOT_TOKEN).expect("failed to write Vault token file");

    (vault_url, token_file, container)
}

/// Starts a Postgres container and returns its connection URL plus the container handle.
///
/// The siglet's `PostgresVault` backend connects to this URL and creates its own schema at
/// assembly time (`CREATE TABLE IF NOT EXISTS`), so no migrations or seeding are needed here.
/// The container handle must be kept alive by the caller for the duration of the test.
pub async fn setup_postgres() -> (String, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("failed to start Postgres container");
    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to map Postgres port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{host_port}/postgres");

    // The Postgres image already waits for its readiness log before `start()` returns; this TCP
    // poll is a cheap extra margin against a race before `assemble_postgres` connects.
    wait_for_port(host_port).await;

    (url, container)
}

/// Builds a Postgres-backed siglet config wired to the provisioned Vault, with signaling auth
/// disabled (so the TCK can call the API without minting JWTs) and one synchronous pull transfer
/// type registered.
pub fn build_config(vault_url: &str, token_file: &Path, pg_url: &str) -> SigletConfig {
    SigletConfig {
        signaling_port: SIGNALING_PORT,
        siglet_api_port: SIGLET_API_PORT,
        refresh_api_port: REFRESH_API_PORT,
        management_api_port: MANAGEMENT_API_PORT,
        storage_backend: StorageBackend::PostgresVault {
            url: pg_url.to_string(),
        },
        signaling_auth: SignalingAuthConfig::Disabled,
        management_api_auth: ManagementApiAuthConfig::Disabled,
        vault: VaultConfig {
            url: Some(vault_url.to_string()),
            token_file: Some(token_file.to_string_lossy().into_owned()),
            use_http_resolution: true,
            ..Default::default()
        },
        transfer_types: vec![
            TransferType::builder()
                .transfer_type("https://w3id.org/dspace-sig/profile/http-pull".to_string())
                .endpoint_type("https://w3id.org/dspace-sig/profile/http-pull".to_string())
                .endpoint("http://host.docker.internal:8081/pull".to_string())
                .token_source(TokenSource::Provider)
                .build(),
        ],
        token: TokenConfig {
            refresh_endpoint: Some(format!("http://host.docker.internal:{}/token", REFRESH_API_PORT)),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Assembles a real siglet from `cfg` and serves all four APIs in a background task, then blocks
/// until the signaling port accepts connections.
pub async fn start_siglet(cfg: SigletConfig) {
    cfg.validate().expect("invalid siglet config");

    let http_client = build_http_client(&cfg.http_client);
    let signaling_auth = build_signaling_auth_layer(&cfg.signaling_auth, http_client.clone());
    let token_api_auth = build_token_api_auth_layer(&cfg.signaling_auth, http_client.clone());
    let (mgmt_read_auth, mgmt_write_auth) =
        build_management_api_auth_layers(&cfg.management_api_auth, http_client.clone());

    let runtime = assemble_postgres(&cfg, http_client)
        .await
        .expect("failed to assemble siglet runtime");

    let bind = cfg.bind;
    let signaling_port = cfg.signaling_port;

    tokio::spawn(async move {
        if let Err(e) = run_server(
            bind,
            cfg.signaling_port,
            cfg.siglet_api_port,
            cfg.refresh_api_port,
            cfg.management_api_port,
            runtime.sdk,
            runtime.token_api_handler,
            runtime.refresh_handler,
            runtime.management_handler,
            signaling_auth,
            token_api_auth,
            mgmt_read_auth,
            mgmt_write_auth,
        )
        .await
        {
            error!("siglet server exited: {e}");
        }
    });

    wait_for_port(signaling_port).await;
}

/// Polls the loopback address until the given port accepts a TCP connection.
async fn wait_for_port(port: u16) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    for _ in 0..100 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("siglet signaling API never became reachable on port {port}");
}

/// Runs the Eclipse Dataspace DPS TCK container against the host-run siglet.
///
/// The container reaches the siglet via `host.docker.internal`; its own callback/verification
/// server is on `8083`, mapped 1:1 to the host. `.start()` blocks until the TCK prints
/// `Test run complete`; pass/fail is scraped from its logs by `reporter`.
pub async fn setup_tck_container(reporter: TckTestReporter) -> ContainerAsync<GenericImage> {
    let props = Path::new("tests/dps.tck.properties");
    GenericImage::new("eclipsedataspacetck/dps-tck-runtime", "1.2.0")
        .with_exposed_port(8083.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Test run complete"))
        .with_mapped_port(8083, ContainerPort::Tcp(8083))
        .with_mount(Mount::bind_mount(
            path::absolute(props).unwrap().as_os_str().to_str().unwrap(),
            "/etc/tck/config.properties",
        ))
        .with_host("host.docker.internal", Host::HostGateway)
        .with_log_consumer(reporter)
        .start()
        .await
        .expect("failed to start TCK container")
}

/// Collects TCK failures by scraping `FAILED: <case>` lines from container logs.
#[derive(Clone, Default)]
pub struct TckTestReporter {
    failures: Arc<Mutex<Vec<String>>>,
}

static FAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"FAILED: (\w+:\d+-\d+)").unwrap());

impl LogConsumer for TckTestReporter {
    fn accept<'a>(&'a self, record: &'a LogFrame) -> BoxFuture<'a, ()> {
        let log = String::from_utf8_lossy(record.bytes());

        if let Some(caps) = FAIL_REGEX.captures(&log) {
            self.failures.lock().unwrap().push(caps[1].to_string());
        }

        info!("{}", log.trim_end());

        futures::future::ready(()).boxed()
    }
}

impl TckTestReporter {
    pub fn failures(&self) -> Vec<String> {
        self.failures.lock().unwrap().clone()
    }
}
