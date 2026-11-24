use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use testcontainers::bollard::{Docker, secret::NetworkCreateRequest};

/// Get an available port by binding to port 0 and retrieving the assigned port
pub fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    let port = listener.local_addr().expect("Failed to get local address").port();
    drop(listener);
    port
}

/// Wait for a server port to be ready by polling with TCP connections.
pub async fn wait_for_port_ready(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("Server at {} did not become ready within {:?}", addr, timeout))
}

/// Creates a Docker network and returns its name.
///
/// Automatically cleans up old test networks from dead processes to prevent Docker
/// address pool exhaustion. Networks are not automatically cleaned up by testcontainers
/// when containers drop, so we must manually remove them.
///
/// Network names include the process ID to avoid race conditions when tests run in parallel.
/// Each process only cleans up networks from processes that no longer exist.
///
/// Note: Rust Testcontainers lacks network creation functionality (which is available in Go and Java).
pub async fn create_network() -> String {
    // Try to connect to Docker using the socket path from DOCKER_HOST env var,
    // or fall back to platform-specific defaults
    let docker = if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        Docker::connect_with_unix(&docker_host, 120, testcontainers::bollard::API_DEFAULT_VERSION)
            .expect("Failed to connect to Docker via DOCKER_HOST")
    } else if cfg!(target_os = "macos") {
        // On macOS with Docker Desktop, socket is typically at ~/.docker/run/docker.sock
        let home = std::env::var("HOME").expect("HOME env var not set");
        let socket_path = format!("{}/.docker/run/docker.sock", home);
        Docker::connect_with_unix(&socket_path, 120, testcontainers::bollard::API_DEFAULT_VERSION).unwrap_or_else(
            |_| {
                // Fall back to default if custom path doesn't work
                Docker::connect_with_local_defaults().expect("Failed to connect to Docker")
            },
        )
    } else {
        Docker::connect_with_local_defaults().expect("Failed to connect to Docker")
    };

    // Clean up networks from dead processes before creating a new one
    cleanup_old_test_networks(&docker).await;

    // Include process ID in network name to prevent race conditions
    let pid = std::process::id();
    let network_name = format!("test-network-{}-{}", pid, uuid::Uuid::new_v4());

    let config = NetworkCreateRequest {
        name: network_name.clone(),
        ..Default::default()
    };

    docker
        .create_network(config)
        .await
        .expect("Failed to create Docker network");

    network_name
}

/// Cleans up test networks from dead processes to prevent address pool exhaustion
async fn cleanup_old_test_networks(docker: &Docker) {
    use testcontainers::bollard::query_parameters::ListNetworksOptions;

    // List all networks (best effort - ignore errors)
    let networks = match docker.list_networks(Option::<ListNetworksOptions>::None).await {
        Ok(networks) => networks,
        Err(_) => return,
    };

    let current_pid = std::process::id();

    for network in networks {
        if let Some(name) = &network.name {
            // Parse network names matching pattern: test-network-{pid}-{uuid}
            if let Some(pid) = parse_network_pid(name) {
                // Skip our own process's networks
                if pid == current_pid {
                    continue;
                }

                // Skip networks from processes that are still running
                if is_process_running(pid) {
                    continue;
                }

                // Remove networks from dead processes (best effort - ignore errors)
                let _ = docker.remove_network(name).await;
            }
        }
    }
}

/// Parses the PID from a network name with format: test-network-{pid}-{uuid}
fn parse_network_pid(name: &str) -> Option<u32> {
    if !name.starts_with("test-network-") {
        return None;
    }

    // Extract the PID part: test-network-{pid}-{uuid}
    let parts: Vec<&str> = name.strip_prefix("test-network-")?.split('-').collect();
    if parts.is_empty() {
        return None;
    }

    parts[0].parse::<u32>().ok()
}

/// Checks if a process with the given PID is currently running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use std::io::ErrorKind;

    // On Unix systems, we can check if a process exists by trying to send signal 0
    // This doesn't actually send a signal but checks if the process exists
    unsafe {
        // kill(pid, 0) returns 0 if process exists and we have permission to signal it
        // Returns -1 with ESRCH if process doesn't exist
        // Returns -1 with EPERM if process exists but we can't signal it (still alive)
        let result = libc::kill(pid as i32, 0);
        if result == 0 {
            return true;
        }

        // Check errno to distinguish between "no such process" and "permission denied"
        let err = std::io::Error::last_os_error();
        match err.kind() {
            ErrorKind::PermissionDenied => true, // Process exists but we can't signal it
            ErrorKind::NotFound => false,        // ESRCH: No such process
            _ => false,
        }
    }
}

/// Host on which published container ports are reachable from the test process.
///
/// Defaults to `127.0.0.1`. Set `TESTCONTAINERS_HOST_OVERRIDE` (the variable testcontainers itself
/// honours) when the Docker daemon publishes ports elsewhere, e.g. inside a dev container that uses
/// the host's Docker socket, where ports are reachable via the Docker network gateway.
pub fn container_host() -> String {
    std::env::var("TESTCONTAINERS_HOST_OVERRIDE")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}
