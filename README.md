![Facet-RS](/assets/facet-rs.logo.svg)

**Facet-RS** is a Rust library that provides feature building blocks for use with
the [Eclipse Rust Data Plane SDK](https://github.com/eclipse-dataplane-core/dataplane-sdk-rust).

## Overview

Facet-RS includes the following components:

### Distributed Locking

Coordinates exclusive access to shared resources across multiple services or instances.
Features include:

- Reentrant locking
- Automatic expiration of stale locks to prevent deadlocks
- Multiple implementations (in-memory for testing, PostgreSQL for production)

### Token Management

Manages OAuth/JWT token lifecycles with automatic refresh and concurrency control:

- Automatic refresh of expiring tokens
- Distributed coordination to prevent concurrent refresh attempts
- Pluggable token storage and client implementations
- Built-in support for in-memory and persistent storage backends

### S3 Proxy

A proxy for accessing S3-compatible object storage services that supports token-based authentication and access control
with refresh capabilities. Features include:

- Transparent handling of S3 API requests
- Support for multiple S3-compatible storage providers
- Pluggable token verification and access control

## Siglet

Siglet, the data plane built on these components, has moved to its own repository:
[eclipse-dataplane-core/siglet](https://github.com/eclipse-dataplane-core/siglet). Its image is now published as
`ghcr.io/eclipse-dataplane-core/siglet` (from `0.1.7`). Releases up to `siglet-v0.1.6` and their images
(`ghcr.io/eclipse-dataplane-core/dsdk-facet-rs/siglet`) remain available from this repository.

## Build Requirements

Note `cmake` is required to build the S3 proxy.

## Running Tests

### Unit and Integration Tests

Run all tests:
```bash
cargo test
```

Or use [cargo-nextest](https://nexte.st/) for faster parallel execution (optional but recommended):
```bash
# Install nextest (once)
cargo install cargo-nextest --locked

# Run tests
cargo nextest run
```

The project includes a `.config/nextest.toml` configuration that optimizes test execution for testcontainer-based tests.

### E2E Tests

E2E tests require a Kubernetes cluster (Kind). See [e2e/README.md](e2e/README.md) for setup instructions.

```bash
cd e2e
make setup    # One-time setup
make test     # Run e2e tests (auto-detects nextest or falls back to cargo test)
```