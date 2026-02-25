# End-to-End Tests for Kubernetes Vault Integration

This directory contains E2E tests for Kubernetes-based JWT authentication with HashiCorp Vault using the sidecar pattern.

## Prerequisites

The E2E tests require the following to be installed:

- **Docker**: Container runtime

- **Kind**: Kubernetes in Docker

- **kubectl**: Kubernetes CLI

- **cross** (macOS only): Cross-compilation tool for building Linux binaries
  - Install with: `cargo install cross`
  - Not required on Linux

## Quick Start

To setup the Kind cluster, deploy test infrastructure, and execute tests, run:

```bash
make all
```
