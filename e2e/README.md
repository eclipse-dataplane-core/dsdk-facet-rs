# E2E Tests

End-to-end tests for the `dsdk-facet-hashicorp-vault` client running in a Kind cluster, authenticating to HashiCorp
Vault through a Vault Agent sidecar.

Siglet's end-to-end tests live in the [siglet repository](https://github.com/eclipse-dataplane-core/siglet).

## Prerequisites

- Docker, Kind, kubectl, cargo

## Quick Start

```bash
cd e2e
make test       # bootstraps cluster on first run, rebuilds the image, runs tests
make cleanup    # tear down Kind cluster when done
```

`make test` is self-bootstrapping: it runs `verify-setup.sh` first, and if any
required component (Kind cluster, Vault) is missing, it runs the full `setup.sh`
before building the image. On subsequent runs the verify check is a no-op and
only the image rebuild + test execution happens.

## Make Targets

| Target               | Description                                                             |
|----------------------|-------------------------------------------------------------------------|
| `setup`              | Bootstrap infra + build/load the image (full ready state)               |
| `ensure-environment` | Run setup.sh only if `verify-setup.sh` fails — used as `test` prereq    |
| `build`              | Build vault-test image and load into Kind                               |
| `test`               | Bootstrap environment (if needed) + rebuild the image + run tests       |
| `test-fast`          | Alias for `test`                                                        |
| `test-verbose`       | Same as `test` with uncaptured stdout                                   |
| `cleanup`            | Delete Kind cluster                                                     |

### Setup vs. test boundary

`setup.sh` provisions infrastructure only (Kind cluster, Vault and its
Kubernetes auth configuration). The application image build (`vault-test:local`)
is owned by the `build` target. This split means `make test` from a clean
machine bootstraps infra once and builds the image exactly once — no duplicate
`kind load` pass.

## Test Runner

Supports both `cargo test` and `cargo nextest` (auto-detected). Install nextest for faster parallel runs:

```bash
cargo install cargo-nextest --locked
```

### Run Specific Tests

```bash
# Single test (nextest)
cargo nextest run -p dsdk-facet-e2e-tests --features e2e --run-ignored only -E 'test(test_hashicorp_vault_client_with_rust_binary)' --no-capture

# All e2e tests
cargo nextest run -p dsdk-facet-e2e-tests --features e2e --run-ignored only
```
