# Makefile for E2E tests
# Makes it easier to run common commands

.PHONY: help setup setup-consumer-did verify build build-siglet test test-fast test-verbose cleanup clean all

# Detect if cargo-nextest is available
NEXTEST_INSTALLED := $(shell command -v cargo-nextest 2> /dev/null)

help:
	@echo "E2E Test Commands:"
	@echo "  make setup              - Setup Kind cluster and deploy all infrastructure"
	@echo "  make setup-consumer-did - Provision consumer DID server (idempotent)"
	@echo "  make verify         - Verify E2E environment is ready"
	@echo "  make build          - Build the vault-test Docker image"
	@echo "  make build-siglet   - Build Siglet image"
	@echo "  make test           - Build all images and run E2E tests"
	@echo "  make test-fast      - Build and test (same as test)"
	@echo "  make test-verbose   - Build images and run E2E tests with verbose output"
	@echo "  make cleanup        - Delete Kind cluster"
	@echo "  make clean          - Clean Rust build artifacts"
	@echo "  make all            - Setup, run tests, and cleanup"
	@echo ""
	@echo "Test runner: $(if $(NEXTEST_INSTALLED),cargo-nextest (installed),cargo test (fallback))"
	@echo "  Install nextest for faster tests: cargo install cargo-nextest --locked"

setup:
	@./scripts/setup.sh

setup-consumer-did:
	@./scripts/setup-consumer-did.sh

verify:
	@./scripts/verify-setup.sh

build:
	@./scripts/build-and-load-image.sh

build-siglet:
	@./scripts/build-and-load-siglet.sh

test: build build-siglet setup-consumer-did
ifdef NEXTEST_INSTALLED
	@echo "Running tests with cargo-nextest..."
	@cargo nextest run --manifest-path ../Cargo.toml --package dsdk-facet-e2e-tests --features e2e --run-ignored only
else
	@echo "cargo-nextest not found, using cargo test (install nextest for faster tests)"
	@echo "  cargo install cargo-nextest --locked"
	@cargo test --manifest-path ../Cargo.toml --package dsdk-facet-e2e-tests --features e2e -- --ignored
endif

test-fast: test

test-verbose: build build-siglet setup-consumer-did
ifdef NEXTEST_INSTALLED
	@echo "Running tests with cargo-nextest..."
	@cargo nextest run --manifest-path ../Cargo.toml --package dsdk-facet-e2e-tests --features e2e --run-ignored only --no-capture
else
	@echo "cargo-nextest not found, using cargo test (install nextest for faster tests)"
	@cargo test --manifest-path ../Cargo.toml --package dsdk-facet-e2e-tests --features e2e -- --ignored --nocapture
endif

cleanup:
	@./scripts/cleanup.sh

clean:
	@cargo clean --manifest-path ../Cargo.toml

all: setup test cleanup
