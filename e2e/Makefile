# Makefile for E2E tests
# Makes it easier to run common commands

.PHONY: help setup verify build test test-verbose cleanup clean all

help:
	@echo "E2E Test Commands:"
	@echo "  make setup         - Setup Kind cluster and deploy Vault"
	@echo "  make verify        - Verify E2E environment is ready"
	@echo "  make build         - Build the vault-test Docker image and load into Kind"
	@echo "  make test          - Build image and run E2E tests"
	@echo "  make test-verbose  - Build image and run E2E tests with verbose output"
	@echo "  make cleanup       - Delete Kind cluster"
	@echo "  make clean         - Clean Rust build artifacts"
	@echo "  make all           - Setup, run tests, and cleanup"

setup:
	@./scripts/setup.sh

verify:
	@./scripts/verify-setup.sh

build:
	@./scripts/build-and-load-image.sh

test: build
	@cd .. && cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --test-threads=1

test-verbose: build
	@cd .. && cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --test-threads=1 --nocapture

cleanup:
	@./scripts/cleanup.sh

clean:
	@cd .. && cargo clean

all: setup test cleanup
