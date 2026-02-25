#!/bin/bash

#  Copyright (c) 2026 Metaform Systems, Inc
#
#  This program and the accompanying materials are made available under the
#  terms of the Apache License, Version 2.0 which is available at
#  https://www.apache.org/licenses/LICENSE-2.0
#
#  SPDX-License-Identifier: Apache-2.0
#
#  Contributors:
#       Metaform Systems, Inc. - initial API and implementation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

echo "======================================"
echo "Building E2E Test Client Binary"
echo "======================================"
echo ""

cd "${WORKSPACE_ROOT}"

# Build the test client binary for the target architecture
# Note: If building on macOS for Linux containers, you may need cross-compilation
echo "Building vault-test binary..."

# Check if we need to cross-compile (macOS to Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS - checking for Linux target..."

    # Try to build for Linux (requires cross or docker)
    if command -v cross &> /dev/null; then
        echo "Using cross for cross-compilation..."
        cross build --bin vault-test --package vault-e2e-test-client --release --target x86_64-unknown-linux-musl
        BINARY_PATH="${WORKSPACE_ROOT}/target/x86_64-unknown-linux-musl/release/vault-test"
    else
        echo "WARNING: 'cross' not found. Attempting native build..."
        echo "This may not work if the test pods are Linux containers."
        echo "Install cross with: cargo install cross"
        echo ""
        cargo build --bin vault-test --package vault-e2e-test-client --release
        BINARY_PATH="${WORKSPACE_ROOT}/target/release/vault-test"
    fi
else
    # Linux - build normally
    echo "Building for native Linux..."
    cargo build --bin vault-test --package vault-e2e-test-client --release
    BINARY_PATH="${WORKSPACE_ROOT}/target/release/vault-test"
fi

if [ ! -f "${BINARY_PATH}" ]; then
    echo "ERROR: Binary not found at ${BINARY_PATH}"
    exit 1
fi

echo ""
echo "Binary built successfully: ${BINARY_PATH}"
echo "Binary size: $(du -h "${BINARY_PATH}" | cut -f1)"
echo ""

# Copy to a known location for tests
mkdir -p "${E2E_DIR}/bin"
cp "${BINARY_PATH}" "${E2E_DIR}/bin/vault-test"
echo "Binary copied to: ${E2E_DIR}/bin/vault-test"
echo ""

echo "======================================"
echo "Build complete!"
echo "======================================"
