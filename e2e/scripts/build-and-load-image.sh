#!/bin/bash
set -e

# Build the test binary and load it into a Docker image for Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
IMAGE_NAME="vault-test:local"

echo "======================================"
echo "Building and Loading Test Image"
echo "======================================"
echo ""

# Step 1: Build the binary
echo "Step 1: Building vault-test binary..."
"${SCRIPT_DIR}/build-test-client.sh"
echo ""

# Step 2: Build Docker image
echo "Step 2: Building Docker image..."
cd "${E2E_DIR}/test-client"

# Copy the binary to the Docker context
cp "${E2E_DIR}/bin/vault-test" .

# Build the image
docker build -t "${IMAGE_NAME}" .

# Clean up copied binary
rm -f vault-test

echo "Docker image built: ${IMAGE_NAME}"
echo ""

# Step 3: Load image into Kind cluster
echo "Step 3: Loading image into Kind cluster '${KIND_CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_NAME}" --name "${KIND_CLUSTER_NAME}"
echo "Image loaded into Kind cluster"
echo ""

echo "======================================"
echo "Image ready in Kind cluster!"
echo "======================================"
