#!/bin/bash
set -e

# Build the vault-test Docker image and load it into Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
IMAGE_NAME="vault-test:local"

echo "======================================"
echo "Building and Loading Test Image"
echo "======================================"
echo ""

echo "Building Docker image..."
cd "${WORKSPACE_ROOT}"
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -f e2e/test-client/Dockerfile -t "${IMAGE_NAME}" .
echo "Docker image built: ${IMAGE_NAME}"
echo ""

# Load image into Kind cluster
echo "Loading image into Kind cluster '${KIND_CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_NAME}" --name "${KIND_CLUSTER_NAME}"
echo "Image loaded into Kind cluster"
echo ""

echo "======================================"
echo "Image ready in Kind cluster!"
echo "======================================"
