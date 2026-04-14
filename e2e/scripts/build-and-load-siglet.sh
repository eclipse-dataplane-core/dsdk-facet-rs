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

set -e

# Build the Siglet Docker image and load it into Kind

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
IMAGE_NAME="siglet:local"

echo "======================================"
echo "Building and Loading Siglet Image"
echo "======================================"
echo ""

cd "${WORKSPACE_ROOT}"

# Invalidate the source compilation layer so uncommitted code changes are picked up.
# The dependency layer (cargo chef cook) is still cached.
CACHE_INVALIDATE=$(date +%s)

echo "Building Siglet Docker image..."
DOCKER_BUILDKIT=1 docker build --build-arg CACHE_INVALIDATE="${CACHE_INVALIDATE}" --platform linux/amd64 -f siglet/Dockerfile.test -t "${IMAGE_NAME}" .
echo "Docker image built: ${IMAGE_NAME}"
echo ""

# Load image into Kind cluster
echo "Loading image into Kind cluster '${KIND_CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_NAME}" --name "${KIND_CLUSTER_NAME}"
echo "Image loaded into Kind cluster"
echo ""

E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

# Restart the deployment if it exists so pods pick up the new image.
# `kind load` replaces the image in containerd but Kubernetes won't notice
# because the tag (`siglet:local`) hasn't changed.
if kubectl get deployment siglet -n "${E2E_NAMESPACE}" &>/dev/null; then
    # Re-apply Vault configuration before restarting. Vault runs in dev mode (in-memory
    # storage), so its config is wiped on pod restart. Even without a restart, the
    # token_reviewer_jwt captured at initial setup can expire. Running configure-vault.sh
    # here (idempotent) ensures Vault auth is always valid before siglet starts.
    echo "Re-applying Vault configuration..."
    "${SCRIPT_DIR}/configure-vault.sh"
    echo ""

    echo "Restarting siglet deployment to pick up new image..."
    kubectl rollout restart deployment/siglet -n "${E2E_NAMESPACE}"

    # Wait for the new pod to become Available. This returns as soon as the desired
    # number of replicas are ready — without waiting for old terminating pods to be
    # fully cleaned up (which can stall on slow nodes / macOS Kind clusters).
    if ! kubectl wait --for=condition=available deployment/siglet \
        -n "${E2E_NAMESPACE}" --timeout=300s; then
        echo ""
        echo "ERROR: Siglet deployment did not become available within 300s."
        echo "--- vault-agent logs ---"
        kubectl logs -n "${E2E_NAMESPACE}" -l app=siglet -c vault-agent --tail=30 2>/dev/null || true
        echo "--- siglet container logs ---"
        kubectl logs -n "${E2E_NAMESPACE}" -l app=siglet -c siglet --tail=30 2>/dev/null || true
        exit 1
    fi

    echo "Siglet restarted"
    echo ""
fi

echo "======================================"
echo "Siglet image ready in Kind cluster!"
echo "======================================"
