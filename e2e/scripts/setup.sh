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

# Configuration
CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

echo "======================================"
echo "Setting up E2E test environment"
echo "======================================"
echo "Cluster name: ${CLUSTER_NAME}"
echo "Namespace: ${NAMESPACE}"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v kind &> /dev/null; then
    echo "ERROR: kind is not installed"
    echo "Install: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed"
    echo "Install: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "ERROR: docker is not installed"
    exit 1
fi

echo "All prerequisites installed"
echo ""

# Create Kind cluster if it doesn't exist
echo "Checking Kind cluster..."
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Kind cluster '${CLUSTER_NAME}' already exists"
else
    echo "Creating Kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --name "${CLUSTER_NAME}" --wait 60s
    echo "Kind cluster created"
fi
echo ""

# Set kubectl context
echo "Setting kubectl context..."
kubectl config use-context "kind-${CLUSTER_NAME}"
echo "Context set"
echo ""

# Create namespace
echo "Creating namespace..."
kubectl apply -f "${MANIFESTS_DIR}/namespace.yaml"
echo "Namespace created"
echo ""

# Deploy service accounts and RBAC
echo "Deploying service accounts and RBAC..."
kubectl apply -f "${MANIFESTS_DIR}/service-accounts.yaml"
echo "Service accounts deployed"
echo ""

# Deploy Vault
echo "Deploying Vault..."
kubectl apply -f "${MANIFESTS_DIR}/vault-deployment.yaml"
echo "Waiting for Vault to be ready..."
kubectl wait --for=condition=ready pod -l app=vault -n "${NAMESPACE}" --timeout=120s
echo "Vault deployed and ready"
echo ""

# Deploy Vault agent configs
echo "Deploying Vault agent configurations..."
kubectl apply -f "${MANIFESTS_DIR}/vault-agent-config.yaml"
echo "Vault agent configs deployed"
echo ""

# Configure Vault
echo "Configuring Vault..."
"${SCRIPT_DIR}/configure-vault.sh"
echo "Vault configured"
echo ""

# Build test client binary and load into Kind
echo "Building test client image and loading into Kind..."
"${SCRIPT_DIR}/build-and-load-image.sh"
echo "Test client image built and loaded"
echo ""

echo "======================================"
echo "E2E environment setup complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Run tests: cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --test-threads=1"
echo "  2. Or use Make: cd e2e && make test"
echo "  3. Cleanup: cd e2e && ./scripts/cleanup.sh"
echo ""
echo "Useful commands:"
echo "  - View Vault logs: kubectl logs -n ${NAMESPACE} -l app=vault"
echo "  - Port-forward Vault UI: kubectl port-forward -n ${NAMESPACE} svc/vault 8200:8200"
echo "  - List pods: kubectl get pods -n ${NAMESPACE}"
echo "  - Rebuild test image: cd e2e && ./scripts/build-and-load-image.sh"
