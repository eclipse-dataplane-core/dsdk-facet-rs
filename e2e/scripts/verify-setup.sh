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

# Script to verify the E2E environment is correctly set up

set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

echo "======================================"
echo "Verifying E2E Environment"
echo "======================================"
echo ""

ERRORS=0

# Check Kind cluster
echo "Checking Kind cluster..."
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Kind cluster '${CLUSTER_NAME}' exists"
else
    echo "✗ Kind cluster '${CLUSTER_NAME}' not found"
    ERRORS=$((ERRORS + 1))
fi

# Check kubectl context
echo ""
echo "Checking kubectl context..."
CURRENT_CONTEXT=$(kubectl config current-context)
if [ "${CURRENT_CONTEXT}" = "kind-${CLUSTER_NAME}" ]; then
    echo "kubectl context is correct: ${CURRENT_CONTEXT}"
else
    echo "✗ kubectl context is '${CURRENT_CONTEXT}', expected 'kind-${CLUSTER_NAME}'"
    ERRORS=$((ERRORS + 1))
fi

# Check namespace
echo ""
echo "Checking namespace..."
if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo "Namespace '${NAMESPACE}' exists"
else
    echo "✗ Namespace '${NAMESPACE}' not found"
    ERRORS=$((ERRORS + 1))
fi

# Check Vault deployment
echo ""
echo "Checking Vault deployment..."
if kubectl get deployment vault -n "${NAMESPACE}" &> /dev/null; then
    echo "Vault deployment exists"

    # Check if Vault is ready
    READY=$(kubectl get deployment vault -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}')
    if [ "${READY}" = "1" ]; then
        echo "Vault pod is ready"
    else
        echo "✗ Vault pod is not ready (ready replicas: ${READY:-0})"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "✗ Vault deployment not found"
    ERRORS=$((ERRORS + 1))
fi

# Check service accounts
echo ""
echo "Checking service accounts..."
for SA in test-app-sa test-app-sa1 test-app-sa2 vault; do
    if kubectl get serviceaccount "${SA}" -n "${NAMESPACE}" &> /dev/null; then
        echo "Service account '${SA}' exists"
    else
        echo "✗ Service account '${SA}' not found"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check ConfigMaps
echo ""
echo "Checking ConfigMaps..."
for CM in vault-agent-config vault-agent-config-short-ttl; do
    if kubectl get configmap "${CM}" -n "${NAMESPACE}" &> /dev/null; then
        echo "ConfigMap '${CM}' exists"
    else
        echo "✗ ConfigMap '${CM}' not found"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check Vault service
echo ""
echo "Checking Vault service..."
if kubectl get service vault -n "${NAMESPACE}" &> /dev/null; then
    echo "Vault service exists"
else
    echo "✗ Vault service not found"
    ERRORS=$((ERRORS + 1))
fi

# Test Vault connectivity (if Vault is ready)
if [ $ERRORS -eq 0 ]; then
    echo ""
    echo "Testing Vault connectivity..."
    VAULT_POD=$(kubectl get pod -n "${NAMESPACE}" -l app=vault -o jsonpath='{.items[0].metadata.name}')

    if kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- env VAULT_TOKEN=root vault status &> /dev/null; then
        echo "Can connect to Vault"
    else
        echo "⚠ Cannot connect to Vault (may not be initialized)"
    fi

    # Check Kubernetes auth
    echo ""
    echo "Checking Vault Kubernetes auth..."
    if kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- env VAULT_TOKEN=root vault auth list 2>/dev/null | grep -q kubernetes; then
        echo "Kubernetes auth method is enabled"
    else
        echo "⚠ Kubernetes auth method not enabled (run configure-vault.sh)"
    fi
fi

# Summary
echo ""
echo "======================================"
if [ $ERRORS -eq 0 ]; then
    echo "All checks passed!"
    echo "======================================"
    echo ""
    echo "Environment is ready for E2E tests."
    echo "Run: cargo test --package dsdk-facet-e2e-tests --features e2e"
    exit 0
else
    echo "✗ ${ERRORS} check(s) failed"
    echo "======================================"
    echo ""
    echo "Please run: cd e2e && ./scripts/setup.sh"
    exit 1
fi
