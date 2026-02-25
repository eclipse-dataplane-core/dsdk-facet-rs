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

NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"
VAULT_TOKEN="root"

echo "Configuring Vault Kubernetes auth..."

# Get Vault pod name
VAULT_POD=$(kubectl get pod -n "${NAMESPACE}" -l app=vault -o jsonpath='{.items[0].metadata.name}')

echo "Using Vault pod: ${VAULT_POD}"

# Function to run Vault commands
vault_cmd() {
    kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- env VAULT_TOKEN="${VAULT_TOKEN}" vault "$@"
}

# Enable Kubernetes auth method
echo "Enabling Kubernetes auth method..."
vault_cmd auth enable kubernetes 2>/dev/null || echo "Kubernetes auth already enabled"

# Get Kubernetes host
K8S_HOST="https://kubernetes.default.svc:443"

# Get service account token and CA cert from the Vault pod itself
echo "Configuring Kubernetes auth backend..."
kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- sh -c "
export VAULT_TOKEN=${VAULT_TOKEN}
export SA_JWT_TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export SA_CA_CRT=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

vault write auth/kubernetes/config \
    token_reviewer_jwt=\"\${SA_JWT_TOKEN}\" \
    kubernetes_host=\"${K8S_HOST}\" \
    kubernetes_ca_cert=\"\${SA_CA_CRT}\" \
    disable_local_ca_jwt=false
"

echo "Kubernetes auth backend configured"

# Create a policy for test applications
echo "Creating test policy..."
kubectl exec -n "${NAMESPACE}" "${VAULT_POD}" -- sh -c "
export VAULT_TOKEN=${VAULT_TOKEN}
vault policy write test-policy - <<'POLICY_EOF'
# Allow full access to secret/ for testing
path \"secret/*\" {
  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]
}

# Allow access to sys/health for health checks
path \"sys/health\" {
  capabilities = [\"read\"]
}
POLICY_EOF
"

echo "Test policy created"

# Create Kubernetes auth roles
echo "Creating Kubernetes auth roles..."

# Role for test-app-sa (default)
vault_cmd write auth/kubernetes/role/test-role \
    bound_service_account_names=test-app-sa \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=test-policy \
    ttl=1h

echo "Created role: test-role (for test-app-sa)"

# Role for test-app-sa1
vault_cmd write auth/kubernetes/role/test-role-sa1 \
    bound_service_account_names=test-app-sa1 \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=test-policy \
    ttl=1h

echo "Created role: test-role-sa1 (for test-app-sa1)"

# Role for test-app-sa2
vault_cmd write auth/kubernetes/role/test-role-sa2 \
    bound_service_account_names=test-app-sa2 \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=test-policy \
    ttl=1h

echo "Created role: test-role-sa2 (for test-app-sa2)"

# Role with short TTL for renewal tests
vault_cmd write auth/kubernetes/role/test-role-short-ttl \
    bound_service_account_names=test-app-sa \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=test-policy \
    ttl=60s

echo "Created role: test-role-short-ttl (60s TTL for renewal tests)"

# Enable KV v2 secrets engine (should already be enabled in dev mode at secret/)
echo "Verifying KV v2 secrets engine..."
vault_cmd secrets list | grep -q "secret/" && echo "KV v2 engine already enabled at secret/" || {
    vault_cmd secrets enable -path=secret kv-v2
    echo "KV v2 engine enabled at secret/"
}

echo ""
echo "======================================"
echo "Vault configuration complete!"
echo "======================================"
echo ""
echo "Configured roles:"
echo "  - test-role (SA: test-app-sa, TTL: 1h)"
echo "  - test-role-sa1 (SA: test-app-sa1, TTL: 1h)"
echo "  - test-role-sa2 (SA: test-app-sa2, TTL: 1h)"
echo "  - test-role-short-ttl (SA: test-app-sa, TTL: 60s)"
echo ""
echo "Root token: ${VAULT_TOKEN}"
echo ""
