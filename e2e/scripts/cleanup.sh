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

CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

echo "======================================"
echo "Cleaning up E2E test environment"
echo "======================================"
echo "Cluster name: ${CLUSTER_NAME}"
echo ""

# Check if cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Kind cluster '${CLUSTER_NAME}' does not exist. Nothing to clean up."
    exit 0
fi

echo "Deleting Kind cluster '${CLUSTER_NAME}'..."
kind delete cluster --name "${CLUSTER_NAME}"
echo "Cluster deleted"
echo ""

echo "======================================"
echo "Cleanup complete"
echo "======================================"
