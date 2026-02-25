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

SKIP_SETUP="${E2E_SKIP_SETUP:-false}"
SKIP_CLEANUP="${E2E_SKIP_CLEANUP:-false}"

echo "======================================"
echo "Running E2E Tests"
echo "======================================"
echo ""

# Setup if not skipped
if [ "${SKIP_SETUP}" != "true" ]; then
    echo "Running setup..."
    "${SCRIPT_DIR}/setup.sh"
    echo ""
else
    echo "Skipping setup (E2E_SKIP_SETUP=true)"
    echo ""
fi

# Run tests
echo "Running E2E tests..."
cd "${WORKSPACE_ROOT}"

# Run with --ignored flag to run tests marked with #[ignore]
# IMPORTANT: --test-threads=1 is required because E2E tests share pod names and infrastructure
cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --test-threads=1 --nocapture

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "All tests passed!"
else
    echo "✗ Tests failed with exit code: ${TEST_EXIT_CODE}"

    # Collect diagnostic info on failure
    echo ""
    echo "======================================"
    echo "Collecting diagnostic information..."
    echo "======================================"

    NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

    echo ""
    echo "Pods in namespace ${NAMESPACE}:"
    kubectl get pods -n "${NAMESPACE}" || true

    echo ""
    echo "Vault logs:"
    kubectl logs -n "${NAMESPACE}" -l app=vault --tail=50 || true

    echo ""
    echo "Test pod logs (if exists):"
    kubectl logs -n "${NAMESPACE}" test-app -c vault-agent --tail=50 2>/dev/null || echo "No test-app pod found"
    kubectl logs -n "${NAMESPACE}" test-app -c test-runner --tail=50 2>/dev/null || echo "No test-runner container found"
fi

# Cleanup if not skipped and tests passed
if [ "${SKIP_CLEANUP}" != "true" ] && [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "Running cleanup..."
    "${SCRIPT_DIR}/cleanup.sh"
elif [ "${SKIP_CLEANUP}" = "true" ]; then
    echo ""
    echo "Skipping cleanup (E2E_SKIP_CLEANUP=true)"
    echo "To manually cleanup: ${SCRIPT_DIR}/cleanup.sh"
else
    echo ""
    echo "Skipping cleanup due to test failures (for debugging)"
    echo "To manually cleanup: ${SCRIPT_DIR}/cleanup.sh"
fi

exit $TEST_EXIT_CODE
