#!/bin/bash
# =============================================================================
# OpenSSL Cross-Tests Runner
# =============================================================================
#
# Runs all OpenSSL cross-validation tests.
#
# Usage: ./test/openssl/run_all.sh
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "       OpenSSL Cross-Validation Tests        "
echo "=============================================="
echo ""
echo "OpenSSL version: $(openssl version)"
echo ""

# Track results
PASSED=0
FAILED=0
SKIPPED=0

run_test() {
    local script="$1"
    local name="$2"

    echo "----------------------------------------------"
    echo "Running: $name"
    echo "----------------------------------------------"

    if "$SCRIPT_DIR/$script"; then
        ((PASSED++))
        echo ""
    else
        if [ $? -eq 0 ]; then
            ((SKIPPED++))
        else
            ((FAILED++))
            echo "FAILED: $name"
        fi
        echo ""
    fi
}

# Run tests
run_test "verify_classical.sh" "Classical ECDSA"
run_test "verify_catalyst.sh" "Catalyst Hybrid"
run_test "verify_pqc.sh" "PQC (ML-DSA, SLH-DSA)"

# Summary
echo "=============================================="
echo "              Test Summary                    "
echo "=============================================="
echo ""
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "RESULT: FAILED"
    exit 1
else
    echo "RESULT: PASSED"
    exit 0
fi
