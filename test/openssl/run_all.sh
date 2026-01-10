#!/bin/bash
# =============================================================================
# OpenSSL Cross-Tests Runner
# =============================================================================
#
# Runs all OpenSSL cross-validation tests for:
#   - Certificates (classical + PQC + hybrid)
#   - CSRs (classical + PQC + hybrid + ML-KEM)
#   - CRLs (classical + PQC + hybrid)
#   - OCSP responses (classical + PQC + hybrid)
#   - TSA tokens (classical + PQC + hybrid)
#   - CMS signatures (classical + PQC + hybrid)
#
# REQUIREMENTS: OpenSSL 3.5+ for full PQC support
#
# Usage: ./test/openssl/run_all.sh
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[CrossCompat] =============================================="
echo "[CrossCompat]        OpenSSL Cross-Validation Tests        "
echo "[CrossCompat] =============================================="
echo ""
echo "OpenSSL version: $(openssl version)"
echo ""

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "Detected version: $OPENSSL_VERSION"

# Compare versions
if command -v bc &> /dev/null; then
    NEED_WARNING=$(echo "$OPENSSL_VERSION < 3.5" | bc)
else
    if [[ "$OPENSSL_VERSION" < "3.5" ]]; then
        NEED_WARNING=1
    else
        NEED_WARNING=0
    fi
fi

if [ "$NEED_WARNING" = "1" ]; then
    echo ""
    echo "WARNING: OpenSSL $OPENSSL_VERSION detected."
    echo "         PQC tests require OpenSSL 3.5+"
    echo "         Some tests may be skipped or fail."
    echo ""
fi

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

    if [ -f "$SCRIPT_DIR/$script" ]; then
        if "$SCRIPT_DIR/$script"; then
            ((++PASSED))
            echo ""
        else
            local exit_code=$?
            if [ $exit_code -eq 0 ]; then
                ((++SKIPPED))
            else
                ((++FAILED))
                echo "FAILED: $name (exit code: $exit_code)"
            fi
            echo ""
        fi
    else
        echo "SKIP: Script not found: $script"
        ((++SKIPPED))
        echo ""
    fi
}

# Run all tests
run_test "verify_certs.sh" "Certificate Verification"
run_test "verify_csr.sh" "CSR Verification"
run_test "verify_crl.sh" "CRL Verification"
run_test "verify_fixtures.sh" "Fixture Verification (CMS/OCSP/TSA)"
run_test "verify_ocsp.sh" "OCSP Response Verification"
run_test "verify_tsa.sh" "TSA Token Verification"
run_test "verify_cms.sh" "CMS Signature Verification"
run_test "verify_cms_encrypt.sh" "CMS Encryption Verification"

# Summary
echo "[CrossCompat] =============================================="
echo "[CrossCompat]               Test Summary                    "
echo "[CrossCompat] =============================================="
echo ""
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "[FAIL] OpenSSL Cross-Validation Tests"
    exit 1
else
    echo "[PASS] OpenSSL Cross-Validation Tests"
    exit 0
fi
