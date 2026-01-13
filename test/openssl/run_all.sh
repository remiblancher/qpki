#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test Orchestrator
# =============================================================================
#
# Runs all OpenSSL cross-validation tests and generates a summary matrix.
#
# Usage: ./test/openssl/run_all.sh
#
# Output: Writes summary to $GITHUB_STEP_SUMMARY if available.
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
LIB_DIR="$SCRIPT_DIR/lib"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Results storage (file-based for bash 3.x compatibility)
RESULTS_FILE=$(mktemp)
trap "rm -f $RESULTS_FILE" EXIT

# =============================================================================
# Helper Functions
# =============================================================================

# Set result for a test case
set_result() {
    local tc_id="$1"
    local status="$2"  # PASS, FAIL, SKIP, N/A
    echo "$tc_id=$status" >> "$RESULTS_FILE"
}

# Get result for a test case
get_result() {
    local tc_id="$1"
    local result
    result=$(grep "^${tc_id}=" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d= -f2)
    echo "${result:-N/A}"
}

# Get emoji for status
get_emoji() {
    case "$1" in
        PASS) echo "✅" ;;
        FAIL) echo "❌" ;;
        SKIP) echo "⚠️" ;;
        N/A)  echo "❌" ;;
        *)    echo "❓" ;;
    esac
}

# =============================================================================
# Check Prerequisites
# =============================================================================

echo "============================================================"
echo "[CrossCompat] OpenSSL 3.6 Interoperability Tests"
echo "============================================================"
echo ""

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version 2>/dev/null | head -1)
echo "OpenSSL: $OPENSSL_VERSION"
echo ""

# Check fixtures exist
if [ ! -d "$FIXTURES" ]; then
    echo -e "${RED}ERROR: Fixtures not found at $FIXTURES${NC}"
    echo "       Run ./test/generate_qpki_fixtures.sh first"
    exit 1
fi

# =============================================================================
# Source Test Libraries
# =============================================================================

for lib in verify_certs verify_crl verify_csr verify_cms verify_cms_encrypt verify_ocsp verify_tsa; do
    if [ -f "$LIB_DIR/${lib}.sh" ]; then
        source "$LIB_DIR/${lib}.sh"
    else
        echo -e "${YELLOW}WARNING: $LIB_DIR/${lib}.sh not found${NC}"
    fi
done

# =============================================================================
# Run All Tests
# =============================================================================

# Run certificate tests
if type run_cert_tests &>/dev/null; then
    echo ">>> Running Certificate Tests..."
    run_cert_tests
    echo ""
fi

# Run CRL tests
if type run_crl_tests &>/dev/null; then
    echo ">>> Running CRL Tests..."
    run_crl_tests
    echo ""
fi

# Run CSR tests
if type run_csr_tests &>/dev/null; then
    echo ">>> Running CSR Tests..."
    run_csr_tests
    echo ""
fi

# Run CMS tests
if type run_cms_tests &>/dev/null; then
    echo ">>> Running CMS Tests..."
    run_cms_tests
    echo ""
fi

# Run CMS Encryption tests
if type run_cms_encrypt_tests &>/dev/null; then
    echo ">>> Running CMS Encryption Tests..."
    run_cms_encrypt_tests
    echo ""
fi

# Run OCSP tests
if type run_ocsp_tests &>/dev/null; then
    echo ">>> Running OCSP Tests..."
    run_ocsp_tests
    echo ""
fi

# Run TSA tests
if type run_tsa_tests &>/dev/null; then
    echo ">>> Running TSA Tests..."
    run_tsa_tests
    echo ""
fi

# =============================================================================
# Generate Summary Matrix
# =============================================================================

echo "============================================================"
echo "Generating Summary Matrix..."
echo "============================================================"
echo ""

# Determine output destination
SUMMARY_OUTPUT=""
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    SUMMARY_OUTPUT="$GITHUB_STEP_SUMMARY"
fi

# Build summary content
SUMMARY_CONTENT="## 🔐 OpenSSL 3.6 Interoperability

| Artefact | Classical | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:------:|:--------:|:---------:|"

# Add result rows
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    ROW="| $artifact"
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XOSL-${artifact}-${algo}"
        STATUS=$(get_result "$TC_ID")
        EMOJI=$(get_emoji "$STATUS")
        if [ "$STATUS" = "PASS" ]; then
            ROW="$ROW | $EMOJI $TC_ID"
        elif [ "$STATUS" = "N/A" ]; then
            ROW="$ROW | ❌"
        else
            ROW="$ROW | $EMOJI"
        fi
    done
    ROW="$ROW |"
    SUMMARY_CONTENT="$SUMMARY_CONTENT
$ROW"
done

# Add legend
SUMMARY_CONTENT="$SUMMARY_CONTENT

**Legend:** ✅ Verified | ⚠️ Parsed only | ❌ Not supported"

# Output summary
if [ -n "$SUMMARY_OUTPUT" ]; then
    echo "$SUMMARY_CONTENT" >> "$SUMMARY_OUTPUT"
fi

# Always print to terminal
echo "$SUMMARY_CONTENT"
echo ""

# =============================================================================
# Final Status
# =============================================================================

# Count results
TOTAL_PASS=$(grep '=PASS$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_FAIL=$(grep '=FAIL$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_SKIP=$(grep '=SKIP$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')

echo "============================================================"
echo "Results: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_SKIP skipped"
echo "============================================================"

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some OpenSSL cross-tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] All OpenSSL cross-tests completed${NC}"
    exit 0
fi
