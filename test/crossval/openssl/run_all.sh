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

# Get badge for status (Shields.io)
get_badge() {
    case "$1" in
        PASS) echo "![PASS](https://img.shields.io/badge/-PASS-success)" ;;
        FAIL) echo "![FAIL](https://img.shields.io/badge/-FAIL-critical)" ;;
        SKIP) echo "![SKIP](https://img.shields.io/badge/-SKIP-yellow)" ;;
        N/A)  echo "-" ;;
        *)    echo "-" ;;
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

# Count results first for executive summary
TOTAL_PASS=$(grep '=PASS$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_FAIL=$(grep '=FAIL$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_SKIP=$(grep '=SKIP$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_TESTS=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))

# Build summary content with executive summary
SUMMARY_CONTENT="## OpenSSL Cross-Compatibility

![OpenSSL 3.6](https://img.shields.io/badge/OpenSSL-3.6-blue) ![QPKI](https://img.shields.io/badge/QPKI-fixtures-green)

### Summary

| ![PASS](https://img.shields.io/badge/-Verified-success) | ![SKIP](https://img.shields.io/badge/-Parsed-yellow) | ![FAIL](https://img.shields.io/badge/-Failed-critical) | Total |
|:-----------:|:---------:|:---------:|:-----:|
| $TOTAL_PASS | $TOTAL_SKIP | $TOTAL_FAIL | $TOTAL_TESTS |

### Results

| Artifact | Classical | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:------:|:--------:|:---------:|"

# Add result rows (clean - badges)
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    ROW="| $artifact"
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XOSL-${artifact}-${algo}"
        STATUS=$(get_result "$TC_ID")
        BADGE=$(get_badge "$STATUS")
        ROW="$ROW | $BADGE"
    done
    ROW="$ROW |"
    SUMMARY_CONTENT="$SUMMARY_CONTENT
$ROW"
done

# Add legend and known limitations
SUMMARY_CONTENT="$SUMMARY_CONTENT

**Legend:** ![PASS](https://img.shields.io/badge/-PASS-success) Verified | ![SKIP](https://img.shields.io/badge/-SKIP-yellow) Parsed only | ![FAIL](https://img.shields.io/badge/-FAIL-critical) Failed | - N/A

### Known Limitations

| Status | Component | Issue |
|:------:|-----------|-------|
| - | Composite | Not supported by OpenSSL (IETF composite OIDs) |

<details>
<summary>Test Case IDs (for traceability)</summary>

| Artifact | EC | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---|:-------|:--------|:-------|:---------|:----------|"

# Add TC-IDs in collapsible section
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    ROW="| $artifact"
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XOSL-${artifact}-${algo}"
        STATUS=$(get_result "$TC_ID")
        if [ "$STATUS" = "N/A" ]; then
            ROW="$ROW | -"
        else
            ROW="$ROW | $TC_ID"
        fi
    done
    ROW="$ROW |"
    SUMMARY_CONTENT="$SUMMARY_CONTENT
$ROW"
done

SUMMARY_CONTENT="$SUMMARY_CONTENT

</details>"

# Output summary
if [ -n "$SUMMARY_OUTPUT" ]; then
    echo "$SUMMARY_CONTENT" >> "$SUMMARY_OUTPUT"
fi

# Always print to terminal
echo "$SUMMARY_CONTENT"
echo ""

# =============================================================================
# Export JSON Results (for CI reporting)
# =============================================================================

JSON_OUTPUT="$SCRIPT_DIR/results.json"
cat > "$JSON_OUTPUT" << EOF
{
  "validator": "OpenSSL",
  "version": "$OPENSSL_VERSION",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total": $TOTAL_TESTS,
  "passed": $TOTAL_PASS,
  "failed": $TOTAL_FAIL,
  "skipped": $TOTAL_SKIP,
  "results": {
EOF

# Add individual results
FIRST=true
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XOSL-${artifact}-${algo}"
        STATUS=$(get_result "$TC_ID")
        if [ "$STATUS" != "N/A" ]; then
            if [ "$FIRST" = true ]; then
                FIRST=false
            else
                echo "," >> "$JSON_OUTPUT"
            fi
            printf '    "%s": "%s"' "$TC_ID" "$STATUS" >> "$JSON_OUTPUT"
        fi
    done
done

cat >> "$JSON_OUTPUT" << EOF

  }
}
EOF

echo "JSON results exported: $JSON_OUTPUT"

# =============================================================================
# Export CTRF Format (Common Test Report Format)
# =============================================================================

CTRF_OUTPUT="$SCRIPT_DIR/ctrf-crosstest-openssl.json"
START_TIME=$(date +%s000)

cat > "$CTRF_OUTPUT" << EOF
{
  "results": {
    "tool": {
      "name": "crosstest-openssl"
    },
    "summary": {
      "tests": $TOTAL_TESTS,
      "passed": $TOTAL_PASS,
      "failed": $TOTAL_FAIL,
      "pending": 0,
      "skipped": $TOTAL_SKIP,
      "other": 0,
      "start": $START_TIME,
      "stop": $(date +%s000)
    },
    "tests": [
EOF

# Add individual test results in CTRF format
FIRST=true
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XOSL-${artifact}-${algo}"
        STATUS=$(get_result "$TC_ID")
        if [ "$STATUS" != "N/A" ]; then
            if [ "$FIRST" = true ]; then
                FIRST=false
            else
                echo "," >> "$CTRF_OUTPUT"
            fi
            # Convert status to CTRF format
            CTRF_STATUS="other"
            case "$STATUS" in
                PASS) CTRF_STATUS="passed" ;;
                FAIL) CTRF_STATUS="failed" ;;
                SKIP) CTRF_STATUS="skipped" ;;
            esac
            printf '      {"name": "%s", "status": "%s"}' "$TC_ID" "$CTRF_STATUS" >> "$CTRF_OUTPUT"
        fi
    done
done

cat >> "$CTRF_OUTPUT" << EOF

    ]
  }
}
EOF

echo "CTRF results exported: $CTRF_OUTPUT"

# =============================================================================
# Final Status
# =============================================================================

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
