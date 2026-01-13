#!/bin/bash
# =============================================================================
# BouncyCastle Cross-Test Summary Generator
# =============================================================================
#
# Parses surefire test reports and generates a summary matrix.
#
# Usage: ./test/bouncycastle/generate_summary.sh
#
# Output: Writes summary to $GITHUB_STEP_SUMMARY if available.
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUREFIRE_DIR="$SCRIPT_DIR/target/surefire-reports"

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

# Parse a test class result from surefire XML
parse_test_class() {
    local xml_file="$1"

    if [ ! -f "$xml_file" ]; then
        echo "N/A"
        return
    fi

    # Extract test counts
    local tests=$(grep -oE 'tests="[0-9]+"' "$xml_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local failures=$(grep -oE 'failures="[0-9]+"' "$xml_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local errors=$(grep -oE 'errors="[0-9]+"' "$xml_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local skipped=$(grep -oE 'skipped="[0-9]+"' "$xml_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')

    tests=${tests:-0}
    failures=${failures:-0}
    errors=${errors:-0}
    skipped=${skipped:-0}

    local passed=$((tests - failures - errors - skipped))

    if [ "$tests" -eq 0 ]; then
        echo "N/A"
    elif [ "$failures" -gt 0 ] || [ "$errors" -gt 0 ]; then
        echo "FAIL"
    elif [ "$skipped" -eq "$tests" ]; then
        echo "SKIP"
    elif [ "$passed" -gt 0 ]; then
        echo "PASS"
    else
        echo "SKIP"
    fi
}

# =============================================================================
# Check Prerequisites
# =============================================================================

echo "============================================================"
echo "[CrossCompat] BouncyCastle Summary Generator"
echo "============================================================"
echo ""

# Check surefire reports exist
if [ ! -d "$SUREFIRE_DIR" ]; then
    echo -e "${RED}ERROR: Surefire reports not found at $SUREFIRE_DIR${NC}"
    echo "       Run 'mvn test' first"
    exit 1
fi

# =============================================================================
# Parse Test Results
# =============================================================================

echo "Parsing test results..."
echo ""

# CERT tests
# Classical (ECDSA)
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.ClassicalVerifyTest.xml")
set_result "TC-XBC-CERT-EC" "$RESULT"
echo "  TC-XBC-CERT-EC: $RESULT"

# ML-DSA (parse PQCVerifyTest for ML-DSA tests)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" ]; then
    if grep -q 'testCrossCompat_Verify_MLDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CERT-ML" "FAIL"
        else
            set_result "TC-XBC-CERT-ML" "PASS"
        fi
    else
        set_result "TC-XBC-CERT-ML" "N/A"
    fi
else
    set_result "TC-XBC-CERT-ML" "N/A"
fi
echo "  TC-XBC-CERT-ML: $(get_result TC-XBC-CERT-ML)"

# SLH-DSA (parse PQCVerifyTest for SLH-DSA tests)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" ]; then
    if grep -q 'testCrossCompat_Verify_SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CERT-SLH" "FAIL"
        else
            set_result "TC-XBC-CERT-SLH" "PASS"
        fi
    else
        set_result "TC-XBC-CERT-SLH" "N/A"
    fi
else
    set_result "TC-XBC-CERT-SLH" "N/A"
fi
echo "  TC-XBC-CERT-SLH: $(get_result TC-XBC-CERT-SLH)"

# Catalyst
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.CatalystVerifyTest.xml")
set_result "TC-XBC-CERT-CAT" "$RESULT"
echo "  TC-XBC-CERT-CAT: $RESULT"

# Composite
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeVerifyTest.xml")
set_result "TC-XBC-CERT-COMP" "$RESULT"
echo "  TC-XBC-CERT-COMP: $RESULT"

# CRL tests
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.CRLVerifyTest.xml")
if [ "$RESULT" != "N/A" ]; then
    set_result "TC-XBC-CRL-EC" "$RESULT"
    set_result "TC-XBC-CRL-ML" "$RESULT"
    set_result "TC-XBC-CRL-SLH" "$RESULT"
fi
# Catalyst CRL
CATALYST_CRL=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.CatalystCRLVerifyTest.xml")
if [ "$CATALYST_CRL" != "N/A" ]; then
    set_result "TC-XBC-CRL-CAT" "$CATALYST_CRL"
else
    set_result "TC-XBC-CRL-CAT" "$(get_result TC-XBC-CRL-EC)"
fi
# Composite CRL
COMP_CRL=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeCRLVerifyTest.xml")
set_result "TC-XBC-CRL-COMP" "${COMP_CRL:-N/A}"
echo "  TC-XBC-CRL-*: EC=$(get_result TC-XBC-CRL-EC), CAT=$(get_result TC-XBC-CRL-CAT), COMP=$(get_result TC-XBC-CRL-COMP)"

# CSR tests
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" ]; then
    # ECDSA CSR
    if grep -q 'testCrossCompat_Verify_CSR_ECDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*ECDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-EC" "FAIL"
        else
            set_result "TC-XBC-CSR-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-EC" "N/A"
    fi

    # ML-DSA CSR
    if grep -q 'testCrossCompat_Verify_CSR_MLDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*MLDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-ML" "FAIL"
        else
            set_result "TC-XBC-CSR-ML" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-ML" "N/A"
    fi

    # SLH-DSA CSR
    if grep -q 'testCrossCompat_Verify_CSR_SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-SLH" "FAIL"
        else
            set_result "TC-XBC-CSR-SLH" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-SLH" "N/A"
    fi

    # Catalyst CSR
    if grep -q 'testCrossCompat_Verify_CSR_Catalyst' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Catalyst' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-CAT" "FAIL"
        else
            set_result "TC-XBC-CSR-CAT" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-CAT" "N/A"
    fi

    # Composite CSR - parse test
    if grep -q 'testCrossCompat_Parse_CSR_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_CSR_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-COMP" "FAIL"
        else
            set_result "TC-XBC-CSR-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-COMP" "N/A"
    fi
else
    set_result "TC-XBC-CSR-EC" "N/A"
    set_result "TC-XBC-CSR-ML" "N/A"
    set_result "TC-XBC-CSR-SLH" "N/A"
    set_result "TC-XBC-CSR-CAT" "N/A"
    set_result "TC-XBC-CSR-COMP" "N/A"
fi
echo "  TC-XBC-CSR-*: EC=$(get_result TC-XBC-CSR-EC), ML=$(get_result TC-XBC-CSR-ML), SLH=$(get_result TC-XBC-CSR-SLH), CAT=$(get_result TC-XBC-CSR-CAT), COMP=$(get_result TC-XBC-CSR-COMP)"

# CMS tests
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" ]; then
    if grep -q 'testCrossCompat_Verify_CMS_Classical' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Classical' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-EC" "FAIL"
        else
            set_result "TC-XBC-CMS-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-EC" "N/A"
    fi

    if grep -q 'testCrossCompat_Verify_CMS_MLDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*MLDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-ML" "FAIL"
        else
            set_result "TC-XBC-CMS-ML" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-ML" "N/A"
    fi

    if grep -q 'testCrossCompat_Verify_CMS_SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*SLHDSA' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-SLH" "FAIL"
        else
            set_result "TC-XBC-CMS-SLH" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-SLH" "N/A"
    fi

    if grep -q 'testCrossCompat_Verify_CMS_Catalyst' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Catalyst' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-CAT" "FAIL"
        else
            set_result "TC-XBC-CMS-CAT" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-CAT" "N/A"
    fi

    # Composite CMS - parse test
    if grep -q 'testCrossCompat_Parse_CMS_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_CMS_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-COMP" "FAIL"
        else
            set_result "TC-XBC-CMS-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-COMP" "N/A"
    fi
else
    set_result "TC-XBC-CMS-EC" "N/A"
    set_result "TC-XBC-CMS-ML" "N/A"
    set_result "TC-XBC-CMS-SLH" "N/A"
    set_result "TC-XBC-CMS-CAT" "N/A"
    set_result "TC-XBC-CMS-COMP" "N/A"
fi
echo "  TC-XBC-CMS-*: EC=$(get_result TC-XBC-CMS-EC), ML=$(get_result TC-XBC-CMS-ML), SLH=$(get_result TC-XBC-CMS-SLH), CAT=$(get_result TC-XBC-CMS-CAT)"

# OCSP tests
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml")
if [ "$RESULT" != "N/A" ]; then
    set_result "TC-XBC-OCSP-EC" "$RESULT"
    set_result "TC-XBC-OCSP-ML" "$RESULT"
    set_result "TC-XBC-OCSP-SLH" "$RESULT"
    set_result "TC-XBC-OCSP-CAT" "$RESULT"
fi
# Composite OCSP - parse test
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" ]; then
    if grep -q 'testCrossCompat_Parse_OCSP_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_OCSP_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-OCSP-COMP" "FAIL"
        else
            set_result "TC-XBC-OCSP-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-OCSP-COMP" "N/A"
    fi
else
    set_result "TC-XBC-OCSP-COMP" "N/A"
fi
echo "  TC-XBC-OCSP-*: EC=$(get_result TC-XBC-OCSP-EC), COMP=$(get_result TC-XBC-OCSP-COMP)"

# TSA tests
RESULT=$(parse_test_class "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml")
if [ "$RESULT" != "N/A" ]; then
    set_result "TC-XBC-TSA-EC" "$RESULT"
    set_result "TC-XBC-TSA-ML" "$RESULT"
    set_result "TC-XBC-TSA-SLH" "$RESULT"
    set_result "TC-XBC-TSA-CAT" "$RESULT"
fi
# Composite TSA - parse test
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" ]; then
    if grep -q 'testCrossCompat_Parse_TSA_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_TSA_Composite' "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-TSA-COMP" "FAIL"
        else
            set_result "TC-XBC-TSA-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-TSA-COMP" "N/A"
    fi
else
    set_result "TC-XBC-TSA-COMP" "N/A"
fi
echo "  TC-XBC-TSA-*: EC=$(get_result TC-XBC-TSA-EC), COMP=$(get_result TC-XBC-TSA-COMP)"

# CMS-ENC tests (EnvelopedData/AuthEnvelopedData)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" ]; then
    # ECDH EnvelopedData/AuthEnvelopedData
    if grep -q 'testCrossCompat_Parse_CMS_ECDH' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_CMS_ECDH' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMSENC-EC" "FAIL"
        else
            set_result "TC-XBC-CMSENC-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CMSENC-EC" "N/A"
    fi

    # ML-KEM AuthEnvelopedData
    if grep -q 'testCrossCompat_Parse_CMS_MLKEM' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
        if grep -q '<failure.*Parse_CMS_MLKEM' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMSENC-KEM" "FAIL"
        else
            set_result "TC-XBC-CMSENC-KEM" "PASS"
        fi
    else
        set_result "TC-XBC-CMSENC-KEM" "N/A"
    fi
else
    set_result "TC-XBC-CMSENC-EC" "N/A"
    set_result "TC-XBC-CMSENC-KEM" "N/A"
fi
echo "  TC-XBC-CMSENC-*: EC=$(get_result TC-XBC-CMSENC-EC), KEM=$(get_result TC-XBC-CMSENC-KEM)"

echo ""

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
SUMMARY_CONTENT="## ☕ BouncyCastle 1.83 Interoperability

| Artefact | Classical | ML-DSA | SLH-DSA | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:--------:|:---------:|"

# Add result rows
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    ROW="| $artifact"
    for algo in EC ML SLH CAT COMP; do
        # Special case: CMSENC uses KEM instead of COMP for the last column
        if [ "$artifact" = "CMSENC" ] && [ "$algo" = "COMP" ]; then
            TC_ID="TC-XBC-CMSENC-KEM"
        else
            TC_ID="TC-XBC-${artifact}-${algo}"
        fi
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

**Legend:** ✅ Verified | ⚠️ Parsed only | ❌ Not supported/tested"

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
    echo -e "${RED}[FAIL] Some BouncyCastle cross-tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] All BouncyCastle cross-tests completed${NC}"
    exit 0
fi
