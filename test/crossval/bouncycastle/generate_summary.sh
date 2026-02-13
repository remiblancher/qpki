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
    if grep -q 'TC-XBC-CERT-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CERT-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
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
    if grep -q 'TC-XBC-CERT-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CERT-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.PQCVerifyTest.xml" 2>/dev/null; then
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

# Composite - Parse only (BC uses draft-07 OIDs, QPKI uses IETF draft-13)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeVerifyTest.xml" ]; then
    if grep -q 'TC-XBC-CERT-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CERT-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CERT-COMP" "FAIL"
        elif grep -E 'Parse.*TC-XBC-CERT-COMP|TC-XBC-CERT-COMP.*Parse' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeVerifyTest.xml" >/dev/null 2>&1; then
            set_result "TC-XBC-CERT-COMP" "SKIP"
        else
            set_result "TC-XBC-CERT-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-CERT-COMP" "N/A"
    fi
else
    set_result "TC-XBC-CERT-COMP" "N/A"
fi
echo "  TC-XBC-CERT-COMP: $(get_result TC-XBC-CERT-COMP)"

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
# Composite CRL - Parse only (BC uses draft-07 OIDs, QPKI uses IETF draft-13)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeCRLVerifyTest.xml" ]; then
    if grep -q 'TC-XBC-CRL-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeCRLVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CRL-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeCRLVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CRL-COMP" "FAIL"
        elif grep -E 'Parse.*TC-XBC-CRL-COMP|TC-XBC-CRL-COMP.*Parse' "$SUREFIRE_DIR/TEST-pki.crosstest.CompositeCRLVerifyTest.xml" >/dev/null 2>&1; then
            set_result "TC-XBC-CRL-COMP" "SKIP"
        else
            set_result "TC-XBC-CRL-COMP" "PASS"
        fi
    else
        set_result "TC-XBC-CRL-COMP" "N/A"
    fi
else
    set_result "TC-XBC-CRL-COMP" "N/A"
fi
echo "  TC-XBC-CRL-*: EC=$(get_result TC-XBC-CRL-EC), CAT=$(get_result TC-XBC-CRL-CAT), COMP=$(get_result TC-XBC-CRL-COMP)"

# CSR tests
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" ]; then
    # ECDSA CSR
    if grep -q 'TC-XBC-CSR-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CSR-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-EC" "FAIL"
        else
            set_result "TC-XBC-CSR-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-EC" "N/A"
    fi

    # ML-DSA CSR
    if grep -q 'TC-XBC-CSR-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CSR-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-ML" "FAIL"
        else
            set_result "TC-XBC-CSR-ML" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-ML" "N/A"
    fi

    # SLH-DSA CSR
    if grep -q 'TC-XBC-CSR-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CSR-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-SLH" "FAIL"
        else
            set_result "TC-XBC-CSR-SLH" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-SLH" "N/A"
    fi

    # Catalyst CSR - Parse only (BC 1.83 bug with alt-key attributes)
    if grep -q 'TC-XBC-CSR-CAT' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CSR-CAT' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-CAT" "FAIL"
        elif grep -E 'Parse.*TC-XBC-CSR-CAT|TC-XBC-CSR-CAT.*Parse' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" >/dev/null 2>&1; then
            set_result "TC-XBC-CSR-CAT" "SKIP"
        else
            set_result "TC-XBC-CSR-CAT" "PASS"
        fi
    else
        set_result "TC-XBC-CSR-CAT" "N/A"
    fi

    # Composite CSR - Parse only (BC uses draft-07 OIDs, QPKI uses IETF draft-13)
    if grep -q 'TC-XBC-CSR-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CSR-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CSR-COMP" "FAIL"
        elif grep -E 'Parse.*TC-XBC-CSR-COMP|TC-XBC-CSR-COMP.*Parse' "$SUREFIRE_DIR/TEST-pki.crosstest.CSRVerifyTest.xml" >/dev/null 2>&1; then
            set_result "TC-XBC-CSR-COMP" "SKIP"
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
    if grep -q 'TC-XBC-CMS-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMS-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-EC" "FAIL"
        else
            set_result "TC-XBC-CMS-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-EC" "N/A"
    fi

    if grep -q 'TC-XBC-CMS-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMS-ML' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-ML" "FAIL"
        else
            set_result "TC-XBC-CMS-ML" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-ML" "N/A"
    fi

    if grep -q 'TC-XBC-CMS-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMS-SLH' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-SLH" "FAIL"
        else
            set_result "TC-XBC-CMS-SLH" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-SLH" "N/A"
    fi

    if grep -q 'TC-XBC-CMS-CAT' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMS-CAT' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-CAT" "FAIL"
        else
            set_result "TC-XBC-CMS-CAT" "PASS"
        fi
    else
        set_result "TC-XBC-CMS-CAT" "N/A"
    fi

    # Composite CMS - Parse only (BC uses draft-07 OIDs, QPKI uses IETF draft-13)
    if grep -q 'TC-XBC-CMS-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMS-COMP' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMS-COMP" "FAIL"
        elif grep -E 'Parse.*TC-XBC-CMS-COMP|TC-XBC-CMS-COMP.*Parse' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSVerifyTest.xml" >/dev/null 2>&1; then
            set_result "TC-XBC-CMS-COMP" "SKIP"
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

# OCSP tests - parse individual TC-IDs from XML
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" ]; then
    for tc in TC-XBC-OCSP-EC TC-XBC-OCSP-ML TC-XBC-OCSP-SLH TC-XBC-OCSP-CAT TC-XBC-OCSP-COMP; do
        if grep -q "$tc" "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" 2>/dev/null; then
            if grep -q "<failure.*$tc" "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" 2>/dev/null; then
                set_result "$tc" "FAIL"
            elif grep -E "Parse.*$tc|$tc.*Parse" "$SUREFIRE_DIR/TEST-pki.crosstest.OCSPVerifyTest.xml" >/dev/null 2>&1; then
                set_result "$tc" "SKIP"
            else
                set_result "$tc" "PASS"
            fi
        else
            set_result "$tc" "N/A"
        fi
    done
else
    for tc in TC-XBC-OCSP-EC TC-XBC-OCSP-ML TC-XBC-OCSP-SLH TC-XBC-OCSP-CAT TC-XBC-OCSP-COMP; do
        set_result "$tc" "N/A"
    done
fi
echo "  TC-XBC-OCSP-*: EC=$(get_result TC-XBC-OCSP-EC), ML=$(get_result TC-XBC-OCSP-ML), SLH=$(get_result TC-XBC-OCSP-SLH), CAT=$(get_result TC-XBC-OCSP-CAT), COMP=$(get_result TC-XBC-OCSP-COMP)"

# TSA tests - parse individual TC-IDs from XML
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" ]; then
    for tc in TC-XBC-TSA-EC TC-XBC-TSA-ML TC-XBC-TSA-SLH TC-XBC-TSA-CAT TC-XBC-TSA-COMP; do
        if grep -q "$tc" "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" 2>/dev/null; then
            if grep -q "<failure.*$tc" "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" 2>/dev/null; then
                set_result "$tc" "FAIL"
            elif grep -E "Parse.*$tc|$tc.*Parse" "$SUREFIRE_DIR/TEST-pki.crosstest.TSAVerifyTest.xml" >/dev/null 2>&1; then
                set_result "$tc" "SKIP"
            else
                set_result "$tc" "PASS"
            fi
        else
            set_result "$tc" "N/A"
        fi
    done
else
    for tc in TC-XBC-TSA-EC TC-XBC-TSA-ML TC-XBC-TSA-SLH TC-XBC-TSA-CAT TC-XBC-TSA-COMP; do
        set_result "$tc" "N/A"
    done
fi
echo "  TC-XBC-TSA-*: EC=$(get_result TC-XBC-TSA-EC), ML=$(get_result TC-XBC-TSA-ML), SLH=$(get_result TC-XBC-TSA-SLH), CAT=$(get_result TC-XBC-TSA-CAT), COMP=$(get_result TC-XBC-TSA-COMP)"

# CMS-ENC tests (EnvelopedData/AuthEnvelopedData)
if [ -f "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" ]; then
    # ECDH EnvelopedData/AuthEnvelopedData
    if grep -q 'TC-XBC-CMSENC-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMSENC-EC' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
            set_result "TC-XBC-CMSENC-EC" "FAIL"
        else
            set_result "TC-XBC-CMSENC-EC" "PASS"
        fi
    else
        set_result "TC-XBC-CMSENC-EC" "N/A"
    fi

    # ML-KEM AuthEnvelopedData
    if grep -q 'TC-XBC-CMSENC-KEM' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
        if grep -q '<failure.*TC-XBC-CMSENC-KEM' "$SUREFIRE_DIR/TEST-pki.crosstest.CMSEnvelopedTest.xml" 2>/dev/null; then
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

# Count results first for executive summary
TOTAL_PASS=$(grep '=PASS$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_FAIL=$(grep '=FAIL$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_SKIP=$(grep '=SKIP$' "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_TESTS=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))

# Build summary content with executive summary
SUMMARY_CONTENT="## BouncyCastle Cross-Compatibility

![BC 1.83](https://img.shields.io/badge/BouncyCastle-1.83-blue) ![QPKI](https://img.shields.io/badge/QPKI-fixtures-green)

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
        TC_ID="TC-XBC-${artifact}-${algo}"
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
| ![SKIP](https://img.shields.io/badge/-SKIP-yellow) | Composite | BC 1.83 uses draft-07 OIDs, QPKI uses IETF draft-13 |
| ![SKIP](https://img.shields.io/badge/-SKIP-yellow) | Catalyst CSR | BC 1.83 bug with alt-key attributes |

<details>
<summary>Test Case IDs (for traceability)</summary>

| Artifact | EC | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---|:-------|:--------|:-------|:---------|:----------|"

# Add TC-IDs in collapsible section
for artifact in CERT CRL CSR CMS CMSENC OCSP TSA; do
    ROW="| $artifact"
    for algo in EC ML SLH KEM CAT COMP; do
        TC_ID="TC-XBC-${artifact}-${algo}"
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
# Final Status
# =============================================================================

# =============================================================================
# Export JSON Results (for CI reporting)
# =============================================================================

JSON_OUTPUT="$SCRIPT_DIR/results.json"
cat > "$JSON_OUTPUT" << EOF
{
  "validator": "BouncyCastle",
  "version": "1.83",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total": $TOTAL_TESTS,
  "passed": $TOTAL_PASS,
  "failed": $TOTAL_FAIL,
  "skipped": $TOTAL_SKIP,
  "results": {
EOF

# Add individual results
FIRST=true
while IFS='=' read -r tc_id status; do
    if [ -n "$tc_id" ] && [ -n "$status" ]; then
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "$JSON_OUTPUT"
        fi
        printf '    "%s": "%s"' "$tc_id" "$status" >> "$JSON_OUTPUT"
    fi
done < "$RESULTS_FILE"

cat >> "$JSON_OUTPUT" << EOF

  }
}
EOF

echo "JSON results exported: $JSON_OUTPUT"

# =============================================================================
# Export CTRF Format (Common Test Report Format)
# =============================================================================

CTRF_OUTPUT="$SCRIPT_DIR/ctrf-crosstest-bc.json"
START_TIME=$(date +%s000)

cat > "$CTRF_OUTPUT" << EOF
{
  "results": {
    "tool": {
      "name": "crosstest-bouncycastle"
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
while IFS='=' read -r tc_id status; do
    if [ -n "$tc_id" ] && [ -n "$status" ]; then
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "$CTRF_OUTPUT"
        fi
        # Convert status to CTRF format
        CTRF_STATUS="other"
        case "$status" in
            PASS) CTRF_STATUS="passed" ;;
            FAIL) CTRF_STATUS="failed" ;;
            SKIP) CTRF_STATUS="skipped" ;;
        esac
        printf '      {"name": "%s", "status": "%s"}' "$tc_id" "$CTRF_STATUS" >> "$CTRF_OUTPUT"
    fi
done < "$RESULTS_FILE"

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
    echo -e "${RED}[FAIL] Some BouncyCastle cross-tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] All BouncyCastle cross-tests completed${NC}"
    exit 0
fi
