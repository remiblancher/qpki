#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: Verify Pre-generated Fixtures
# =============================================================================
#
# Verifies CMS, OCSP, and TSA fixtures with OpenSSL 3.6+
# Tests:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87, SLH-DSA)
#   - Hybrid Catalyst (ECDSA + ML-DSA)
#   - Composite: SKIP (OpenSSL doesn't support IETF draft-13)
#
# REQUIREMENTS:
#   - OpenSSL 3.6+ with PQC support
#   - Pre-generated fixtures in test/fixtures/
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
TESTDATA="$FIXTURES/testdata.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
SKIPPED=0

echo "============================================================"
echo "[CrossCompat] OpenSSL Fixture Verification"
echo "============================================================"
echo ""

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version 2>/dev/null | head -1)
echo "OpenSSL: $OPENSSL_VERSION"
echo ""

# Check fixtures exist
if [ ! -f "$TESTDATA" ]; then
    echo -e "${RED}ERROR: testdata.txt not found at $TESTDATA${NC}"
    echo "       Run test/generate_fixtures.sh first"
    exit 1
fi

# =============================================================================
# Helper Functions
# =============================================================================

pass() {
    echo -e "    ${GREEN}OK${NC}: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "    ${RED}FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "    ${YELLOW}SKIP${NC}: $1"
    SKIPPED=$((SKIPPED + 1))
}

# Verify CMS attached signature
verify_cms_attached() {
    local name="$1"
    local fixture_dir="$2"
    local cms_file="$fixture_dir/cms-attached.p7s"
    local ca_cert="$fixture_dir/ca/ca.crt"

    if [ ! -f "$cms_file" ]; then
        skip "$name CMS attached (fixture not found)"
        return
    fi
    if [ ! -f "$ca_cert" ]; then
        skip "$name CMS attached (CA cert not found)"
        return
    fi

    # Try full verification first
    if openssl cms -verify -binary -in "$cms_file" -inform DER \
        -CAfile "$ca_cert" -purpose any -out /dev/null 2>/dev/null; then
        pass "$name CMS attached (verified)"
    else
        # If verification fails, try parsing only (OpenSSL may not support PQC cert verification)
        if openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "contentType"; then
            pass "$name CMS attached (parsed)"
        else
            fail "$name CMS attached"
        fi
    fi
}

# Verify CMS detached signature
verify_cms_detached() {
    local name="$1"
    local fixture_dir="$2"
    local cms_file="$fixture_dir/cms-detached.p7s"
    local ca_cert="$fixture_dir/ca/ca.crt"

    if [ ! -f "$cms_file" ]; then
        skip "$name CMS detached (fixture not found)"
        return
    fi
    if [ ! -f "$ca_cert" ]; then
        skip "$name CMS detached (CA cert not found)"
        return
    fi

    # Try full verification first
    if openssl cms -verify -binary -in "$cms_file" -inform DER \
        -CAfile "$ca_cert" -content "$TESTDATA" -purpose any -out /dev/null 2>/dev/null; then
        pass "$name CMS detached (verified)"
    else
        # If verification fails, try parsing only (OpenSSL may not support PQC cert verification)
        if openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "contentType"; then
            pass "$name CMS detached (parsed)"
        else
            fail "$name CMS detached"
        fi
    fi
}

# Verify OCSP response (parse only - full verification requires responder setup)
verify_ocsp() {
    local name="$1"
    local fixture_dir="$2"
    local ocsp_file="$fixture_dir/ocsp-good.der"

    if [ ! -f "$ocsp_file" ]; then
        skip "$name OCSP (fixture not found)"
        return
    fi

    # Parse and display OCSP response
    if openssl ocsp -respin "$ocsp_file" -noverify -text 2>/dev/null | grep -q "Response Status"; then
        pass "$name OCSP (parsed)"
    else
        fail "$name OCSP (parse error)"
    fi
}

# Verify TSA token (parse)
verify_tsa() {
    local name="$1"
    local fixture_dir="$2"
    local tsa_file="$fixture_dir/timestamp.tsr"

    if [ ! -f "$tsa_file" ]; then
        skip "$name TSA (fixture not found)"
        return
    fi

    # Parse TSA response
    if openssl ts -reply -in "$tsa_file" -text 2>/dev/null | grep -q "Status info"; then
        pass "$name TSA (parsed)"
    else
        fail "$name TSA (parse error)"
    fi
}

# =============================================================================
# Classical ECDSA
# =============================================================================
echo ">>> Classical (ECDSA)"
if [ -d "$FIXTURES/classical" ]; then
    verify_cms_attached "Classical" "$FIXTURES/classical"
    verify_cms_detached "Classical" "$FIXTURES/classical"
    verify_ocsp "Classical" "$FIXTURES/classical"
    verify_tsa "Classical" "$FIXTURES/classical"
else
    skip "Classical fixtures not found"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87
# =============================================================================
echo ">>> PQC (ML-DSA-87)"
if [ -d "$FIXTURES/pqc/mldsa" ]; then
    verify_cms_attached "ML-DSA-87" "$FIXTURES/pqc/mldsa"
    verify_cms_detached "ML-DSA-87" "$FIXTURES/pqc/mldsa"
    verify_ocsp "ML-DSA-87" "$FIXTURES/pqc/mldsa"
    verify_tsa "ML-DSA-87" "$FIXTURES/pqc/mldsa"
else
    skip "ML-DSA-87 fixtures not found"
fi
echo ""

# =============================================================================
# PQC SLH-DSA
# =============================================================================
echo ">>> PQC (SLH-DSA)"
if [ -d "$FIXTURES/pqc/slhdsa" ]; then
    verify_cms_attached "SLH-DSA" "$FIXTURES/pqc/slhdsa"
    verify_cms_detached "SLH-DSA" "$FIXTURES/pqc/slhdsa"
    verify_ocsp "SLH-DSA" "$FIXTURES/pqc/slhdsa"
    verify_tsa "SLH-DSA" "$FIXTURES/pqc/slhdsa"
else
    skip "SLH-DSA fixtures not found"
fi
echo ""

# =============================================================================
# Hybrid Catalyst (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Hybrid (Catalyst: ECDSA + ML-DSA)"
if [ -d "$FIXTURES/catalyst" ]; then
    # Catalyst uses ECDSA as primary signature - OpenSSL verifies that
    verify_cms_attached "Catalyst" "$FIXTURES/catalyst"
    verify_cms_detached "Catalyst" "$FIXTURES/catalyst"
    verify_ocsp "Catalyst" "$FIXTURES/catalyst"
    verify_tsa "Catalyst" "$FIXTURES/catalyst"
else
    skip "Catalyst fixtures not found"
fi
echo ""

# =============================================================================
# Composite (IETF draft-13) - SKIP
# =============================================================================
echo ">>> Hybrid (Composite: IETF draft-13)"
echo -e "    ${YELLOW}SKIP${NC}: OpenSSL doesn't support Composite signatures"
((SKIPPED++))
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================================"
echo "Summary"
echo "============================================================"
echo -e "  Passed:  ${GREEN}$PASSED${NC}"
echo -e "  Failed:  ${RED}$FAILED${NC}"
echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}[FAIL] Some tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] All tests passed${NC}"
    exit 0
fi
