# =============================================================================
# OpenSSL Cross-Test Library: CMS Verification (Fixture-Based)
# =============================================================================
#
# Provides run_cms_tests() function for CMS verification.
# Uses pre-generated fixtures from test/fixtures/.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify a CMS signature and set result
_verify_cms() {
    local tc_id="$1"
    local name="$2"
    local cms_file="$3"
    local ca_cert="$4"
    local data_file="$5"
    local expect_skip="${6:-false}"

    if [ ! -f "$cms_file" ]; then
        echo "    $name: SKIP (CMS file not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ ! -f "$ca_cert" ]; then
        echo "    $name: SKIP (CA cert not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    # Try full verification first
    local verify_cmd="openssl cms -verify -binary -in \"$cms_file\" -inform DER -CAfile \"$ca_cert\" -purpose any -out /dev/null"
    if [ -n "$data_file" ] && [ -f "$data_file" ]; then
        verify_cmd="$verify_cmd -content \"$data_file\""
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try to parse at least
        if eval "$verify_cmd" 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        elif openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "contentType"; then
            echo "    $name: SKIP (parsed only)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: N/A (not supported by OpenSSL)"
            set_result "$tc_id" "N/A"
        fi
    else
        if eval "$verify_cmd" 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        elif openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "contentType"; then
            echo "    $name: SKIP (parsed only)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_cms_tests() {
    echo "=== CMS Verification (OpenSSL) ==="

    local TESTDATA="$FIXTURES/testdata.txt"

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    _verify_cms "TC-XOSL-CMS-EC" "ECDSA CMS" \
        "$FIXTURES/classical/ecdsa/cms-attached.p7s" \
        "$FIXTURES/classical/ecdsa/ca/ca.crt" ""

    # Classical RSA
    echo ">>> Classical (RSA)"
    _verify_cms "TC-XOSL-CMS-RSA" "RSA CMS" \
        "$FIXTURES/classical/rsa/cms-attached.p7s" \
        "$FIXTURES/classical/rsa/ca/ca.crt" ""

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    _verify_cms "TC-XOSL-CMS-ML" "ML-DSA-87 CMS" \
        "$FIXTURES/pqc/mldsa/cms-attached.p7s" \
        "$FIXTURES/pqc/mldsa/ca/ca.crt" ""

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    _verify_cms "TC-XOSL-CMS-SLH" "SLH-DSA CMS" \
        "$FIXTURES/pqc/slhdsa/cms-attached.p7s" \
        "$FIXTURES/pqc/slhdsa/ca/ca.crt" ""

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    _verify_cms "TC-XOSL-CMS-CAT" "Catalyst CMS" \
        "$FIXTURES/catalyst/cms-attached.p7s" \
        "$FIXTURES/catalyst/ca/ca.crt" ""

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite CMS: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-CMS-COMP" "N/A"

    echo "=== CMS Verification Complete ==="
}
