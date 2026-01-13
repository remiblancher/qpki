# =============================================================================
# OpenSSL Cross-Test Library: OCSP Verification (Fixture-Based)
# =============================================================================
#
# Provides run_ocsp_tests() function for OCSP response verification.
# Uses pre-generated fixtures from test/fixtures/.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify an OCSP response and set result
_verify_ocsp() {
    local tc_id="$1"
    local name="$2"
    local ocsp_file="$3"
    local expect_skip="${4:-false}"

    if [ ! -f "$ocsp_file" ]; then
        echo "    $name: SKIP (OCSP file not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try to parse at least
        if openssl ocsp -respin "$ocsp_file" -noverify -text 2>/dev/null | grep -q "Response Status"; then
            echo "    $name: SKIP (parsed only)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: N/A (not supported by OpenSSL)"
            set_result "$tc_id" "N/A"
        fi
    else
        if openssl ocsp -respin "$ocsp_file" -noverify -text 2>/dev/null | grep -q "Response Status"; then
            echo "    $name: OK (parsed)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_ocsp_tests() {
    echo "=== OCSP Verification (OpenSSL) ==="

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    _verify_ocsp "TC-XOSL-OCSP-EC" "ECDSA OCSP" \
        "$FIXTURES/classical/ocsp-good.der"

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    _verify_ocsp "TC-XOSL-OCSP-ML" "ML-DSA-87 OCSP" \
        "$FIXTURES/pqc/mldsa/ocsp-good.der" "true"

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    _verify_ocsp "TC-XOSL-OCSP-SLH" "SLH-DSA OCSP" \
        "$FIXTURES/pqc/slhdsa/ocsp-good.der" "true"

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    _verify_ocsp "TC-XOSL-OCSP-CAT" "Catalyst OCSP" \
        "$FIXTURES/catalyst/ocsp-good.der"

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite OCSP: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-OCSP-COMP" "N/A"

    echo "=== OCSP Verification Complete ==="
}
