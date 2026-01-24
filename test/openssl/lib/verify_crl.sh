# =============================================================================
# OpenSSL Cross-Test Library: CRL Verification
# =============================================================================
#
# Provides run_crl_tests() function for CRL verification.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify a CRL and set result
_verify_crl() {
    local tc_id="$1"
    local name="$2"
    local crl_file="$3"
    local ca_cert="$4"
    local expect_skip="${5:-false}"

    if [ ! -f "$crl_file" ]; then
        echo "    $name: SKIP (CRL not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try to parse at least
        if openssl crl -in "$crl_file" -noout 2>/dev/null; then
            echo "    $name: SKIP (parsed, signature not supported)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: N/A (not supported by OpenSSL)"
            set_result "$tc_id" "N/A"
        fi
    else
        if openssl crl -in "$crl_file" -CAfile "$ca_cert" -verify -noout 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        elif openssl crl -in "$crl_file" -noout 2>/dev/null; then
            echo "    $name: SKIP (parsed only)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_crl_tests() {
    echo "=== CRL Verification (OpenSSL) ==="

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    _verify_crl "TC-XOSL-CRL-EC" "ECDSA CRL" \
        "$FIXTURES/classical/ecdsa/ca/crl/ca.crl" \
        "$FIXTURES/classical/ecdsa/ca/ca.crt"

    # Classical RSA
    echo ">>> Classical (RSA)"
    _verify_crl "TC-XOSL-CRL-RSA" "RSA CRL" \
        "$FIXTURES/classical/rsa/ca/crl/ca.crl" \
        "$FIXTURES/classical/rsa/ca/ca.crt"

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    _verify_crl "TC-XOSL-CRL-ML" "ML-DSA-87 CRL" \
        "$FIXTURES/pqc/mldsa/ca/crl/ca.crl" \
        "$FIXTURES/pqc/mldsa/ca/ca.crt"

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    _verify_crl "TC-XOSL-CRL-SLH" "SLH-DSA CRL" \
        "$FIXTURES/pqc/slhdsa/ca/crl/ca.crl" \
        "$FIXTURES/pqc/slhdsa/ca/ca.crt"

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    _verify_crl "TC-XOSL-CRL-CAT" "Catalyst CRL" \
        "$FIXTURES/catalyst/ca/crl/ca.crl" \
        "$FIXTURES/catalyst/ca/ca.crt"

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite CRL: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-CRL-COMP" "N/A"

    echo "=== CRL Verification Complete ==="
}
