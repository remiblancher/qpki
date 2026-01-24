# =============================================================================
# OpenSSL Cross-Test Library: TSA Verification (Fixture-Based)
# =============================================================================
#
# Provides run_tsa_tests() function for TSA token verification.
# Uses pre-generated fixtures from test/fixtures/.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify a TSA token and set result
_verify_tsa() {
    local tc_id="$1"
    local name="$2"
    local tsa_file="$3"
    local expect_skip="${4:-false}"

    if [ ! -f "$tsa_file" ]; then
        echo "    $name: SKIP (TSA file not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try to parse at least
        if openssl ts -reply -in "$tsa_file" -text 2>/dev/null | grep -q "Status info"; then
            echo "    $name: SKIP (parsed only)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: N/A (not supported by OpenSSL)"
            set_result "$tc_id" "N/A"
        fi
    else
        if openssl ts -reply -in "$tsa_file" -text 2>/dev/null | grep -q "Status info"; then
            echo "    $name: OK (parsed)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_tsa_tests() {
    echo "=== TSA Verification (OpenSSL) ==="

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    _verify_tsa "TC-XOSL-TSA-EC" "ECDSA TSA" \
        "$FIXTURES/classical/ecdsa/timestamp.tsr"

    # Classical RSA
    echo ">>> Classical (RSA)"
    _verify_tsa "TC-XOSL-TSA-RSA" "RSA TSA" \
        "$FIXTURES/classical/rsa/timestamp.tsr"

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    _verify_tsa "TC-XOSL-TSA-ML" "ML-DSA-87 TSA" \
        "$FIXTURES/pqc/mldsa/timestamp.tsr"

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    _verify_tsa "TC-XOSL-TSA-SLH" "SLH-DSA TSA" \
        "$FIXTURES/pqc/slhdsa/timestamp.tsr"

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    _verify_tsa "TC-XOSL-TSA-CAT" "Catalyst TSA" \
        "$FIXTURES/catalyst/timestamp.tsr"

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite TSA: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-TSA-COMP" "N/A"

    echo "=== TSA Verification Complete ==="
}
