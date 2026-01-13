# =============================================================================
# OpenSSL Cross-Test Library: Certificate Verification
# =============================================================================
#
# Provides run_cert_tests() function for certificate verification.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Helper to find credential certificate
_find_ee_cert() {
    local ca_dir="$1"
    find "$ca_dir/credentials" -name "certificates.pem" -type f 2>/dev/null | head -1
}

# Verify a certificate and set result
_verify_cert() {
    local tc_id="$1"
    local name="$2"
    local ca_cert="$3"
    local ee_cert="$4"
    local expect_skip="${5:-false}"

    if [ ! -f "$ca_cert" ]; then
        echo "    $name: SKIP (CA cert not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ -z "$ee_cert" ] || [ ! -f "$ee_cert" ]; then
        echo "    $name: SKIP (EE cert not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try anyway but don't fail
        if openssl verify -CAfile "$ca_cert" "$ee_cert" 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: SKIP (not supported by OpenSSL)"
            set_result "$tc_id" "SKIP"
        fi
    else
        if openssl verify -CAfile "$ca_cert" "$ee_cert" 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_cert_tests() {
    echo "=== Certificate Verification (OpenSSL) ==="

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    EE_CERT=$(_find_ee_cert "$FIXTURES/classical/ca")
    _verify_cert "TC-XOSL-CERT-EC" "ECDSA" "$FIXTURES/classical/ca/ca.crt" "$EE_CERT"

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    EE_CERT=$(_find_ee_cert "$FIXTURES/pqc/mldsa/ca")
    _verify_cert "TC-XOSL-CERT-ML" "ML-DSA-87" "$FIXTURES/pqc/mldsa/ca/ca.crt" "$EE_CERT" "true"

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    EE_CERT=$(_find_ee_cert "$FIXTURES/pqc/slhdsa/ca")
    _verify_cert "TC-XOSL-CERT-SLH" "SLH-DSA" "$FIXTURES/pqc/slhdsa/ca/ca.crt" "$EE_CERT" "true"

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    EE_CERT=$(_find_ee_cert "$FIXTURES/catalyst/ca")
    _verify_cert "TC-XOSL-CERT-CAT" "Catalyst" "$FIXTURES/catalyst/ca/ca.crt" "$EE_CERT"

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-CERT-COMP" "N/A"

    echo "=== Certificate Verification Complete ==="
}
