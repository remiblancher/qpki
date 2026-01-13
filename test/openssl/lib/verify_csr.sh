# =============================================================================
# OpenSSL Cross-Test Library: CSR Verification
# =============================================================================
#
# Provides run_csr_tests() function for CSR verification.
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify a CSR and set result
_verify_csr() {
    local tc_id="$1"
    local name="$2"
    local csr_file="$3"
    local expect_skip="${4:-false}"

    if [ ! -f "$csr_file" ]; then
        echo "    $name: SKIP (CSR not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    if [ "$expect_skip" = "true" ]; then
        # Known unsupported - try anyway but don't fail
        if openssl req -in "$csr_file" -verify -noout 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: SKIP (not supported by OpenSSL)"
            set_result "$tc_id" "SKIP"
        fi
    else
        if openssl req -in "$csr_file" -verify -noout 2>/dev/null; then
            echo "    $name: OK (verified)"
            set_result "$tc_id" "PASS"
        else
            echo "    $name: FAIL"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_csr_tests() {
    echo "=== CSR Verification (OpenSSL) ==="

    # Classical ECDSA
    echo ">>> Classical (ECDSA)"
    _verify_csr "TC-XOSL-CSR-EC" "ECDSA CSR" "$FIXTURES/csr/ecdsa.csr"

    # PQC ML-DSA-87
    echo ">>> PQC (ML-DSA-87)"
    _verify_csr "TC-XOSL-CSR-ML" "ML-DSA-87 CSR" "$FIXTURES/csr/mldsa87.csr"

    # PQC SLH-DSA
    echo ">>> PQC (SLH-DSA)"
    _verify_csr "TC-XOSL-CSR-SLH" "SLH-DSA CSR" "$FIXTURES/csr/slhdsa256f.csr"

    # Catalyst Hybrid
    echo ">>> Hybrid (Catalyst)"
    _verify_csr "TC-XOSL-CSR-CAT" "Catalyst CSR" "$FIXTURES/csr/catalyst.csr"

    # Composite - Not supported by OpenSSL
    echo ">>> Hybrid (Composite)"
    echo "    Composite CSR: N/A (not supported by OpenSSL)"
    set_result "TC-XOSL-CSR-COMP" "N/A"

    echo "=== CSR Verification Complete ==="
}
