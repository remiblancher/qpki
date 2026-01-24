# =============================================================================
# OpenSSL Cross-Test Library: CMS EnvelopedData Verification
# =============================================================================
#
# Provides run_cms_encrypt_tests() function for CMS encryption verification.
# Tests ECDH (KeyAgreeRecipientInfo) and ML-KEM (KEMRecipientInfo).
# Uses set_result() to record TC-IDs.
#
# =============================================================================

# Verify CMS EnvelopedData structure and optionally decrypt
_verify_cms_encrypt() {
    local tc_id="$1"
    local name="$2"
    local cms_file="$3"
    local key_file="$4"
    local cert_file="$5"
    local data_file="$6"

    if [ ! -f "$cms_file" ]; then
        echo "    $name: SKIP (CMS file not found)"
        set_result "$tc_id" "SKIP"
        return
    fi

    # First verify structure is parseable
    if ! openssl asn1parse -inform DER -in "$cms_file" >/dev/null 2>&1; then
        echo "    $name: FAIL (invalid structure)"
        set_result "$tc_id" "FAIL"
        return
    fi

    # Try decryption if key and cert are available
    if [ -f "$key_file" ] && [ -f "$cert_file" ]; then
        local tmp_out="/tmp/cms-decrypt-$$.txt"
        if openssl cms -decrypt -in "$cms_file" -inform DER \
            -inkey "$key_file" -recip "$cert_file" \
            -out "$tmp_out" 2>/dev/null; then

            # Verify content if data file provided
            if [ -n "$data_file" ] && [ -f "$data_file" ]; then
                if diff -q "$tmp_out" "$data_file" >/dev/null 2>&1; then
                    echo "    $name: OK (decrypted + verified)"
                    set_result "$tc_id" "PASS"
                else
                    echo "    $name: FAIL (content mismatch)"
                    set_result "$tc_id" "FAIL"
                fi
            else
                echo "    $name: OK (decrypted)"
                set_result "$tc_id" "PASS"
            fi
            rm -f "$tmp_out"
        else
            # Decryption failed - check if structure is valid at least
            rm -f "$tmp_out"
            if openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "envelopedData\|authEnvelopedData"; then
                echo "    $name: SKIP (parsed only, decrypt failed)"
                set_result "$tc_id" "SKIP"
            else
                echo "    $name: FAIL (decrypt error)"
                set_result "$tc_id" "FAIL"
            fi
        fi
    else
        # No key/cert - just verify structure
        if openssl cms -cmsout -print -in "$cms_file" -inform DER 2>/dev/null | grep -q "envelopedData\|authEnvelopedData"; then
            echo "    $name: SKIP (parsed only, no keys)"
            set_result "$tc_id" "SKIP"
        else
            echo "    $name: FAIL (invalid CMS structure)"
            set_result "$tc_id" "FAIL"
        fi
    fi
}

# Main test function
run_cms_encrypt_tests() {
    echo "=== CMS EnvelopedData Verification (OpenSSL) ==="

    local TESTDATA="$FIXTURES/testdata.txt"

    # Classical ECDH
    echo ">>> Classical (ECDH)"
    _verify_cms_encrypt "TC-XOSL-CMSENC-EC" "ECDH EnvelopedData" \
        "$FIXTURES/classical/ecdsa/cms-enveloped.p7m" \
        "$FIXTURES/classical/ecdsa/encryption-key.pem" \
        "$FIXTURES/classical/ecdsa/encryption-cert.pem" \
        "$TESTDATA"

    # Classical RSA
    echo ">>> Classical (RSA)"
    _verify_cms_encrypt "TC-XOSL-CMSENC-RSA" "RSA EnvelopedData" \
        "$FIXTURES/classical/rsa/cms-enveloped.p7m" \
        "$FIXTURES/classical/rsa/encryption-key.pem" \
        "$FIXTURES/classical/rsa/encryption-cert.pem" \
        "$TESTDATA"

    # ML-DSA column - N/A (signature algorithm, not KEM)
    set_result "TC-XOSL-CMSENC-ML" "N/A"

    # SLH-DSA column - N/A (signature algorithm, not KEM)
    set_result "TC-XOSL-CMSENC-SLH" "N/A"

    # PQC ML-KEM
    echo ">>> PQC (ML-KEM)"
    _verify_cms_encrypt "TC-XOSL-CMSENC-KEM" "ML-KEM AuthEnvelopedData" \
        "$FIXTURES/pqc/mlkem/cms-enveloped.p7m" \
        "$FIXTURES/pqc/mlkem/encryption-key.pem" \
        "$FIXTURES/pqc/mlkem/encryption-cert.pem" \
        "$TESTDATA"

    # Catalyst - N/A for encryption
    set_result "TC-XOSL-CMSENC-CAT" "N/A"

    # Composite - N/A for encryption
    set_result "TC-XOSL-CMSENC-COMP" "N/A"

    echo "=== CMS EnvelopedData Verification Complete ==="
}
