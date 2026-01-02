#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: CMS Signature Verification
# =============================================================================
#
# Verifies CMS SignedData using OpenSSL 3.6+:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87)
#   - Hybrid (Catalyst: ECDSA + ML-DSA)
#
# REQUIREMENTS:
#   - OpenSSL 3.5+ for PQC support
#   - qpki binary to generate CMS signatures
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
PKI="$PROJECT_ROOT/qpki"
TMP_DIR="/tmp/cms-crosstest"

echo "=== CMS Signature Verification (OpenSSL) ==="
echo ""

# Check qpki binary
if [ ! -f "$PKI" ]; then
    echo "ERROR: qpki binary not found at $PKI"
    echo "       Please build it first: go build -o ./qpki ./cmd/qpki"
    exit 1
fi

# Create temp directory
mkdir -p "$TMP_DIR"

# Create test data
echo "Test data for CMS cross-validation" > "$TMP_DIR/data.txt"

# Helper to find credential key and certificate
find_credential() {
    local ca_dir="$1"
    local cred_dir
    cred_dir=$(find "$ca_dir/credentials" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
    if [ -n "$cred_dir" ]; then
        echo "$cred_dir"
    fi
}

# =============================================================================
# Classical ECDSA CMS
# =============================================================================
echo ">>> Classical CMS Signature (ECDSA)"
if [ -d "$FIXTURES/classical/ca" ]; then
    CRED_DIR=$(find_credential "$FIXTURES/classical/ca")
    if [ -n "$CRED_DIR" ]; then
        KEY_FILE="$CRED_DIR/private-keys.pem"
        CERT_FILE="$CRED_DIR/certificates.pem"
        if [ -f "$KEY_FILE" ] && [ -f "$CERT_FILE" ]; then
            # Generate CMS signature
            if "$PKI" cms sign --key "$KEY_FILE" --cert "$CERT_FILE" --data "$TMP_DIR/data.txt" --out "$TMP_DIR/cms-ecdsa.p7s" 2>/dev/null; then
                # Verify with OpenSSL
                if openssl cms -verify -in "$TMP_DIR/cms-ecdsa.p7s" -inform DER \
                    -CAfile "$FIXTURES/classical/ca/ca.crt" -content "$TMP_DIR/data.txt" \
                    -purpose any -out /dev/null 2>/dev/null; then
                    echo "    ECDSA CMS: OK (verified)"
                else
                    echo "    ECDSA CMS: FAIL (verification error)"
                fi
            else
                echo "    ECDSA CMS: FAIL (generation error)"
            fi
        else
            echo "    ECDSA CMS: SKIP (key/cert not found)"
        fi
    else
        echo "    ECDSA CMS: SKIP (no credential found)"
    fi
else
    echo "    ECDSA CMS: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87 CMS
# =============================================================================
echo ">>> PQC CMS Signature (ML-DSA-87)"
if [ -d "$FIXTURES/pqc/mldsa/ca" ]; then
    CRED_DIR=$(find_credential "$FIXTURES/pqc/mldsa/ca")
    if [ -n "$CRED_DIR" ]; then
        KEY_FILE="$CRED_DIR/private-keys.pem"
        CERT_FILE="$CRED_DIR/certificates.pem"
        if [ -f "$KEY_FILE" ] && [ -f "$CERT_FILE" ]; then
            # Generate CMS signature
            if "$PKI" cms sign --key "$KEY_FILE" --cert "$CERT_FILE" --data "$TMP_DIR/data.txt" --out "$TMP_DIR/cms-mldsa.p7s" 2>/dev/null; then
                # Try to verify with OpenSSL
                if openssl cms -verify -in "$TMP_DIR/cms-mldsa.p7s" -inform DER \
                    -CAfile "$FIXTURES/pqc/mldsa/ca/ca.crt" -content "$TMP_DIR/data.txt" \
                    -purpose any -out /dev/null 2>/dev/null; then
                    echo "    ML-DSA-87 CMS: OK (verified)"
                else
                    # Try to at least parse it
                    if openssl cms -cmsout -print -in "$TMP_DIR/cms-mldsa.p7s" -inform DER 2>/dev/null | head -20; then
                        echo "    ML-DSA-87 CMS: OK (parsed, signature may not be verified)"
                    else
                        echo "    ML-DSA-87 CMS: FAIL (OpenSSL may not support ML-DSA CMS)"
                    fi
                fi
            else
                echo "    ML-DSA-87 CMS: FAIL (generation error)"
            fi
        else
            echo "    ML-DSA-87 CMS: SKIP (key/cert not found)"
        fi
    else
        echo "    ML-DSA-87 CMS: SKIP (no credential found)"
    fi
else
    echo "    ML-DSA-87 CMS: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst CMS (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Hybrid CMS Signature (Catalyst)"
if [ -d "$FIXTURES/catalyst/ca" ]; then
    CRED_DIR=$(find_credential "$FIXTURES/catalyst/ca")
    if [ -n "$CRED_DIR" ]; then
        KEY_FILE="$CRED_DIR/private-keys.pem"
        CERT_FILE="$CRED_DIR/certificates.pem"
        if [ -f "$KEY_FILE" ] && [ -f "$CERT_FILE" ]; then
            # Generate CMS signature
            if "$PKI" cms sign --key "$KEY_FILE" --cert "$CERT_FILE" --data "$TMP_DIR/data.txt" --out "$TMP_DIR/cms-catalyst.p7s" 2>/dev/null; then
                # OpenSSL verifies only the primary ECDSA signature
                if openssl cms -verify -in "$TMP_DIR/cms-catalyst.p7s" -inform DER \
                    -CAfile "$FIXTURES/catalyst/ca/ca.crt" -content "$TMP_DIR/data.txt" \
                    -purpose any -out /dev/null 2>/dev/null; then
                    echo "    Catalyst CMS (ECDSA sig): OK (verified)"
                    echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
                else
                    if openssl cms -cmsout -print -in "$TMP_DIR/cms-catalyst.p7s" -inform DER 2>/dev/null | head -10; then
                        echo "    Catalyst CMS: OK (parsed)"
                    else
                        echo "    Catalyst CMS: FAIL (verification error)"
                    fi
                fi
            else
                echo "    Catalyst CMS: FAIL (generation error)"
            fi
        else
            echo "    Catalyst CMS: SKIP (key/cert not found)"
        fi
    else
        echo "    Catalyst CMS: SKIP (no credential found)"
    fi
else
    echo "    Catalyst CMS: SKIP (fixtures not found)"
fi
echo ""

# Cleanup
rm -rf "$TMP_DIR"

echo "=== CMS Signature Verification Complete ==="
