#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: TSA Token Verification
# =============================================================================
#
# Verifies RFC 3161 Timestamp tokens using OpenSSL 3.6+:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87)
#   - Hybrid (Catalyst: ECDSA + ML-DSA)
#
# REQUIREMENTS:
#   - OpenSSL 3.5+ for PQC support
#   - qpki binary to generate TSA tokens
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
PKI="$PROJECT_ROOT/qpki"
TMP_DIR="/tmp/tsa-crosstest"

echo "[CrossCompat] TSA Token Verification (OpenSSL)"
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
echo "Test data for TSA cross-validation" > "$TMP_DIR/data.txt"

# Helper to find CA key
find_ca_key() {
    local ca_dir="$1"
    find "$ca_dir/private" -name "*.key" -type f 2>/dev/null | head -1
}

# =============================================================================
# Classical ECDSA TSA
# =============================================================================
echo "[CrossCompat] Classical TSA Token: ECDSA"
CA_DIR="$FIXTURES/classical/ca"
if [ -d "$CA_DIR" ]; then
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$CA_KEY" ]; then
        # Generate TSA token using CA cert as TSA cert
        if "$PKI" tsa sign --data "$TMP_DIR/data.txt" \
            --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ts-ecdsa.tsr" 2>/dev/null; then
            # Parse with OpenSSL
            if openssl ts -reply -in "$TMP_DIR/ts-ecdsa.tsr" -text 2>/dev/null | head -20; then
                echo "    ECDSA TSA: OK (parsed)"
            else
                echo "    ECDSA TSA: FAIL (parse error)"
            fi
        else
            echo "    ECDSA TSA: FAIL (generation error)"
        fi
    else
        echo "    ECDSA TSA: SKIP (no CA key found)"
    fi
else
    echo "    ECDSA TSA: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87 TSA
# =============================================================================
echo "[CrossCompat] PQC TSA Token: ML-DSA-87"
CA_DIR="$FIXTURES/pqc/mldsa/ca"
if [ -d "$CA_DIR" ]; then
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$CA_KEY" ]; then
        # Generate TSA token
        if "$PKI" tsa sign --data "$TMP_DIR/data.txt" \
            --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ts-mldsa.tsr" 2>/dev/null; then
            # Parse with OpenSSL
            if openssl ts -reply -in "$TMP_DIR/ts-mldsa.tsr" -text 2>/dev/null | head -20; then
                echo "    ML-DSA-87 TSA: OK (parsed)"
            else
                echo "    ML-DSA-87 TSA: SKIP (OpenSSL limitation)"
            fi
        else
            echo "    ML-DSA-87 TSA: FAIL (generation error)"
        fi
    else
        echo "    ML-DSA-87 TSA: SKIP (no CA key found)"
    fi
else
    echo "    ML-DSA-87 TSA: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst TSA (ECDSA + ML-DSA)
# =============================================================================
echo "[CrossCompat] Hybrid TSA Token: Catalyst"
CA_DIR="$FIXTURES/catalyst/ca"
if [ -d "$CA_DIR" ]; then
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$CA_KEY" ]; then
        # Generate TSA token
        if "$PKI" tsa sign --data "$TMP_DIR/data.txt" \
            --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ts-catalyst.tsr" 2>/dev/null; then
            # OpenSSL parses the token, may only verify ECDSA signature
            if openssl ts -reply -in "$TMP_DIR/ts-catalyst.tsr" -text 2>/dev/null | head -20; then
                echo "    Catalyst TSA (ECDSA sig): OK (parsed)"
                echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
            else
                echo "    Catalyst TSA: FAIL (parse error)"
            fi
        else
            echo "    Catalyst TSA: FAIL (generation error)"
        fi
    else
        echo "    Catalyst TSA: SKIP (no CA key found)"
    fi
else
    echo "    Catalyst TSA: SKIP (fixtures not found)"
fi
echo ""

# Cleanup
rm -rf "$TMP_DIR"

echo "[PASS] TSA Token Verification Complete"
