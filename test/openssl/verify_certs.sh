#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: Certificate Verification
# =============================================================================
#
# Verifies certificates using OpenSSL 3.6+:
#   - Classical (ECDSA, RSA)
#   - PQC (ML-DSA-87, SLH-DSA-256f)
#   - Hybrid (Catalyst: ECDSA + ML-DSA)
#
# REQUIREMENTS: OpenSSL 3.5+ for PQC support
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"

echo "=== Certificate Verification (OpenSSL) ==="
echo ""

# Helper to find credential certificate
find_ee_cert() {
    local ca_dir="$1"
    find "$ca_dir/credentials" -name "certificates.pem" -type f 2>/dev/null | head -1
}

# =============================================================================
# Classical ECDSA
# =============================================================================
echo ">>> Classical (ECDSA)"
if [ -d "$FIXTURES/classical/ca" ]; then
    EE_CERT=$(find_ee_cert "$FIXTURES/classical/ca")
    if [ -n "$EE_CERT" ]; then
        openssl verify -CAfile "$FIXTURES/classical/ca/ca.crt" "$EE_CERT"
        echo "    ECDSA: OK"
    else
        echo "    ECDSA: SKIP (no EE cert found)"
    fi
else
    echo "    ECDSA: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87
# =============================================================================
echo ">>> PQC (ML-DSA-87)"
if [ -d "$FIXTURES/pqc/mldsa/ca" ]; then
    EE_CERT=$(find_ee_cert "$FIXTURES/pqc/mldsa/ca")
    if [ -n "$EE_CERT" ]; then
        if openssl verify -CAfile "$FIXTURES/pqc/mldsa/ca/ca.crt" "$EE_CERT" 2>/dev/null; then
            echo "    ML-DSA-87: OK"
        else
            echo "    ML-DSA-87: FAIL (OpenSSL may not support ML-DSA)"
        fi
    else
        echo "    ML-DSA-87: SKIP (no EE cert found)"
    fi
else
    echo "    ML-DSA-87: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC SLH-DSA-256f
# =============================================================================
echo ">>> PQC (SLH-DSA-256f)"
if [ -d "$FIXTURES/pqc/slhdsa/ca" ]; then
    EE_CERT=$(find_ee_cert "$FIXTURES/pqc/slhdsa/ca")
    if [ -n "$EE_CERT" ]; then
        if openssl verify -CAfile "$FIXTURES/pqc/slhdsa/ca/ca.crt" "$EE_CERT" 2>/dev/null; then
            echo "    SLH-DSA-256f: OK"
        else
            echo "    SLH-DSA-256f: FAIL (OpenSSL may not support SLH-DSA)"
        fi
    else
        echo "    SLH-DSA-256f: SKIP (no EE cert found)"
    fi
else
    echo "    SLH-DSA-256f: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Hybrid (Catalyst: ECDSA + ML-DSA)"
if [ -d "$FIXTURES/catalyst/ca" ]; then
    EE_CERT=$(find_ee_cert "$FIXTURES/catalyst/ca")
    if [ -n "$EE_CERT" ]; then
        # OpenSSL verifies only the primary ECDSA signature
        if openssl verify -CAfile "$FIXTURES/catalyst/ca/ca.crt" "$EE_CERT" 2>/dev/null; then
            echo "    Catalyst (ECDSA sig): OK"
            echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
        else
            echo "    Catalyst: FAIL"
        fi
    else
        echo "    Catalyst: SKIP (no EE cert found)"
    fi
else
    echo "    Catalyst: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Composite Hybrid
# =============================================================================
echo ">>> Hybrid (Composite: ECDSA + ML-DSA)"
if [ -d "$FIXTURES/composite/ca" ]; then
    EE_CERT=$(find_ee_cert "$FIXTURES/composite/ca")
    if [ -n "$EE_CERT" ]; then
        if openssl verify -CAfile "$FIXTURES/composite/ca/ca.crt" "$EE_CERT" 2>/dev/null; then
            echo "    Composite: OK"
        else
            echo "    Composite: FAIL (OpenSSL may not support Composite)"
        fi
    else
        echo "    Composite: SKIP (no EE cert found)"
    fi
else
    echo "    Composite: SKIP (fixtures not found)"
fi
echo ""

echo "=== Certificate Verification Complete ==="
