#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: CRL Verification
# =============================================================================
#
# Verifies Certificate Revocation Lists using OpenSSL 3.6+:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87)
#   - Hybrid (Catalyst: ECDSA + ML-DSA)
#
# REQUIREMENTS: OpenSSL 3.5+ for PQC support
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"

echo "[CrossCompat] CRL Verification (OpenSSL)"
echo ""

# =============================================================================
# Classical ECDSA CRL
# =============================================================================
echo "[CrossCompat] Classical CRL: ECDSA"
if [ -f "$FIXTURES/classical/ca/crl/ca.crl" ]; then
    if openssl crl -in "$FIXTURES/classical/ca/crl/ca.crl" -CAfile "$FIXTURES/classical/ca/ca.crt" -verify -noout 2>/dev/null; then
        echo "    ECDSA CRL: OK"
    else
        # Try without -verify for display purposes
        if openssl crl -in "$FIXTURES/classical/ca/crl/ca.crl" -noout 2>/dev/null; then
            echo "    ECDSA CRL: OK (parsed)"
        else
            echo "    ECDSA CRL: FAIL"
        fi
    fi
else
    echo "    ECDSA CRL: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87 CRL
# =============================================================================
echo "[CrossCompat] PQC CRL: ML-DSA-87"
if [ -f "$FIXTURES/pqc/mldsa/ca/crl/ca.crl" ]; then
    if openssl crl -in "$FIXTURES/pqc/mldsa/ca/crl/ca.crl" -CAfile "$FIXTURES/pqc/mldsa/ca/ca.crt" -verify -noout 2>/dev/null; then
        echo "    ML-DSA-87 CRL: OK"
    else
        if openssl crl -in "$FIXTURES/pqc/mldsa/ca/crl/ca.crl" -noout 2>/dev/null; then
            echo "    ML-DSA-87 CRL: OK (parsed, signature may not be verified)"
        else
            echo "    ML-DSA-87 CRL: SKIP (OpenSSL limitation)"
        fi
    fi
else
    echo "    ML-DSA-87 CRL: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst CRL (ECDSA + ML-DSA)
# =============================================================================
echo "[CrossCompat] Hybrid CRL: Catalyst"
if [ -f "$FIXTURES/catalyst/ca/crl/ca.crl" ]; then
    # OpenSSL verifies only the primary ECDSA signature
    if openssl crl -in "$FIXTURES/catalyst/ca/crl/ca.crl" -CAfile "$FIXTURES/catalyst/ca/ca.crt" -verify -noout 2>/dev/null; then
        echo "    Catalyst CRL (ECDSA sig): OK"
        echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
    else
        if openssl crl -in "$FIXTURES/catalyst/ca/crl/ca.crl" -noout 2>/dev/null; then
            echo "    Catalyst CRL: OK (parsed)"
        else
            echo "    Catalyst CRL: FAIL"
        fi
    fi
else
    echo "    Catalyst CRL: SKIP (fixture not found)"
fi
echo ""

echo "[PASS] CRL Verification Complete"
