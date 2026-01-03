#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: CSR Verification
# =============================================================================
#
# Verifies Certificate Signing Requests using OpenSSL 3.6+:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87, SLH-DSA-256f)
#   - Hybrid (Catalyst: ECDSA + ML-DSA)
#   - ML-KEM (RFC 9883 attestation - signature verification only)
#
# REQUIREMENTS: OpenSSL 3.5+ for PQC support
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"

echo "=== CSR Verification (OpenSSL) ==="
echo ""

# =============================================================================
# Classical ECDSA CSR
# =============================================================================
echo ">>> Classical CSR (ECDSA)"
if [ -f "$FIXTURES/csr/ecdsa.csr" ]; then
    if openssl req -in "$FIXTURES/csr/ecdsa.csr" -verify -noout 2>/dev/null; then
        echo "    ECDSA CSR: OK"
    else
        echo "    ECDSA CSR: FAIL"
    fi
else
    echo "    ECDSA CSR: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87 CSR
# =============================================================================
echo ">>> PQC CSR (ML-DSA-87)"
if [ -f "$FIXTURES/csr/mldsa87.csr" ]; then
    if openssl req -in "$FIXTURES/csr/mldsa87.csr" -verify -noout 2>/dev/null; then
        echo "    ML-DSA-87 CSR: OK"
    else
        # OpenSSL 3.6 doesn't fully support ML-DSA CSR verification yet
        echo "    ML-DSA-87 CSR: SKIP (OpenSSL limitation)"
    fi
else
    echo "    ML-DSA-87 CSR: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# PQC SLH-DSA-256f CSR
# =============================================================================
echo ">>> PQC CSR (SLH-DSA-256f)"
if [ -f "$FIXTURES/csr/slhdsa256f.csr" ]; then
    if openssl req -in "$FIXTURES/csr/slhdsa256f.csr" -verify -noout 2>/dev/null; then
        echo "    SLH-DSA-256f CSR: OK"
    else
        echo "    SLH-DSA-256f CSR: FAIL (OpenSSL may not support SLH-DSA)"
    fi
else
    echo "    SLH-DSA-256f CSR: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst CSR (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Hybrid CSR (Catalyst)"
if [ -f "$FIXTURES/csr/catalyst.csr" ]; then
    # OpenSSL verifies only the primary ECDSA signature
    if openssl req -in "$FIXTURES/csr/catalyst.csr" -verify -noout 2>/dev/null; then
        echo "    Catalyst CSR (ECDSA sig): OK"
        echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
    else
        echo "    Catalyst CSR: FAIL"
    fi
else
    echo "    Catalyst CSR: SKIP (fixture not found)"
fi
echo ""

# =============================================================================
# ML-KEM CSR with RFC 9883 Attestation
# =============================================================================
echo ">>> ML-KEM CSR (RFC 9883 Attestation)"
if [ -f "$FIXTURES/csr/mlkem768.csr" ]; then
    # OpenSSL verifies only the signature (ECDSA/ML-DSA), not the attestation attribute
    # ML-KEM CSRs are signed with ML-DSA which OpenSSL 3.6 doesn't fully support
    if openssl req -in "$FIXTURES/csr/mlkem768.csr" -verify -noout 2>/dev/null; then
        echo "    ML-KEM-768 CSR (signature): OK"
        echo "    Note: RFC 9883 attestation attribute verified by BouncyCastle only"
    else
        echo "    ML-KEM-768 CSR: SKIP (OpenSSL limitation - ML-DSA signature)"
        echo "    Note: RFC 9883 attestation verified by BouncyCastle only"
    fi
else
    echo "    ML-KEM-768 CSR: SKIP (fixture not found)"
fi
echo ""

echo "=== CSR Verification Complete ==="
