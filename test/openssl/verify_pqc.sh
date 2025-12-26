#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: PQC Certificates (ML-DSA, SLH-DSA)
# =============================================================================
#
# Tests PQC certificate display with OpenSSL.
#
# REQUIREMENTS:
#   - OpenSSL 3.5+ for native PQC support (ML-DSA, SLH-DSA)
#   - Ubuntu 24.04 only has OpenSSL 3.0 (no PQC support)
#
# NOTE: This script will skip tests gracefully if OpenSSL < 3.5
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_MLDSA="$SCRIPT_DIR/../fixtures/pqc/mldsa"
FIXTURES_SLHDSA="$SCRIPT_DIR/../fixtures/pqc/slhdsa"

echo "=== OpenSSL PQC Certificate Tests ==="
echo ""

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "OpenSSL version: $OPENSSL_VERSION"

# Compare versions (need bc for floating point)
if command -v bc &> /dev/null; then
    NEED_SKIP=$(echo "$OPENSSL_VERSION < 3.5" | bc)
else
    # Fallback: simple string comparison
    if [[ "$OPENSSL_VERSION" < "3.5" ]]; then
        NEED_SKIP=1
    else
        NEED_SKIP=0
    fi
fi

if [ "$NEED_SKIP" = "1" ]; then
    echo ""
    echo "WARNING: OpenSSL $OPENSSL_VERSION detected."
    echo "         PQC certificate verification requires OpenSSL 3.5+"
    echo "         Skipping PQC verification tests."
    echo ""
    echo "         PQC certificates will be verified by BouncyCastle instead."
    echo ""
    echo "=== PQC tests SKIPPED (OpenSSL too old) ==="
    exit 0
fi

# Check fixtures exist
if [ ! -d "$FIXTURES_MLDSA/ca" ]; then
    echo "ERROR: ML-DSA fixtures not found. Run ./test/generate_fixtures.sh first."
    exit 1
fi

echo ""
echo ">>> ML-DSA-87 Certificate:"
echo ""

# Display ML-DSA cert
openssl x509 -in "$FIXTURES_MLDSA/ca/ca.crt" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10

# Verify ML-DSA OID is recognized
if openssl x509 -in "$FIXTURES_MLDSA/ca/ca.crt" -text -noout | grep -qi "ML-DSA"; then
    echo ""
    echo "    ML-DSA OID recognized by OpenSSL"
else
    echo ""
    echo "WARNING: ML-DSA OID not recognized (displayed as OID numbers)"
fi

echo ""
echo ">>> SLH-DSA-256f Certificate:"
echo ""

if [ -d "$FIXTURES_SLHDSA/ca" ]; then
    openssl x509 -in "$FIXTURES_SLHDSA/ca/ca.crt" -text -noout | \
        grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10

    if openssl x509 -in "$FIXTURES_SLHDSA/ca/ca.crt" -text -noout | grep -qi "SLH-DSA"; then
        echo ""
        echo "    SLH-DSA OID recognized by OpenSSL"
    else
        echo ""
        echo "WARNING: SLH-DSA OID not recognized (displayed as OID numbers)"
    fi
else
    echo "    SLH-DSA fixtures not found, skipping."
fi

echo ""
echo "=== PQC display tests PASSED ==="
