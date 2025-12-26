#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: Classical Certificates (ECDSA)
# =============================================================================
#
# Verifies classical ECDSA certificates using OpenSSL.
# This validates interoperability with standard PKI tools.
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures/classical"

echo "=== OpenSSL Classical Certificate Tests (ECDSA) ==="
echo ""

# Check fixtures exist
if [ ! -d "$FIXTURES/ca" ]; then
    echo "ERROR: Fixtures not found. Run ./test/generate_fixtures.sh first."
    exit 1
fi

# Find the bundle certificate
BUNDLE_CERT=$(find "$FIXTURES/ca/bundles" -name "certificates.pem" -type f 2>/dev/null | head -1)
if [ -z "$BUNDLE_CERT" ]; then
    echo "ERROR: Bundle certificate not found."
    exit 1
fi

echo "CA Certificate: $FIXTURES/ca/ca.crt"
echo "EE Certificate: $BUNDLE_CERT"
echo ""

# Verify chain
echo ">>> Verifying certificate chain..."
openssl verify -CAfile "$FIXTURES/ca/ca.crt" "$BUNDLE_CERT"
echo ""

# Display CA certificate details
echo ">>> CA Certificate details:"
openssl x509 -in "$FIXTURES/ca/ca.crt" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

# Display EE certificate details
echo ">>> End-Entity Certificate details:"
openssl x509 -in "$BUNDLE_CERT" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

echo "=== Classical ECDSA verification PASSED ==="
