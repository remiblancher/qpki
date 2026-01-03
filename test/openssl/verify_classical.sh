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

echo "[CrossCompat] OpenSSL Classical Certificate Tests (ECDSA)"
echo ""

# Check fixtures exist
if [ ! -d "$FIXTURES/ca" ]; then
    echo "ERROR: Fixtures not found. Run ./test/generate_fixtures.sh first."
    exit 1
fi

# Find the credential certificate
CRED_CERT=$(find "$FIXTURES/ca/credentials" -name "certificates.pem" -type f 2>/dev/null | head -1)
if [ -z "$CRED_CERT" ]; then
    echo "ERROR: Credential certificate not found."
    exit 1
fi

echo "CA Certificate: $FIXTURES/ca/ca.crt"
echo "EE Certificate: $CRED_CERT"
echo ""

# Verify chain
echo "[CrossCompat] Verify: Certificate Chain"
openssl verify -CAfile "$FIXTURES/ca/ca.crt" "$CRED_CERT"
echo ""

# Display CA certificate details
echo "[CrossCompat] CA Certificate Details:"
openssl x509 -in "$FIXTURES/ca/ca.crt" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

# Display EE certificate details
echo "[CrossCompat] End-Entity Certificate Details:"
openssl x509 -in "$CRED_CERT" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

echo "[PASS] Classical ECDSA Verification"
