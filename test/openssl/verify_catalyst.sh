#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: Catalyst Hybrid Certificates
# =============================================================================
#
# Verifies classical signature of Catalyst hybrid certificates using OpenSSL.
#
# NOTE: OpenSSL only verifies the classical (ECDSA) signature.
#       It ignores the PQC signature in the AltSignatureValue extension.
#       This demonstrates backward compatibility of Catalyst certificates.
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures/catalyst"

echo "[CrossCompat] OpenSSL Catalyst Certificate Tests"
echo "NOTE: OpenSSL verifies classical signature only (ignores PQC extension)"
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

# Verify chain (classical signature only)
echo "[CrossCompat] Verify: Certificate Chain (Classical Signature)"
openssl verify -CAfile "$FIXTURES/ca/ca.crt" "$CRED_CERT"
echo ""

# Display CA certificate details
echo "[CrossCompat] CA Certificate Details:"
openssl x509 -in "$FIXTURES/ca/ca.crt" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

# Show extensions (AltSignatureValue should be visible)
echo "[CrossCompat] X.509v3 Extensions (Catalyst-Specific):"
openssl x509 -in "$CRED_CERT" -text -noout | \
    grep -A 3 "X509v3 extensions:" || echo "    (extensions section)"

# Look for unknown extensions (Catalyst OIDs)
echo ""
echo "[CrossCompat] Catalyst Extensions (may appear as 'unknown'):"
openssl x509 -in "$CRED_CERT" -text -noout | \
    grep -E "(2\.5\.29\.72|2\.5\.29\.73|2\.5\.29\.74)" || echo "    (OIDs not displayed by name)"
echo ""

echo "[PASS] Catalyst Classical Verification"
echo "    (PQC signature requires pki verify or BouncyCastle)"
