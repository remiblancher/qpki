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

echo "=== OpenSSL Catalyst Certificate Tests ==="
echo "NOTE: OpenSSL verifies classical signature only (ignores PQC extension)"
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

# Verify chain (classical signature only)
echo ">>> Verifying certificate chain (classical signature)..."
openssl verify -CAfile "$FIXTURES/ca/ca.crt" "$BUNDLE_CERT"
echo ""

# Display CA certificate details
echo ">>> CA Certificate details:"
openssl x509 -in "$FIXTURES/ca/ca.crt" -text -noout | \
    grep -E "(Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:)" | head -10
echo ""

# Show extensions (AltSignatureValue should be visible)
echo ">>> X.509v3 Extensions (showing Catalyst-specific extensions):"
openssl x509 -in "$BUNDLE_CERT" -text -noout | \
    grep -A 3 "X509v3 extensions:" || echo "    (extensions section)"

# Look for unknown extensions (Catalyst OIDs)
echo ""
echo ">>> Catalyst extensions (may appear as 'unknown'):"
openssl x509 -in "$BUNDLE_CERT" -text -noout | \
    grep -E "(2\.5\.29\.72|2\.5\.29\.73|2\.5\.29\.74)" || echo "    (OIDs not displayed by name)"
echo ""

echo "=== Catalyst classical verification PASSED ==="
echo "    (PQC signature requires pki verify or BouncyCastle)"
