#!/bin/bash
# =============================================================================
# Cross-Test Fixture Generator
# =============================================================================
#
# Generates test certificates for cross-validation with external tools:
# - OpenSSL (classical + Catalyst classical part)
# - BouncyCastle 1.83+ (all certificate types including Composite)
#
# Usage: ./test/generate_fixtures.sh
#
# =============================================================================

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PKI="$PROJECT_ROOT/pki"
OUT="$SCRIPT_DIR/fixtures"

# Check if pki binary exists
if [ ! -f "$PKI" ]; then
    echo "Building pki binary..."
    cd "$PROJECT_ROOT"
    go build -o ./pki ./cmd/pki
    PKI="$PROJECT_ROOT/pki"
fi

echo "=== Cross-Test Fixture Generator ==="
echo "Output directory: $OUT"
echo ""

# Clean previous fixtures
rm -rf "$OUT"
mkdir -p "$OUT"/{classical,pqc/mldsa,pqc/slhdsa,catalyst,composite}

# -----------------------------------------------------------------------------
# Classical ECDSA
# -----------------------------------------------------------------------------
echo ">>> Generating Classical ECDSA certificates..."
"$PKI" init-ca --profile ec/root-ca --name "Test ECDSA CA" --dir "$OUT/classical/ca"
"$PKI" bundle enroll --ca-dir "$OUT/classical/ca" --profile ec/tls-server \
    --subject "CN=ecdsa.test.local" --dns ecdsa.test.local
echo "    Classical ECDSA: OK"

# -----------------------------------------------------------------------------
# PQC ML-DSA-87
# -----------------------------------------------------------------------------
echo ">>> Generating PQC ML-DSA-87 certificates..."
"$PKI" init-ca --profile ml-dsa-kem/root-ca --name "Test ML-DSA CA" --dir "$OUT/pqc/mldsa/ca"
"$PKI" bundle enroll --ca-dir "$OUT/pqc/mldsa/ca" --profile ml-dsa-kem/tls-server \
    --subject "CN=mldsa.test.local" --dns mldsa.test.local
echo "    PQC ML-DSA-87: OK"

# -----------------------------------------------------------------------------
# PQC SLH-DSA-256f
# -----------------------------------------------------------------------------
echo ">>> Generating PQC SLH-DSA-256f certificates..."
"$PKI" init-ca --profile slh-dsa/root-ca-256f --name "Test SLH-DSA CA" --dir "$OUT/pqc/slhdsa/ca"
"$PKI" bundle enroll --ca-dir "$OUT/pqc/slhdsa/ca" --profile slh-dsa/tls-server-256f \
    --subject "CN=slhdsa.test.local" --dns slhdsa.test.local
echo "    PQC SLH-DSA-256f: OK"

# -----------------------------------------------------------------------------
# Catalyst Hybrid (ECDSA + ML-DSA)
# -----------------------------------------------------------------------------
echo ">>> Generating Catalyst Hybrid certificates..."
"$PKI" init-ca --profile hybrid/catalyst/root-ca --name "Test Catalyst CA" --dir "$OUT/catalyst/ca"
"$PKI" bundle enroll --ca-dir "$OUT/catalyst/ca" --profile hybrid/catalyst/tls-server \
    --subject "CN=catalyst.test.local" --dns catalyst.test.local
echo "    Catalyst Hybrid: OK"

# -----------------------------------------------------------------------------
# Composite Hybrid (IETF draft-ietf-lamps-pq-composite-sigs-13)
# -----------------------------------------------------------------------------
echo ">>> Generating Composite Hybrid certificates..."
"$PKI" init-ca --profile hybrid/composite/root-ca --name "Test Composite CA" --dir "$OUT/composite/ca"
"$PKI" bundle enroll --ca-dir "$OUT/composite/ca" --profile hybrid/composite/tls-server \
    --subject "CN=composite.test.local" --dns composite.test.local
echo "    Composite Hybrid: OK"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "=== Fixture Generation Complete ==="
echo ""
echo "Generated certificates:"
echo "  - Classical ECDSA:    $OUT/classical/ca/"
echo "  - PQC ML-DSA-87:      $OUT/pqc/mldsa/ca/"
echo "  - PQC SLH-DSA-256f:   $OUT/pqc/slhdsa/ca/"
echo "  - Catalyst Hybrid:    $OUT/catalyst/ca/"
echo "  - Composite Hybrid:   $OUT/composite/ca/"
echo ""
echo "Run cross-tests with:"
echo "  cd test/openssl && ./run_all.sh"
echo "  cd test/bouncycastle && mvn test"
