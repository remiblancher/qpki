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

PKI="$PROJECT_ROOT/qpki"
OUT="$SCRIPT_DIR/fixtures"

# Check if qpki binary exists
if [ ! -f "$PKI" ]; then
    echo "Building qpki binary..."
    cd "$PROJECT_ROOT"
    go build -o ./qpki ./cmd/qpki
    PKI="$PROJECT_ROOT/qpki"
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
"$PKI" ca init --profile ec/root-ca --name "Test ECDSA CA" --dir "$OUT/classical/ca"
"$PKI" credential enroll -d "$OUT/classical/ca" --profile ec/tls-server \
    --var cn=ecdsa.test.local --var dns_names=ecdsa.test.local
echo "    Classical ECDSA: OK"

# -----------------------------------------------------------------------------
# PQC ML-DSA-87
# -----------------------------------------------------------------------------
echo ">>> Generating PQC ML-DSA-87 certificates..."
"$PKI" ca init --profile ml/root-ca --name "Test ML-DSA CA" --dir "$OUT/pqc/mldsa/ca"
"$PKI" credential enroll -d "$OUT/pqc/mldsa/ca" --profile ml/tls-server-sign \
    --var cn=mldsa.test.local --var dns_names=mldsa.test.local
echo "    PQC ML-DSA-87: OK"

# -----------------------------------------------------------------------------
# PQC SLH-DSA
# -----------------------------------------------------------------------------
echo ">>> Generating PQC SLH-DSA certificates..."
"$PKI" ca init --profile slh/root-ca --name "Test SLH-DSA CA" --dir "$OUT/pqc/slhdsa/ca"
"$PKI" credential enroll -d "$OUT/pqc/slhdsa/ca" --profile slh/tls-server \
    --var cn=slhdsa.test.local --var dns_names=slhdsa.test.local
echo "    PQC SLH-DSA: OK"

# -----------------------------------------------------------------------------
# Catalyst Hybrid (ECDSA + ML-DSA)
# -----------------------------------------------------------------------------
echo ">>> Generating Catalyst Hybrid certificates..."
"$PKI" ca init --profile hybrid/catalyst/root-ca --name "Test Catalyst CA" --dir "$OUT/catalyst/ca"
"$PKI" credential enroll -d "$OUT/catalyst/ca" --profile hybrid/catalyst/tls-server \
    --var cn=catalyst.test.local --var dns_names=catalyst.test.local
echo "    Catalyst Hybrid: OK"

# -----------------------------------------------------------------------------
# Composite Hybrid (IETF draft-ietf-lamps-pq-composite-sigs-13)
# -----------------------------------------------------------------------------
echo ">>> Generating Composite Hybrid certificates..."
"$PKI" ca init --profile hybrid/composite/root-ca --name "Test Composite CA" --dir "$OUT/composite/ca"
"$PKI" credential enroll -d "$OUT/composite/ca" --profile hybrid/composite/tls-server \
    --var cn=composite.test.local --var dns_names=composite.test.local
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
echo "  - PQC SLH-DSA:        $OUT/pqc/slhdsa/ca/"
echo "  - Catalyst Hybrid:    $OUT/catalyst/ca/"
echo "  - Composite Hybrid:   $OUT/composite/ca/"
echo ""
echo "Run cross-tests with:"
echo "  cd test/openssl && ./run_all.sh"
echo "  cd test/bouncycastle && mvn test"
