#!/bin/bash
# =============================================================================
# Cross-Test Fixture Generator
# =============================================================================
#
# Generates test fixtures for cross-validation with external tools:
# - OpenSSL 3.6+ (classical + PQC + Catalyst classical part)
# - BouncyCastle 1.83+ (all certificate types including Composite)
#
# Generated artifacts:
# - CA hierarchies (classical, PQC, hybrid)
# - End-entity certificates
# - CRLs for each CA
# - CSRs (classical, PQC, hybrid, ML-KEM with RFC 9883)
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
mkdir -p "$OUT"/{classical,pqc/mldsa,pqc/slhdsa,catalyst,composite,csr}

# =============================================================================
# Classical ECDSA
# =============================================================================
echo ">>> Generating Classical ECDSA..."
"$PKI" ca init --profile ec/root-ca --name "Test ECDSA CA" --dir "$OUT/classical/ca"
"$PKI" credential enroll -d "$OUT/classical/ca" --profile ec/tls-server \
    --var cn=ecdsa.test.local --var dns_names=ecdsa.test.local
"$PKI" ca crl gen -d "$OUT/classical/ca"
echo "    Classical ECDSA: OK (CA + EE + CRL)"

# =============================================================================
# PQC ML-DSA-87
# =============================================================================
echo ">>> Generating PQC ML-DSA-87..."
"$PKI" ca init --profile ml/root-ca --name "Test ML-DSA CA" --dir "$OUT/pqc/mldsa/ca"
"$PKI" credential enroll -d "$OUT/pqc/mldsa/ca" --profile ml/tls-server-sign \
    --var cn=mldsa.test.local --var dns_names=mldsa.test.local
"$PKI" ca crl gen -d "$OUT/pqc/mldsa/ca"
echo "    PQC ML-DSA-87: OK (CA + EE + CRL)"

# =============================================================================
# PQC SLH-DSA
# =============================================================================
echo ">>> Generating PQC SLH-DSA..."
"$PKI" ca init --profile slh/root-ca --name "Test SLH-DSA CA" --dir "$OUT/pqc/slhdsa/ca"
"$PKI" credential enroll -d "$OUT/pqc/slhdsa/ca" --profile slh/tls-server \
    --var cn=slhdsa.test.local --var dns_names=slhdsa.test.local
"$PKI" ca crl gen -d "$OUT/pqc/slhdsa/ca"
echo "    PQC SLH-DSA: OK (CA + EE + CRL)"

# =============================================================================
# Catalyst Hybrid (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Generating Catalyst Hybrid..."
"$PKI" ca init --profile hybrid/catalyst/root-ca --name "Test Catalyst CA" --dir "$OUT/catalyst/ca"
"$PKI" credential enroll -d "$OUT/catalyst/ca" --profile hybrid/catalyst/tls-server \
    --var cn=catalyst.test.local --var dns_names=catalyst.test.local
"$PKI" ca crl gen -d "$OUT/catalyst/ca"
echo "    Catalyst Hybrid: OK (CA + EE + CRL)"

# =============================================================================
# Composite Hybrid (IETF draft-ietf-lamps-pq-composite-sigs-13)
# =============================================================================
echo ">>> Generating Composite Hybrid..."
"$PKI" ca init --profile hybrid/composite/root-ca --name "Test Composite CA" --dir "$OUT/composite/ca"
"$PKI" credential enroll -d "$OUT/composite/ca" --profile hybrid/composite/tls-server \
    --var cn=composite.test.local --var dns_names=composite.test.local
"$PKI" ca crl gen -d "$OUT/composite/ca"
echo "    Composite Hybrid: OK (CA + EE + CRL)"

# =============================================================================
# CSR Generation (for cross-testing CSR verification)
# =============================================================================
echo ""
echo ">>> Generating CSRs..."

# Classical ECDSA CSR
"$PKI" cert csr --algorithm ecdsa-p256 --keyout "$OUT/csr/ecdsa.key" \
    --cn "CSR Test ECDSA" --dns csr.ecdsa.test.local -o "$OUT/csr/ecdsa.csr"
echo "    CSR ECDSA: OK"

# PQC ML-DSA-87 CSR
"$PKI" cert csr --algorithm ml-dsa-87 --keyout "$OUT/csr/mldsa87.key" \
    --cn "CSR Test ML-DSA-87" --dns csr.mldsa.test.local -o "$OUT/csr/mldsa87.csr"
echo "    CSR ML-DSA-87: OK"

# PQC SLH-DSA-256f CSR
"$PKI" cert csr --algorithm slh-dsa-256f --keyout "$OUT/csr/slhdsa256f.key" \
    --cn "CSR Test SLH-DSA-256f" --dns csr.slhdsa.test.local -o "$OUT/csr/slhdsa256f.csr"
echo "    CSR SLH-DSA-256f: OK"

# Hybrid Catalyst CSR (ECDSA + ML-DSA)
"$PKI" cert csr --algorithm ecdsa-p256 --keyout "$OUT/csr/catalyst-classical.key" \
    --hybrid ml-dsa-65 --hybrid-keyout "$OUT/csr/catalyst-pqc.key" \
    --cn "CSR Test Catalyst" --dns csr.catalyst.test.local -o "$OUT/csr/catalyst.csr"
echo "    CSR Catalyst Hybrid: OK"

# ML-KEM CSR with RFC 9883 attestation
# First, create an attestation certificate (reuse the classical credential)
ATTEST_CRED=$(find "$OUT/classical/ca/credentials" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
if [ -n "$ATTEST_CRED" ]; then
    "$PKI" cert csr --algorithm ml-kem-768 --keyout "$OUT/csr/mlkem768.key" \
        --attest-cert "$ATTEST_CRED/certificates.pem" --attest-key "$ATTEST_CRED/private-keys.pem" \
        --cn "CSR Test ML-KEM-768" --email mlkem@test.local -o "$OUT/csr/mlkem768.csr"
    echo "    CSR ML-KEM-768 (RFC 9883): OK"
else
    echo "    CSR ML-KEM-768: SKIP (no attestation credential found)"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=== Fixture Generation Complete ==="
echo ""
echo "Generated CA hierarchies:"
echo "  - Classical ECDSA:    $OUT/classical/ca/"
echo "  - PQC ML-DSA-87:      $OUT/pqc/mldsa/ca/"
echo "  - PQC SLH-DSA:        $OUT/pqc/slhdsa/ca/"
echo "  - Catalyst Hybrid:    $OUT/catalyst/ca/"
echo "  - Composite Hybrid:   $OUT/composite/ca/"
echo ""
echo "Generated CSRs:"
echo "  - $OUT/csr/ecdsa.csr"
echo "  - $OUT/csr/mldsa87.csr"
echo "  - $OUT/csr/slhdsa256f.csr"
echo "  - $OUT/csr/catalyst.csr"
echo "  - $OUT/csr/mlkem768.csr (if attestation available)"
echo ""
echo "Run cross-tests with:"
echo "  cd test/openssl && ./run_all.sh"
echo "  cd test/bouncycastle && mvn test"
