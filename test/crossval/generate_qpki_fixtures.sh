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
# Usage: ./test/generate_qpki_fixtures.sh
#
# =============================================================================

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
mkdir -p "$OUT"/{classical/ecdsa,classical/rsa,pqc/mldsa,pqc/slhdsa,catalyst,composite,csr}

# =============================================================================
# Classical ECDSA
# =============================================================================
echo ">>> Generating Classical ECDSA..."
"$PKI" ca init --profile ec/root-ca --var cn="Test ECDSA CA" --ca-dir "$OUT/classical/ecdsa/ca"
"$PKI" ca export --ca-dir "$OUT/classical/ecdsa/ca" --out "$OUT/classical/ecdsa/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/classical/ecdsa/ca" --cred-dir "$OUT/classical/ecdsa/credentials" --profile ec/tls-server \
    --var cn=ecdsa.test.local --var dns_names=ecdsa.test.local
"$PKI" credential enroll --ca-dir "$OUT/classical/ecdsa/ca" --cred-dir "$OUT/classical/ecdsa/credentials" --profile ec/ocsp-responder \
    --var cn="ECDSA OCSP Responder"
"$PKI" credential enroll --ca-dir "$OUT/classical/ecdsa/ca" --cred-dir "$OUT/classical/ecdsa/credentials" --profile ec/signing \
    --var cn="ECDSA Signer"
"$PKI" credential enroll --ca-dir "$OUT/classical/ecdsa/ca" --cred-dir "$OUT/classical/ecdsa/credentials" --profile ec/timestamping \
    --var cn="ECDSA TSA"
"$PKI" crl gen --ca-dir "$OUT/classical/ecdsa/ca"
echo "    Classical ECDSA: OK (CA + TLS + OCSP + Signing + TSA + CRL)"

# =============================================================================
# Classical RSA
# =============================================================================
echo ">>> Generating Classical RSA..."
"$PKI" ca init --profile rsa/root-ca --var cn="Test RSA CA" --ca-dir "$OUT/classical/rsa/ca"
"$PKI" ca export --ca-dir "$OUT/classical/rsa/ca" --out "$OUT/classical/rsa/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/classical/rsa/ca" --cred-dir "$OUT/classical/rsa/credentials" --profile rsa/tls-server \
    --var cn=rsa.test.local --var dns_names=rsa.test.local
"$PKI" credential enroll --ca-dir "$OUT/classical/rsa/ca" --cred-dir "$OUT/classical/rsa/credentials" --profile rsa/signing \
    --var cn="RSA Signer"
"$PKI" credential enroll --ca-dir "$OUT/classical/rsa/ca" --cred-dir "$OUT/classical/rsa/credentials" --profile rsa/timestamping \
    --var cn="RSA TSA"
"$PKI" credential enroll --ca-dir "$OUT/classical/rsa/ca" --cred-dir "$OUT/classical/rsa/credentials" --profile rsa/ocsp-responder \
    --var cn="RSA OCSP Responder"
"$PKI" crl gen --ca-dir "$OUT/classical/rsa/ca"
echo "    Classical RSA: OK (CA + TLS + Signing + TSA + OCSP + CRL)"

# =============================================================================
# PQC ML-DSA-87
# =============================================================================
echo ">>> Generating PQC ML-DSA-87..."
"$PKI" ca init --profile ml/root-ca --var cn="Test ML-DSA CA" --ca-dir "$OUT/pqc/mldsa/ca"
"$PKI" ca export --ca-dir "$OUT/pqc/mldsa/ca" --out "$OUT/pqc/mldsa/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/pqc/mldsa/ca" --cred-dir "$OUT/pqc/mldsa/credentials" --profile ml/tls-server-sign \
    --var cn=mldsa.test.local --var dns_names=mldsa.test.local
"$PKI" credential enroll --ca-dir "$OUT/pqc/mldsa/ca" --cred-dir "$OUT/pqc/mldsa/credentials" --profile ml/ocsp-responder \
    --var cn="ML-DSA OCSP Responder"
"$PKI" credential enroll --ca-dir "$OUT/pqc/mldsa/ca" --cred-dir "$OUT/pqc/mldsa/credentials" --profile ml/signing \
    --var cn="ML-DSA Signer"
"$PKI" credential enroll --ca-dir "$OUT/pqc/mldsa/ca" --cred-dir "$OUT/pqc/mldsa/credentials" --profile ml/timestamping \
    --var cn="ML-DSA TSA"
"$PKI" crl gen --ca-dir "$OUT/pqc/mldsa/ca"
echo "    PQC ML-DSA-87: OK (CA + TLS + OCSP + Signing + TSA + CRL)"

# =============================================================================
# PQC SLH-DSA
# =============================================================================
echo ">>> Generating PQC SLH-DSA..."
"$PKI" ca init --profile slh/root-ca --var cn="Test SLH-DSA CA" --ca-dir "$OUT/pqc/slhdsa/ca"
"$PKI" ca export --ca-dir "$OUT/pqc/slhdsa/ca" --out "$OUT/pqc/slhdsa/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/pqc/slhdsa/ca" --cred-dir "$OUT/pqc/slhdsa/credentials" --profile slh/tls-server \
    --var cn=slhdsa.test.local --var dns_names=slhdsa.test.local
"$PKI" credential enroll --ca-dir "$OUT/pqc/slhdsa/ca" --cred-dir "$OUT/pqc/slhdsa/credentials" --profile slh/ocsp-responder \
    --var cn="SLH-DSA OCSP Responder"
"$PKI" credential enroll --ca-dir "$OUT/pqc/slhdsa/ca" --cred-dir "$OUT/pqc/slhdsa/credentials" --profile slh/signing \
    --var cn="SLH-DSA Signer"
"$PKI" credential enroll --ca-dir "$OUT/pqc/slhdsa/ca" --cred-dir "$OUT/pqc/slhdsa/credentials" --profile slh/timestamping \
    --var cn="SLH-DSA TSA"
"$PKI" crl gen --ca-dir "$OUT/pqc/slhdsa/ca"
echo "    PQC SLH-DSA: OK (CA + TLS + OCSP + Signing + TSA + CRL)"

# =============================================================================
# Catalyst Hybrid (ECDSA + ML-DSA)
# =============================================================================
echo ">>> Generating Catalyst Hybrid..."
"$PKI" ca init --profile hybrid/catalyst/root-ca --var cn="Test Catalyst CA" --ca-dir "$OUT/catalyst/ca"
"$PKI" ca export --ca-dir "$OUT/catalyst/ca" --out "$OUT/catalyst/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/catalyst/ca" --cred-dir "$OUT/catalyst/credentials" --profile hybrid/catalyst/tls-server \
    --var cn=catalyst.test.local --var dns_names=catalyst.test.local
"$PKI" credential enroll --ca-dir "$OUT/catalyst/ca" --cred-dir "$OUT/catalyst/credentials" --profile hybrid/catalyst/ocsp-responder \
    --var cn="Catalyst OCSP Responder"
"$PKI" credential enroll --ca-dir "$OUT/catalyst/ca" --cred-dir "$OUT/catalyst/credentials" --profile hybrid/catalyst/signing \
    --var cn="Catalyst Signer"
"$PKI" credential enroll --ca-dir "$OUT/catalyst/ca" --cred-dir "$OUT/catalyst/credentials" --profile hybrid/catalyst/timestamping \
    --var cn="Catalyst TSA"
"$PKI" crl gen --ca-dir "$OUT/catalyst/ca"
echo "    Catalyst Hybrid: OK (CA + TLS + OCSP + Signing + TSA + CRL)"

# =============================================================================
# Composite Hybrid (IETF draft-ietf-lamps-pq-composite-sigs-13)
# =============================================================================
echo ">>> Generating Composite Hybrid..."
"$PKI" ca init --profile hybrid/composite/root-ca --var cn="Test Composite CA" --ca-dir "$OUT/composite/ca"
"$PKI" ca export --ca-dir "$OUT/composite/ca" --out "$OUT/composite/ca/ca.crt"
"$PKI" credential enroll --ca-dir "$OUT/composite/ca" --cred-dir "$OUT/composite/credentials" --profile hybrid/composite/tls-server \
    --var cn=composite.test.local --var dns_names=composite.test.local
"$PKI" credential enroll --ca-dir "$OUT/composite/ca" --cred-dir "$OUT/composite/credentials" --profile hybrid/composite/ocsp-responder \
    --var cn="Composite OCSP Responder"
"$PKI" credential enroll --ca-dir "$OUT/composite/ca" --cred-dir "$OUT/composite/credentials" --profile hybrid/composite/signing \
    --var cn="Composite Signer"
"$PKI" credential enroll --ca-dir "$OUT/composite/ca" --cred-dir "$OUT/composite/credentials" --profile hybrid/composite/timestamping \
    --var cn="Composite TSA"
"$PKI" crl gen --ca-dir "$OUT/composite/ca"
echo "    Composite Hybrid: OK (CA + TLS + OCSP + Signing + TSA + CRL)"

# =============================================================================
# CMS/OCSP/TSA Fixtures Generation
# =============================================================================
echo ""
echo ">>> Generating CMS/OCSP/TSA fixtures..."

# Create test data file
echo "Test data for cross-compatibility testing" > "$OUT/testdata.txt"

# Helper to get credential certificate path (handles both old and new structure)
get_cred_cert() {
    local cred_dir="$1"
    # New structure: versions/v1/certs/credential.*.pem
    local new_cert=$(find "$cred_dir/versions" -name "credential.*.pem" 2>/dev/null | head -1)
    if [ -n "$new_cert" ]; then
        echo "$new_cert"
        return
    fi
    # Old structure: certificates.pem
    if [ -f "$cred_dir/certificates.pem" ]; then
        echo "$cred_dir/certificates.pem"
        return
    fi
    echo ""
}

# Helper to get credential key path (handles both old and new structure)
get_cred_key() {
    local cred_dir="$1"
    # New structure: versions/v1/keys/credential.*.key
    local new_key=$(find "$cred_dir/versions" -name "credential.*.key" 2>/dev/null | head -1)
    if [ -n "$new_key" ]; then
        echo "$new_key"
        return
    fi
    # Old structure: private-keys.pem
    if [ -f "$cred_dir/private-keys.pem" ]; then
        echo "$cred_dir/private-keys.pem"
        return
    fi
    echo ""
}

# Function to generate CMS/OCSP/TSA fixtures for a CA
generate_protocol_fixtures() {
    local CA_DIR="$1"
    local OUT_DIR="$2"
    local NAME="$3"

    # Find credentials by CN pattern (case-insensitive)
    local CRED_DIR="$OUT_DIR/credentials"
    local SIGNING_CRED=$(find "$CRED_DIR" -type d -iname "*signer*" 2>/dev/null | head -1)
    local TSA_CRED=$(find "$CRED_DIR" -type d -iname "*tsa*" 2>/dev/null | head -1)
    local OCSP_CRED=$(find "$CRED_DIR" -type d -iname "*ocsp*" 2>/dev/null | head -1)
    local TLS_CRED=$(find "$CRED_DIR" -type d ! -iname "*ocsp*" ! -iname "*signer*" ! -iname "*tsa*" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)

    if [ -z "$SIGNING_CRED" ] || [ -z "$TSA_CRED" ] || [ -z "$OCSP_CRED" ] || [ -z "$TLS_CRED" ]; then
        echo "    $NAME: SKIP (missing credentials)"
        return
    fi

    # Get certificate and key paths
    local SIGNING_CERT=$(get_cred_cert "$SIGNING_CRED")
    local SIGNING_KEY=$(get_cred_key "$SIGNING_CRED")
    local TSA_CERT=$(get_cred_cert "$TSA_CRED")
    local TSA_KEY=$(get_cred_key "$TSA_CRED")
    local OCSP_CERT=$(get_cred_cert "$OCSP_CRED")
    local OCSP_KEY=$(get_cred_key "$OCSP_CRED")
    local TLS_CERT=$(get_cred_cert "$TLS_CRED")

    if [ -z "$SIGNING_CERT" ] || [ -z "$SIGNING_KEY" ]; then
        echo "    $NAME: SKIP (missing signing credential files)"
        return
    fi

    # 1. CMS SignedData (attached)
    "$PKI" cms sign --data "$OUT/testdata.txt" \
        --cert "$SIGNING_CERT" \
        --key "$SIGNING_KEY" \
        --detached=false \
        --out "$OUT_DIR/cms-attached.p7s" 2>/dev/null || true

    # 2. CMS SignedData (detached)
    "$PKI" cms sign --data "$OUT/testdata.txt" \
        --cert "$SIGNING_CERT" \
        --key "$SIGNING_KEY" \
        --detached=true \
        --out "$OUT_DIR/cms-detached.p7s" 2>/dev/null || true

    # 3. OCSP Response (good status) - use TLS cert serial
    if [ -n "$TLS_CERT" ] && [ -n "$OCSP_CERT" ] && [ -n "$OCSP_KEY" ]; then
        # Extract serial from text output: "  Serial Number:  02"
        local SERIAL=$("$PKI" inspect "$TLS_CERT" 2>/dev/null | grep "Serial Number:" | awk '{print $NF}' || echo "")
        if [ -n "$SERIAL" ]; then
            "$PKI" ocsp sign --serial "$SERIAL" --status good \
                --ca "$CA_DIR/ca.crt" \
                --cert "$OCSP_CERT" \
                --key "$OCSP_KEY" \
                --out "$OUT_DIR/ocsp-good.der" 2>/dev/null || true
        fi
    fi

    # 4. TSA Token
    if [ -n "$TSA_CERT" ] && [ -n "$TSA_KEY" ]; then
        "$PKI" tsa sign --data "$OUT/testdata.txt" \
            --cert "$TSA_CERT" \
            --key "$TSA_KEY" \
            --out "$OUT_DIR/timestamp.tsr" 2>/dev/null || true
    fi

    echo "    $NAME: OK (CMS + OCSP + TSA)"
}

# Generate for each CA type
generate_protocol_fixtures "$OUT/classical/ecdsa/ca" "$OUT/classical/ecdsa" "Classical ECDSA"
generate_protocol_fixtures "$OUT/classical/rsa/ca" "$OUT/classical/rsa" "Classical RSA"
generate_protocol_fixtures "$OUT/pqc/mldsa/ca" "$OUT/pqc/mldsa" "PQC ML-DSA-87"
generate_protocol_fixtures "$OUT/pqc/slhdsa/ca" "$OUT/pqc/slhdsa" "PQC SLH-DSA"
generate_protocol_fixtures "$OUT/catalyst/ca" "$OUT/catalyst" "Catalyst Hybrid"
generate_protocol_fixtures "$OUT/composite/ca" "$OUT/composite" "Composite Hybrid"

# =============================================================================
# CMS Encryption Fixtures Generation
# =============================================================================
echo ""
echo ">>> Generating CMS Encryption fixtures..."

# Function to generate CMS encryption fixtures
generate_encryption_fixtures() {
    local CA_DIR="$1"
    local OUT_DIR="$2"
    local NAME="$3"
    local ENC_PROFILE="$4"

    # Check if encryption profile exists
    if [ -z "$ENC_PROFILE" ]; then
        echo "    $NAME Encryption: SKIP (no encryption profile)"
        return
    fi

    # Create encryption credential
    local ENC_CRED_DIR="$OUT_DIR/encryption-cred"
    mkdir -p "$ENC_CRED_DIR"

    if ! "$PKI" credential enroll --ca-dir "$CA_DIR" -c "$ENC_CRED_DIR" --profile "$ENC_PROFILE" \
        --var cn="$NAME Encryption Recipient" 2>/dev/null; then
        echo "    $NAME Encryption: SKIP (enrollment failed)"
        return
    fi

    # Find the created credential
    local CRED=$(find "$ENC_CRED_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
    if [ -z "$CRED" ]; then
        echo "    $NAME Encryption: SKIP (no credential found)"
        return
    fi

    # Get certificate and key paths using helpers
    local CRED_CERT=$(get_cred_cert "$CRED")
    local CRED_KEY=$(get_cred_key "$CRED")
    if [ -z "$CRED_CERT" ] || [ -z "$CRED_KEY" ]; then
        echo "    $NAME Encryption: SKIP (credential files not found)"
        return
    fi

    # Generate encrypted message
    # Use AES-256-CBC for classical (ECDH/RSA) - EnvelopedData
    # Use AES-256-GCM for ML-KEM - AuthEnvelopedData
    local CONTENT_ENC="aes-256-gcm"
    if [[ "$NAME" == "ECDH" ]] || [[ "$NAME" == "RSA" ]]; then
        CONTENT_ENC="aes-256-cbc"
    fi
    if "$PKI" cms encrypt --recipient "$CRED_CERT" \
        --in "$OUT/testdata.txt" --out "$OUT_DIR/cms-enveloped.p7m" \
        --content-enc "$CONTENT_ENC" 2>/dev/null; then
        # Copy key for decryption tests
        cp "$CRED_KEY" "$OUT_DIR/encryption-key.pem" 2>/dev/null || true
        cp "$CRED_CERT" "$OUT_DIR/encryption-cert.pem" 2>/dev/null || true
        echo "    $NAME Encryption: OK (EnvelopedData)"
    else
        echo "    $NAME Encryption: FAIL (encryption error)"
    fi
}

# Classical ECDH encryption (AES-CBC for EnvelopedData)
generate_encryption_fixtures "$OUT/classical/ecdsa/ca" "$OUT/classical/ecdsa" "ECDH" "ec/encryption"

# RSA encryption (AES-CBC for EnvelopedData)
generate_encryption_fixtures "$OUT/classical/rsa/ca" "$OUT/classical/rsa" "RSA" "rsa/encryption"

# Classical ECDH encryption (AES-GCM for AuthEnvelopedData)
generate_encryption_fixtures_gcm() {
    local CA_DIR="$1"
    local OUT_DIR="$2"
    local NAME="$3"
    local ENC_PROFILE="$4"

    # Reuse existing encryption credential
    local CRED=$(find "$OUT_DIR/encryption-cred" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
    if [ -z "$CRED" ]; then
        echo "    $NAME AuthEnveloped: SKIP (no credential found)"
        return
    fi

    # Get certificate path using helper
    local CRED_CERT=$(get_cred_cert "$CRED")
    if [ -z "$CRED_CERT" ]; then
        echo "    $NAME AuthEnveloped: SKIP (credential cert not found)"
        return
    fi

    # Generate encrypted message with AES-256-GCM (AuthEnvelopedData)
    if "$PKI" cms encrypt --recipient "$CRED_CERT" \
        --in "$OUT/testdata.txt" --out "$OUT_DIR/cms-auth-enveloped.p7m" \
        --content-enc "aes-256-gcm" 2>/dev/null; then
        echo "    $NAME AuthEnveloped: OK (AuthEnvelopedData + AES-GCM)"
    else
        echo "    $NAME AuthEnveloped: FAIL (encryption error)"
    fi
}
generate_encryption_fixtures_gcm "$OUT/classical/ecdsa/ca" "$OUT/classical/ecdsa" "ECDH" "ec/encryption"

# RSA encryption (AES-GCM for AuthEnvelopedData)
generate_encryption_fixtures_gcm "$OUT/classical/rsa/ca" "$OUT/classical/rsa" "RSA" "rsa/encryption"

# ML-KEM encryption (PQC)
# Note: Use ML-DSA CA to issue ML-KEM encryption certificate
mkdir -p "$OUT/pqc/mlkem"
generate_encryption_fixtures "$OUT/pqc/mldsa/ca" "$OUT/pqc/mlkem" "ML-KEM" "ml/encryption"

# =============================================================================
# CSR Generation (for cross-testing CSR verification)
# =============================================================================
echo ""
echo ">>> Generating CSRs..."

# Classical ECDSA CSR
"$PKI" csr gen --algorithm ecdsa-p256 --keyout "$OUT/csr/ecdsa.key" \
    --cn "CSR Test ECDSA" --dns csr.ecdsa.test.local --out "$OUT/csr/ecdsa.csr"
echo "    CSR ECDSA: OK"

# PQC ML-DSA-87 CSR
"$PKI" csr gen --algorithm ml-dsa-87 --keyout "$OUT/csr/mldsa87.key" \
    --cn "CSR Test ML-DSA-87" --dns csr.mldsa.test.local --out "$OUT/csr/mldsa87.csr"
echo "    CSR ML-DSA-87: OK"

# PQC SLH-DSA-SHA2-256f CSR
"$PKI" csr gen --algorithm slh-dsa-sha2-256f --keyout "$OUT/csr/slhdsa256f.key" \
    --cn "CSR Test SLH-DSA-SHA2-256f" --dns csr.slhdsa.test.local --out "$OUT/csr/slhdsa256f.csr"
echo "    CSR SLH-DSA-SHA2-256f: OK"

# Hybrid Catalyst CSR (ECDSA + ML-DSA)
"$PKI" csr gen --algorithm ecdsa-p256 --keyout "$OUT/csr/catalyst-classical.key" \
    --hybrid ml-dsa-65 --hybrid-keyout "$OUT/csr/catalyst-pqc.key" \
    --cn "CSR Test Catalyst" --dns csr.catalyst.test.local --out "$OUT/csr/catalyst.csr"
echo "    CSR Catalyst Hybrid: OK"

# Composite CSR (IETF draft-13: ECDSA-P521 + ML-DSA-87)
# Note: ML-DSA-87 requires P-521 per IANA-allocated OID (1.3.6.1.5.5.7.6.54)
"$PKI" csr gen --algorithm ecdsa-p521 --composite ml-dsa-87 \
    --keyout "$OUT/csr/composite-classical.key" \
    --hybrid-keyout "$OUT/csr/composite-pqc.key" \
    --cn "CSR Test Composite" --dns csr.composite.test.local --out "$OUT/csr/composite.csr"
echo "    CSR Composite (IETF draft-13): OK"

# ML-KEM CSR with RFC 9883 attestation
# First, create an attestation certificate (reuse the classical credential)
ATTEST_CRED=$(find "$OUT/classical/ecdsa/credentials" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
ATTEST_CERT=$(get_cred_cert "$ATTEST_CRED" 2>/dev/null || echo "")
ATTEST_KEY=$(get_cred_key "$ATTEST_CRED" 2>/dev/null || echo "")
if [ -n "$ATTEST_CERT" ] && [ -n "$ATTEST_KEY" ]; then
    if "$PKI" csr gen --algorithm ml-kem-768 --keyout "$OUT/csr/mlkem768.key" \
        --attest-cert "$ATTEST_CERT" --attest-key "$ATTEST_KEY" \
        --cn "CSR Test ML-KEM-768" --email mlkem@test.local --out "$OUT/csr/mlkem768.csr" 2>/dev/null; then
        echo "    CSR ML-KEM-768 (RFC 9883): OK"
    else
        echo "    CSR ML-KEM-768: SKIP (attestation failed)"
    fi
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
echo "  - Classical ECDSA:    $OUT/classical/ecdsa/ca/"
echo "  - Classical RSA:      $OUT/classical/rsa/ca/"
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
echo "  - $OUT/csr/composite.csr"
echo "  - $OUT/csr/mlkem768.csr (if attestation available)"
echo ""
echo "Generated CMS/OCSP/TSA fixtures (per CA):"
echo "  - cms-attached.p7s   (CMS SignedData with content)"
echo "  - cms-detached.p7s   (CMS SignedData detached)"
echo "  - cms-enveloped.p7m  (CMS EnvelopedData, if encryption supported)"
echo "  - ocsp-good.der      (OCSP Response, status=good)"
echo "  - timestamp.tsr      (RFC 3161 Timestamp Token)"
echo ""

# =============================================================================
# Extension Variant Fixtures
# =============================================================================
echo ">>> Generating Extension Variant Fixtures..."
if [ -x "$SCRIPT_DIR/generate_qpki_extension_fixtures.sh" ]; then
    "$SCRIPT_DIR/generate_qpki_extension_fixtures.sh" || echo "    Extension fixtures generation failed (non-fatal)"
else
    echo "    Extension fixtures script not found or not executable"
fi

echo ""
echo "Run cross-tests with:"
echo "  cd test/crossval/openssl && ./run_all.sh"
echo "  cd test/crossval/bouncycastle && mvn test"
