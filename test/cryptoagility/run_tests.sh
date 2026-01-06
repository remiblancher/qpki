#!/bin/bash
# =============================================================================
# Crypto-Agility Transition Tests
# =============================================================================
#
# Tests CA and credential rotation across algorithm families:
#   1. EC -> Catalyst -> ML-DSA (full transition via hybrid)
#   2. EC -> Composite -> ML-DSA (full transition via hybrid)
#   3. RSA -> EC -> ML-DSA (legacy migration)
#   4. EC -> ML-DSA (direct transition)
#   5. Catalyst -> ML-DSA (hybrid to PQ)
#   6. Composite -> ML-DSA (hybrid to PQ)
#
# Usage:
#   ./run_tests.sh                    # Run all scenarios
#   ./run_tests.sh --scenario <name>  # Run specific scenario
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PKI="$PROJECT_ROOT/qpki"
TEST_OUT="/tmp/cryptoagility-tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
log_section() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

# Extract CA version ID from rotate output (format: v2, v3, etc.)
extract_ca_version() {
    grep -oE 'New version:[[:space:]]+v[0-9]+' | grep -oE 'v[0-9]+' | head -1
}

# Extract credential version ID from rotate output (format: v2, v3, etc.)
extract_cred_version() {
    grep -oE 'Version:[[:space:]]+v[0-9]+' | grep -oE 'v[0-9]+' | head -1
}

# Get first credential ID from CA directory
get_first_credential() {
    local ca_dir="$1"
    ls "$ca_dir/credentials/" 2>/dev/null | head -1
}

# Verify CA was rotated to expected profile
verify_ca_profile() {
    local ca_dir="$1"
    local expected="$2"

    if "$PKI" ca info -d "$ca_dir" 2>&1 | grep -qi "$expected"; then
        log_pass "CA using profile: $expected"
    else
        log_fail "CA profile mismatch: expected $expected"
    fi
}

# Verify credential certificate exists
verify_credential() {
    local ca_dir="$1"
    local cred_id="$2"
    local cred_dir="$ca_dir/credentials/$cred_id"

    # Try versioned path first, then legacy path
    local cert_path=""
    if [ -f "$cred_dir/certificates.pem" ]; then
        cert_path="$cred_dir/certificates.pem"
    elif [ -d "$cred_dir/versions" ]; then
        # Find active version certificates
        local active_dir=$(find "$cred_dir/versions" -maxdepth 1 -type d | tail -1)
        cert_path=$(find "$active_dir" -name "certificates.pem" 2>/dev/null | head -1)
    fi

    if [ -z "$cert_path" ] || [ ! -f "$cert_path" ]; then
        log_fail "Credential certificate not found for $cred_id"
    fi

    log_pass "Credential $cred_id has certificates"
}

# =============================================================================
# Test Scenarios
# =============================================================================

# Scenario 1: EC -> Catalyst -> ML-DSA (Full 3-step transition)
# Tests full crypto-agility path: classical -> hybrid -> post-quantum
test_ec_catalyst_pq() {
    log_section "Scenario 1: EC -> Catalyst -> ML-DSA"
    local ca_dir="$TEST_OUT/ec-catalyst-pq"
    rm -rf "$ca_dir"

    # Step 1: Initialize EC Root CA
    log_info "Step 1: Initialize EC Root CA"
    "$PKI" ca init --profile ec/root-ca --var cn="EC-Catalyst-PQ Agility Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "ec\|ecdsa"

    # Step 2: Create EC credential
    log_info "Step 2: Enroll EC credential"
    "$PKI" credential enroll -d "$ca_dir" --profile ec/tls-server \
        --var cn=ec-catalyst.test.local --var dns_names=ec-catalyst.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA to Catalyst Hybrid
    log_info "Step 3: Rotate CA -> Catalyst Hybrid"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile hybrid/catalyst/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "catalyst\|ecdsa.*ml-dsa"

    # Step 4: Rotate credential to Catalyst Hybrid
    log_info "Step 4: Rotate credential -> Catalyst Hybrid"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile hybrid/catalyst/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Step 5: Rotate CA to Pure ML-DSA
    log_info "Step 5: Rotate CA -> Pure ML-DSA"
    CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 6: Rotate credential to Pure ML-DSA
    log_info "Step 6: Rotate credential -> Pure ML-DSA"
    CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary - should show 3 CA versions
    log_info "CA version history (should show 3 versions):"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history (should show 3 versions):"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 1 EC -> Catalyst -> ML-DSA: PASSED"
}

# Scenario 2: EC -> Composite -> ML-DSA (Full 3-step transition)
# Tests full crypto-agility path: classical -> IETF composite -> post-quantum
test_ec_composite_pq() {
    log_section "Scenario 2: EC -> Composite -> ML-DSA"
    local ca_dir="$TEST_OUT/ec-composite-pq"
    rm -rf "$ca_dir"

    # Step 1: Initialize EC Root CA
    log_info "Step 1: Initialize EC Root CA"
    "$PKI" ca init --profile ec/root-ca --var cn="EC-Composite-PQ Agility Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "ec\|ecdsa"

    # Step 2: Create EC credential
    log_info "Step 2: Enroll EC credential"
    "$PKI" credential enroll -d "$ca_dir" --profile ec/tls-server \
        --var cn=ec-composite.test.local --var dns_names=ec-composite.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA to Composite Hybrid
    log_info "Step 3: Rotate CA -> Composite Hybrid"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile hybrid/composite/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "composite\|ecdsa.*ml-dsa"

    # Step 4: Rotate credential to Composite Hybrid
    log_info "Step 4: Rotate credential -> Composite Hybrid"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile hybrid/composite/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Step 5: Rotate CA to Pure ML-DSA
    log_info "Step 5: Rotate CA -> Pure ML-DSA"
    CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 6: Rotate credential to Pure ML-DSA
    log_info "Step 6: Rotate credential -> Pure ML-DSA"
    CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary - should show 3 CA versions
    log_info "CA version history (should show 3 versions):"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history (should show 3 versions):"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 2 EC -> Composite -> ML-DSA: PASSED"
}

# Scenario 5: Catalyst Hybrid -> ML-DSA Pure
# Tests crypto-agility from hybrid (ITU-T Catalyst) to pure post-quantum
test_catalyst_to_pq() {
    log_section "Scenario 5: Catalyst Hybrid -> ML-DSA"
    local ca_dir="$TEST_OUT/catalyst-pq"
    rm -rf "$ca_dir"

    # Step 1: Initialize Catalyst Hybrid CA
    log_info "Step 1: Initialize Catalyst Hybrid CA"
    "$PKI" ca init --profile hybrid/catalyst/root-ca --var cn="Catalyst Agility Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "catalyst\|ecdsa.*ml-dsa"

    # Step 2: Create Catalyst credential
    log_info "Step 2: Enroll Catalyst credential"
    "$PKI" credential enroll -d "$ca_dir" --profile hybrid/catalyst/tls-server \
        --var cn=catalyst.test.local --var dns_names=catalyst.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA to Pure ML-DSA
    log_info "Step 3: Rotate CA -> Pure ML-DSA"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 4: Rotate credential to Pure ML-DSA
    log_info "Step 4: Rotate credential -> Pure ML-DSA"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary
    log_info "CA version history:"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history:"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 5 Catalyst -> ML-DSA: PASSED"
}

# Scenario 6: Composite Hybrid -> ML-DSA Pure
# Tests crypto-agility from hybrid (IETF Composite) to pure post-quantum
test_composite_to_pq() {
    log_section "Scenario 6: Composite Hybrid -> ML-DSA"
    local ca_dir="$TEST_OUT/composite-pq"
    rm -rf "$ca_dir"

    # Step 1: Initialize Composite Hybrid CA
    log_info "Step 1: Initialize Composite Hybrid CA"
    "$PKI" ca init --profile hybrid/composite/root-ca --var cn="Composite Agility Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "composite\|ecdsa.*ml-dsa"

    # Step 2: Create Composite credential
    log_info "Step 2: Enroll Composite credential"
    "$PKI" credential enroll -d "$ca_dir" --profile hybrid/composite/tls-server \
        --var cn=composite.test.local --var dns_names=composite.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA to Pure ML-DSA
    log_info "Step 3: Rotate CA -> Pure ML-DSA"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 4: Rotate credential to Pure ML-DSA
    log_info "Step 4: Rotate credential -> Pure ML-DSA"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary
    log_info "CA version history:"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history:"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 6 Composite -> ML-DSA: PASSED"
}

# Scenario 3: RSA -> EC -> ML-DSA
# Tests multi-step migration from legacy RSA through EC to post-quantum
test_rsa_ec_pq() {
    log_section "Scenario 3: RSA -> EC -> ML-DSA"
    local ca_dir="$TEST_OUT/rsa-ec-pq"
    rm -rf "$ca_dir"

    # Step 1: Initialize RSA Root CA
    log_info "Step 1: Initialize RSA Root CA"
    "$PKI" ca init --profile rsa/root-ca --var cn="RSA Migration Agility Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "rsa"

    # Step 2: Create RSA credential
    log_info "Step 2: Enroll RSA credential"
    "$PKI" credential enroll -d "$ca_dir" --profile rsa/tls-server \
        --var cn=rsa.test.local --var dns_names=rsa.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA to EC
    log_info "Step 3: Rotate CA -> EC"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ec/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ec\|ecdsa"

    # Step 4: Rotate credential to EC
    log_info "Step 4: Rotate credential -> EC"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ec/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Step 5: Rotate CA to ML-DSA
    log_info "Step 5: Rotate CA -> ML-DSA"
    CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 6: Rotate credential to ML-DSA
    log_info "Step 6: Rotate credential -> ML-DSA"
    CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary
    log_info "CA version history:"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history:"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 3 RSA -> EC -> ML-DSA: PASSED"
}

# Scenario 4: EC -> ML-DSA Direct (no hybrid intermediate)
# Tests direct migration from classical EC to post-quantum
test_ec_pq_direct() {
    log_section "Scenario 4: EC -> ML-DSA (Direct)"
    local ca_dir="$TEST_OUT/ec-pq-direct"
    rm -rf "$ca_dir"

    # Step 1: Initialize EC Root CA
    log_info "Step 1: Initialize EC Root CA"
    "$PKI" ca init --profile ec/root-ca --var cn="Direct PQ Migration Test" --ca-dir "$ca_dir"
    verify_ca_profile "$ca_dir" "ec\|ecdsa"

    # Step 2: Create EC credential
    log_info "Step 2: Enroll EC credential"
    "$PKI" credential enroll -d "$ca_dir" --profile ec/tls-server \
        --var cn=direct.test.local --var dns_names=direct.test.local
    local CRED_ID=$(get_first_credential "$ca_dir")
    [ -n "$CRED_ID" ] || log_fail "Failed to create credential"
    log_pass "Created credential: $CRED_ID"

    # Step 3: Rotate CA directly to ML-DSA with cross-sign enabled
    log_info "Step 3: Rotate CA -> ML-DSA (direct, with cross-sign)"
    local CA_VERSION=$("$PKI" ca rotate -d "$ca_dir" --profile ml/root-ca --cross-sign 2>&1 | extract_ca_version)
    [ -n "$CA_VERSION" ] || log_fail "Failed to get CA version from rotate output"
    log_info "Activating CA version: $CA_VERSION"
    "$PKI" ca activate -d "$ca_dir" --version "$CA_VERSION"
    verify_ca_profile "$ca_dir" "ml-dsa"

    # Step 4: Rotate credential directly to ML-DSA
    log_info "Step 4: Rotate credential -> ML-DSA (direct)"
    local CRED_VERSION=$("$PKI" credential rotate "$CRED_ID" -d "$ca_dir" --profile ml/signing 2>&1 | extract_cred_version)
    [ -n "$CRED_VERSION" ] || log_fail "Failed to get credential version from rotate output"
    log_info "Activating credential version: $CRED_VERSION"
    "$PKI" credential activate "$CRED_ID" -d "$ca_dir" --version "$CRED_VERSION"
    verify_credential "$ca_dir" "$CRED_ID"

    # Final summary
    log_info "CA version history:"
    "$PKI" ca versions -d "$ca_dir"
    log_info "Credential version history:"
    "$PKI" credential versions "$CRED_ID" -d "$ca_dir"

    log_pass "Scenario 4 EC -> ML-DSA (Direct): PASSED"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "=============================================="
    echo "    Crypto-Agility Transition Tests"
    echo "=============================================="
    echo ""
    echo "Binary: $PKI"
    echo "Output: $TEST_OUT"
    echo ""

    # Check binary exists
    if [ ! -f "$PKI" ]; then
        log_fail "qpki binary not found at $PKI"
    fi

    mkdir -p "$TEST_OUT"

    case "${1:-all}" in
        --scenario)
            case "$2" in
                ec-catalyst-pq)   test_ec_catalyst_pq ;;
                ec-composite-pq)  test_ec_composite_pq ;;
                rsa-ec-pq)        test_rsa_ec_pq ;;
                ec-pq-direct)     test_ec_pq_direct ;;
                catalyst-pq)      test_catalyst_to_pq ;;
                composite-pq)     test_composite_to_pq ;;
                *)
                    echo "Unknown scenario: $2"
                    echo "Available: ec-catalyst-pq, ec-composite-pq, rsa-ec-pq, ec-pq-direct, catalyst-pq, composite-pq"
                    exit 1
                    ;;
            esac
            ;;
        all)
            test_ec_catalyst_pq
            test_ec_composite_pq
            test_rsa_ec_pq
            test_ec_pq_direct
            test_catalyst_to_pq
            test_composite_to_pq
            echo ""
            echo "=============================================="
            log_pass "ALL 6 CRYPTO-AGILITY TESTS PASSED"
            echo "=============================================="
            ;;
        *)
            echo "Usage: $0 [--scenario <name>|all]"
            echo ""
            echo "Scenarios:"
            echo "  1. ec-catalyst-pq   EC -> Catalyst -> ML-DSA (full transition)"
            echo "  2. ec-composite-pq  EC -> Composite -> ML-DSA (full transition)"
            echo "  3. rsa-ec-pq        RSA -> EC -> ML-DSA (legacy migration)"
            echo "  4. ec-pq-direct     EC -> ML-DSA (direct)"
            echo "  5. catalyst-pq      Catalyst -> ML-DSA (hybrid to PQ)"
            echo "  6. composite-pq     Composite -> ML-DSA (hybrid to PQ)"
            exit 1
            ;;
    esac
}

main "$@"
