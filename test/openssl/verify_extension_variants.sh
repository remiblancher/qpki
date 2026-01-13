#!/bin/bash
# =============================================================================
# RFC 5280 Extension Variants Cross-Test
# =============================================================================
#
# Verifies that each extension variant is correctly parsed by OpenSSL.
# Tests individual extension configurations in isolation.
#
# =============================================================================

# Don't exit on error - we want to run all tests
# set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures/extension-variants"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    if [ -n "$2" ]; then
        echo "       $2"
    fi
    ((FAILED++))
}

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

# =============================================================================
# CertificatePolicies Tests
# =============================================================================

test_cp_cps() {
    local cert="$FIXTURES/ext-cp-cps.crt"
    if [ ! -f "$cert" ]; then skip "ext-cp-cps: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "CPS:"; then
        pass "ext-cp-cps: CPS URI parsed correctly"
    else
        fail "ext-cp-cps: CPS URI not found"
    fi
}

test_cp_notice() {
    local cert="$FIXTURES/ext-cp-notice.crt"
    if [ ! -f "$cert" ]; then skip "ext-cp-notice: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Explicit Text:"; then
        pass "ext-cp-notice: UserNotice parsed correctly"
    else
        fail "ext-cp-notice: UserNotice Explicit Text not found"
    fi
}

test_cp_both() {
    local cert="$FIXTURES/ext-cp-both.crt"
    if [ ! -f "$cert" ]; then skip "ext-cp-both: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local ok=true

    if ! echo "$text" | grep -q "CPS:"; then
        fail "ext-cp-both: CPS URI not found"
        ok=false
    fi

    if ! echo "$text" | grep -q "Explicit Text:"; then
        fail "ext-cp-both: UserNotice Explicit Text not found"
        ok=false
    fi

    if $ok; then
        pass "ext-cp-both: CPS and UserNotice parsed correctly"
    fi
}

# =============================================================================
# SubjectAltName Tests
# =============================================================================

test_san_dns() {
    local cert="$FIXTURES/ext-san-dns.crt"
    if [ ! -f "$cert" ]; then skip "ext-san-dns: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "DNS:"; then
        pass "ext-san-dns: DNS names parsed correctly"
    else
        fail "ext-san-dns: DNS names not found"
    fi
}

test_san_email() {
    local cert="$FIXTURES/ext-san-email.crt"
    if [ ! -f "$cert" ]; then skip "ext-san-email: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "email:"; then
        pass "ext-san-email: Email addresses parsed correctly"
    else
        fail "ext-san-email: Email addresses not found"
    fi
}

test_san_uri() {
    local cert="$FIXTURES/ext-san-uri.crt"
    if [ ! -f "$cert" ]; then skip "ext-san-uri: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "URI:"; then
        pass "ext-san-uri: URIs parsed correctly"
    else
        fail "ext-san-uri: URIs not found"
    fi
}

test_san_ip() {
    local cert="$FIXTURES/ext-san-ip.crt"
    if [ ! -f "$cert" ]; then skip "ext-san-ip: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local ok=true

    if ! echo "$text" | grep -q "IP Address:192.168.1.1"; then
        fail "ext-san-ip: IPv4 address not found"
        ok=false
    fi

    if ! echo "$text" | grep -q "IP Address:2001"; then
        fail "ext-san-ip: IPv6 address not found"
        ok=false
    fi

    if $ok; then
        pass "ext-san-ip: IPv4 and IPv6 addresses parsed correctly"
    fi
}

test_san_all() {
    local cert="$FIXTURES/ext-san-all.crt"
    if [ ! -f "$cert" ]; then skip "ext-san-all: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local ok=true

    echo "$text" | grep -q "DNS:" || { fail "ext-san-all: DNS not found"; ok=false; }
    echo "$text" | grep -q "email:" || { fail "ext-san-all: email not found"; ok=false; }
    echo "$text" | grep -q "URI:" || { fail "ext-san-all: URI not found"; ok=false; }
    echo "$text" | grep -q "IP Address:" || { fail "ext-san-all: IP not found"; ok=false; }

    if $ok; then
        pass "ext-san-all: All SAN types parsed correctly"
    fi
}

# =============================================================================
# BasicConstraints Tests
# =============================================================================

test_bc_ca() {
    local cert="$FIXTURES/ext-bc-ca.crt"
    if [ ! -f "$cert" ]; then skip "ext-bc-ca: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "CA:TRUE"; then
        pass "ext-bc-ca: CA:TRUE parsed correctly"
    else
        fail "ext-bc-ca: CA:TRUE not found"
    fi
}

test_bc_ca_pathlen() {
    local cert="$FIXTURES/ext-bc-ca-pathlen.crt"
    if [ ! -f "$cert" ]; then skip "ext-bc-ca-pathlen: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local ok=true

    if ! echo "$text" | grep -q "CA:TRUE"; then
        fail "ext-bc-ca-pathlen: CA:TRUE not found"
        ok=false
    fi

    if ! echo "$text" | grep -qi "pathlen"; then
        fail "ext-bc-ca-pathlen: pathlen not found"
        ok=false
    fi

    if $ok; then
        pass "ext-bc-ca-pathlen: CA:TRUE with pathlen parsed correctly"
    fi
}

# =============================================================================
# KeyUsage Tests
# =============================================================================

test_ku_ca() {
    local cert="$FIXTURES/ext-ku-ca.crt"
    if [ ! -f "$cert" ]; then skip "ext-ku-ca: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Certificate Sign"; then
        pass "ext-ku-ca: Certificate Sign key usage parsed correctly"
    else
        fail "ext-ku-ca: Certificate Sign key usage not found"
    fi
}

test_ku_ee() {
    local cert="$FIXTURES/ext-ku-ee.crt"
    if [ ! -f "$cert" ]; then skip "ext-ku-ee: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Digital Signature"; then
        pass "ext-ku-ee: Digital Signature key usage parsed correctly"
    else
        fail "ext-ku-ee: Digital Signature key usage not found"
    fi
}

# =============================================================================
# ExtendedKeyUsage Tests
# =============================================================================

test_eku_tls() {
    local cert="$FIXTURES/ext-eku-tls.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-tls: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "TLS Web Server Authentication"; then
        pass "ext-eku-tls: TLS Server Auth EKU parsed correctly"
    else
        fail "ext-eku-tls: TLS Server Auth EKU not found"
    fi
}

test_eku_code() {
    local cert="$FIXTURES/ext-eku-code.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-code: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Code Signing"; then
        pass "ext-eku-code: Code Signing EKU parsed correctly"
    else
        fail "ext-eku-code: Code Signing EKU not found"
    fi
}

test_eku_ocsp() {
    local cert="$FIXTURES/ext-eku-ocsp.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-ocsp: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "OCSP Signing"; then
        pass "ext-eku-ocsp: OCSP Signing EKU parsed correctly"
    else
        fail "ext-eku-ocsp: OCSP Signing EKU not found"
    fi
}

test_eku_tsa() {
    local cert="$FIXTURES/ext-eku-tsa.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-tsa: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Time Stamping"; then
        pass "ext-eku-tsa: Time Stamping EKU parsed correctly"
    else
        fail "ext-eku-tsa: Time Stamping EKU not found"
    fi
}

# =============================================================================
# CRLDistributionPoints Tests
# =============================================================================

test_crldp_http() {
    local cert="$FIXTURES/ext-crldp-http.crt"
    if [ ! -f "$cert" ]; then skip "ext-crldp-http: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -qE "URI:https?://"; then
        pass "ext-crldp-http: CRL Distribution Point URI parsed correctly"
    else
        fail "ext-crldp-http: CRL Distribution Point URI not found"
    fi
}

test_crldp_multi() {
    local cert="$FIXTURES/ext-crldp-multi.crt"
    if [ ! -f "$cert" ]; then skip "ext-crldp-multi: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local count=$(echo "$text" | grep -c "URI:" || true)

    if [ "$count" -ge 2 ]; then
        pass "ext-crldp-multi: Multiple CRL Distribution Points parsed correctly ($count URIs)"
    else
        fail "ext-crldp-multi: Expected multiple URIs, found $count"
    fi
}

# =============================================================================
# AuthorityInfoAccess Tests
# =============================================================================

test_aia_ocsp() {
    local cert="$FIXTURES/ext-aia-ocsp.crt"
    if [ ! -f "$cert" ]; then skip "ext-aia-ocsp: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    # Check for OCSP URI in AIA
    if echo "$text" | grep -q "OCSP - URI:"; then
        pass "ext-aia-ocsp: OCSP responder URI parsed correctly"
    else
        fail "ext-aia-ocsp: OCSP responder URI not found in AIA"
    fi
}

test_aia_ca() {
    local cert="$FIXTURES/ext-aia-ca.crt"
    if [ ! -f "$cert" ]; then skip "ext-aia-ca: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "CA Issuers"; then
        pass "ext-aia-ca: CA Issuers URI parsed correctly"
    else
        fail "ext-aia-ca: CA Issuers URI not found"
    fi
}

test_aia_both() {
    local cert="$FIXTURES/ext-aia-both.crt"
    if [ ! -f "$cert" ]; then skip "ext-aia-both: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    local ok=true

    if ! echo "$text" | grep -q "OCSP - URI:"; then
        fail "ext-aia-both: OCSP not found in AIA"
        ok=false
    fi

    if ! echo "$text" | grep -q "CA Issuers"; then
        fail "ext-aia-both: CA Issuers not found"
        ok=false
    fi

    if $ok; then
        pass "ext-aia-both: OCSP and CA Issuers parsed correctly"
    fi
}

# =============================================================================
# NameConstraints Tests
# =============================================================================

test_nc_permit() {
    local cert="$FIXTURES/ext-nc-permit.crt"
    if [ ! -f "$cert" ]; then skip "ext-nc-permit: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Permitted"; then
        pass "ext-nc-permit: Permitted subtrees parsed correctly"
    else
        fail "ext-nc-permit: Permitted subtrees not found"
    fi
}

test_nc_exclude() {
    local cert="$FIXTURES/ext-nc-exclude.crt"
    if [ ! -f "$cert" ]; then skip "ext-nc-exclude: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "Excluded"; then
        pass "ext-nc-exclude: Excluded subtrees parsed correctly"
    else
        fail "ext-nc-exclude: Excluded subtrees not found"
    fi
}

# =============================================================================
# Criticality Configuration Tests
# =============================================================================

test_eku_critical() {
    local cert="$FIXTURES/ext-eku-critical.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-critical: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "X509v3 Extended Key Usage: critical"; then
        pass "ext-eku-critical: EKU is critical when configured"
    else
        fail "ext-eku-critical: EKU should be critical"
    fi
}

test_eku_noncritical() {
    local cert="$FIXTURES/ext-eku-noncritical.crt"
    if [ ! -f "$cert" ]; then skip "ext-eku-noncritical: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    # Should have EKU but NOT critical
    if echo "$text" | grep -q "X509v3 Extended Key Usage:" && ! echo "$text" | grep -q "X509v3 Extended Key Usage: critical"; then
        pass "ext-eku-noncritical: EKU is non-critical when configured"
    else
        fail "ext-eku-noncritical: EKU should be non-critical"
    fi
}

test_cp_critical() {
    local cert="$FIXTURES/ext-cp-critical.crt"
    if [ ! -f "$cert" ]; then skip "ext-cp-critical: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    if echo "$text" | grep -q "X509v3 Certificate Policies: critical"; then
        pass "ext-cp-critical: CertPolicies is critical when configured"
    else
        fail "ext-cp-critical: CertPolicies should be critical"
    fi
}

test_cp_noncritical() {
    local cert="$FIXTURES/ext-cp-noncritical.crt"
    if [ ! -f "$cert" ]; then skip "ext-cp-noncritical: fixture not found"; return; fi

    local text=$(openssl x509 -in "$cert" -text -noout 2>/dev/null)
    # Should have CertPolicies but NOT critical
    if echo "$text" | grep -q "X509v3 Certificate Policies:" && ! echo "$text" | grep -q "X509v3 Certificate Policies: critical"; then
        pass "ext-cp-noncritical: CertPolicies is non-critical when configured"
    else
        fail "ext-cp-noncritical: CertPolicies should be non-critical"
    fi
}

# =============================================================================
# Main
# =============================================================================

echo "============================================================"
echo "RFC 5280 Extension Variants Cross-Test (OpenSSL)"
echo "============================================================"
echo ""

if [ ! -d "$FIXTURES" ]; then
    echo "Fixtures not found at: $FIXTURES"
    echo "Run ./test/generate_qpki_extension_fixtures.sh first"
    exit 1
fi

echo ">>> CertificatePolicies Variants"
test_cp_cps
test_cp_notice
test_cp_both
echo ""

echo ">>> SubjectAltName Variants"
test_san_dns
test_san_email
test_san_uri
test_san_ip
test_san_all
echo ""

echo ">>> BasicConstraints Variants"
test_bc_ca
test_bc_ca_pathlen
echo ""

echo ">>> KeyUsage Variants"
test_ku_ca
test_ku_ee
echo ""

echo ">>> ExtendedKeyUsage Variants"
test_eku_tls
test_eku_code
test_eku_ocsp
test_eku_tsa
echo ""

echo ">>> CRLDistributionPoints Variants"
test_crldp_http
test_crldp_multi
echo ""

echo ">>> AuthorityInfoAccess Variants"
test_aia_ocsp
test_aia_ca
test_aia_both
echo ""

echo ">>> NameConstraints Variants"
test_nc_permit
test_nc_exclude
echo ""

echo ">>> Criticality Configuration Variants"
test_eku_critical
test_eku_noncritical
test_cp_critical
test_cp_noncritical
echo ""

# Summary
echo "============================================================"
echo "Extension Variants Cross-Test Summary"
echo "============================================================"
echo ""
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}[FAIL]${NC} Extension Variants Cross-Test"
    exit 1
else
    echo -e "${GREEN}[PASS]${NC} Extension Variants Cross-Test"
    exit 0
fi
