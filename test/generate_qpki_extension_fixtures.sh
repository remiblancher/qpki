#!/bin/bash
# =============================================================================
# Extension Variant Test Fixture Generator
# =============================================================================
#
# Generates test certificates for each extension variant to cross-test with
# OpenSSL. Each profile tests a specific extension configuration.
#
# Usage: ./test/generate_qpki_extension_fixtures.sh
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PKI="$PROJECT_ROOT/qpki"
PROFILES_DIR="$SCRIPT_DIR/profiles/extensions"
OUT_DIR="$SCRIPT_DIR/fixtures/extension-variants"

# Check if qpki binary exists
if [ ! -f "$PKI" ]; then
    echo "Building qpki binary..."
    cd "$PROJECT_ROOT"
    go build -o ./qpki ./cmd/qpki
    PKI="$PROJECT_ROOT/qpki"
fi

echo "=== Extension Variant Fixture Generator ==="
echo "Profiles directory: $PROFILES_DIR"
echo "Output directory: $OUT_DIR"
echo ""

# Clean previous fixtures
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Count profiles
PROFILE_COUNT=$(ls -1 "$PROFILES_DIR"/*.yaml 2>/dev/null | wc -l | tr -d ' ')
echo "Found $PROFILE_COUNT extension variant profiles"
echo ""

# Generate a CA certificate for each profile
SUCCESS=0
FAILED=0

for profile in "$PROFILES_DIR"/*.yaml; do
    name=$(basename "$profile" .yaml)
    echo -n ">>> Generating $name... "

    # Skip non-profile yaml files
    [[ "$name" == "test-vars" ]] && continue

    # Create CA directory for this variant
    CA_DIR="$OUT_DIR/$name"
    mkdir -p "$CA_DIR"

    # Generate self-signed CA certificate using the profile file path directly
    # Profiles have default CN values, no --var needed
    if "$PKI" ca init \
        --profile "$profile" \
        --ca-dir "$CA_DIR" 2>/dev/null; then

        # Export the certificate to a .crt file
        "$PKI" ca export -d "$CA_DIR" -o "$OUT_DIR/$name.crt" 2>/dev/null
        echo "OK"
        ((SUCCESS++))
    else
        echo "FAILED"
        ((FAILED++))
    fi
done

echo ""
echo "=== Generation Complete ==="
echo "  Success: $SUCCESS"
echo "  Failed:  $FAILED"
echo ""
echo "Output directory: $OUT_DIR"
echo ""
echo "Run cross-tests with:"
echo "  ./test/openssl/verify_extension_variants.sh"
