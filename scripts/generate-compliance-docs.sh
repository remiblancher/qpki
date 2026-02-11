#!/bin/bash
# Generate compliance documentation from machine-readable specs
# Single source of truth: specs/compliance/standards-matrix.yaml
#
# Usage: ./scripts/generate-compliance-docs.sh

set -e

SPECS_FILE="specs/compliance/standards-matrix.yaml"
OUTPUT_DIR="docs/quality/compliance"
DATE=$(date -u +"%Y-%m-%d")

if ! command -v yq &> /dev/null; then
    echo "Error: yq is required. Install with: brew install yq"
    exit 1
fi

if [ ! -f "$SPECS_FILE" ]; then
    echo "Error: $SPECS_FILE not found"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# =============================================================================
# Generate FIPS.md
# =============================================================================

cat > "$OUTPUT_DIR/FIPS.md" << 'HEADER'
---
title: "FIPS Compliance Matrix"
description: "NIST FIPS 203, 204, 205 compliance status for QPKI."
generated: true
---

# FIPS Compliance Matrix

> **Note**: This file is auto-generated from `specs/compliance/standards-matrix.yaml`.
> Do not edit manually. Run `make compliance-docs` to regenerate.

This document details QPKI's compliance with NIST FIPS post-quantum cryptography standards.

## Implementation Note

QPKI uses [cloudflare/circl](https://github.com/cloudflare/circl) for all PQC algorithm implementations. CIRCL includes:
- NIST KAT (Known Answer Test) vectors for all algorithms
- Comprehensive test coverage
- Constant-time implementations

HEADER

# Extract FIPS standards
for fips_id in $(yq -r '.fips_standards[].id' "$SPECS_FILE"); do
    title=$(yq -r ".fips_standards[] | select(.id == \"$fips_id\") | .title" "$SPECS_FILE")

    echo "## $fips_id - $title" >> "$OUTPUT_DIR/FIPS.md"
    echo "" >> "$OUTPUT_DIR/FIPS.md"

    # Algorithms table
    echo "| Algorithm | NIST Level | Status | Tests |" >> "$OUTPUT_DIR/FIPS.md"
    echo "|-----------|------------|--------|-------|" >> "$OUTPUT_DIR/FIPS.md"

    yq -r ".fips_standards[] | select(.id == \"$fips_id\") | .algorithms[] | \"| \(.name) | \(.nist_level) | \(.status | ascii_upcase | .[0:1] + .[1:]) | \(.tests | join(\", \")) |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/FIPS.md"

    echo "" >> "$OUTPUT_DIR/FIPS.md"

    # Cross-validation
    echo "### Cross-Validation" >> "$OUTPUT_DIR/FIPS.md"
    echo "" >> "$OUTPUT_DIR/FIPS.md"
    echo "| Validator | Status | Artifacts |" >> "$OUTPUT_DIR/FIPS.md"
    echo "|-----------|--------|-----------|" >> "$OUTPUT_DIR/FIPS.md"

    yq -r ".fips_standards[] | select(.id == \"$fips_id\") | .cross_validation[] | \"| \(.validator) | \(.status | ascii_upcase | .[0:1] + .[1:]) | \(.artifacts | join(\", \")) |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/FIPS.md"

    echo "" >> "$OUTPUT_DIR/FIPS.md"
done

cat >> "$OUTPUT_DIR/FIPS.md" << 'FOOTER'
## Certification Status

| Aspect | Status | Notes |
|--------|--------|-------|
| FIPS 140-3 Module | Not certified | CIRCL library provides cryptographic primitives |
| NIST KAT Vectors | Pass | Validated via CIRCL test suite |
| Cross-validation | Pass | OpenSSL 3.6 + BouncyCastle 1.83 |
| Audit readiness | Prepared | Traceability matrix available |

## See Also

- [RFC Compliance](RFC.md) - X.509 and protocol compliance
- [specs/compliance/standards-matrix.yaml](../../specs/compliance/standards-matrix.yaml) - Source data
FOOTER

echo "Generated: $OUTPUT_DIR/FIPS.md"

# =============================================================================
# Generate RFC.md
# =============================================================================

cat > "$OUTPUT_DIR/RFC.md" << 'HEADER'
---
title: "RFC Compliance Matrix"
description: "IETF RFC compliance status for QPKI PKI operations."
generated: true
---

# RFC Compliance Matrix

> **Note**: This file is auto-generated from `specs/compliance/standards-matrix.yaml`.
> Do not edit manually. Run `make compliance-docs` to regenerate.

This document details QPKI's compliance with IETF RFCs for PKI operations.

HEADER

# Extract RFC standards
for rfc_id in $(yq -r '.rfc_standards[].id' "$SPECS_FILE"); do
    title=$(yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .title" "$SPECS_FILE")
    status=$(yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .status" "$SPECS_FILE")

    echo "## $rfc_id - $title" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "**Status**: $status" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"

    # Check if has sections
    has_sections=$(yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .sections // empty" "$SPECS_FILE")

    if [ -n "$has_sections" ]; then
        echo "| Section | Requirement | Status | Tests |" >> "$OUTPUT_DIR/RFC.md"
        echo "|---------|-------------|--------|-------|" >> "$OUTPUT_DIR/RFC.md"

        yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .sections[] | \"| \(.ref) | \(.name) | \(.status) | \(.tests // [] | join(\", \")) |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"
    else
        tests=$(yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .tests // [] | join(\", \")" "$SPECS_FILE")
        if [ -n "$tests" ]; then
            echo "**Tests**: $tests" >> "$OUTPUT_DIR/RFC.md"
        fi
    fi

    echo "" >> "$OUTPUT_DIR/RFC.md"

    # Cross-validation if exists
    has_cv=$(yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .cross_validation // empty" "$SPECS_FILE")
    if [ -n "$has_cv" ]; then
        echo "### Cross-Validation" >> "$OUTPUT_DIR/RFC.md"
        echo "" >> "$OUTPUT_DIR/RFC.md"
        echo "| Validator | Status |" >> "$OUTPUT_DIR/RFC.md"
        echo "|-----------|--------|" >> "$OUTPUT_DIR/RFC.md"

        yq -r ".rfc_standards[] | select(.id == \"$rfc_id\") | .cross_validation[] | \"| \(.validator) | \(.status) |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"
        echo "" >> "$OUTPUT_DIR/RFC.md"
    fi
done

# Hybrid standards
echo "## Hybrid Standards" >> "$OUTPUT_DIR/RFC.md"
echo "" >> "$OUTPUT_DIR/RFC.md"

for hybrid_id in $(yq -r '.hybrid_standards[].id' "$SPECS_FILE"); do
    title=$(yq -r ".hybrid_standards[] | select(.id == \"$hybrid_id\") | .title" "$SPECS_FILE")
    source=$(yq -r ".hybrid_standards[] | select(.id == \"$hybrid_id\") | .source" "$SPECS_FILE")
    status=$(yq -r ".hybrid_standards[] | select(.id == \"$hybrid_id\") | .status" "$SPECS_FILE")

    echo "### $title" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "**Source**: $source | **Status**: $status" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"

    echo "| Validator | Status | Notes |" >> "$OUTPUT_DIR/RFC.md"
    echo "|-----------|--------|-------|" >> "$OUTPUT_DIR/RFC.md"

    yq -r ".hybrid_standards[] | select(.id == \"$hybrid_id\") | .cross_validation[] | \"| \(.validator) | \(.status) | \(.note // \"-\") |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
done

cat >> "$OUTPUT_DIR/RFC.md" << 'FOOTER'
## See Also

- [FIPS Compliance](FIPS.md) - PQC algorithm compliance
- [specs/compliance/standards-matrix.yaml](../../specs/compliance/standards-matrix.yaml) - Source data
FOOTER

echo "Generated: $OUTPUT_DIR/RFC.md"
echo "Done. Source: $SPECS_FILE"
