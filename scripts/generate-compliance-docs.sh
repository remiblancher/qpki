#!/bin/bash
# Generate compliance documentation from machine-readable specs
# Single source of truth: specs/compliance/standards-matrix.yaml
#
# Usage: ./scripts/generate-compliance-docs.sh

set -e

SPECS_FILE="specs/compliance/standards-matrix.yaml"
OUTPUT_DIR="docs/quality/compliance"

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

cat > "$OUTPUT_DIR/FIPS.md" << 'EOF'
---
title: "FIPS Compliance Matrix"
description: "NIST FIPS 203, 204, 205 compliance status for QPKI."
generated: true
---

# FIPS Compliance Matrix

> **Note**: This file is auto-generated from `specs/compliance/standards-matrix.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document details QPKI's compliance with NIST FIPS post-quantum cryptography standards.

## Implementation Note

QPKI uses [cloudflare/circl](https://github.com/cloudflare/circl) for all PQC algorithm implementations. CIRCL includes:
- NIST KAT (Known Answer Test) vectors for all algorithms
- Comprehensive test coverage
- Constant-time implementations

EOF

# Generate FIPS sections from YAML
for fips_idx in $(yq '.fips_standards | keys | .[]' "$SPECS_FILE"); do
    fips_id=$(yq ".fips_standards[$fips_idx].id" "$SPECS_FILE")
    fips_title=$(yq ".fips_standards[$fips_idx].title" "$SPECS_FILE")

    # Determine algorithm type for header
    case "$fips_id" in
        FIPS203) algo_type="ML-KEM (Key Encapsulation)" ;;
        FIPS204) algo_type="ML-DSA (Digital Signatures)" ;;
        FIPS205) algo_type="SLH-DSA (Hash-Based Signatures)" ;;
        *) algo_type="$fips_title" ;;
    esac

    echo "## $fips_id - $algo_type" >> "$OUTPUT_DIR/FIPS.md"
    echo "" >> "$OUTPUT_DIR/FIPS.md"
    echo "| Algorithm | NIST Level | Status | Tests |" >> "$OUTPUT_DIR/FIPS.md"
    echo "|-----------|------------|--------|-------|" >> "$OUTPUT_DIR/FIPS.md"

    # Generate algorithm rows
    yq -r ".fips_standards[$fips_idx].algorithms[] | \"| \" + .name + \" | \" + (.nist_level | tostring) + \" | \" + .status + \" | \" + (.tests | join(\", \")) + \" |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/FIPS.md"

    echo "" >> "$OUTPUT_DIR/FIPS.md"
    echo "### Cross-Validation" >> "$OUTPUT_DIR/FIPS.md"
    echo "" >> "$OUTPUT_DIR/FIPS.md"
    echo "| Validator | Status | Artifacts |" >> "$OUTPUT_DIR/FIPS.md"
    echo "|-----------|--------|-----------|" >> "$OUTPUT_DIR/FIPS.md"

    # Generate cross-validation rows
    yq -r ".fips_standards[$fips_idx].cross_validation[] | \"| \" + .validator + \" | \" + .status + \" | \" + (.artifacts | join(\", \")) + \" |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/FIPS.md"

    echo "" >> "$OUTPUT_DIR/FIPS.md"
done

# Add certification status
cat >> "$OUTPUT_DIR/FIPS.md" << 'EOF'
## Certification Status

| Aspect | Status | Notes |
|--------|--------|-------|
| FIPS 140-3 Module | Not certified | CIRCL library provides cryptographic primitives |
| NIST KAT Vectors | Pass | Validated via CIRCL test suite |
| Cross-validation | Pass | OpenSSL 3.6 + BouncyCastle 1.83 |
| Audit readiness | Prepared | Traceability matrix available |

## See Also

- [RFC Compliance](RFC.md) - X.509 and protocol compliance
- [specs/compliance/standards-matrix.yaml](../../../specs/compliance/standards-matrix.yaml) - Source data
EOF

echo "Generated: $OUTPUT_DIR/FIPS.md"

# =============================================================================
# Generate RFC.md
# =============================================================================

cat > "$OUTPUT_DIR/RFC.md" << 'EOF'
---
title: "RFC Compliance Matrix"
description: "IETF RFC compliance status for QPKI PKI operations."
generated: true
---

# RFC Compliance Matrix

> **Note**: This file is auto-generated from `specs/compliance/standards-matrix.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document details QPKI's compliance with IETF RFCs for PKI operations.

EOF

# Generate RFC sections from YAML
for rfc_idx in $(yq '.rfc_standards | keys | .[]' "$SPECS_FILE"); do
    rfc_id=$(yq ".rfc_standards[$rfc_idx].id" "$SPECS_FILE")
    rfc_title=$(yq ".rfc_standards[$rfc_idx].title" "$SPECS_FILE")
    rfc_status=$(yq ".rfc_standards[$rfc_idx].status" "$SPECS_FILE")

    echo "## $rfc_id - $rfc_title" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "**Status**: $rfc_status" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"

    # Check if RFC has sections
    has_sections=$(yq ".rfc_standards[$rfc_idx].sections | length" "$SPECS_FILE")
    if [ "$has_sections" != "0" ] && [ "$has_sections" != "null" ]; then
        echo "| Section | Requirement | Status | Tests |" >> "$OUTPUT_DIR/RFC.md"
        echo "|---------|-------------|--------|-------|" >> "$OUTPUT_DIR/RFC.md"

        yq -r ".rfc_standards[$rfc_idx].sections[] | \"| \" + .ref + \" | \" + .name + \" | \" + .status + \" | \" + ((.tests // [\"-\"]) | join(\", \")) + \" |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"

        echo "" >> "$OUTPUT_DIR/RFC.md"
    else
        # Just show tests if no sections
        tests=$(yq -r ".rfc_standards[$rfc_idx].tests | join(\", \")" "$SPECS_FILE" 2>/dev/null || echo "-")
        if [ "$tests" != "null" ] && [ -n "$tests" ]; then
            echo "**Tests**: $tests" >> "$OUTPUT_DIR/RFC.md"
            echo "" >> "$OUTPUT_DIR/RFC.md"
        fi
    fi

    # Check for cross-validation
    has_crossval=$(yq ".rfc_standards[$rfc_idx].cross_validation | length" "$SPECS_FILE" 2>/dev/null || echo "0")
    if [ "$has_crossval" != "0" ] && [ "$has_crossval" != "null" ]; then
        echo "### Cross-Validation" >> "$OUTPUT_DIR/RFC.md"
        echo "" >> "$OUTPUT_DIR/RFC.md"
        echo "| Validator | Status |" >> "$OUTPUT_DIR/RFC.md"
        echo "|-----------|--------|" >> "$OUTPUT_DIR/RFC.md"

        yq -r ".rfc_standards[$rfc_idx].cross_validation[] | \"| \" + .validator + \" | \" + .status + \" |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"

        echo "" >> "$OUTPUT_DIR/RFC.md"
    fi
done

# Add hybrid standards section
cat >> "$OUTPUT_DIR/RFC.md" << 'EOF'
## Hybrid Standards

EOF

for hybrid_idx in $(yq '.hybrid_standards | keys | .[]' "$SPECS_FILE"); do
    hybrid_title=$(yq ".hybrid_standards[$hybrid_idx].title" "$SPECS_FILE")
    hybrid_source=$(yq ".hybrid_standards[$hybrid_idx].source" "$SPECS_FILE")
    hybrid_status=$(yq ".hybrid_standards[$hybrid_idx].status" "$SPECS_FILE")
    hybrid_tests=$(yq -r ".hybrid_standards[$hybrid_idx].tests | join(\", \")" "$SPECS_FILE")

    echo "### $hybrid_title" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "**Source**: $hybrid_source | **Status**: $hybrid_status" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "**Tests**: $hybrid_tests" >> "$OUTPUT_DIR/RFC.md"
    echo "" >> "$OUTPUT_DIR/RFC.md"
    echo "| Validator | Status | Notes |" >> "$OUTPUT_DIR/RFC.md"
    echo "|-----------|--------|-------|" >> "$OUTPUT_DIR/RFC.md"

    yq -r ".hybrid_standards[$hybrid_idx].cross_validation[] | \"| \" + .validator + \" | \" + .status + \" | \" + (.note // \"-\") + \" |\"" "$SPECS_FILE" >> "$OUTPUT_DIR/RFC.md"

    echo "" >> "$OUTPUT_DIR/RFC.md"
done

# Add footer
cat >> "$OUTPUT_DIR/RFC.md" << 'EOF'
## See Also

- [FIPS Compliance](FIPS.md) - PQC algorithm compliance
- [specs/compliance/standards-matrix.yaml](../../../specs/compliance/standards-matrix.yaml) - Source data
EOF

echo "Generated: $OUTPUT_DIR/RFC.md"

echo "Done."
