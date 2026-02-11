#!/bin/bash
# Generate interoperability documentation from specs
# Single source of truth: specs/compliance/interop-matrix.yaml
#
# Usage: ./scripts/generate-interop-docs.sh
# Output: docs/quality/compliance/INTEROP.md

set -e

SPECS_FILE="specs/compliance/interop-matrix.yaml"
OUTPUT_FILE="docs/quality/compliance/INTEROP.md"
DATE=$(date -u +"%Y-%m-%d")

if ! command -v yq &> /dev/null; then
    echo "Error: yq is required. Install with: brew install yq"
    exit 1
fi

if [ ! -f "$SPECS_FILE" ]; then
    echo "Error: $SPECS_FILE not found"
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

# Get metadata
TITLE=$(yq '.metadata.title' "$SPECS_FILE")
DESCRIPTION=$(yq '.metadata.description' "$SPECS_FILE")

# Generate markdown header
cat > "$OUTPUT_FILE" << EOF
---
title: "$TITLE"
description: "$DESCRIPTION"
generated: true
---

# $TITLE

> **Note**: This file is auto-generated from \`specs/compliance/interop-matrix.yaml\`.
> Do not edit manually. Run \`make quality-docs\` to regenerate.

This document details the cross-validation testing between QPKI and external implementations.

## External Validators

| Tool | Version | Capabilities |
|------|---------|--------------|
EOF

# Generate validators table
yq -r '.validators[] | "| **" + .name + "** | " + .version + " | " + (.capabilities | join(", ")) + " |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# TC-ID naming section
cat >> "$OUTPUT_FILE" << 'EOF'

## TC-ID Naming Convention

Cross-validation test case IDs follow the format: `TC-C-<TOOL>-<ARTIFACT>-<SEQ>`

| Segment | Values |
|---------|--------|
| **TOOL** | `OSL` (OpenSSL), `BC` (BouncyCastle) |
| **ARTIFACT** | `CERT`, `CRL`, `CSR`, `CMS`, `CMSENC`, `OCSP`, `TSA`, `CAT`, `COMP`, `EXT` |
| **SEQ** | `001-999` |

## Cross-Validation Matrix

EOF

# Generate per-validator sections
for validator in $(yq -r '.validators[].name' "$SPECS_FILE"); do
    version=$(yq -r ".validators[] | select(.name == \"$validator\") | .version" "$SPECS_FILE")

    echo "### $validator $version" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "| Artifact | TC-IDs | Status | Notes |" >> "$OUTPUT_FILE"
    echo "|----------|--------|--------|-------|" >> "$OUTPUT_FILE"

    yq -r ".validators[] | select(.name == \"$validator\") | .artifacts[] | \"| \" + .type + \" | \`\" + ((.tc_ids // []) | join(\", \")) + \"\` | \" + .status + \" | \" + (.notes // \"-\") + \" |\"" "$SPECS_FILE" >> "$OUTPUT_FILE"

    echo "" >> "$OUTPUT_FILE"
done

# Known limitations
cat >> "$OUTPUT_FILE" << 'EOF'
## Known Limitations

| Feature | Status | Details |
|---------|--------|---------|
EOF

yq -r '.limitations[] | "| **" + .feature + "** | " + .status + " | " + .details + " |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# CI jobs section
cat >> "$OUTPUT_FILE" << 'EOF'

## CI Job Reference

| CI Job | Test Pattern | Scripts | Duration |
|--------|--------------|---------|----------|
EOF

yq -r '.ci_jobs[] | "| `" + .name + "` | " + .tc_pattern + " | " + .scripts + " | " + .duration + " |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# OpenSSL scripts section
cat >> "$OUTPUT_FILE" << 'EOF'

## OpenSSL Cross-Test Scripts

| Script | TC-IDs | Description |
|--------|--------|-------------|
EOF

yq -r '.openssl_scripts.scripts[] | "| `" + .name + "` | " + ((.tc_ids // []) | join(", ")) + " | " + .description + " |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# BouncyCastle classes section
cat >> "$OUTPUT_FILE" << 'EOF'

## BouncyCastle Cross-Test Classes

| Class | TC-IDs | Description |
|-------|--------|-------------|
EOF

yq -r '.bouncycastle_classes.classes[] | "| `" + .name + "` | " + ((.tc_ids // []) | join(", ")) + " | " + .description + " |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# Footer
cat >> "$OUTPUT_FILE" << 'EOF'

## Running Cross-Validation Tests

```bash
# Run all cross-validation tests
make crosstest

# Run OpenSSL tests only
make crosstest-openssl

# Run BouncyCastle tests only
make crosstest-bc
```

## See Also

- [Test Strategy](../testing/STRATEGY.md) - Testing philosophy
- [FIPS Compliance](FIPS.md) - PQC algorithm compliance
- [RFC Compliance](RFC.md) - Protocol compliance
- [specs/compliance/interop-matrix.yaml](../../../specs/compliance/interop-matrix.yaml) - Source data
EOF

echo "Generated: $OUTPUT_FILE"
