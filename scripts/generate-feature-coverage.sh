#!/bin/bash
# Generate feature coverage documentation from specs
# Single source of truth: specs/tests/feature-coverage.yaml
#
# Usage: ./scripts/generate-feature-coverage.sh
# Output: docs/quality/testing/COVERAGE-FEATURES.md

set -e

SPECS_FILE="specs/tests/feature-coverage.yaml"
OUTPUT_FILE="docs/quality/testing/COVERAGE-FEATURES.md"
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

# Count statistics
TOTAL=$(yq '.features | length' "$SPECS_FILE")
COVERED=$(yq '[.features[] | select(.status == "covered")] | length' "$SPECS_FILE")
PARTIAL=$(yq '[.features[] | select(.status == "partial")] | length' "$SPECS_FILE")
GAP=$(yq '[.features[] | select(.status == "gap")] | length' "$SPECS_FILE")

# Generate markdown
cat > "$OUTPUT_FILE" << EOF
---
title: "Feature Test Coverage"
description: "Test coverage by feature for QPKI."
generated: true
---

# Feature Test Coverage

> **Note**: This file is auto-generated from \`specs/tests/feature-coverage.yaml\`.
> Do not edit manually. Run \`make quality-docs\` to regenerate.

This document tracks test coverage by feature, identifying what is tested and what gaps exist.

## Summary

| Metric | Value |
|--------|-------|
| Total Features | $TOTAL |
| Covered | $COVERED |
| Partial | $PARTIAL |
| **Gap** | **$GAP** |
| Last Updated | $DATE |

## Coverage Matrix

| Feature | Status | Tests | Gaps |
|---------|--------|-------|------|
EOF

# Generate feature table
yq -r '.features[] | "| \(.name) | \(.status) | \(.tests | length) | \(.gaps | length) |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# Generate detailed feature sections
cat >> "$OUTPUT_FILE" << 'EOF'

## Feature Details

EOF

# Generate feature details (simplified for yq v4 compatibility)
yq -r '.features[] | "### \(.name)\n\n**ID**: `\(.id)`\n\n**Status**: \(.status)\n\n\(.description)\n\n**Tests**:\n" + (.tests | map("- `" + . + "`") | join("\n")) + "\n\n**Gaps**:\n" + (.gaps | map("- " + .) | join("\n")) + "\n\n---\n"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# Add gap summary
cat >> "$OUTPUT_FILE" << 'EOF'

## Gap Summary

Features requiring immediate attention:

EOF

yq -r '.features[] | select(.status == "gap") | "- **\(.name)**: " + (.gaps | join("; "))' "$SPECS_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "Features with partial coverage:" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

yq -r '.features[] | select(.status == "partial") | "- **\(.name)**: " + (.gaps | join("; "))' "$SPECS_FILE" >> "$OUTPUT_FILE"

# Add footer
cat >> "$OUTPUT_FILE" << 'EOF'

## See Also

- [CLI Coverage](COVERAGE-CLI.md) - CLI command test coverage
- [Test Strategy](STRATEGY.md) - Testing philosophy
- [specs/tests/feature-coverage.yaml](../../../specs/tests/feature-coverage.yaml) - Source data
EOF

echo "Generated: $OUTPUT_FILE"
