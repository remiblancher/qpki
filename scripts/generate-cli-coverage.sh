#!/bin/bash
# Generate CLI coverage documentation from specs
# Single source of truth: specs/tests/cli-coverage.yaml
#
# Usage: ./scripts/generate-cli-coverage.sh
# Output: docs/quality/testing/COVERAGE-CLI.md

set -e

SPECS_FILE="specs/tests/cli-coverage.yaml"
OUTPUT_FILE="docs/quality/testing/COVERAGE-CLI.md"
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
TOTAL=$(yq '.commands | length' "$SPECS_FILE")
COVERED=$(yq '[.commands[] | select(.status == "covered")] | length' "$SPECS_FILE")
PARTIAL=$(yq '[.commands[] | select(.status == "partial")] | length' "$SPECS_FILE")
GAP=$(yq '[.commands[] | select(.status == "gap")] | length' "$SPECS_FILE")

# Generate markdown
cat > "$OUTPUT_FILE" << EOF
---
title: "CLI Test Coverage"
description: "Acceptance test coverage for QPKI CLI commands."
generated: true
---

# CLI Test Coverage

> **Note**: This file is auto-generated from \`specs/tests/cli-coverage.yaml\`.
> Do not edit manually. Run \`make quality-docs\` to regenerate.

This document tracks acceptance test (TestA_*) coverage for each CLI command.

## Summary

| Metric | Value |
|--------|-------|
| Total Commands | $TOTAL |
| Covered | $COVERED |
| Partial | $PARTIAL |
| **Gap** | **$GAP** |
| Last Updated | $DATE |

## Coverage Legend

| Status | Description |
|--------|-------------|
| covered | All major paths tested |
| partial | Some paths tested, gaps identified |
| gap | No acceptance tests exist |

## Commands

| Command | Status | Tests | Gaps |
|---------|--------|-------|------|
EOF

# Generate command table using simple yq
yq -r '.commands[] | "| \(.name) | \(.status) | \(.tests | length) | \(.gaps | length) |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# Generate gaps section
cat >> "$OUTPUT_FILE" << 'EOF'

## Identified Gaps

Commands without acceptance tests (TestA_*):

EOF

# List gap commands
yq -r '.commands[] | select(.status == "gap") | "### \(.name)\n\n" + (.gaps | map("- " + .) | join("\n")) + "\n"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# Add partial coverage section
cat >> "$OUTPUT_FILE" << 'EOF'

## Partial Coverage

Commands with some tests but identified gaps:

EOF

yq -r '.commands[] | select(.status == "partial") | "### \(.name)\n\nTests: " + (.tests | join(", ")) + "\n\nGaps:\n" + (.gaps | map("- " + .) | join("\n")) + "\n"' "$SPECS_FILE" >> "$OUTPUT_FILE"

# Add footer
cat >> "$OUTPUT_FILE" << 'EOF'

## How to Add Acceptance Tests

1. Create test file in `test/acceptance/` directory
2. Use `//go:build acceptance` build tag
3. Name tests `TestA_<Command>_<Scenario>`
4. Update `specs/tests/cli-coverage.yaml` with new tests
5. Run `make quality-docs` to regenerate this file

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [Test Naming](NAMING.md) - Naming conventions
- [specs/tests/cli-coverage.yaml](../../../specs/tests/cli-coverage.yaml) - Source data
EOF

echo "Generated: $OUTPUT_FILE"
