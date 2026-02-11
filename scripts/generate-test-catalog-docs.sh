#!/bin/bash
# Generate test catalog documentation from machine-readable specs
# Single source of truth: specs/tests/test-catalog.yaml
#
# Usage: ./scripts/generate-test-catalog-docs.sh

set -e

SPECS_FILE="specs/tests/test-catalog.yaml"
OUTPUT_FILE="docs/quality/testing/CATALOG.md"
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

# =============================================================================
# Generate CATALOG.md
# =============================================================================

cat > "$OUTPUT_FILE" << 'HEADER'
---
title: "Test Catalog"
description: "Exhaustive list of QPKI test cases following ISO/IEC 29119-3."
generated: true
---

# QPKI Test Catalog

> **Note**: This file is auto-generated from `specs/tests/test-catalog.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This catalog documents all test cases following ISO/IEC 29119-3 Test Documentation standard.

## Summary

HEADER

# Count totals
total_suites=$(yq -r '.test_suites | length' "$SPECS_FILE")
total_cases=$(yq -r '[.test_suites[].test_cases | length] | add' "$SPECS_FILE")

cat >> "$OUTPUT_FILE" << EOF
| Metric | Value |
|--------|-------|
| Test Suites | $total_suites |
| Total Test Cases | $total_cases |
| Last Updated | $DATE |

## Test Suites

EOF

# Generate table of contents
echo "| Suite ID | Name | Category | Test Cases |" >> "$OUTPUT_FILE"
echo "|----------|------|----------|------------|" >> "$OUTPUT_FILE"

yq -r '.test_suites[] | "| [\(.id)](#\(.id | ascii_downcase)) | \(.name) | \(.category) | \(.test_cases | length) |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Generate detailed sections for each suite
for suite_id in $(yq -r '.test_suites[].id' "$SPECS_FILE"); do
    name=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .name" "$SPECS_FILE")
    objective=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .objective" "$SPECS_FILE")
    category=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .category" "$SPECS_FILE")
    characteristic=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .iso_quality_characteristic" "$SPECS_FILE")

    echo "## $suite_id" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "**$name**" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "- **Objective**: $objective" >> "$OUTPUT_FILE"
    echo "- **Category**: \`$category\`" >> "$OUTPUT_FILE"
    echo "- **ISO 25010 Characteristic**: $characteristic" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    # Check for validator info (for interop suites)
    validator=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .validator // empty" "$SPECS_FILE")
    if [ -n "$validator" ]; then
        validator_version=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .validator_version" "$SPECS_FILE")
        echo "- **Validator**: $validator $validator_version" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi

    echo "### Test Cases" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "| ID | Name | Type | Priority | Requirement |" >> "$OUTPUT_FILE"
    echo "|----|------|------|----------|-------------|" >> "$OUTPUT_FILE"

    yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | \"| \(.id) | \(.name) | \(.type) | \(.priority) | \(.requirement // \"-\") |\"" "$SPECS_FILE" >> "$OUTPUT_FILE"

    echo "" >> "$OUTPUT_FILE"

    # Add details for each test case
    echo "<details>" >> "$OUTPUT_FILE"
    echo "<summary>Test Case Details</summary>" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    for case_id in $(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[].id" "$SPECS_FILE"); do
        case_name=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | select(.id == \"$case_id\") | .name" "$SPECS_FILE")
        case_file=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | select(.id == \"$case_id\") | .file // empty" "$SPECS_FILE")
        case_function=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | select(.id == \"$case_id\") | .function // empty" "$SPECS_FILE")
        case_expected=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | select(.id == \"$case_id\") | .expected_result // empty" "$SPECS_FILE")
        case_note=$(yq -r ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | select(.id == \"$case_id\") | .note // empty" "$SPECS_FILE")

        echo "#### $case_id: $case_name" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"

        if [ -n "$case_file" ]; then
            echo "- **File**: \`$case_file\`" >> "$OUTPUT_FILE"
        fi
        if [ -n "$case_function" ]; then
            echo "- **Function**: \`$case_function\`" >> "$OUTPUT_FILE"
        fi
        if [ -n "$case_expected" ]; then
            echo "- **Expected Result**: $case_expected" >> "$OUTPUT_FILE"
        fi
        if [ -n "$case_note" ]; then
            echo "- **Note**: $case_note" >> "$OUTPUT_FILE"
        fi
        echo "" >> "$OUTPUT_FILE"
    done

    echo "</details>" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "---" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
done

# Categories section
echo "## Categories" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

for category in $(yq -r '.categories | keys[]' "$SPECS_FILE"); do
    description=$(yq -r ".categories.$category.description" "$SPECS_FILE")
    suites=$(yq -r ".categories.$category.suites | join(\", \")" "$SPECS_FILE")

    echo "### $category" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "$description" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "**Suites**: $suites" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
done

# Priorities section
echo "## Priority Definitions" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "| Priority | Description | CI Blocking |" >> "$OUTPUT_FILE"
echo "|----------|-------------|-------------|" >> "$OUTPUT_FILE"

yq -r '.priorities | to_entries[] | "| \(.key) | \(.value.description) | \(.value.ci_blocking) |"' "$SPECS_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "## See Also" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "- [Test Strategy](STRATEGY.md) - Testing philosophy and approach" >> "$OUTPUT_FILE"
echo "- [specs/tests/test-catalog.yaml](../../../specs/tests/test-catalog.yaml) - Source data" >> "$OUTPUT_FILE"
echo "- [specs/tests/traceability-matrix.yaml](../../../specs/tests/traceability-matrix.yaml) - Requirements traceability" >> "$OUTPUT_FILE"

echo "Generated: $OUTPUT_FILE"
