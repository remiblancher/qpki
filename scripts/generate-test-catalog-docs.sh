#!/bin/bash
# Generate test catalog documentation from machine-readable specs
# Single source of truth: specs/tests/test-catalog.yaml
#
# TC-ID Format: TC-<TYPE>-<DOMAIN>-<SEQ>
#   TYPE: U (Unit), F (Functional), A (Acceptance), C (Crossval), Z (fuZz)
#   DOMAIN: KEY, CA, CERT, CRL, OCSP, TSA, CMS, HSM, AGILITY
#   SEQ: 001-999
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
# Helper Functions
# =============================================================================

# Get total test case count
count_total_tests() {
    yq eval '[.test_suites[].test_cases[]] | length' "$SPECS_FILE"
}

# Generate table for a test suite with given format
generate_suite_table() {
    local suite_id="$1"
    local table_format="$2"  # "unit", "acceptance", "crossval", "fuzz"
    local suite_name

    suite_name=$(yq eval ".test_suites[] | select(.id == \"$suite_id\") | .name" "$SPECS_FILE")

    echo "### $suite_id - $suite_name"
    echo ""

    case "$table_format" in
        crossval)
            echo "| ID | Name | Validator | Artifact |"
            echo "|----|------|-----------|----------|"
            local validator
            validator=$(yq eval ".test_suites[] | select(.id == \"$suite_id\") | .validator // \"-\"" "$SPECS_FILE")
            yq eval ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | \"| \" + .id + \" | \" + .name + \" | $validator | \" + (.expected_result // \"-\") + \" |\"" "$SPECS_FILE"
            ;;
        fuzz)
            echo "| ID | Name | Go Test | File |"
            echo "|----|------|---------|------|"
            yq eval ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | \"| \" + .id + \" | \" + .name + \" | \\\`\" + .function + \"\\\` | \" + .file + \" |\"" "$SPECS_FILE"
            ;;
        acceptance)
            echo "| ID | Name | Go Test | File |"
            echo "|----|------|---------|------|"
            yq eval ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | \"| \" + .id + \" | \" + .name + \" | \\\`\" + .function + \"\\\` | \" + .file + \" |\"" "$SPECS_FILE"
            ;;
        *)
            # Default: unit/functional
            echo "| ID | Name | Go Test | Requirement |"
            echo "|----|------|---------|-------------|"
            yq eval ".test_suites[] | select(.id == \"$suite_id\") | .test_cases[] | \"| \" + .id + \" | \" + .name + \" | \\\`\" + .function + \"\\\` | \" + (.requirement // \"-\") + \" |\"" "$SPECS_FILE"
            ;;
    esac
    echo ""
}

# =============================================================================
# Generate CATALOG.md
# =============================================================================

{
cat << 'HEADER'
---
title: "Test Catalog"
description: "Exhaustive list of QPKI test cases following ISO/IEC 29119-3."
generated: true
---

# QPKI Test Catalog

> **Note**: This file is auto-generated from `specs/tests/test-catalog.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This catalog documents all test cases following ISO/IEC 29119-3 Test Documentation standard.

## TC-ID Format

```
TC-<TYPE>-<DOMAIN>-<SEQ>

TYPE:   U (Unit), F (Functional), A (Acceptance), C (Crossval), Z (fuZz)
DOMAIN: KEY, CA, CERT, CRL, EXT, CRED, PROFILE, LIST, REVOKE, INFO, VERIFY, OCSP, TSA, CMS, HSM, AGILITY
SEQ:    001-999
```

## Summary

HEADER

# Generate summary table
total_tests=$(count_total_tests)
echo "| Metric | Value |"
echo "|--------|-------|"
echo "| Total Test Cases | $total_tests |"
echo "| Test Types | 5 (U, F, A, C, Z) |"
echo "| Last Updated | $DATE |"
echo ""
echo "---"
echo ""

# =============================================================================
# Unit Tests Section
# =============================================================================
echo "## Unit Tests (TC-U-*)"
echo ""
echo "Unit tests validate individual functions in isolation."
echo ""

# Get suites that have unit type test cases (checking first test case type)
unit_suites=$(yq eval '.test_suites[] | select(.test_cases[0].type == "unit") | .id' "$SPECS_FILE")
for suite_id in $unit_suites; do
    generate_suite_table "$suite_id" "unit"
done

echo "---"
echo ""

# =============================================================================
# Functional Tests Section
# =============================================================================
echo "## Functional Tests (TC-F-*)"
echo ""
echo "Functional tests validate internal workflows and APIs."
echo ""

func_suites=$(yq eval '.test_suites[] | select(.test_cases[0].type == "functional") | .id' "$SPECS_FILE")
for suite_id in $func_suites; do
    generate_suite_table "$suite_id" "functional"
done

echo "---"
echo ""

# =============================================================================
# Acceptance Tests Section
# =============================================================================
echo "## Acceptance Tests (TC-A-*)"
echo ""
echo "Acceptance tests validate CLI commands end-to-end (black box)."
echo ""
echo "**Location**: \`test/acceptance/\`"
echo ""

accept_suites=$(yq eval '.test_suites[] | select(.test_cases[0].type == "acceptance") | .id' "$SPECS_FILE")
if [ -n "$accept_suites" ]; then
    for suite_id in $accept_suites; do
        generate_suite_table "$suite_id" "acceptance"
    done
else
    echo "> **Note**: See [CLI-COVERAGE.md](CLI-COVERAGE.md) for complete CLI test coverage."
    echo ""
fi

echo "---"
echo ""

# =============================================================================
# Cross-Validation Tests Section
# =============================================================================
echo "## Cross-Validation Tests (TC-C-*)"
echo ""
echo "Cross-validation tests verify interoperability with external implementations."
echo ""
echo "**Location**: \`test/crossval/bouncycastle/\`, \`test/crossval/openssl/\`"
echo ""

cross_suites=$(yq eval '.test_suites[] | select(.test_cases[0].type == "integration") | .id' "$SPECS_FILE")
for suite_id in $cross_suites; do
    generate_suite_table "$suite_id" "crossval"
done

echo "---"
echo ""

# =============================================================================
# Fuzzing Tests Section
# =============================================================================
echo "## Fuzzing Tests (TC-Z-*)"
echo ""
echo "Fuzzing tests ensure parsers handle malformed input without panicking."
echo ""

fuzz_suites=$(yq eval '.test_suites[] | select(.test_cases[0].type == "fuzz") | .id' "$SPECS_FILE")
for suite_id in $fuzz_suites; do
    generate_suite_table "$suite_id" "fuzz"
done

echo "---"
echo ""

# =============================================================================
# Priority Definitions
# =============================================================================
cat << 'FOOTER'
## Priority Definitions

| Priority | Description | CI Blocking |
|----------|-------------|-------------|
| P1 | Critical - Must pass for release | true |
| P2 | High - Should pass, may have known limitations | false |
| P3 | Medium - Nice to have | false |

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [Test Naming](NAMING.md) - Naming conventions
- [CLI Coverage](CLI-COVERAGE.md) - CLI command coverage
- [Feature Coverage](FEATURE-COVERAGE.md) - Feature coverage
FOOTER

} > "$OUTPUT_FILE"

echo "Generated: $OUTPUT_FILE ($(wc -l < "$OUTPUT_FILE") lines)"
