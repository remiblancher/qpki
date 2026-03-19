#!/bin/bash
# =============================================================================
# Generate Consolidated CI Quality Report (CTRF-based)
# =============================================================================
#
# Reads aggregated CTRF and interop results, generates unified quality report.
#
# Inputs (environment variables):
#   CTRF_FILE         - Path to merged CTRF JSON (required)
#   COVERAGE_FILE     - Path to coverage.out (optional)
#   OPENSSL_RESULTS   - Path to OpenSSL results.json (optional)
#   BC_RESULTS        - Path to BouncyCastle results.json (optional)
#   OUTPUT_FILE       - Output markdown file (default: quality-report.md)
#   GITHUB_STEP_SUMMARY - GitHub Actions summary file
#
# Usage in CI:
#   CTRF_FILE=ctrf-merged.json ./scripts/ci/generate-ci-report.sh

set -e

# Defaults
CTRF_FILE="${CTRF_FILE:-ctrf-merged.json}"
OUTPUT_FILE="${OUTPUT_FILE:-quality-report.md}"
OPENSSL_RESULTS="${OPENSSL_RESULTS:-test/crossval/openssl/results.json}"
BC_RESULTS="${BC_RESULTS:-test/crossval/bouncycastle/results.json}"

VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
DATE=$(date -u +"%Y-%m-%d %H:%M UTC")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Generating CI Quality Report..."

# =============================================================================
# Collect Metrics
# =============================================================================

# Coverage
if [ -f "${COVERAGE_FILE:-coverage.out}" ]; then
    COVERAGE=$(go tool cover -func="${COVERAGE_FILE:-coverage.out}" 2>/dev/null | grep total | awk '{print $3}' || echo "N/A")
    COVERAGE_PCT=$(echo "$COVERAGE" | tr -d '%')
    if [ "$COVERAGE" != "N/A" ] && [ "$(echo "$COVERAGE_PCT >= 70" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        COVERAGE_STATUS="pass"
    else
        COVERAGE_STATUS="warn"
    fi
else
    COVERAGE="N/A"
    COVERAGE_PCT="0"
    COVERAGE_STATUS="unknown"
fi

# Parse CTRF file
if [ -f "$CTRF_FILE" ]; then
    TOTAL_TESTS=$(jq '.results.summary.tests // 0' "$CTRF_FILE")
    TOTAL_PASSED=$(jq '.results.summary.passed // 0' "$CTRF_FILE")
    TOTAL_FAILED=$(jq '.results.summary.failed // 0' "$CTRF_FILE")
    TOTAL_SKIPPED=$(jq '.results.summary.skipped // 0' "$CTRF_FILE")

    # Calculate duration from CTRF timestamps
    START_TS=$(jq '.results.summary.start // 0' "$CTRF_FILE")
    STOP_TS=$(jq '.results.summary.stop // 0' "$CTRF_FILE")
    if [ "$START_TS" -gt 0 ] && [ "$STOP_TS" -gt 0 ]; then
        DURATION_MS=$((STOP_TS - START_TS))
        DURATION_SEC=$((DURATION_MS / 1000))
        DURATION_MIN=$((DURATION_SEC / 60))
        DURATION_REM=$((DURATION_SEC % 60))
        if [ "$DURATION_MIN" -gt 0 ]; then
            DURATION="${DURATION_MIN}m ${DURATION_REM}s"
        else
            DURATION="${DURATION_SEC}s"
        fi
    else
        DURATION="N/A"
    fi
else
    echo "WARNING: CTRF file not found: $CTRF_FILE"
    TOTAL_TESTS=0
    TOTAL_PASSED=0
    TOTAL_FAILED=0
    TOTAL_SKIPPED=0
    DURATION="N/A"
fi

# =============================================================================
# Helper Functions
# =============================================================================

# Get emoji for interop status
get_interop_emoji() {
    case "$1" in
        PASS) echo "✅" ;;
        FAIL) echo "❌" ;;
        SKIP) echo "⚠️" ;;
        *)    echo "-" ;;
    esac
}

# Get interop result from JSON
get_interop_result() {
    local json_file="$1"
    local tc_id="$2"

    if [ -f "$json_file" ]; then
        jq -r ".results[\"$tc_id\"] // \"N/A\"" "$json_file" 2>/dev/null || echo "N/A"
    else
        echo "N/A"
    fi
}

# Generate interop matrix row
generate_interop_row() {
    local json_file="$1"
    local artifact="$2"
    local prefix="$3"  # TC-XOSL or TC-XBC

    local row="| $artifact"
    for algo in EC ML SLH KEM CAT COMP; do
        local tc_id="${prefix}-${artifact}-${algo}"
        local status=$(get_interop_result "$json_file" "$tc_id")
        local emoji=$(get_interop_emoji "$status")
        row="$row | $emoji"
    done
    echo "$row |"
}

# =============================================================================
# Generate Suite Table
# =============================================================================

generate_suite_table() {
    if [ ! -f "$CTRF_FILE" ]; then
        echo "| No data | - | - | - |"
        return
    fi

    jq -r '.results.suites[]? | "| \(.name) | \(.tests) | \(.passed) | \(.failed) |"' "$CTRF_FILE" 2>/dev/null || echo "| No suites | - | - | - |"
}

# =============================================================================
# Generate Skipped Tests Details
# =============================================================================

generate_skipped_details() {
    if [ ! -f "$CTRF_FILE" ] || [ "$TOTAL_SKIPPED" -eq 0 ]; then
        return
    fi

    echo ""
    echo "<details>"
    echo "<summary>$TOTAL_SKIPPED tests skipped - see details</summary>"
    echo ""
    echo "| Suite | Skipped | Reason |"
    echo "|-------|--------:|--------|"

    # Known skip reasons by suite
    jq -r '.results.suites[]? | select(.skipped > 0) | "\(.name)|\(.skipped)"' "$CTRF_FILE" 2>/dev/null | while IFS='|' read -r suite skipped; do
        reason="-"
        case "$suite" in
            crosstest-bouncycastle) reason="BC 1.83 draft-07 OIDs (Composite)" ;;
            crosstest-openssl) reason="Composite not supported" ;;
            hsm) reason="SoftHSM only in CI" ;;
            unit) reason="Build tags" ;;
        esac
        echo "| $suite | $skipped | $reason |"
    done

    echo ""
    echo "</details>"
}

# =============================================================================
# Generate Interop Matrix
# =============================================================================

generate_openssl_matrix() {
    if [ ! -f "$OPENSSL_RESULTS" ]; then
        echo "| N/A | - | - | - | - | - | - |"
        return
    fi

    for artifact in CERT CRL CSR CMS CMSENC OCSP TSA COSE; do
        generate_interop_row "$OPENSSL_RESULTS" "$artifact" "TC-XOSL"
    done
}

generate_bc_matrix() {
    if [ ! -f "$BC_RESULTS" ]; then
        echo "| N/A | - | - | - | - | - | - |"
        return
    fi

    for artifact in CERT CRL CSR CMS CMSENC OCSP TSA COSE; do
        generate_interop_row "$BC_RESULTS" "$artifact" "TC-XBC"
    done
}

# =============================================================================
# Build Report Content
# =============================================================================

# Header with metadata
REPORT_CONTENT="# QPKI Quality Report

> \`$COMMIT\` • $DATE • $DURATION

## Summary

| Tests | Passed | Failed | Skipped | Coverage |
|------:|-------:|-------:|--------:|:--------:|
| $TOTAL_TESTS | $TOTAL_PASSED ✅ | $TOTAL_FAILED $([ "$TOTAL_FAILED" -eq 0 ] && echo "✅" || echo "❌") | $TOTAL_SKIPPED $([ "$TOTAL_SKIPPED" -eq 0 ] && echo "✅" || echo "⚠️") | $COVERAGE $([ "$COVERAGE_STATUS" = "pass" ] && echo "✅" || echo "⚠️") |"

# Add skipped details if any
REPORT_CONTENT="$REPORT_CONTENT$(generate_skipped_details)"

# Test Suites
REPORT_CONTENT="$REPORT_CONTENT

## Test Suites

| Suite | Tests | Passed | Failed |
|-------|------:|-------:|-------:|
$(generate_suite_table)"

# Interop section (only if results exist)
if [ -f "$OPENSSL_RESULTS" ] || [ -f "$BC_RESULTS" ]; then
    REPORT_CONTENT="$REPORT_CONTENT

## Interoperability"

    if [ -f "$OPENSSL_RESULTS" ]; then
        OSL_VERSION=$(jq -r '.version // "3.6"' "$OPENSSL_RESULTS" 2>/dev/null | sed 's/^OpenSSL //' || echo "3.6")
        REPORT_CONTENT="$REPORT_CONTENT

### OpenSSL $OSL_VERSION

| Artifact | Classical | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:------:|:--------:|:---------:|
$(generate_openssl_matrix)"
    fi

    if [ -f "$BC_RESULTS" ]; then
        BC_VERSION=$(jq -r '.version // "1.83"' "$BC_RESULTS" 2>/dev/null || echo "1.83")
        REPORT_CONTENT="$REPORT_CONTENT

### BouncyCastle $BC_VERSION

| Artifact | Classical | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:------:|:--------:|:---------:|
$(generate_bc_matrix)

> ⚠️ Composite: BC uses draft-07 OIDs, QPKI uses IETF draft-13"
    fi
fi

# Compliance section
REPORT_CONTENT="$REPORT_CONTENT

## Compliance

| Standard | Status | Description |
|----------|:------:|-------------|
| FIPS 203 | ✅ | ML-KEM-512/768/1024 |
| FIPS 204 | ✅ | ML-DSA-44/65/87 |
| FIPS 205 | ✅ | SLH-DSA SHA2 |
| RFC 5280 | ✅ | X.509 Certificates |
| RFC 5652 | ✅ | CMS |
| RFC 6960 | ✅ | OCSP |
| RFC 3161 | ✅ | TSA |
| RFC 9052 | ✅ | COSE |
| RFC 8392 | ✅ | CWT |
| RFC 9880 | ✅ | ML-KEM for CMS |
| RFC 9881 | ✅ | ML-DSA in X.509 |
| RFC 9882 | ✅ | ML-DSA in CMS |
| RFC 9883 | ✅ | ML-KEM in CMS |"

# =============================================================================
# Write Outputs
# =============================================================================

# Write markdown report
echo "$REPORT_CONTENT" > "$OUTPUT_FILE"
echo "Report generated: $OUTPUT_FILE"

# Write to GitHub Step Summary (single source of truth)
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    echo "$REPORT_CONTENT" >> "$GITHUB_STEP_SUMMARY"
    echo "Summary added to GitHub Step Summary"
fi

# =============================================================================
# JSON Output
# =============================================================================

cat > "${OUTPUT_FILE%.md}.json" << EOF
{
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "generated": "${DATE}",
  "duration": "${DURATION}",
  "format": "ctrf",
  "metrics": {
    "coverage": "${COVERAGE}",
    "total_tests": ${TOTAL_TESTS},
    "passed": ${TOTAL_PASSED},
    "failed": ${TOTAL_FAILED},
    "skipped": ${TOTAL_SKIPPED}
  },
  "ctrf": $(cat "$CTRF_FILE" 2>/dev/null || echo '{}'),
  "compliance": {
    "fips203": "implemented",
    "fips204": "implemented",
    "fips205": "implemented",
    "rfc5280": "implemented",
    "rfc5652": "implemented",
    "rfc6960": "implemented",
    "rfc3161": "implemented",
    "rfc9052": "implemented",
    "rfc8392": "implemented",
    "rfc9882": "implemented",
    "rfc9883": "implemented"
  }
}
EOF

echo "JSON report generated: ${OUTPUT_FILE%.md}.json"
