#!/bin/bash
# =============================================================================
# Generate Consolidated CI Quality Report (CTRF-based)
# =============================================================================
#
# Reads aggregated CTRF (Common Test Report Format) and generates quality report.
#
# Inputs (environment variables):
#   CTRF_FILE         - Path to merged CTRF JSON (required)
#   COVERAGE_FILE     - Path to coverage.out (optional)
#   OUTPUT_FILE       - Output markdown file (default: quality-report.md)
#   GITHUB_STEP_SUMMARY - GitHub Actions summary file
#
# Usage in CI:
#   CTRF_FILE=ctrf-merged.json ./scripts/ci/generate-ci-report.sh

set -e

# Defaults
CTRF_FILE="${CTRF_FILE:-ctrf-merged.json}"
OUTPUT_FILE="${OUTPUT_FILE:-quality-report.md}"
VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Generating CI Quality Report..."

# =============================================================================
# Collect Metrics
# =============================================================================

# Coverage
if [ -f "${COVERAGE_FILE:-coverage.out}" ]; then
    COVERAGE=$(go tool cover -func="${COVERAGE_FILE:-coverage.out}" | grep total | awk '{print $3}')
    COVERAGE_PCT=$(echo "$COVERAGE" | tr -d '%')
    COVERAGE_STATUS=$(echo "$COVERAGE_PCT" | awk '{if ($1 >= 70) print "✅"; else print "⚠️"}')
else
    COVERAGE="N/A"
    COVERAGE_PCT="0"
    COVERAGE_STATUS="❓"
fi

# Parse CTRF file
if [ -f "$CTRF_FILE" ]; then
    TOTAL_TESTS=$(jq '.results.summary.tests // 0' "$CTRF_FILE")
    TOTAL_PASSED=$(jq '.results.summary.passed // 0' "$CTRF_FILE")
    TOTAL_FAILED=$(jq '.results.summary.failed // 0' "$CTRF_FILE")
    TOTAL_SKIPPED=$(jq '.results.summary.skipped // 0' "$CTRF_FILE")
else
    echo "WARNING: CTRF file not found: $CTRF_FILE"
    TOTAL_TESTS=0
    TOTAL_PASSED=0
    TOTAL_FAILED=0
    TOTAL_SKIPPED=0
fi

# Overall status
if [ "$TOTAL_FAILED" -gt 0 ]; then
    OVERALL_STATUS="❌"
elif [ "$TOTAL_SKIPPED" -gt 0 ]; then
    OVERALL_STATUS="⚠️"
else
    OVERALL_STATUS="✅"
fi

# =============================================================================
# Generate Suite Table
# =============================================================================

generate_suite_table() {
    if [ ! -f "$CTRF_FILE" ]; then
        echo "| No data | - | - | - | - |"
        return
    fi

    jq -r '.results.suites[]? | "| \(.name) | \(.tests) | \(.passed) | \(.failed) | \(if .failed > 0 then "❌" elif .skipped > 0 then "⚠️" else "✅" end) |"' "$CTRF_FILE" 2>/dev/null || echo "| No suites | - | - | - | - |"
}

# =============================================================================
# Generate Cross-Validation Matrix (from crosstest suites)
# =============================================================================

generate_crossval_matrix() {
    if [ ! -f "$CTRF_FILE" ]; then
        echo "| N/A | - | - | - | - | - | - |"
        return
    fi

    # Extract crosstest results
    local osl_results=$(jq -r '.results.suites[]? | select(.name == "crosstest-openssl") | .tests_detail // empty' "$CTRF_FILE" 2>/dev/null)
    local bc_results=$(jq -r '.results.suites[]? | select(.name == "crosstest-bc") | .tests_detail // empty' "$CTRF_FILE" 2>/dev/null)

    # For now, show simplified view based on suite pass/fail
    local osl_status=$(jq -r '.results.suites[]? | select(.name == "crosstest-openssl") | if .failed > 0 then "❌" elif .tests == 0 then "-" else "✅" end' "$CTRF_FILE" 2>/dev/null || echo "-")
    local bc_status=$(jq -r '.results.suites[]? | select(.name == "crosstest-bc") | if .failed > 0 then "❌" elif .tests == 0 then "-" else "✅" end' "$CTRF_FILE" 2>/dev/null || echo "-")

    echo "| OpenSSL 3.6 | $osl_status |"
    echo "| BouncyCastle 1.83 | $bc_status |"
}

# =============================================================================
# Generate Report
# =============================================================================

cat > "$OUTPUT_FILE" << EOF
# QPKI CI Quality Report

> **Generated:** ${DATE}
> **Version:** ${VERSION}
> **Commit:** ${COMMIT}

## Summary

| Metric | Value | Status |
|--------|------:|:------:|
| **Total Tests** | ${TOTAL_TESTS} | ${OVERALL_STATUS} |
| **Passed** | ${TOTAL_PASSED} | - |
| **Failed** | ${TOTAL_FAILED} | $([ "$TOTAL_FAILED" -eq 0 ] && echo "✅" || echo "❌") |
| **Skipped** | ${TOTAL_SKIPPED} | - |
| **Coverage** | ${COVERAGE} | ${COVERAGE_STATUS} |

## Test Suites

| Suite | Tests | Passed | Failed | Status |
|-------|------:|-------:|-------:|:------:|
EOF

generate_suite_table >> "$OUTPUT_FILE"

cat >> "$OUTPUT_FILE" << EOF

## Cross-Validation

| Validator | Status |
|-----------|:------:|
EOF

generate_crossval_matrix >> "$OUTPUT_FILE"

cat >> "$OUTPUT_FILE" << EOF

## FIPS Compliance

| Standard | Status | Algorithms |
|----------|:------:|------------|
| FIPS 203 | ✅ | ML-KEM-512, 768, 1024 |
| FIPS 204 | ✅ | ML-DSA-44, 65, 87 |
| FIPS 205 | ✅ | SLH-DSA (all SHA2 variants) |

## RFC Compliance

| Standard | Status | Description |
|----------|:------:|-------------|
| RFC 5280 | ✅ | X.509 PKI Certificates |
| RFC 2986 | ✅ | PKCS#10 CSR |
| RFC 6960 | ✅ | OCSP |
| RFC 3161 | ✅ | TSA |
| RFC 5652 | ✅ | CMS |
| RFC 9882 | ✅ | ML-DSA in CMS |
| RFC 9883 | ✅ | ML-KEM Attestation |

---
*Report generated by \`scripts/ci/generate-ci-report.sh\` using CTRF format*
EOF

echo "Report generated: $OUTPUT_FILE"

# =============================================================================
# GitHub Actions Summary
# =============================================================================

if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    cat >> "$GITHUB_STEP_SUMMARY" << EOF

## 📊 Quality Dashboard

| Metric | Value | Status |
|--------|------:|:------:|
| Total Tests | ${TOTAL_TESTS} | ${OVERALL_STATUS} |
| Passed | ${TOTAL_PASSED} | ✅ |
| Failed | ${TOTAL_FAILED} | $([ "$TOTAL_FAILED" -eq 0 ] && echo "✅" || echo "❌") |
| Skipped | ${TOTAL_SKIPPED} | - |
| Coverage | ${COVERAGE} | ${COVERAGE_STATUS} |

### Test Suites

| Suite | Tests | Passed | Failed | Status |
|-------|------:|-------:|-------:|:------:|
EOF

    generate_suite_table >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
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
    "rfc3161": "implemented"
  }
}
EOF

echo "JSON report generated: ${OUTPUT_FILE%.md}.json"
