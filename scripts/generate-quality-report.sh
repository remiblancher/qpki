#!/bin/bash
# Generate QPKI Quality Dashboard Report
# ISO 25010 compliant quality metrics
#
# Usage: ./scripts/generate-quality-report.sh [output_file]
#
# Outputs: docs/QUALITY-DASHBOARD.md (or specified file)

set -e

OUTPUT_FILE="${1:-docs/QUALITY-DASHBOARD.md}"
VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Generating QPKI Quality Dashboard..."

# Count tests
TOTAL_TESTS=$(go test -list '.*' ./... 2>/dev/null | grep -c '^Test' || echo "0")
FUZZ_TARGETS=$(go test -list '.*' ./... 2>/dev/null | grep -c '^Fuzz' || echo "0")

# Get coverage (if coverage.out exists)
if [ -f coverage.out ]; then
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
else
    COVERAGE="N/A"
fi

# Count test files
TEST_FILES=$(find . -name '*_test.go' -not -path './vendor/*' | wc -l | tr -d ' ')

# Count profiles
PROFILE_COUNT=$(find profiles -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')

# Generate report
cat > "$OUTPUT_FILE" << EOF
---
title: "Quality Dashboard"
description: "QPKI quality metrics and compliance status"
---

# QPKI Quality Dashboard

> Generated: ${DATE}
> Version: ${VERSION}

## Summary

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Test Files | ${TEST_FILES} | - | - |
| Total Tests | ${TOTAL_TESTS} | - | - |
| Fuzz Targets | ${FUZZ_TARGETS} | 8+ | $([ "$FUZZ_TARGETS" -ge 8 ] && echo "✅" || echo "⚠️") |
| Code Coverage | ${COVERAGE} | 70% | - |
| Profile Templates | ${PROFILE_COUNT} | - | - |

## ISO 25010 Quality Characteristics

### Functional Suitability

| Characteristic | Status | Evidence |
|----------------|--------|----------|
| Functional Correctness | ✅ | ${TEST_FILES} test files, cross-validation |
| Functional Completeness | ✅ | All RFC operations implemented |
| Functional Appropriateness | ✅ | CLI-first design, no database required |

### Reliability

| Characteristic | Metric | Value | Target |
|----------------|--------|-------|--------|
| Maturity | Code Coverage | ${COVERAGE} | 70% |
| Fault Tolerance | Fuzz Targets | ${FUZZ_TARGETS} | 8+ |
| Recoverability | CA Rotation Tests | Yes | - |

### Security

| Characteristic | Status | Implementation |
|----------------|--------|----------------|
| Confidentiality | ✅ | ML-KEM encryption, HSM support |
| Integrity | ✅ | All signature algorithms, cross-validation |
| Non-repudiation | ✅ | TSA timestamping, CMS signatures |
| Authenticity | ✅ | X.509 certificate chains |

### Compatibility

| Characteristic | Status | Evidence |
|----------------|--------|----------|
| Interoperability | ✅ | OpenSSL 3.6+, BouncyCastle 1.83+ |
| Co-existence | ✅ | Hybrid Catalyst + Composite support |

### Maintainability

| Characteristic | Status | Evidence |
|----------------|--------|----------|
| Modularity | ✅ | internal/ package structure |
| Testability | ✅ | TC-ID convention, ISO 29119 catalog |
| Analysability | ✅ | Machine-readable specs in specs/ |

## Compliance Status

### FIPS Standards

| Standard | Status | Algorithms |
|----------|--------|------------|
| FIPS 203 (ML-KEM) | ✅ Implemented | ML-KEM-512, 768, 1024 |
| FIPS 204 (ML-DSA) | ✅ Implemented | ML-DSA-44, 65, 87 |
| FIPS 205 (SLH-DSA) | ✅ Implemented | All SHA2 variants |

### RFC Standards

| Standard | Status |
|----------|--------|
| RFC 5280 (X.509) | ✅ Implemented |
| RFC 2986 (CSR) | ✅ Implemented |
| RFC 6960 (OCSP) | ✅ Implemented |
| RFC 3161 (TSA) | ✅ Implemented |
| RFC 5652 (CMS) | ✅ Implemented |
| RFC 9882 (ML-DSA CMS) | ✅ Implemented |
| RFC 9883 (ML-KEM Attestation) | ✅ Implemented |

## Cross-Validation Matrix

| Artifact | OpenSSL 3.6 | BouncyCastle 1.83 |
|----------|-------------|-------------------|
| Certificate | ✅ | ✅ |
| CRL | ✅ | ✅ |
| CSR | ✅ | ✅ |
| CMS SignedData | ✅ | ✅ |
| CMS EnvelopedData | ✅ | ✅ |
| OCSP | ✅ | ✅ |
| TSA | ✅ | ✅ |
| Catalyst | ⚠️ Classical only | ✅ |
| Composite | ❌ Not supported | ⚠️ OID mismatch |

## Artifacts

| Artifact | Location |
|----------|----------|
| Test Catalog | [specs/tests/test-catalog.yaml](../specs/tests/test-catalog.yaml) |
| Traceability Matrix | [specs/tests/traceability-matrix.yaml](../specs/tests/traceability-matrix.yaml) |
| Standards Matrix | [specs/compliance/standards-matrix.yaml](../specs/compliance/standards-matrix.yaml) |
| OID Registry | [specs/compliance/algorithm-oids.yaml](../specs/compliance/algorithm-oids.yaml) |
| Profile Schema | [specs/schemas/profile-schema.json](../specs/schemas/profile-schema.json) |

## See Also

- [FIPS Compliance](compliance/FIPS-COMPLIANCE.md)
- [RFC Compliance](compliance/RFC-COMPLIANCE.md)
- [Testing Strategy](dev/TESTING.md)
- [Interoperability](dev/INTEROPERABILITY.md)
EOF

echo -e "${GREEN}✓${NC} Quality dashboard generated: ${OUTPUT_FILE}"
echo "  Tests: ${TOTAL_TESTS}, Fuzz: ${FUZZ_TARGETS}, Coverage: ${COVERAGE}"
