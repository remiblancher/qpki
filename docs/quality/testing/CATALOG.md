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

| Metric | Value |
|--------|-------|
| Test Suites | 10 |
| Total Test Cases | 40+ |
| Last Updated | 2026-02-11 |

## Test Suites

| Suite ID | Name | Category | Description |
|----------|------|----------|-------------|
| TC-KEY | Key Generation | core-pki | Cryptographic key generation tests |
| TC-CA | Certificate Authority | core-pki | CA initialization and management |
| TC-CERT | Certificate Operations | core-pki | Certificate issuance and validation |
| TC-CRL | CRL Operations | core-pki | Certificate revocation lists |
| TC-OCSP | OCSP | protocols | Online Certificate Status Protocol |
| TC-TSA | TSA | protocols | Time-Stamp Authority |
| TC-CMS | CMS | protocols | Cryptographic Message Syntax |
| TC-XOSL | OpenSSL Cross-Validation | interop | OpenSSL interoperability |
| TC-XBC | BouncyCastle Cross-Validation | interop | BouncyCastle interoperability |
| TC-FUZZ | Fuzzing | security | Parser robustness testing |

---

## TC-KEY - Key Generation Operations

**Objective**: Validate cryptographic key generation for all supported algorithms

**Category**: `core-pki` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-KEY-EC-001 | ECDSA P-256 key generation | unit | P1 | FIPS 186-5 |
| TC-KEY-EC-002 | ECDSA P-384 key generation | unit | P1 | FIPS 186-5 |
| TC-KEY-ML-001 | ML-DSA-44 key generation | unit | P1 | FIPS 204 |
| TC-KEY-ML-002 | ML-DSA-65 key generation | unit | P1 | FIPS 204 |
| TC-KEY-ML-003 | ML-DSA-87 key generation | unit | P1 | FIPS 204 |
| TC-KEY-SLH-001 | SLH-DSA-128f key generation | unit | P2 | FIPS 205 |
| TC-KEY-KEM-001 | ML-KEM-768 key generation | unit | P1 | FIPS 203 |

---

## TC-CA - Certificate Authority Operations

**Objective**: Validate CA initialization, certificate issuance, and management

**Category**: `core-pki` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-CA-EC-001 | ECDSA P-256 CA initialization | functional | P1 | RFC 5280 |
| TC-CA-ML-001 | ML-DSA-65 CA initialization | functional | P1 | RFC 5280, FIPS 204 |
| TC-CA-CAT-001 | Catalyst hybrid CA initialization | functional | P1 | ITU-T X.509 9.8 |
| TC-CA-COMP-001 | Composite hybrid CA initialization | functional | P1 | IETF draft-13 |

---

## TC-CERT - X.509 Certificate Operations

**Objective**: Validate certificate issuance, verification, and lifecycle

**Category**: `core-pki` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-CERT-EC-001 | ECDSA certificate issuance from CSR | functional | P1 | RFC 5280, RFC 2986 |
| TC-CERT-ML-001 | ML-DSA-65 certificate issuance | functional | P1 | RFC 5280, FIPS 204 |
| TC-CERT-KEM-001 | ML-KEM certificate with attestation | functional | P1 | RFC 9883 |

---

## TC-CRL - CRL Operations

**Objective**: Validate CRL generation, distribution, and verification

**Category**: `core-pki` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-CRL-EC-001 | ECDSA CRL generation | functional | P1 | RFC 5280 |
| TC-CRL-ML-001 | ML-DSA CRL generation | functional | P1 | RFC 5280, FIPS 204 |

---

## TC-OCSP - OCSP Operations

**Objective**: Validate OCSP request/response handling per RFC 6960

**Category**: `protocols` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-OCSP-EC-001 | ECDSA OCSP response signing | functional | P1 | RFC 6960 |
| TC-OCSP-ML-001 | ML-DSA OCSP response signing | functional | P1 | RFC 6960, FIPS 204 |

---

## TC-TSA - TSA Operations

**Objective**: Validate timestamping per RFC 3161

**Category**: `protocols` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-TSA-EC-001 | ECDSA timestamp signing | functional | P1 | RFC 3161 |
| TC-TSA-ML-001 | ML-DSA timestamp signing | functional | P1 | RFC 3161, FIPS 204 |

---

## TC-CMS - CMS Operations

**Objective**: Validate CMS SignedData and EnvelopedData per RFC 5652

**Category**: `protocols` | **ISO 25010**: Functional Correctness

### Test Cases

| ID | Name | Type | Priority | Requirement |
|----|------|------|----------|-------------|
| TC-CMS-SIGN-EC-001 | ECDSA CMS SignedData | functional | P1 | RFC 5652 |
| TC-CMS-SIGN-ML-001 | ML-DSA CMS SignedData | functional | P1 | RFC 5652, RFC 9882 |
| TC-CMS-ENC-KEM-001 | ML-KEM CMS EnvelopedData | functional | P1 | RFC 5652, FIPS 203 |

---

## TC-XOSL - OpenSSL Cross-Validation

**Objective**: Verify QPKI artifacts with OpenSSL 3.6+

**Category**: `interop` | **ISO 25010**: Interoperability

**Validator**: OpenSSL 3.6+

### Test Cases

| ID | Name | Type | Priority |
|----|------|------|----------|
| TC-XOSL-CERT-EC | OpenSSL verifies ECDSA certificate | integration | P1 |
| TC-XOSL-CERT-ML | OpenSSL verifies ML-DSA certificate | integration | P1 |
| TC-XOSL-CMS-ML | OpenSSL verifies ML-DSA CMS signature | integration | P1 |
| TC-XOSL-CMSENC-KEM | OpenSSL decrypts ML-KEM CMS | integration | P1 |

---

## TC-XBC - BouncyCastle Cross-Validation

**Objective**: Verify QPKI artifacts with BouncyCastle 1.83+

**Category**: `interop` | **ISO 25010**: Interoperability

**Validator**: BouncyCastle 1.83+

### Test Cases

| ID | Name | Type | Priority |
|----|------|------|----------|
| TC-XBC-CERT-EC | BouncyCastle verifies ECDSA certificate | integration | P1 |
| TC-XBC-CERT-ML | BouncyCastle verifies ML-DSA certificate | integration | P1 |
| TC-XBC-CERT-CAT | BouncyCastle verifies Catalyst certificate | integration | P1 |
| TC-XBC-CERT-COMP | BouncyCastle verifies Composite certificate | integration | P2 |

---

## TC-FUZZ - Fuzzing Tests

**Objective**: Ensure parsers handle malformed input without panicking

**Category**: `security` | **ISO 25010**: Security

### Test Cases

| ID | Name | Type | Priority | File |
|----|------|------|----------|------|
| TC-FUZZ-CMS-001 | CMS SignedData parser fuzzing | fuzz | P1 | internal/cms/fuzz_test.go |
| TC-FUZZ-OCSP-001 | OCSP request parser fuzzing | fuzz | P1 | internal/ocsp/fuzz_test.go |
| TC-FUZZ-PROFILE-001 | Profile YAML parser fuzzing | fuzz | P1 | internal/profile/fuzz_test.go |
| TC-FUZZ-CSR-001 | PQC CSR parser fuzzing | fuzz | P1 | internal/x509util/fuzz_test.go |

---

## Categories

### core-pki

Core PKI operations: keys, CA, certificates, CRL

**Suites**: TC-KEY, TC-CA, TC-CERT, TC-CRL

### protocols

RFC protocol implementations: OCSP, TSA, CMS

**Suites**: TC-OCSP, TC-TSA, TC-CMS

### interop

Cross-validation with external implementations

**Suites**: TC-XOSL, TC-XBC

### security

Security testing: fuzzing, static analysis

**Suites**: TC-FUZZ

## Priority Definitions

| Priority | Description | CI Blocking |
|----------|-------------|-------------|
| P1 | Critical - Must pass for release | true |
| P2 | High - Should pass, may have known limitations | false |
| P3 | Medium - Nice to have | false |

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy and approach
- [specs/tests/test-catalog.yaml](../../../specs/tests/test-catalog.yaml) - Source data
- [specs/tests/traceability-matrix.yaml](../../../specs/tests/traceability-matrix.yaml) - Requirements traceability
