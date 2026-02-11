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

## FIPS203 - ML-KEM (Key Encapsulation)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| ML-KEM-512 | 1 | implemented | TC-U-KEY-007, TC-F-CMS-003 |
| ML-KEM-768 | 3 | implemented | TC-U-KEY-007, TC-F-CMS-003 |
| ML-KEM-1024 | 5 | implemented | TC-U-KEY-007, TC-F-CMS-003 |

### Cross-Validation

| Validator | Status | Artifacts |
|-----------|--------|-----------|
| OpenSSL 3.6+ | pass | CMS EnvelopedData |
| BouncyCastle 1.83+ | pass | CMS EnvelopedData |

## FIPS204 - ML-DSA (Digital Signatures)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| ML-DSA-44 | 1 | implemented | TC-U-KEY-003, TC-F-CA-002, TC-F-CERT-002 |
| ML-DSA-65 | 3 | implemented | TC-U-KEY-004, TC-F-CA-002, TC-F-CERT-002 |
| ML-DSA-87 | 5 | implemented | TC-U-KEY-005, TC-F-CA-002, TC-F-CERT-002 |

### Cross-Validation

| Validator | Status | Artifacts |
|-----------|--------|-----------|
| OpenSSL 3.6+ | pass | Certificate, CRL, CSR, CMS, OCSP, TSA |
| BouncyCastle 1.83+ | pass | Certificate, CRL, CSR, CMS, OCSP, TSA |

## FIPS205 - SLH-DSA (Hash-Based Signatures)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| SLH-DSA-SHA2-128f | 1 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |
| SLH-DSA-SHA2-128s | 1 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |
| SLH-DSA-SHA2-192f | 3 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |
| SLH-DSA-SHA2-192s | 3 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |
| SLH-DSA-SHA2-256f | 5 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |
| SLH-DSA-SHA2-256s | 5 | implemented | TC-U-KEY-006, TC-F-CA-005, TC-F-CERT-005, TC-F-CERT-004, TC-F-CMS-004, TC-F-CMS-005, TC-F-TSA-003 |

### Cross-Validation

| Validator | Status | Artifacts |
|-----------|--------|-----------|
| OpenSSL 3.6+ | pass | Certificate, CRL, CSR, CMS |
| BouncyCastle 1.83+ | pass | Certificate, CRL, CSR, CMS |

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
