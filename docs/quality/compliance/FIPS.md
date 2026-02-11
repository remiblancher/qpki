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

## FIPS 203 - ML-KEM (Key Encapsulation)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| ML-KEM-512 | 1 | implemented | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |
| ML-KEM-768 | 3 | implemented | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |
| ML-KEM-1024 | 5 | implemented | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |

### Cross-Validation

| Validator | Status | Artifacts |
|-----------|--------|-----------|
| OpenSSL 3.6+ | pass | CMS EnvelopedData |
| BouncyCastle 1.83+ | pass | CMS EnvelopedData |

## FIPS 204 - ML-DSA (Digital Signatures)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| ML-DSA-44 | 1 | implemented | TC-KEY-ML-001, TC-CA-ML-*, TC-CERT-ML-* |
| ML-DSA-65 | 3 | implemented | TC-KEY-ML-002, TC-CA-ML-*, TC-CERT-ML-* |
| ML-DSA-87 | 5 | implemented | TC-KEY-ML-003, TC-CA-ML-*, TC-CERT-ML-* |

### Cross-Validation

| Validator | Status | Artifacts |
|-----------|--------|-----------|
| OpenSSL 3.6+ | pass | Certificate, CRL, CSR, CMS, OCSP, TSA |
| BouncyCastle 1.83+ | pass | Certificate, CRL, CSR, CMS, OCSP, TSA |

## FIPS 205 - SLH-DSA (Hash-Based Signatures)

| Algorithm | NIST Level | Status | Tests |
|-----------|------------|--------|-------|
| SLH-DSA-SHA2-128f | 1 | implemented | TC-KEY-SLH-* |
| SLH-DSA-SHA2-128s | 1 | implemented | TC-KEY-SLH-* |
| SLH-DSA-SHA2-192f | 3 | implemented | TC-KEY-SLH-* |
| SLH-DSA-SHA2-192s | 3 | implemented | TC-KEY-SLH-* |
| SLH-DSA-SHA2-256f | 5 | implemented | TC-KEY-SLH-* |
| SLH-DSA-SHA2-256s | 5 | implemented | TC-KEY-SLH-* |

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
