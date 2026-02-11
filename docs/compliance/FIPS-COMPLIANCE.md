---
title: "FIPS Compliance Matrix"
description: "NIST FIPS 203, 204, 205 compliance status for QPKI."
---

# FIPS Compliance Matrix

This document details QPKI's compliance with NIST FIPS post-quantum cryptography standards.

## Implementation Note

QPKI uses [cloudflare/circl](https://github.com/cloudflare/circl) for all PQC algorithm implementations. CIRCL includes:
- NIST KAT (Known Answer Test) vectors for all algorithms
- Comprehensive test coverage
- Constant-time implementations

## FIPS 203 - ML-KEM (Key Encapsulation)

| Algorithm | NIST Level | Status | Key Size | Ciphertext | Tests |
|-----------|------------|--------|----------|------------|-------|
| ML-KEM-512 | 1 | Implemented | 800 B | 768 B | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |
| ML-KEM-768 | 3 | Implemented | 1184 B | 1088 B | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |
| ML-KEM-1024 | 5 | Implemented | 1568 B | 1568 B | TC-KEY-KEM-*, TC-CMS-ENC-KEM-* |

### Cross-Validation

| Validator | Status | Notes |
|-----------|--------|-------|
| OpenSSL 3.6+ | Pass | CMS EnvelopedData decryption |
| BouncyCastle 1.83+ | Pass | CMS EnvelopedData decryption |

### RFC Support

- **RFC 9883**: ML-KEM CSR Attestation (Proof of Possession)

## FIPS 204 - ML-DSA (Digital Signatures)

| Algorithm | NIST Level | Status | Public Key | Signature | Tests |
|-----------|------------|--------|------------|-----------|-------|
| ML-DSA-44 | 1 | Implemented | 1312 B | 2420 B | TC-KEY-ML-001, TC-CA-ML-*, TC-CERT-ML-* |
| ML-DSA-65 | 3 | Implemented | 1952 B | 3293 B | TC-KEY-ML-002, TC-CA-ML-*, TC-CERT-ML-* |
| ML-DSA-87 | 5 | Implemented | 2592 B | 4595 B | TC-KEY-ML-003, TC-CA-ML-*, TC-CERT-ML-* |

### Cross-Validation

| Validator | Artifact | Status |
|-----------|----------|--------|
| OpenSSL 3.6+ | Certificate | Pass |
| OpenSSL 3.6+ | CRL | Pass |
| OpenSSL 3.6+ | CSR | Pass |
| OpenSSL 3.6+ | CMS SignedData | Pass |
| OpenSSL 3.6+ | OCSP Response | Pass |
| OpenSSL 3.6+ | TSA Token | Pass |
| BouncyCastle 1.83+ | All artifacts | Pass |

### RFC Support

- **RFC 9882**: ML-DSA in CMS

## FIPS 205 - SLH-DSA (Hash-Based Signatures)

| Algorithm | NIST Level | Variant | Public Key | Signature | Status |
|-----------|------------|---------|------------|-----------|--------|
| SLH-DSA-SHA2-128s | 1 | Small | 32 B | 7856 B | Implemented |
| SLH-DSA-SHA2-128f | 1 | Fast | 32 B | 17088 B | Implemented |
| SLH-DSA-SHA2-192s | 3 | Small | 48 B | 16224 B | Implemented |
| SLH-DSA-SHA2-192f | 3 | Fast | 48 B | 35664 B | Implemented |
| SLH-DSA-SHA2-256s | 5 | Small | 64 B | 29792 B | Implemented |
| SLH-DSA-SHA2-256f | 5 | Fast | 64 B | 49856 B | Implemented |

### Cross-Validation

| Validator | Artifact | Status |
|-----------|----------|--------|
| OpenSSL 3.6+ | Certificate | Pass |
| OpenSSL 3.6+ | CRL | Pass |
| OpenSSL 3.6+ | CSR | Pass |
| OpenSSL 3.6+ | CMS SignedData | Pass |
| BouncyCastle 1.83+ | All artifacts | Pass |

### RFC Support

- **RFC 9814**: SLH-DSA in CMS

## Certification Status

| Aspect | Status | Notes |
|--------|--------|-------|
| FIPS 140-3 Module | Not certified | CIRCL library provides cryptographic primitives |
| NIST KAT Vectors | Pass | Validated via CIRCL test suite |
| Cross-validation | Pass | OpenSSL 3.6 + BouncyCastle 1.83 |
| Audit readiness | Prepared | Traceability matrix available |

## See Also

- [RFC Compliance](RFC-COMPLIANCE.md) - X.509 and protocol compliance
- [Interoperability Report](INTEROP-REPORT.md) - Cross-validation details
- [Standards Reference](../reference/STANDARDS.md) - OID registry
- [specs/compliance/standards-matrix.yaml](../../specs/compliance/standards-matrix.yaml) - Machine-readable matrix
