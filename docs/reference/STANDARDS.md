---
title: "Standards Reference"
description: "OID registry, X.509 extensions, and file formats reference."
---

# Standards Reference

This document provides reference information for OIDs, X.509 extensions, and file formats used by QPKI.

## 1. OID Registry

### 1.1 Classical Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| ECDSA P-256 | 1.2.840.10045.3.1.7 |
| ECDSA P-384 | 1.3.132.0.34 |
| ECDSA P-521 | 1.3.132.0.35 |
| Ed25519 | 1.3.101.112 |
| RSA | 1.2.840.113549.1.1.1 |

### 1.2 Post-Quantum Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 |
| SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 |
| SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 |
| SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 |
| SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 |
| SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 |
| SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 |
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 |

### 1.3 Catalyst Extension OIDs

| OID | Name |
|-----|------|
| 2.5.29.72 | AltSubjectPublicKeyInfo |
| 2.5.29.73 | AltSignatureAlgorithm |
| 2.5.29.74 | AltSignatureValue |

### 1.4 Composite Algorithm OIDs (IANA-allocated)

| Algorithm | OID |
|-----------|-----|
| MLDSA65-ECDSA-P256-SHA512 | 1.3.6.1.5.5.7.6.45 |
| MLDSA65-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.46 |
| MLDSA87-ECDSA-P521-SHA512 | 1.3.6.1.5.5.7.6.54 |

## 2. X.509 Extension OIDs

| OID | Name | Usage |
|-----|------|-------|
| 2.5.29.14 | Subject Key Identifier | Certificate extension |
| 2.5.29.35 | Authority Key Identifier | Certificate extension |
| 2.5.29.15 | Key Usage | Certificate extension |
| 2.5.29.37 | Extended Key Usage | Certificate extension |
| 2.5.29.17 | Subject Alternative Name | Certificate extension |
| 2.5.29.19 | Basic Constraints | Certificate extension |
| 2.5.29.31 | CRL Distribution Points | Certificate extension |

## 3. File Formats

### 3.1 Private Keys

- Format: PEM (PKCS#8)
- Encryption: Optional AES-256-CBC with PBKDF2
- Header: `-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`

### 3.2 Certificates

- Format: PEM (X.509)
- Header: `-----BEGIN CERTIFICATE-----`

### 3.3 Certificate Revocation Lists

- Format: PEM and DER
- Header: `-----BEGIN X509 CRL-----`

## See Also

- [Concepts](../getting-started/CONCEPTS.md) - Introduction to PQC algorithms
- [Hybrid Certificates](../migration/HYBRID.md) - Hybrid certificate formats
- [CLI Reference](CLI-REFERENCE.md) - Command reference
