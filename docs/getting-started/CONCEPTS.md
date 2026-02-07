---
title: "Concepts"
description: "Introduction to post-quantum cryptography and hybrid certificates."
---

# Concepts

This document covers the fundamentals of post-quantum cryptography and hybrid certificates in QPKI.

## 1. Post-Quantum Cryptography

### 1.1 Why Post-Quantum?

Current public-key cryptography (RSA, ECDSA, ECDH) is vulnerable to attacks by quantum computers using Shor's algorithm. While large-scale quantum computers don't exist yet, data encrypted today could be stored and decrypted later ("harvest now, decrypt later" attacks).

### 1.2 NIST Standardization

NIST has standardized three post-quantum algorithms:

| Algorithm | Standard | Type | Use Case |
|-----------|----------|------|----------|
| ML-KEM | FIPS 203 | Key Encapsulation | Key exchange |
| ML-DSA | FIPS 204 | Digital Signature | Signing, authentication |
| SLH-DSA | FIPS 205 | Digital Signature | Signing (stateless) |

This PKI implements **ML-DSA** and **SLH-DSA** for signatures, and **ML-KEM** for key material transport.

## 2. Supported Algorithms

### 2.1 ML-DSA (Digital Signatures) - FIPS 204

ML-DSA (Module-Lattice Digital Signature Algorithm) is the standardized version of Dilithium.

| Variant | Security Level | Public Key | Signature | Performance |
|---------|----------------|------------|-----------|-------------|
| ML-DSA-44 | NIST Level 1 | 1,312 bytes | 2,420 bytes | Fastest |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,309 bytes | Balanced |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,627 bytes | Most secure |

**Recommendation**: Use ML-DSA-65 for most applications (equivalent to AES-192 security).

### 2.2 SLH-DSA (Digital Signatures) - FIPS 205

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is the standardized version of SPHINCS+.
It provides an alternative to ML-DSA based on hash functions rather than lattice problems.

| Variant | Security Level | Public Key | Signature | Signing Speed |
|---------|----------------|------------|-----------|---------------|
| SLH-DSA-128s | NIST Level 1 | 32 bytes | ~7,856 bytes | Slow |
| SLH-DSA-128f | NIST Level 1 | 32 bytes | ~17,088 bytes | Fast |
| SLH-DSA-192s | NIST Level 3 | 48 bytes | ~16,224 bytes | Slow |
| SLH-DSA-192f | NIST Level 3 | 48 bytes | ~35,664 bytes | Fast |
| SLH-DSA-256s | NIST Level 5 | 64 bytes | ~29,792 bytes | Slow |
| SLH-DSA-256f | NIST Level 5 | 64 bytes | ~49,856 bytes | Fast |

**Variants:**
- `s` (small) = Smaller signatures, slower signing
- `f` (fast) = Larger signatures, faster signing

**Recommendation**: Use SLH-DSA as a conservative alternative when hash-based security is preferred over lattice assumptions.

### 2.3 ML-KEM (Key Encapsulation) - FIPS 203

ML-KEM (Module-Lattice Key Encapsulation Mechanism) is the standardized version of Kyber.

| Variant | Security Level | Public Key | Ciphertext | Shared Secret |
|---------|----------------|------------|------------|---------------|
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | NIST Level 3 | 1,184 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | NIST Level 5 | 1,568 bytes | 1,568 bytes | 32 bytes |

**Note**: ML-KEM is included for key transport but is not used for X.509 certificate signing.

### 2.4 Algorithm Selection Guide

| Use Case | Recommended | Rationale |
|----------|-------------|-----------|
| General purpose | ML-DSA-65 | Balance of security and size |
| Long-term secrets | ML-DSA-87 | Maximum security |
| Constrained devices | ML-DSA-44 | Smallest signatures |
| Conservative choice | SLH-DSA | Hash-based (different assumptions) |

## 3. Hybrid Certificates

### 3.1 Why Hybrid?

Pure PQC certificates face challenges:

1. **Existing infrastructure** (browsers, TLS libraries) doesn't recognize PQC
2. **Security uncertainty** - PQC algorithms are newer, less analyzed than classical

Hybrid certificates provide:
- **Backward compatibility** via classical signature
- **Forward security** via PQC material
- **Gradual migration** path

### 3.2 Hybrid Modes

QPKI supports three hybrid approaches:

| Mode | Standard | Certificates | Description |
|------|----------|--------------|-------------|
| **Catalyst (Combined)** | ITU-T X.509 9.8 | 1 | Dual keys in single cert |
| **Composite** | IETF draft-13 | 1 | Single composite key/signature |
| **Separate (Linked)** | draft-ietf-lamps-cert-binding | 2 | Two linked certificates |

For technical details on each hybrid mode, see [Hybrid Certificates](../migration/HYBRID.md).

## See Also

- [GLOSSARY](../reference/GLOSSARY.md) - Terminology reference
- [Hybrid Certificates](../migration/HYBRID.md) - Detailed hybrid certificate formats
- [Standards](../reference/STANDARDS.md) - OIDs and file formats
