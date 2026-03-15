---
title: "Post-Quantum Cryptography"
description: "Introduction to post-quantum cryptography and hybrid certificates."
---

# Post-Quantum Cryptography

This document covers the fundamentals of post-quantum cryptography and hybrid certificates in QPKI.

For PKI basics (certificates, keys, CAs, trust chains), see [PKI Fundamentals](../reference/PKI-BASICS.md).

## 1. Why Post-Quantum?

### 1.1 The Quantum Threat

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

### 2.4 ML-DSA vs SLH-DSA Decision Guide

Both algorithms are NIST-standardized for post-quantum signatures, but they differ in fundamental ways:

| Criterion | ML-DSA (FIPS 204) | SLH-DSA (FIPS 205) |
|-----------|-------------------|---------------------|
| Math basis | Lattice problems | Hash functions |
| Maturity of assumption | ~15 years of analysis | Decades (hash security) |
| Public key size | 1,312 – 2,592 bytes | 32 – 64 bytes |
| Signature size | 2,420 – 4,627 bytes | 7,856 – 49,856 bytes |
| Signing speed | Fast (~2 ms) | Slow (~100 ms for `s` variants) |
| Verification speed | Fast (~1 ms) | Fast (~5 ms) |
| Stateless | Yes | Yes |

**When to use ML-DSA (default choice):**
- General-purpose PKI (CA certificates, TLS, code signing)
- Bandwidth-sensitive environments (smaller signatures)
- High-volume signing (fast signing performance)
- CNSA 2.0 compliance (ML-DSA-65 or ML-DSA-87 recommended)

**When to use SLH-DSA instead:**
- Maximum conservatism — if lattice-based cryptography were broken, SLH-DSA remains secure because it relies only on hash function security
- Long-lived root CA certificates where signature size is less critical and signing happens rarely
- Regulatory environments requiring hash-based signatures as a fallback
- Environments that already use XMSS/LMS and want a stateless alternative

### 2.5 Algorithm Selection Summary

| Use Case | Recommended | Rationale |
|----------|-------------|-----------|
| General purpose | ML-DSA-65 | Balance of security and size |
| Long-term secrets | ML-DSA-87 | Maximum security |
| Constrained devices | ML-DSA-44 | Smallest signatures |
| Conservative root CA | SLH-DSA-SHA2-192s | Hash-based, small signatures |
| High-volume signing | ML-DSA-65 | Fast signing (~2 ms) |
| Regulatory fallback | SLH-DSA | Different mathematical assumption |

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

## 4. Certificate Size Impact

PQC certificates are significantly larger than classical ones. This affects TLS handshake size, bandwidth, and storage.

### 4.1 Single Certificate Size

| Certificate Type | Approximate Size |
|------------------|------------------|
| ECDSA P-384 | ~1 KB |
| ML-DSA-65 (pure PQC) | ~5 KB |
| ECDSA P-384 + ML-DSA-65 (Catalyst) | ~6 KB |
| MLDSA65-ECDSA-P256-SHA512 (Composite) | ~5.5 KB |

### 4.2 Full Chain Impact (Root → Intermediate → End-Entity)

| Chain Type | Total Size | vs Classical |
|------------|------------|--------------|
| ECDSA P-384 (3 certs) | ~3 KB | baseline |
| ML-DSA-65 (3 certs) | ~15 KB | ~5x |
| Catalyst hybrid (3 certs) | ~18 KB | ~6x |
| ML-DSA-87 (3 certs) | ~21 KB | ~7x |

### 4.3 TLS Handshake Considerations

A typical TLS 1.3 handshake with classical certificates fits in a single TCP round-trip (~1,500 bytes MTU). With PQC certificates:

- **ML-DSA-65 chain (~15 KB)**: requires TCP fragmentation across ~10 packets. On high-latency links, this adds measurable handshake time.
- **Catalyst hybrid chain (~18 KB)**: similar fragmentation but provides backward compatibility.
- **Impact in practice**: on a 50 ms RTT link, expect 1–3 additional round-trips for certificate transmission.

**Mitigations:**
- Use certificate compression (RFC 8879) where supported
- Prefer `s` (small) SLH-DSA variants if using hash-based signatures
- Consider caching and session resumption to amortize handshake cost

## 5. TLS Deployment

### 5.1 Current State (2026)

PQC in TLS is progressing but not yet universally available:

| Component | PQC Status |
|-----------|------------|
| **Key exchange (ML-KEM)** | Supported in Chrome, Firefox, OpenSSL 3.5+, BoringSSL. Active in production. |
| **Authentication (ML-DSA certificates)** | Not yet supported in browsers. OpenSSL 3.6+ has experimental support. |
| **Hybrid certificates (Catalyst/Composite)** | Not recognized by standard TLS stacks. Requires PQC-aware verifiers. |

### 5.2 What You Can Do Today

1. **Internal PKI**: deploy PQC and hybrid certificates for internal services where you control both endpoints (mutual TLS, microservices, IoT).
2. **Key exchange**: enable ML-KEM key exchange in TLS 1.3 on supported servers (this is separate from certificate authentication).
3. **Prepare certificates**: issue hybrid certificates now so PQC material is in place when client support arrives.
4. **Code signing & timestamping**: PQC signatures work today for CMS-based workflows (code signing, document signing, long-term archival).

### 5.3 Future Timeline

| Year | Expected Milestone |
|------|-------------------|
| 2025–2026 | ML-KEM key exchange widely deployed |
| 2027–2028 | Browser support for ML-DSA certificate authentication (expected) |
| 2028–2030 | Industry mandates for PQC certificates (CNSA 2.0 timeline) |
| 2030+ | Classical-only certificates deprecated |

> **Recommendation**: start with hybrid Catalyst certificates for maximum backward compatibility, and switch to pure PQC when ecosystem support is confirmed.

## See Also

- [PKI Fundamentals](../reference/PKI-BASICS.md) - Certificates, keys, CAs, trust chains
- [Glossary](../reference/GLOSSARY.md) - Terminology reference
- [Hybrid Certificates](../migration/HYBRID.md) - Detailed hybrid certificate formats
- [Standards](../reference/STANDARDS.md) - OIDs and file formats
