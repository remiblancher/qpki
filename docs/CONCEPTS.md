# Concepts

## Table of Contents

- [1. Post-Quantum Cryptography](#1-post-quantum-cryptography)
- [2. Supported Algorithms](#2-supported-algorithms)
- [3. Hybrid Certificates](#3-hybrid-certificates)
- [4. Catalyst Certificates (ITU-T X.509 Section 9.8)](#4-catalyst-certificates-itu-t-x509-section-98)
- [5. Composite Certificates (IETF draft-13)](#5-composite-certificates-ietf-draft-13)
- [6. Separate Linked Certificates](#6-separate-linked-certificates)
- [7. Technical Reference](#7-technical-reference)
- [8. Security Considerations](#8-security-considerations)
- [9. Migration Path](#9-migration-path)
- [10. References](#10-references)
- [See Also](#see-also)

---

This document covers post-quantum cryptography, hybrid certificate formats, and the technical concepts behind QPKI.

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

1. **Go's crypto/x509** doesn't support PQC signature algorithms
2. **Existing infrastructure** (browsers, TLS libraries) doesn't recognize PQC
3. **Security uncertainty** - PQC algorithms are newer, less analyzed than classical

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

## 4. Catalyst Certificates (ITU-T X.509 Section 9.8)

Catalyst certificates embed **two public keys and two signatures** in a single X.509 certificate using standard extensions.

### 4.1 X.509 Extensions

| OID | Name | Content |
|-----|------|---------|
| 2.5.29.72 | AltSubjectPublicKeyInfo | Alternative public key (PQC) |
| 2.5.29.73 | AltSignatureAlgorithm | Algorithm of alternative signature |
| 2.5.29.74 | AltSignatureValue | Alternative signature value |

All three extensions are **non-critical** - legacy systems ignore them and use classical verification.

### 4.2 Certificate Structure

```
Certificate:
  Data:
    Subject: CN=Alice, O=Acme
    Subject Public Key Info:
      Algorithm: ECDSA P-256           <- Classical (primary)
      Public Key: [EC public key]
    Extensions:
      AltSubjectPublicKeyInfo:         <- PQC (alternative)
        Algorithm: ML-DSA-65
        Public Key: [ML-DSA public key]
      AltSignatureAlgorithm:
        Algorithm: ML-DSA-65
      AltSignatureValue:
        [ML-DSA signature]             <- Signs TBS without alt extensions
  Signature Algorithm: SHA256WithECDSA <- Classical signature
  Signature: [ECDSA signature]
```

### 4.3 Signature Process

**Issuing a Catalyst Certificate:**

1. Build TBS (To-Be-Signed) certificate WITHOUT alternative extensions
2. Generate classical signature over TBS
3. Add `AltSubjectPublicKeyInfo` extension with PQC public key
4. Generate alternative signature over TBS (same data as step 1)
5. Add `AltSignatureAlgorithm` extension
6. Add `AltSignatureValue` extension
7. Re-sign entire certificate with classical algorithm

**Verifying a Catalyst Certificate:**

- **Legacy systems**: Verify classical signature only (extensions ignored)
- **PQC-aware systems**: Verify both signatures

### 4.4 When to Use Catalyst

- Maximum backward compatibility needed
- Single certificate preferred
- Unified key lifecycle desired
- Systems that can't handle multiple certs

## 5. Composite Certificates (IETF draft-13)

> **Note:** This specification is a **DRAFT** and subject to change before final standardization.

Composite certificates use **a single composite public key and a single composite signature** that cryptographically bind both classical and post-quantum algorithms together.

### 5.1 Composite vs Catalyst

| Aspect | Catalyst (ITU-T X.509 9.8) | Composite (IETF draft-13) |
|--------|---------------------------|---------------------------|
| Standard | ITU-T X.509 (2019) - **Final** | IETF draft-13 - **DRAFT** |
| Public Key | SPKI + AltSubjectPublicKeyInfo extension | Single composite SPKI |
| Signature | signatureValue + AltSignatureValue extension | Single composite signatureValue |
| OIDs | Individual algorithm OIDs | Single composite algorithm OID |
| Fallback | Legacy verifiers use classical only | No fallback - both required |
| Use Case | Backward compatibility needed | Maximum security, PQC-only environments |

### 5.2 Supported Composite Algorithms

Only IANA-allocated OIDs from draft-ietf-lamps-pq-composite-sigs-13 are supported:

| Composite Algorithm | Classical | PQC | Security Level |
|---------------------|-----------|-----|----------------|
| MLDSA65-ECDSA-P256-SHA512 | ECDSA P-256 | ML-DSA-65 | NIST Level 3 |
| MLDSA65-ECDSA-P384-SHA512 | ECDSA P-384 | ML-DSA-65 | NIST Level 3 |
| MLDSA87-ECDSA-P521-SHA512 | ECDSA P-521 | ML-DSA-87 | NIST Level 5 |

### 5.3 ASN.1 Structures

```asn1
-- Composite Public Key
CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA public key, [1] Classical public key

-- Composite Signature
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA signature, [1] Classical signature
```

### 5.4 Signature Process

Per draft Section 5, the signature is computed as:

1. **Build domain separator**: DER-encode the composite OID
2. **Construct message**: `M' = DomainSeparator || TBSCertificate`
3. **Sign with ML-DSA**: Sign full M' directly
4. **Sign with ECDSA**: Sign SHA-512(M')
5. **Encode result**: `SEQUENCE { mldsaSig, ecdsaSig }`

### 5.5 Compatibility Warning

Composite certificates are **NOT compatible** with:
- Standard browsers (Chrome, Firefox, Safari)
- Standard TLS libraries (OpenSSL without PQC patches)
- Any software unaware of composite OIDs

Use composite certificates only when all verifiers support composite signatures.

## 6. Separate Linked Certificates

Two certificates linked via the `RelatedCertificate` extension:

```
Certificate 1 (Classical):
  Public Key: ECDSA P-256
  Extensions:
    RelatedCertificate: [hash of Cert 2]

Certificate 2 (PQC):
  Public Key: ML-DSA-65
  Extensions:
    RelatedCertificate: [hash of Cert 1]
```

Use when different validity periods or independent key rotation is needed.

## 7. Technical Reference

### 7.1 OID Registry

#### Classical Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| ECDSA P-256 | 1.2.840.10045.3.1.7 |
| ECDSA P-384 | 1.3.132.0.34 |
| ECDSA P-521 | 1.3.132.0.35 |
| Ed25519 | 1.3.101.112 |
| RSA | 1.2.840.113549.1.1.1 |

#### Post-Quantum Algorithm OIDs

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

#### Catalyst Extension OIDs

| OID | Name |
|-----|------|
| 2.5.29.72 | AltSubjectPublicKeyInfo |
| 2.5.29.73 | AltSignatureAlgorithm |
| 2.5.29.74 | AltSignatureValue |

#### Composite Algorithm OIDs (IANA-allocated)

| Algorithm | OID |
|-----------|-----|
| MLDSA65-ECDSA-P256-SHA512 | 1.3.6.1.5.5.7.6.45 |
| MLDSA65-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.46 |
| MLDSA87-ECDSA-P521-SHA512 | 1.3.6.1.5.5.7.6.54 |

### 7.2 X.509 Extension OIDs

| OID | Name | Usage |
|-----|------|-------|
| 2.5.29.14 | Subject Key Identifier | Certificate extension |
| 2.5.29.35 | Authority Key Identifier | Certificate extension |
| 2.5.29.15 | Key Usage | Certificate extension |
| 2.5.29.37 | Extended Key Usage | Certificate extension |
| 2.5.29.17 | Subject Alternative Name | Certificate extension |
| 2.5.29.19 | Basic Constraints | Certificate extension |
| 2.5.29.31 | CRL Distribution Points | Certificate extension |

### 7.3 File Formats

#### Private Keys
- Format: PEM (PKCS#8)
- Encryption: Optional AES-256-CBC with PBKDF2
- Header: `-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`

#### Certificates
- Format: PEM (X.509)
- Header: `-----BEGIN CERTIFICATE-----`

#### Certificate Revocation Lists
- Format: PEM and DER
- Header: `-----BEGIN X509 CRL-----`

## 8. Security Considerations

### 8.1 Certificate Size

Hybrid certificates are significantly larger:

| Type | Approximate Size |
|------|------------------|
| ECDSA P-384 only | ~1 KB |
| ECDSA P-384 + ML-DSA-65 | ~6 KB |

### 8.2 Performance

| Operation | ECDSA P-384 | ML-DSA-65 | Ratio |
|-----------|-------------|-----------|-------|
| Key Generation | ~1 ms | ~1 ms | 1x |
| Sign | ~1 ms | ~2 ms | 2x |
| Verify | ~2 ms | ~1 ms | 0.5x |

ML-DSA verification is actually faster than ECDSA.

### 8.3 Key Storage

- PQC private keys are larger than classical keys
- ML-DSA-65 private key: ~4,000 bytes (vs ECDSA P-384: ~48 bytes)
- Encrypted storage adds overhead

## 9. Migration Path

### Phase 1: Hybrid (Current)

- Issue hybrid certificates
- Classical signature for TLS
- PQC material stored for future use

### Phase 2: Dual Validation

- Applications verify both signatures
- Reject if either fails
- Requires application changes

### Phase 3: Pure PQC

- Issue pure PQC certificates
- Requires ecosystem support
- Target: 2030+ (NIST recommendation)

## 10. References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [ITU-T X.509 (2019)](https://www.itu.int/rec/T-REC-X.509) - Section 9.8
- [IETF Composite Signatures](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)

## See Also

- [GLOSSARY](GLOSSARY.md) - Terminology reference
- [ARCHITECTURE](ARCHITECTURE.md) - System design
- [CA](CA.md) - CA operations and certificate issuance
- [PROFILES](PROFILES.md) - Certificate templates
