---
title: "Standards Compliance"
description: "QPKI compliance with FIPS and RFC standards."
---

# Standards Compliance

This document covers QPKI compliance with cryptographic and PKI standards.

## Cryptographic Standards

### FIPS 203 - ML-KEM (Key Encapsulation)

| Parameter | Support | Usage |
|-----------|:-------:|-------|
| ML-KEM-512 | Yes | CMS EnvelopedData |
| ML-KEM-768 | Yes | CMS EnvelopedData (recommended) |
| ML-KEM-1024 | Yes | CMS EnvelopedData |

### FIPS 204 - ML-DSA (Signatures)

| Parameter | Support | Usage |
|-----------|:-------:|-------|
| ML-DSA-44 | Yes | Signatures (128-bit) |
| ML-DSA-65 | Yes | Signatures (recommended, 192-bit) |
| ML-DSA-87 | Yes | Signatures (256-bit) |

### FIPS 205 - SLH-DSA (Stateless Hash-Based Signatures)

| Parameter | Support | Usage |
|-----------|:-------:|-------|
| SLH-DSA-SHA2-128f | Yes | Fast signing |
| SLH-DSA-SHA2-128s | Yes | Small signatures |
| SLH-DSA-SHA2-192f | Yes | Fast signing |
| SLH-DSA-SHA2-192s | Yes | Small signatures |
| SLH-DSA-SHA2-256f | Yes | Fast signing |
| SLH-DSA-SHA2-256s | Yes | Small signatures |
| SLH-DSA-SHAKE-* | Yes | SHAKE variants |

## PKI Standards

### RFC 5280 - X.509 Certificates

| Feature | Support | Notes |
|---------|:-------:|-------|
| Certificate v3 | Yes | Standard extensions |
| CRL v2 | Yes | Delta CRL supported |
| Basic Constraints | Yes | CA/End-entity |
| Key Usage | Yes | digitalSignature, keyEncipherment, etc. |
| Extended Key Usage | Yes | serverAuth, clientAuth, codeSigning, etc. |
| Subject Alt Name | Yes | DNS, IP, Email, URI |
| Authority Key Identifier | Yes | |
| Subject Key Identifier | Yes | |
| CRL Distribution Points | Yes | |
| Authority Information Access | Yes | OCSP, CA Issuers |

### RFC 5652 - CMS (Cryptographic Message Syntax)

| Feature | Support | Notes |
|---------|:-------:|-------|
| SignedData | Yes | EC, RSA, ML-DSA, SLH-DSA |
| EnvelopedData | Yes | RSA, ECDH, ML-KEM |
| AuthEnvelopedData | Yes | AES-GCM |
| Multiple signers | Yes | |
| Multiple recipients | Yes | |

### RFC 6960 - OCSP

| Feature | Support | Notes |
|---------|:-------:|-------|
| Basic OCSP | Yes | GET and POST |
| Nonce extension | Yes | |
| Signed response | Yes | EC, ML-DSA |
| Delegated responder | Yes | |

### RFC 3161 - TSA (Time-Stamp Protocol)

| Feature | Support | Notes |
|---------|:-------:|-------|
| TimeStampReq | Yes | |
| TimeStampResp | Yes | |
| Accuracy | Yes | Configurable |
| Ordering | Yes | |
| Nonce | Yes | |

## Hybrid Algorithms

### Catalyst (ITU-T X.509 Section 9.8)

Dual-signature certificates using standard X.509 extensions.

| Extension | OID | Content |
|-----------|-----|---------|
| AltSubjectPublicKeyInfo | 2.5.29.72 | Alternative public key (PQC) |
| AltSignatureAlgorithm | 2.5.29.73 | Algorithm of alternative signature |
| AltSignatureValue | 2.5.29.74 | Alternative signature value |

Supported combinations:

| Combination | Support |
|-------------|:-------:|
| ECDSA-P256 + ML-DSA-44 | Yes |
| ECDSA-P384 + ML-DSA-65 | Yes |
| ECDSA-P384 + ML-DSA-87 | Yes |

### Composite (IETF draft-ietf-lamps-pq-composite-sigs-13)

| Combination | Support | OID |
|-------------|:-------:|-----|
| MLDSA65-ECDSA-P256-SHA512 | Yes | 1.3.6.1.5.5.7.6.45 |
| MLDSA65-ECDSA-P384-SHA512 | Yes | 1.3.6.1.5.5.7.6.46 |
| MLDSA87-ECDSA-P521-SHA512 | Yes | 1.3.6.1.5.5.7.6.54 |

## Interoperability

| Validator | Version | Status |
|-----------|---------|--------|
| OpenSSL | 3.6+ | Partial (native PQC, no Composite) |
| BouncyCastle | 1.83+ | Partial (draft-07 for Composite) |

See [TESTS-INTEROP.md](TESTS-INTEROP.md) for test details.

## See Also

- [STRATEGY.md](STRATEGY.md) - Testing philosophy
- [TESTS-ACCEPTANCE.md](TESTS-ACCEPTANCE.md) - Acceptance tests
- [TESTS-INTEROP.md](TESTS-INTEROP.md) - Interoperability tests
