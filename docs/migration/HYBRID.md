---
title: "Hybrid Certificates"
description: "Technical details on Catalyst, Composite, and Separate hybrid certificate formats."
---

# Hybrid Certificates

This document covers the technical details of hybrid certificate formats supported by QPKI.

> For an introduction to hybrid certificates and why they're needed, see [Post-Quantum](../getting-started/POST-QUANTUM.md).

## 1. Catalyst Certificates (ITU-T X.509 Section 9.8)

Catalyst certificates embed **two public keys and two signatures** in a single X.509 certificate using standard extensions.

### 1.1 X.509 Extensions

| OID | Name | Content |
|-----|------|---------|
| 2.5.29.72 | AltSubjectPublicKeyInfo | Alternative public key (PQC) |
| 2.5.29.73 | AltSignatureAlgorithm | Algorithm of alternative signature |
| 2.5.29.74 | AltSignatureValue | Alternative signature value |

All three extensions are **non-critical** - legacy systems ignore them and use classical verification.

### 1.2 Certificate Structure

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

### 1.3 Signature Process

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

### 1.4 When to Use Catalyst

- Maximum backward compatibility needed
- Single certificate preferred
- Unified key lifecycle desired
- Systems that can't handle multiple certs

## 2. Composite Certificates (IETF draft-13)

> **Note:** This specification is a **DRAFT** and subject to change before final standardization.

Composite certificates use **a single composite public key and a single composite signature** that cryptographically bind both classical and post-quantum algorithms together.

### 2.1 Composite vs Catalyst

| Aspect | Catalyst (ITU-T X.509 9.8) | Composite (IETF draft-13) |
|--------|---------------------------|---------------------------|
| Standard | ITU-T X.509 (2019) - **Final** | IETF draft-13 - **DRAFT** |
| Public Key | SPKI + AltSubjectPublicKeyInfo extension | Single composite SPKI |
| Signature | signatureValue + AltSignatureValue extension | Single composite signatureValue |
| OIDs | Individual algorithm OIDs | Single composite algorithm OID |
| Fallback | Legacy verifiers use classical only | No fallback - both required |
| Use Case | Backward compatibility needed | Maximum security, PQC-only environments |

### 2.2 Supported Composite Algorithms

Only IANA-allocated OIDs from draft-ietf-lamps-pq-composite-sigs-13 are supported:

| Composite Algorithm | Classical | PQC | Security Level |
|---------------------|-----------|-----|----------------|
| MLDSA65-ECDSA-P256-SHA512 | ECDSA P-256 | ML-DSA-65 | NIST Level 3 |
| MLDSA65-ECDSA-P384-SHA512 | ECDSA P-384 | ML-DSA-65 | NIST Level 3 |
| MLDSA87-ECDSA-P521-SHA512 | ECDSA P-521 | ML-DSA-87 | NIST Level 5 |

### 2.3 ASN.1 Structures

```asn1
-- Composite Public Key
CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA public key, [1] Classical public key

-- Composite Signature
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA signature, [1] Classical signature
```

### 2.4 Signature Process

Per draft Section 5, the signature is computed as:

1. **Build domain separator**: DER-encode the composite OID
2. **Construct message**: `M' = DomainSeparator || TBSCertificate`
3. **Sign with ML-DSA**: Sign full M' directly
4. **Sign with ECDSA**: Sign SHA-512(M')
5. **Encode result**: `SEQUENCE { mldsaSig, ecdsaSig }`

### 2.5 Compatibility Warning

Composite certificates are **NOT compatible** with:
- Standard browsers (Chrome, Firefox, Safari)
- Standard TLS libraries (OpenSSL without PQC patches)
- Any software unaware of composite OIDs

Use composite certificates only when all verifiers support composite signatures.

## 3. Separate Linked Certificates

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

## 4. Client-Side Verification

### 4.1 Verifying Catalyst Certificates

Catalyst certificates can be verified at two levels:

**Classical only (legacy clients):**
Legacy TLS libraries and browsers verify only the classical signature (`signatureValue`). The alternative extensions (`2.5.29.72-74`) are non-critical and silently ignored.

**Dual verification (PQC-aware clients):**

```bash
# Verify both signatures with qpki
qpki cert verify --hybrid --cert server.pem --ca-cert ca.pem

# Output:
# ✓ Classical signature (ECDSA-P384): valid
# ✓ Alternative signature (ML-DSA-65): valid
# ✓ Certificate chain: valid
```

The verification process:
1. Verify the classical signature over the full certificate
2. Extract `AltSignatureValue` and `AltSignatureAlgorithm` extensions
3. Rebuild TBS without alternative extensions (same data the issuer signed)
4. Verify the alternative signature over that TBS
5. Both must pass for dual verification to succeed

### 4.2 Verifying Composite Certificates

Composite certificates require all verifiers to support composite OIDs. There is no fallback.

```bash
# Verify composite certificate
qpki cert verify --cert composite-server.pem --ca-cert composite-ca.pem

# Output:
# ✓ Composite signature (MLDSA65-ECDSA-P256-SHA512): valid
# ✓ Certificate chain: valid
```

The composite signature verification:
1. Extract the `CompositeSignatureValue` (SEQUENCE of two BIT STRINGs)
2. Reconstruct `M' = DomainSeparator || TBSCertificate`
3. Verify ML-DSA signature over M'
4. Verify ECDSA signature over SHA-512(M')
5. Both must pass — if either fails, the certificate is rejected

### 4.3 Verifying Separate Linked Certificates

Both certificates must be presented and verified independently:

```bash
# Verify linked certificate pair
qpki cert verify --cert classical.pem --linked-cert pqc.pem --ca-cert ca.pem

# Output:
# ✓ Classical certificate (ECDSA-P384): valid
# ✓ PQC certificate (ML-DSA-65): valid
# ✓ RelatedCertificate binding: valid
```

The binding verification:
1. Verify each certificate independently against its CA
2. Check that each certificate's `RelatedCertificate` extension contains the hash of the other
3. Both certificates must share the same Subject

### 4.4 Verification Matrix

| Client Type | Catalyst | Composite | Separate |
|-------------|----------|-----------|----------|
| Legacy (OpenSSL < 3.6) | Classical only ✓ | Fails ✗ | Classical only ✓ |
| PQC-aware (qpki, OQS) | Dual ✓ | Full ✓ | Dual ✓ |
| BouncyCastle 1.83+ | Dual ✓ | Partial (draft-07) | Dual ✓ |

## 5. Security Considerations

### 5.1 Certificate Size

Hybrid certificates are significantly larger:

| Type | Approximate Size |
|------|------------------|
| ECDSA P-384 only | ~1 KB |
| ECDSA P-384 + ML-DSA-65 | ~6 KB |

### 5.2 Performance

| Operation | ECDSA P-384 | ML-DSA-65 | Ratio |
|-----------|-------------|-----------|-------|
| Key Generation | ~1 ms | ~1 ms | 1x |
| Sign | ~1 ms | ~2 ms | 2x |
| Verify | ~2 ms | ~1 ms | 0.5x |

ML-DSA verification is actually faster than ECDSA.

### 5.3 Key Storage

- PQC private keys are larger than classical keys
- ML-DSA-65 private key: ~4,000 bytes (vs ECDSA P-384: ~48 bytes)
- Encrypted storage adds overhead

## 6. Migration Path

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

## 7. References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [ITU-T X.509 (2019)](https://www.itu.int/rec/T-REC-X.509) - Section 9.8
- [IETF Composite Signatures](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)

## See Also

- [Post-Quantum](../getting-started/POST-QUANTUM.md) - Introduction to PQC and hybrid certificates
- [Crypto-Agility](CRYPTO-AGILITY.md) - Algorithm migration guide
- [Standards](../reference/STANDARDS.md) - OIDs and file formats
