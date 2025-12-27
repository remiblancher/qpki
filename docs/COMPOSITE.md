# Composite Certificates (IETF draft-ietf-lamps-pq-composite-sigs-13)

> **Note:** This specification is a **DRAFT** and subject to change before final standardization.

Composite certificates use **a single composite public key and a single composite signature** that cryptographically bind both classical and post-quantum algorithms together.

## Overview

A **Composite certificate** follows IETF [draft-ietf-lamps-pq-composite-sigs-13](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/). It contains:

1. **Composite public key**: Both keys encoded in a single SubjectPublicKeyInfo
2. **Composite signature**: Both signatures encoded in a single signatureValue

This approach provides:
- **Strict security**: Both signatures MUST validate (no fallback)
- **Single OID**: Algorithm pair identified by one composite OID
- **Cryptographic binding**: Domain separator ties algorithms together

## Composite vs Catalyst

| Aspect | Catalyst (ITU-T X.509 9.8) | Composite (IETF draft-13) |
|--------|---------------------------|---------------------------|
| Standard | ITU-T X.509 (2019) - **Final** | draft-ietf-lamps-pq-composite-sigs-13 - **DRAFT** |
| Public Key | SPKI + AltSubjectPublicKeyInfo extension | Single composite SPKI |
| Signature | signatureValue + AltSignatureValue extension | Single composite signatureValue |
| OIDs | Individual algorithm OIDs | Single composite algorithm OID |
| Fallback | Legacy verifiers use classical only | No fallback - both required |
| Use Case | Backward compatibility needed | Maximum security, PQC-only environments |

**When to use which:**
- **Catalyst**: When legacy systems must verify certificates (browsers, existing infrastructure)
- **Composite**: When all verifiers are PQC-aware and you want maximum security

## Supported Algorithms

| Composite OID | Classical | PQC | Security Level |
|---------------|-----------|-----|----------------|
| MLDSA87-ECDSA-P384-SHA512 | ECDSA P-384 | ML-DSA-87 | ~192-bit / NIST Level 5 |
| MLDSA65-ECDSA-P256-SHA512 | ECDSA P-256 | ML-DSA-65 | ~128-bit / NIST Level 3 |
| MLDSA44-ECDSA-P256-SHA256 | ECDSA P-256 | ML-DSA-44 | ~128-bit / NIST Level 2 |

OID arc: `1.3.6.1.5.5.7.6.x` (IETF id-smime algorithms)

| Algorithm | OID |
|-----------|-----|
| MLDSA44-ECDSA-P256-SHA256 | `1.3.6.1.5.5.7.6.40` |
| MLDSA65-ECDSA-P256-SHA512 | `1.3.6.1.5.5.7.6.45` |
| MLDSA87-ECDSA-P384-SHA512 | `1.3.6.1.5.5.7.6.49` |

## ASN.1 Structures

```asn1
-- Composite Public Key (Section 6)
CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA public key bytes, [1] Classical public key bytes
-- Each BIT STRING contains raw public key bytes (NOT wrapped in SubjectPublicKeyInfo)

-- Composite Signature (Section 5)
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
-- Order: [0] ML-DSA signature, [1] Classical signature
```

## Signature Process

Per draft Section 5, the signature is computed as:

1. **Build domain separator**: DER-encode the composite OID
2. **Construct message**: `M' = DomainSeparator || TBSCertificate`
3. **Sign with ML-DSA**: Sign full M' directly
4. **Sign with ECDSA**: Sign SHA-512(M')
5. **Encode result**: `SEQUENCE { mldsaSig, ecdsaSig }`

The domain separator cryptographically binds the algorithm choice to the signature.

## CLI Usage

### Create a Composite CA

```bash
pki ca init --name "Composite Root CA" \
  --profile hybrid/composite/root-ca \
  --dir ./composite-ca
```

Output:
```
Initializing CA at ./composite-ca...
  Algorithm: ECDSA with P-384 curve
  Hybrid PQC: ML-DSA-87 (NIST Level 5)

CA initialized successfully!
  Subject:     CN=Composite Root CA,O=ACME Corp,C=US
  Mode:        Composite (IETF)
  PQC Key:     ./composite-ca/private/ca.key.pqc
```

### Issue a Composite Certificate

```bash
pki credential enroll --ca-dir ./composite-ca \
  --profile hybrid/composite/tls-server \
  --var cn=secure.example.com \
  --var dns_names=secure.example.com
```

### Verify a Composite Certificate

```bash
pki verify --cert ./certificate.pem --ca ./composite-ca/ca.crt
```

Both ML-DSA and ECDSA signatures are verified. If either fails, the certificate is rejected.

### Inspect Certificate

```bash
pki inspect ./certificate.pem
```

Output shows:
```
Certificate:
  Signature Alg:  MLDSA87-ECDSA-P384-SHA512
  Public Key Alg: MLDSA65-ECDSA-P256-SHA512
```

## Available Profiles

| Profile | Description |
|---------|-------------|
| `hybrid/composite/root-ca` | Root CA with ECDSA-P384 + ML-DSA-87 |
| `hybrid/composite/issuing-ca` | Subordinate CA |
| `hybrid/composite/tls-server` | TLS server with ECDSA-P256 + ML-DSA-65 |
| `hybrid/composite/tls-client` | TLS client authentication |
| `hybrid/composite/timestamping` | Timestamping service |

## Verification Behavior

Per the specification, composite certificate verification:
1. Parses the composite public key to extract both component keys
2. Parses the composite signature to extract both component signatures
3. Reconstructs the domain separator and message
4. Verifies BOTH signatures independently
5. **Returns valid ONLY if both signatures verify**

There is no fallback mode. This is intentional for maximum security.

## Compatibility Warning

Composite certificates are **NOT compatible** with:
- Standard browsers (Chrome, Firefox, Safari)
- Standard TLS libraries (OpenSSL without PQC patches)
- Any software unaware of composite OIDs

Use composite certificates only when:
- All verifiers support composite signatures
- You're building a PQC-only environment
- Testing or research purposes

For broad compatibility, use [Catalyst certificates](CATALYST.md) instead.

## References

- [draft-ietf-lamps-pq-composite-sigs-13](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) - IETF Composite Signatures (**DRAFT**)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Final)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Final)
- [ITU-T X.509 (2019)](https://www.itu.int/rec/T-REC-X.509) - Catalyst certificates (Section 9.8)
