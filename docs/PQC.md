# Post-Quantum Cryptography (PQC)

This document covers the post-quantum cryptography implementation, hybrid certificate format, and migration considerations.

## 1. Overview

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
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,293 bytes | Balanced |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,595 bytes | Most secure |

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

## 3. Implementation

### 3.1 Library

PQC algorithms are provided by **Cloudflare's CIRCL** library:

- Repository: https://github.com/cloudflare/circl
- Pure Go implementation (no CGO)
- Tested against NIST test vectors
- Used in production at Cloudflare

### 3.2 Algorithm IDs

```go
const (
    // ML-DSA (FIPS 204)
    AlgMLDSA44   AlgorithmID = "ml-dsa-44"
    AlgMLDSA65   AlgorithmID = "ml-dsa-65"
    AlgMLDSA87   AlgorithmID = "ml-dsa-87"

    // SLH-DSA (FIPS 205)
    AlgSLHDSA128s AlgorithmID = "slh-dsa-128s"
    AlgSLHDSA128f AlgorithmID = "slh-dsa-128f"
    AlgSLHDSA192s AlgorithmID = "slh-dsa-192s"
    AlgSLHDSA192f AlgorithmID = "slh-dsa-192f"
    AlgSLHDSA256s AlgorithmID = "slh-dsa-256s"
    AlgSLHDSA256f AlgorithmID = "slh-dsa-256f"

    // ML-KEM (FIPS 203)
    AlgMLKEM512  AlgorithmID = "ml-kem-512"
    AlgMLKEM768  AlgorithmID = "ml-kem-768"
    AlgMLKEM1024 AlgorithmID = "ml-kem-1024"
)
```

### 3.3 OIDs

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

## 4. Hybrid Certificates

### 4.1 Why Hybrid?

Pure PQC certificates face challenges:

1. **Go's crypto/x509** doesn't support PQC signature algorithms
2. **Existing infrastructure** (browsers, TLS libraries) doesn't recognize PQC
3. **Security uncertainty** - PQC algorithms are newer, less analyzed than classical

Hybrid certificates provide:
- **Backward compatibility** via classical signature
- **Forward security** via PQC material
- **Gradual migration** path

### 4.2 Hybrid Modes

This PKI supports three hybrid approaches:

| Mode | Standard | Certificates | Description |
|------|----------|--------------|-------------|
| **Catalyst (Combined)** | ITU-T X.509 9.8 | 1 | Dual keys in single cert |
| **Separate (Linked)** | draft-ietf-lamps-cert-binding | 2 | Two linked certificates |
| **Legacy Extension** | Proprietary | 1 | PQC in custom extension |

**Catalyst** is the recommended approach for new deployments.

### 4.3 Catalyst Certificates (ITU-T X.509 Section 9.8)

Catalyst certificates embed **two public keys and two signatures** in a single X.509 certificate using standard extensions:

```
Certificate:
  Data:
    Subject Public Key Info:
      Algorithm: ECDSA P-256           ← Classical (primary)
      Public Key: [EC public key]
    Extensions:
      AltSubjectPublicKeyInfo (2.5.29.72):
        Algorithm: ML-DSA-65           ← PQC (alternative)
        Public Key: [ML-DSA public key]
      AltSignatureAlgorithm (2.5.29.73):
        Algorithm: ML-DSA-65
      AltSignatureValue (2.5.29.74):
        [ML-DSA signature]
  Signature Algorithm: SHA256WithECDSA ← Classical signature
  Signature: [ECDSA signature]
```

See [CATALYST.md](CATALYST.md) for detailed information.

### 4.4 Separate Linked Certificates

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

### 4.5 Creating Hybrid Certificates

Using profiles with credential enroll (recommended):
```bash
# Enroll with Catalyst profile
pki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# Enroll with composite profile
pki credential enroll --profile hybrid/composite/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# TLS server with hybrid profile
pki credential enroll --profile hybrid/catalyst/tls-server \
    --var cn=example.com --var dns_names=example.com --ca-dir ./hybrid-ca
```

Using CSR workflow with hybrid extension:
```bash
# Create hybrid CA
pki ca init --name "Hybrid CA" \
  --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 \
  --dir ./hybrid-ca

# Generate CSR
pki cert csr --algorithm ecdsa-p256 --keyout server.key \
    --cn example.com --dns example.com -o server.csr

# Issue with hybrid extension
pki cert issue --ca-dir ./hybrid-ca --profile ec/tls-server \
  --csr server.csr --hybrid ml-dsa-65 --out hybrid.crt
```

### 4.6 Parsing Hybrid Extensions

```go
import "github.com/remiblancher/pki/internal/x509util"

cert, _ := x509.ParseCertificate(certDER)

// Parse Catalyst extensions
catalyst, err := x509util.ParseCatalystExtensions(cert.Extensions)
if err == nil && catalyst != nil {
    fmt.Printf("Alternative Algorithm: %s\n", catalyst.AltAlgorithm)
    fmt.Printf("Alternative Public Key: %x\n", catalyst.AltPublicKey)
}

// Parse legacy hybrid extension
hybrid, err := x509util.ParseHybridExtension(cert)
if err == nil && hybrid != nil {
    fmt.Printf("PQC Algorithm: %s\n", hybrid.Algorithm)
}
```

## 5. Security Considerations

### 5.1 Algorithm Selection

| Use Case | Recommended | Rationale |
|----------|-------------|-----------|
| General purpose | ML-DSA-65 | Balance of security and size |
| Long-term secrets | ML-DSA-87 | Maximum security |
| Constrained devices | ML-DSA-44 | Smallest signatures |

### 5.2 Key Storage

- PQC private keys are larger than classical keys
- ML-DSA-65 private key: ~4,000 bytes (vs ECDSA P-384: ~48 bytes)
- Encrypted storage adds overhead

### 5.3 Certificate Size

Hybrid certificates are significantly larger:

| Type | Approximate Size |
|------|------------------|
| ECDSA P-384 only | ~1 KB |
| ECDSA P-384 + ML-DSA-65 | ~6 KB |

### 5.4 Performance

| Operation | ECDSA P-384 | ML-DSA-65 | Ratio |
|-----------|-------------|-----------|-------|
| Key Generation | ~1 ms | ~1 ms | 1x |
| Sign | ~1 ms | ~2 ms | 2x |
| Verify | ~2 ms | ~1 ms | 0.5x |

ML-DSA verification is actually faster than ECDSA!

## 6. Limitations

### 6.1 Current Limitations

1. **No pure PQC certificates** - Go's crypto/x509 doesn't support PQC signatures
2. **No HSM support for PQC** - Most HSMs don't yet support ML-DSA
3. **No browser support** - Browsers ignore the hybrid extension
4. **Experimental OID** - Using private OID space (2.999.x)

### 6.2 Interoperability

| Component | Classical | Hybrid Extension |
|-----------|-----------|------------------|
| Go crypto/x509 | ✓ | Parsed as unknown extension |
| OpenSSL | ✓ | Ignored |
| Browsers | ✓ | Ignored |
| This PKI | ✓ | ✓ |

### 6.3 Future Improvements

1. **Standard OIDs** - Use official IETF OIDs when standardized
2. **Pure PQC mode** - When Go supports PQC certificates
3. **Composite signatures** - Sign with both algorithms per IETF draft

## 7. Migration Path

### 7.1 Phase 1: Hybrid (Current)

- Issue hybrid certificates
- Classical signature for TLS
- PQC material stored for future use

### 7.2 Phase 2: Dual Validation

- Applications verify both signatures
- Reject if either fails
- Requires application changes

### 7.3 Phase 3: Pure PQC

- Issue pure PQC certificates
- Requires ecosystem support
- Target: 2030+ (NIST recommendation)

## 8. References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)
- [IETF Composite Signatures](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [NIST PQC Migration](https://www.nist.gov/pqcrypto)
