# Catalyst Certificates (ITU-T X.509 Section 9.8)

Catalyst certificates embed **two public keys and two signatures** in a single X.509 certificate, enabling a smooth transition to post-quantum cryptography while maintaining backward compatibility.

## Overview

A **Catalyst certificate** follows ITU-T X.509 (2019) Section 9.8 "Hybrid public-key certificates". It contains:

1. **Primary key and signature**: Classical algorithm (ECDSA, RSA) in standard X.509 fields
2. **Alternative key and signature**: PQC algorithm (ML-DSA) in non-critical X.509 extensions

This approach provides:
- **Backward compatibility**: Legacy systems use the classical signature (extensions ignored)
- **Forward security**: PQC-aware systems verify both signatures
- **Single certificate**: No need to manage multiple certificates

## X.509 Extensions

Catalyst certificates use three non-critical extensions defined in ITU-T X.509 Section 9.8:

| OID | Name | Content |
|-----|------|---------|
| 2.5.29.72 | AltSubjectPublicKeyInfo | Alternative public key (PQC) |
| 2.5.29.73 | AltSignatureAlgorithm | Algorithm of alternative signature |
| 2.5.29.74 | AltSignatureValue | Alternative signature value |

### Extension Criticality

All three extensions are **non-critical**:
- Legacy systems ignore them and use classical verification
- PQC-aware systems verify both signatures

## Certificate Structure

```
Certificate:
  Data:
    Subject: CN=Alice, O=Acme
    Subject Public Key Info:
      Algorithm: ECDSA P-256           ← Classical (primary)
      Public Key: [EC public key]
    Extensions:
      AltSubjectPublicKeyInfo:         ← PQC (alternative)
        Algorithm: ML-DSA-65
        Public Key: [ML-DSA public key]
      AltSignatureAlgorithm:
        Algorithm: ML-DSA-65
      AltSignatureValue:
        [ML-DSA signature]             ← Signs TBS without alt extensions
  Signature Algorithm: SHA256WithECDSA ← Classical signature
  Signature: [ECDSA signature]
```

## Signature Process

### Issuing a Catalyst Certificate

1. Build TBS (To-Be-Signed) certificate WITHOUT alternative extensions
2. Generate classical signature over TBS
3. Add `AltSubjectPublicKeyInfo` extension with PQC public key
4. Generate alternative signature over TBS (same data as step 1)
5. Add `AltSignatureAlgorithm` extension
6. Add `AltSignatureValue` extension
7. Re-sign entire certificate with classical algorithm

### Verifying a Catalyst Certificate

**Classical verification (legacy systems):**
1. Verify classical signature in standard X.509 field
2. Ignore all extensions (non-critical)

**Full verification (PQC-aware systems):**
1. Verify classical signature
2. Extract alternative signature from `AltSignatureValue`
3. Reconstruct TBS without alternative extensions
4. Verify alternative signature over reconstructed TBS

## Usage

### Create Catalyst CA

```bash
# Initialize CA with Catalyst profile
qpkica init --name "Hybrid CA" \
    --profile hybrid/catalyst/root-ca \
    --dir ./hybrid-ca
```

### Issue Catalyst Certificates

Using profiles (recommended):
```bash
# Issue with Catalyst profile
qpkicert issue --profile hybrid/catalyst/tls-server \
    --cn server.example.com \
    --dns server.example.com
```

Catalyst profile format:
```yaml
name: hybrid/catalyst/tls-server
description: "TLS server hybrid ECDSA P-256 + ML-DSA-65"

mode: catalyst
algorithms:
  - ecdsa-p256           # Classical (first)
  - ml-dsa-65            # PQC (second)
validity: 365d

extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
  extKeyUsage:
    values:
      - serverAuth
```

### Inspect Catalyst Certificate

```bash
qpkiinspect alice.crt
```

Output:
```
Certificate:
  Subject: CN=alice.example.com
  Issuer: CN=Hybrid CA
  Serial: 0x01
  Valid: 2025-01-15 - 2026-01-15

  Public Key:
    Algorithm: ECDSA P-384

  Catalyst Extensions:
    Alternative Public Key: ML-DSA-65
    Alternative Signature: ML-DSA-65 (verified)

  Signature:
    Algorithm: SHA384WithECDSA
    Status: Valid
```

## Hybrid vs Separate Certificates

| Aspect | Catalyst (Combined) | Separate Certificates |
|--------|--------------------|-----------------------|
| Certificates | 1 | 2 |
| Compatibility | High (single cert) | Medium (two certs) |
| Key lifecycle | Coupled | Can be independent |
| Revocation | Single operation | Two operations |
| Storage | Smaller | Larger |
| Standards | ITU-T X.509 9.8 | RelatedCertificate draft |

### When to Use Catalyst

- Maximum backward compatibility needed
- Single certificate preferred
- Unified key lifecycle desired
- Systems that can't handle multiple certs

### When to Use Separate Certificates

- Different validity periods needed
- Independent key rotation required
- Algorithm agility (replace one without the other)
- Systems expecting single-key certificates

## CSR for Catalyst Enrollment

When requesting a Catalyst certificate, the CSR should prove possession of both keys:

```
Certificate Request:
  Subject: CN=Alice
  Public Key: ECDSA P-256          ← Classical
  Attributes:
    subjectAltPublicKeyInfo:       ← PQC public key
      Algorithm: ML-DSA-65
      Public Key: [ML-DSA key]
    altSignatureAlgorithm:
      Algorithm: ML-DSA-65
    altSignatureValue:
      [ML-DSA signature over CSR]
  Signature Algorithm: SHA256WithECDSA
  Signature: [ECDSA signature]
```

Both signatures must be valid for the CA to accept the CSR.

## Programmatic Usage

```go
import (
    "github.com/remiblancher/post-quantum-pki/internal/ca"
    pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
    "github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// Generate hybrid key pair
classicalSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
pqcSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)

// Create Catalyst CSR
csr, _ := x509util.CreateHybridCSR(x509util.HybridCSRRequest{
    Subject:         pkix.Name{CommonName: "Alice"},
    ClassicalSigner: classicalSigner,
    PQCSigner:       pqcSigner,
})

// Issue Catalyst certificate
caInstance, _ := ca.New(caStore)
cert, _ := caInstance.IssueCatalyst(ca.CatalystRequest{
    Template:           template,
    ClassicalPublicKey: classicalSigner.Public(),
    PQCPublicKey:       pqcSigner.Public(),
    PQCAlgorithm:       pkicrypto.AlgMLDSA65,
    Profile:            profiles.NewTLSServerProfile(),
})

// Verify Catalyst signatures
valid, _ := ca.VerifyCatalystSignatures(cert, caCert)
```

## Parsing Catalyst Extensions

```go
import "github.com/remiblancher/post-quantum-pki/internal/x509util"

// Parse a certificate's Catalyst extensions
info, err := x509util.ParseCatalystExtensions(cert.Extensions)
if err == nil && info != nil {
    fmt.Printf("Alternative Algorithm: %s\n", info.AltAlgorithm)
    fmt.Printf("Alternative Public Key: %x\n", info.AltPublicKey)
    fmt.Printf("Alternative Signature: %x\n", info.AltSignature)
}
```

## Security Considerations

1. **Both signatures required**: A PQC-aware verifier MUST verify both signatures
2. **Non-repudiation**: The subject possesses both private keys
3. **Algorithm independence**: Classical and PQC algorithms should not share mathematical weaknesses
4. **Key generation**: Both keys must be generated with appropriate randomness
5. **Extension integrity**: AltSignatureValue signs the TBS WITHOUT alternative extensions (prevents tampering)

## Standards Reference

- **ITU-T X.509 (2019)**: Section 9.8 "Hybrid public-key certificates"
- **NIST SP 800-208**: Recommendation for Stateful Hash-Based Signature Schemes
- **draft-ietf-lamps-pq-composite-sigs**: Composite ML-DSA for use in X.509

## Interoperability

### OpenSSL Compatibility

OpenSSL 3.x ignores unknown non-critical extensions:

```bash
# Verify classical signature (works)
openssl verify -CAfile ca.crt catalyst-cert.crt

# Show certificate (extensions displayed as raw hex)
openssl x509 -in catalyst-cert.crt -text
```

### Go crypto/x509

The Go standard library parses Catalyst certificates but ignores unknown extensions:

```go
cert, _ := x509.ParseCertificate(der)
// cert.PublicKey contains classical key only
// Use x509util.ParseCatalystExtensions for PQC key
```

## See Also

- [PROFILES.md](PROFILES.md) - Profiles include Catalyst modes
- [BUNDLES.md](BUNDLES.md) - Bundle management for Catalyst certs
- [PQC.md](PQC.md) - Post-quantum cryptography overview
