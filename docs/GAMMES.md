# Gammes (Certificate Policy Templates)

Gammes define certificate enrollment policies that specify which algorithms, signature modes, and encryption requirements to use when issuing certificates.

## Overview

A **gamme** is a policy template stored as a YAML file that determines:

- **Signature requirements**: Algorithm(s) and hybrid mode
- **Encryption requirements**: Whether encryption certificates are needed and which algorithms
- **Validity period**: How long certificates remain valid
- **Certificate count**: How many certificates are generated per enrollment

Gammes are stored in the CA's `gammes/` directory and can be customized per-CA.

## Signature Modes

| Mode | Description | Certificates |
|------|-------------|--------------|
| `simple` | Single algorithm signature | 1 |
| `hybrid-combined` | Catalyst certificate (dual keys in one cert) | 1 |
| `hybrid-separate` | Two linked certificates (classical + PQC) | 2 |

### Simple Signature

Standard X.509 certificate with a single signature algorithm:

```yaml
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
```

### Hybrid Combined (Catalyst)

A single certificate containing both classical and PQC public keys, following ITU-T X.509 Section 9.8. The certificate is signed by both CA keys.

```yaml
signature:
  required: true
  mode: hybrid-combined
  algorithms:
    primary: ecdsa-p256      # Classical (main signature)
    alternative: ml-dsa-65   # PQC (via extensions)
```

### Hybrid Separate

Two separate certificates linked via the `RelatedCertificate` extension:

```yaml
signature:
  required: true
  mode: hybrid-separate
  algorithms:
    primary: ecdsa-p256      # First certificate
    alternative: ml-dsa-65   # Second certificate (linked)
```

## Encryption Modes

| Mode | Description | Additional Certificates |
|------|-------------|------------------------|
| `none` | No encryption capability | 0 |
| `simple` | Single encryption algorithm | 1 |
| `hybrid-combined` | Catalyst encryption certificate | 1 |
| `hybrid-separate` | Two linked encryption certificates | 2 |

**Note**: Encryption certificates are always linked to the signature certificate.

```yaml
encryption:
  required: true
  mode: simple
  algorithms:
    primary: ml-kem-768
```

## Default Gammes

The following gammes are built-in and can be installed to any CA:

| Name | Signature | Encryption | Total Certs |
|------|-----------|------------|-------------|
| `classic` | ECDSA P-256 (simple) | None | 1 |
| `pqc-basic` | ML-DSA-65 (simple) | None | 1 |
| `pqc-full` | ML-DSA-65 (simple) | ML-KEM-768 | 2 |
| `hybrid-catalyst` | ECDSA + ML-DSA (combined) | None | 1 |
| `hybrid-separate` | ECDSA + ML-DSA (separate) | None | 2 |
| `hybrid-full` | ECDSA + ML-DSA (combined) | ML-KEM-768 | 2 |
| `tls-server-hybrid` | ECDSA + ML-DSA (combined) | None | 1 + full extensions |

### Install Default Gammes

```bash
pki gamme install --dir ./ca
```

### List Available Gammes

```bash
pki gamme list --dir ./ca
```

### View Gamme Details

```bash
pki gamme info hybrid-catalyst --dir ./ca
```

## Creating Custom Gammes

Create a YAML file in `ca/gammes/`:

```yaml
# ca/gammes/my-custom-gamme.yaml
name: my-custom-gamme
description: "Custom policy for internal servers"

signature:
  required: true
  mode: hybrid-combined
  algorithms:
    primary: ecdsa-p384
    alternative: ml-dsa-87

encryption:
  required: true
  mode: simple
  algorithms:
    primary: ml-kem-1024

validity: 180d  # 6 months
```

### Validate a Gamme

```bash
pki gamme validate my-gamme.yaml
```

## YAML Schema

```yaml
name: string              # Unique identifier
description: string       # Human-readable description

signature:
  required: true          # Always true (signature is mandatory)
  mode: string            # simple | hybrid-combined | hybrid-separate
  algorithms:
    primary: string       # Main algorithm
    alternative: string   # Alt algorithm (for hybrid modes)

encryption:
  required: boolean       # Whether encryption is needed
  mode: string            # none | simple | hybrid-combined | hybrid-separate
  algorithms:
    primary: string       # Main algorithm
    alternative: string   # Alt algorithm (for hybrid modes)

validity: duration        # Go duration format (e.g., 365d, 8760h)

extensions:               # Optional X.509 extensions (see below)
  keyUsage: ...
  extKeyUsage: ...
  basicConstraints: ...
  crlDistributionPoints: ...
  authorityInfoAccess: ...
  certificatePolicies: ...
  nameConstraints: ...
```

## X.509 Extensions

Gammes can optionally define X.509 extensions with explicit criticality.
If `extensions:` is omitted, default profile extensions are used.

### Extensions Configuration

```yaml
extensions:
  keyUsage:
    critical: true                      # RFC 5280: MUST be critical
    values:
      - digitalSignature
      - keyEncipherment

  extKeyUsage:
    critical: false
    values:
      - serverAuth
      - clientAuth

  basicConstraints:
    critical: true                      # RFC 5280: MUST be critical
    ca: false

  crlDistributionPoints:
    critical: false
    urls:
      - "http://pki.example.com/crl/ca.crl"

  authorityInfoAccess:
    critical: false                     # RFC 5280: MUST be non-critical
    ocsp:
      - "http://ocsp.example.com"
    caIssuers:
      - "http://pki.example.com/ca.crt"

  certificatePolicies:
    critical: false
    policies:
      - oid: "2.23.140.1.2.1"           # DV certificate policy
        cps: "http://example.com/cps"

  nameConstraints:                       # CA certificates only
    critical: true                       # RFC 5280: MUST be critical
    permitted:
      dns: [".example.com"]
    excluded:
      dns: [".test.example.com"]
```

### Certificate Extensions Reference

| Extension | Configurable | Criticality | Auto |
|-----------|:------------:|:-----------:|:----:|
| `subject` | Yes | - | |
| `san` | Yes | Configurable | |
| `validity` | Yes | - | |
| `serialNumber` | No | - | Auto (random) |
| `issuer` | No | - | Auto (CA DN) |
| `keyUsage` | Yes | Configurable (default: critical) | |
| `extKeyUsage` | Yes | Configurable (default: non-critical) | |
| `basicConstraints` | Yes | Configurable (default: critical) | |
| `subjectKeyIdentifier` | No | - | Auto (hash of public key) |
| `authorityKeyIdentifier` | No | - | Auto (CA's SKI) |
| `crlDistributionPoints` | Yes | Configurable | |
| `authorityInfoAccess` | Yes | Configurable | |
| `certificatePolicies` | Yes | Configurable | |
| `nameConstraints` | Yes (CA) | Configurable (default: critical) | |

### Key Usage Values

| Value | Description |
|-------|-------------|
| `digitalSignature` | Verify digital signatures |
| `keyEncipherment` | Encrypt keys (RSA key transport) |
| `dataEncipherment` | Encrypt data directly |
| `keyAgreement` | Key agreement (ECDH) |
| `keyCertSign` | Sign certificates (CA only) |
| `crlSign` | Sign CRLs (CA only) |
| `encipherOnly` | Only encipher during key agreement |
| `decipherOnly` | Only decipher during key agreement |

### Extended Key Usage Values

| Value | Description | OID |
|-------|-------------|-----|
| `serverAuth` | TLS server authentication | 1.3.6.1.5.5.7.3.1 |
| `clientAuth` | TLS client authentication | 1.3.6.1.5.5.7.3.2 |
| `codeSigning` | Code signing | 1.3.6.1.5.5.7.3.3 |
| `emailProtection` | S/MIME email | 1.3.6.1.5.5.7.3.4 |
| `timeStamping` | Trusted timestamping | 1.3.6.1.5.5.7.3.8 |
| `ocspSigning` | OCSP responder signing | 1.3.6.1.5.5.7.3.9 |

### RFC 5280 Criticality Defaults

If `critical` is not specified, these RFC 5280 defaults are used:

| Extension | Default Critical |
|-----------|:----------------:|
| `keyUsage` | **true** |
| `basicConstraints` | **true** |
| `nameConstraints` | **true** |
| `extKeyUsage` | false |
| `crlDistributionPoints` | false |
| `authorityInfoAccess` | false |
| `certificatePolicies` | false |
| `subjectAltName` | false (true if subject empty) |

## CRL Profile

CRL generation also supports configurable profiles:

```yaml
name: default-crl
description: "Default CRL profile"

validity: 7d

extensions:
  issuingDistributionPoint:
    critical: true
    fullName: "http://pki.example.com/crl/ca.crl"
```

### CRL Fields Reference

| Field | Configurable | Auto |
|-------|:------------:|:----:|
| `validity` | Yes | |
| `issuer` | No | Auto (CA DN) |
| `thisUpdate` | No | Auto (now) |
| `nextUpdate` | No | Auto (now + validity) |
| `crlNumber` | No | Auto (incremented) |
| `authorityKeyIdentifier` | No | Auto (CA's SKI) |
| `issuingDistributionPoint` | Yes | |
| `deltaCRLIndicator` | Yes (delta CRL) | |
| `signature` | No | Auto (CA's algorithm) |

## Supported Algorithms

### Signature Algorithms

| ID | Algorithm | Type | Security Level |
|----|-----------|------|----------------|
| `ecdsa-p256` | ECDSA with P-256 | Classical | ~128-bit |
| `ecdsa-p384` | ECDSA with P-384 | Classical | ~192-bit |
| `ecdsa-p521` | ECDSA with P-521 | Classical | ~256-bit |
| `ed25519` | Ed25519 | Classical | ~128-bit |
| `rsa-2048` | RSA 2048-bit | Classical | ~112-bit |
| `rsa-4096` | RSA 4096-bit | Classical | ~140-bit |
| `ml-dsa-44` | ML-DSA-44 | PQC | NIST Level 1 |
| `ml-dsa-65` | ML-DSA-65 | PQC | NIST Level 3 |
| `ml-dsa-87` | ML-DSA-87 | PQC | NIST Level 5 |
| `slh-dsa-128f` | SLH-DSA-128f | PQC | NIST Level 1 |
| `slh-dsa-192f` | SLH-DSA-192f | PQC | NIST Level 3 |
| `slh-dsa-256f` | SLH-DSA-256f | PQC | NIST Level 5 |

### KEM Algorithms (Encryption)

| ID | Algorithm | Type | Security Level |
|----|-----------|------|----------------|
| `ml-kem-512` | ML-KEM-512 | PQC | NIST Level 1 |
| `ml-kem-768` | ML-KEM-768 | PQC | NIST Level 3 |
| `ml-kem-1024` | ML-KEM-1024 | PQC | NIST Level 5 |

## Usage Examples

### Enroll with a Gamme

```bash
# Enroll using the hybrid-full gamme
pki enroll --subject "CN=Alice,O=Acme" --gamme hybrid-full --out ./alice

# This creates:
# ./alice/bundles/<bundle-id>/
#   bundle.json
#   certificates.pem
#   private-keys.pem
```

### Recommended Gammes by Use Case

| Use Case | Recommended Gamme | Rationale |
|----------|------------------|-----------|
| Maximum compatibility | `classic` | Works with all systems |
| Future-proof | `hybrid-catalyst` | Classical + PQC in one cert |
| Maximum security | `hybrid-full` | Signature + encryption, both hybrid |
| IoT/constrained | `pqc-basic` | Lightweight PQC only |
| High-security env | `hybrid-separate` | Separate key lifecycles |

## CA Directory Structure

After installing gammes:

```
ca/
├── ca.crt
├── private/ca.key
├── gammes/
│   ├── classic.yaml
│   ├── pqc-basic.yaml
│   ├── pqc-full.yaml
│   ├── hybrid-catalyst.yaml
│   ├── hybrid-separate.yaml
│   └── hybrid-full.yaml
├── bundles/
│   └── <bundle-id>/
│       ├── bundle.json
│       ├── certificates.pem
│       └── private-keys.pem
└── ...
```

## See Also

- [BUNDLES.md](BUNDLES.md) - Certificate bundle management
- [CATALYST.md](CATALYST.md) - Catalyst certificate details
- [PQC.md](PQC.md) - Post-quantum cryptography overview
