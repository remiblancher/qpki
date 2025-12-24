# Profiles (Certificate Policy Templates)

Profiles define certificate enrollment policies that specify which algorithms to use when issuing certificates.

## Design Principle: 1 Profile = 1 Certificate

Each profile produces exactly **one certificate**. To create multiple certificates (e.g., signature + encryption), use multiple profiles.

## Overview

A **profile** is a policy template stored as a YAML file that determines:

- **Algorithm**: The cryptographic algorithm for this certificate
- **Mode**: How multiple algorithms are combined (simple, catalyst, composite)
- **Validity period**: How long the certificate remains valid
- **Extensions**: X.509 extensions configuration

Profiles are organized by category and stored in `profiles/`:
- `ec/` - ECDSA-based profiles (modern classical)
- `rsa/` - RSA-based profiles (legacy compatibility)
- `rsa-pss/` - RSA-PSS profiles
- `ml-dsa-kem/` - ML-DSA and ML-KEM profiles (post-quantum)
- `slh-dsa/` - SLH-DSA profiles (hash-based post-quantum)
- `hybrid/catalyst/` - Catalyst hybrid profiles (ITU-T X.509 Section 9.8)
- `hybrid/composite/` - IETF composite hybrid profiles

## Profile Modes

| Mode | Description | Algorithm(s) |
|------|-------------|--------------|
| `simple` | Single algorithm | 1 |
| `catalyst` | Dual-key certificate (ITU-T X.509 9.8) | 2 |
| `composite` | IETF composite signature format | 2 |

### Simple Mode

Standard X.509 certificate with a single algorithm:

```yaml
name: ec/tls-server
description: "TLS server ECDSA P-256"

algorithm: ecdsa-p256
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

### Catalyst Mode (ITU-T X.509 Section 9.8)

A single certificate containing both classical and PQC public keys:

```yaml
name: hybrid/catalyst/tls-server
description: "TLS server hybrid ECDSA P-256 + ML-DSA-65"

mode: catalyst
algorithms:
  - ecdsa-p256           # Classical algorithm (first)
  - ml-dsa-65            # PQC algorithm (second)
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

### Composite Mode (IETF Format)

IETF composite signature where both signatures are combined and must validate:

```yaml
name: hybrid/composite/tls-server
description: "TLS server hybrid composite ECDSA P-256 + ML-DSA-65"

mode: composite
algorithms:
  - ecdsa-p256           # Classical algorithm (first)
  - ml-dsa-65            # PQC algorithm (second)
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

## Builtin Profiles

### EC (ECDSA - Modern Classical)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `ec/root-ca` | ECDSA P-384 | Root CA |
| `ec/issuing-ca` | ECDSA P-256 | Intermediate CA |
| `ec/tls-server` | ECDSA P-256 | TLS server |
| `ec/tls-client` | ECDSA P-256 | TLS client |
| `ec/email` | ECDSA P-256 | S/MIME email |
| `ec/code-signing` | ECDSA P-256 | Code signing |
| `ec/timestamping` | ECDSA P-256 | RFC 3161 TSA |
| `ec/ocsp-responder` | ECDSA P-384 | OCSP responder |

### RSA (Legacy Compatibility)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `rsa/root-ca` | RSA 4096 | Root CA |
| `rsa/issuing-ca` | RSA 4096 | Intermediate CA |
| `rsa/tls-server` | RSA 2048 | TLS server |
| `rsa/tls-client` | RSA 2048 | TLS client |
| `rsa/email` | RSA 2048 | S/MIME email |
| `rsa/code-signing` | RSA 2048 | Code signing |
| `rsa/timestamping` | RSA 2048 | RFC 3161 TSA |

### ML-DSA-KEM (Post-Quantum)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `ml-dsa-kem/root-ca` | ML-DSA-87 | Root CA |
| `ml-dsa-kem/issuing-ca` | ML-DSA-65 | Intermediate CA |
| `ml-dsa-kem/tls-server-sign` | ML-DSA-65 | TLS server signature |
| `ml-dsa-kem/tls-server-encrypt` | ML-KEM-768 | TLS server encryption |
| `ml-dsa-kem/tls-client` | ML-DSA-65 | TLS client |
| `ml-dsa-kem/email-sign` | ML-DSA-65 | S/MIME signature |
| `ml-dsa-kem/email-encrypt` | ML-KEM-768 | S/MIME encryption |
| `ml-dsa-kem/code-signing` | ML-DSA-65 | Code signing |
| `ml-dsa-kem/timestamping` | ML-DSA-65 | RFC 3161 TSA |
| `ml-dsa-kem/ocsp-responder` | ML-DSA-65 | OCSP responder |

### SLH-DSA (Hash-Based Post-Quantum)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `slh-dsa/root-ca` | SLH-DSA-256f | Root CA |
| `slh-dsa/issuing-ca` | SLH-DSA-192f | Intermediate CA |
| `slh-dsa/tls-server` | SLH-DSA-128f | TLS server |
| `slh-dsa/tls-client` | SLH-DSA-128f | TLS client |
| `slh-dsa/timestamping` | SLH-DSA-256s | RFC 3161 TSA |

### Hybrid Catalyst (ITU-T X.509 Section 9.8)

| Name | Algorithms | Use Case |
|------|------------|----------|
| `hybrid/catalyst/root-ca` | ECDSA P-384 + ML-DSA-87 | Root CA |
| `hybrid/catalyst/issuing-ca` | ECDSA P-256 + ML-DSA-65 | Intermediate CA |
| `hybrid/catalyst/tls-server` | ECDSA P-256 + ML-DSA-65 | TLS server |
| `hybrid/catalyst/tls-client` | ECDSA P-256 + ML-DSA-65 | TLS client |
| `hybrid/catalyst/timestamping` | ECDSA P-384 + ML-DSA-65 | RFC 3161 TSA |
| `hybrid/catalyst/ocsp-responder` | ECDSA P-384 + ML-DSA-65 | OCSP responder |

### Hybrid Composite (IETF Format)

| Name | Algorithms | Use Case |
|------|------------|----------|
| `hybrid/composite/root-ca` | ECDSA P-384 + ML-DSA-87 | Root CA |
| `hybrid/composite/issuing-ca` | ECDSA P-256 + ML-DSA-65 | Intermediate CA |
| `hybrid/composite/tls-server` | ECDSA P-256 + ML-DSA-65 | TLS server |
| `hybrid/composite/tls-client` | ECDSA P-256 + ML-DSA-65 | TLS client |
| `hybrid/composite/timestamping` | ECDSA P-384 + ML-DSA-65 | RFC 3161 TSA |

## CLI Commands

### List Available Profiles

```bash
pki profile list
```

### View Profile Details

```bash
pki profile info hybrid/catalyst/tls-server
```

### Show Profile YAML

```bash
pki profile show ec/root-ca
```

### Export Profile for Customization

```bash
# Export single profile
pki profile export ec/tls-server ./my-tls-server.yaml

# Export all profiles to a directory
pki profile export --all ./templates/
```

### Validate a Custom Profile

```bash
pki profile validate my-profile.yaml
```

## Creating Custom Profiles

Export a builtin profile, modify it, and use it:

```bash
# Export a template
pki profile export ec/tls-server ./my-custom.yaml

# Edit the file
vim ./my-custom.yaml

# Use the custom profile
pki issue --profile ./my-custom.yaml --cn server.example.com
```

### Simple Profile Example

```yaml
# my-custom.yaml
name: my-custom-server
description: "Custom policy for internal servers"

algorithm: ecdsa-p384
validity: 180d

extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
  extKeyUsage:
    critical: false
    values:
      - serverAuth
  basicConstraints:
    critical: true
    ca: false
```

### Catalyst Profile Example

```yaml
# my-catalyst.yaml
name: my-catalyst-server
description: "Hybrid server with classical + PQC"

mode: catalyst
algorithms:
  - ecdsa-p384
  - ml-dsa-87
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

## YAML Schema

```yaml
name: string              # Unique identifier (category/name format)
description: string       # Human-readable description

# Simple profile (single algorithm)
algorithm: string         # e.g., ecdsa-p256, rsa-4096, ml-dsa-65

# Hybrid profile (two algorithms)
mode: string              # catalyst | composite
algorithms:               # List of algorithm IDs
  - ecdsa-p256            # Classical algorithm (first)
  - ml-dsa-65             # PQC algorithm (second)

validity: duration        # Duration format (e.g., 365d, 8760h, 1y)

subject:                  # Optional subject DN configuration
  fixed:                  # Fixed attributes
    c: "FR"
    o: "ACME Corp"
  required:               # Required from user
    - cn
  optional:               # Optional from user
    - email

extensions:               # X.509 extensions (see below)
  keyUsage: ...
  extKeyUsage: ...
  basicConstraints: ...
```

## X.509 Extensions

### Extensions Configuration

```yaml
extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
      - keyEncipherment

  extKeyUsage:
    critical: false
    values:
      - serverAuth
      - clientAuth

  basicConstraints:
    critical: true
    ca: false

  crlDistributionPoints:
    urls:
      - "http://pki.example.com/crl/ca.crl"

  authorityInfoAccess:
    ocsp:
      - "http://ocsp.example.com"
    caIssuers:
      - "http://pki.example.com/ca.crt"

  certificatePolicies:
    policies:
      - oid: "2.23.140.1.2.1"
        cps: "http://example.com/cps"

  subjectAltName:
    dns:
      - "${DNS}"
    email:
      - "${EMAIL}"
```

### Key Usage Values

| Value | Description |
|-------|-------------|
| `digitalSignature` | Verify digital signatures |
| `keyEncipherment` | Encrypt keys (RSA key transport) |
| `dataEncipherment` | Encrypt data directly |
| `keyAgreement` | Key agreement (ECDH) |
| `keyCertSign` | Sign certificates (CA only) |
| `crlSign` | Sign CRLs (CA only) |

### Extended Key Usage Values

| Value | Description | OID |
|-------|-------------|-----|
| `serverAuth` | TLS server authentication | 1.3.6.1.5.5.7.3.1 |
| `clientAuth` | TLS client authentication | 1.3.6.1.5.5.7.3.2 |
| `codeSigning` | Code signing | 1.3.6.1.5.5.7.3.3 |
| `emailProtection` | S/MIME email | 1.3.6.1.5.5.7.3.4 |
| `timeStamping` | Trusted timestamping | 1.3.6.1.5.5.7.3.8 |
| `ocspSigning` | OCSP responder signing | 1.3.6.1.5.5.7.3.9 |

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
| `slh-dsa-256s` | SLH-DSA-256s | PQC | NIST Level 5 |

### KEM Algorithms (Encryption)

| ID | Algorithm | Type | Security Level |
|----|-----------|------|----------------|
| `ml-kem-512` | ML-KEM-512 | PQC | NIST Level 1 |
| `ml-kem-768` | ML-KEM-768 | PQC | NIST Level 3 |
| `ml-kem-1024` | ML-KEM-1024 | PQC | NIST Level 5 |

## Usage Examples

### Issue with a Profile

```bash
# Issue using an ECDSA profile
pki issue --profile ec/tls-server --cn server.example.com --dns server.example.com

# Issue using a hybrid profile
pki issue --profile hybrid/catalyst/tls-server --cn server.example.com

# Issue using a PQC profile
pki issue --profile ml-dsa-kem/tls-server-sign --cn server.example.com
```

### Recommended Profiles by Use Case

| Use Case | Recommended Profile | Rationale |
|----------|---------------------|-----------|
| Maximum compatibility | `ec/tls-server` | Works with all modern systems |
| Legacy compatibility | `rsa/tls-server` | Works with older systems |
| Quantum transition | `hybrid/catalyst/tls-server` | Classical + PQC in one cert |
| Full post-quantum | `ml-dsa-kem/tls-server-sign` | Pure PQC signature |
| Long-term archive | `slh-dsa/timestamping` | Conservative hash-based |

## See Also

- [BUNDLES.md](BUNDLES.md) - Certificate bundle management
- [CATALYST.md](CATALYST.md) - Catalyst certificate details
- [PQC.md](PQC.md) - Post-quantum cryptography overview
