# Profiles (Certificate Policy Templates)

Profiles define certificate enrollment policies that specify which algorithms, signature modes, and encryption requirements to use when issuing certificates.

## Overview

A **profile** is a policy template stored as a YAML file that determines:

- **Signature requirements**: Algorithm(s) and hybrid mode
- **Encryption requirements**: Whether encryption certificates are needed and which algorithms
- **Validity period**: How long certificates remain valid
- **Certificate count**: How many certificates are generated per enrollment

Profiles are organized by category and stored in `internal/profile/builtin/`:
- `rsa/` - RSA-based profiles (legacy compatibility)
- `ecdsa/` - ECDSA-based profiles (modern classical)
- `hybrid/catalyst/` - Catalyst hybrid profiles (combined signatures)
- `hybrid/composite/` - IETF composite hybrid profiles
- `pqc/` - Full post-quantum profiles

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
  algorithms:
    - ec-p256
```

### Hybrid Combined (Catalyst)

A single certificate containing both classical and PQC public keys, following ITU-T X.509 Section 9.8. The certificate is signed by both CA keys.

```yaml
signature:
  mode: catalyst           # or "composite"
  algorithms:
    - ec-p256              # Classical algorithm (first)
    - ml-dsa-65            # PQC algorithm (second)
```

### Hybrid Separate

Two separate certificates linked via the `RelatedCertificate` extension:

```yaml
signature:
  mode: separate           # Separate certificates
  algorithms:
    - ec-p256              # First certificate
    - ml-dsa-65            # Second certificate (linked)
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
  algorithms:
    - ml-kem-768
```

For hybrid encryption:

```yaml
encryption:
  mode: catalyst           # or "composite"
  algorithms:
    - ec-p256              # Classical KEM (first)
    - ml-kem-768           # PQC KEM (second)
```

## Builtin Profiles

Profiles are organized by cryptographic category:

### RSA (Legacy Compatibility)

| Name | Signature | Encryption | Use Case |
|------|-----------|------------|----------|
| `rsa/root-ca` | RSA 4096 | None | Root CA |
| `rsa/issuing-ca` | RSA 4096 | None | Intermediate CA |
| `rsa/tls-server` | RSA 2048 | None | TLS server |
| `rsa/tls-client` | RSA 2048 | None | TLS client |

### ECDSA (Modern Classical)

| Name | Signature | Encryption | Use Case |
|------|-----------|------------|----------|
| `ecdsa/root-ca` | ECDSA P-384 | None | Root CA |
| `ecdsa/issuing-ca` | ECDSA P-256 | None | Intermediate CA |
| `ecdsa/tls-server` | ECDSA P-256 | None | TLS server |
| `ecdsa/tls-client` | ECDSA P-256 | None | TLS client |

### Hybrid Catalyst (Combined Signatures)

| Name | Signature | Encryption | Use Case |
|------|-----------|------------|----------|
| `hybrid/catalyst/root-ca` | ECDSA P-384 + ML-DSA-87 | None | Root CA |
| `hybrid/catalyst/issuing-ca` | ECDSA P-256 + ML-DSA-65 | None | Intermediate CA |
| `hybrid/catalyst/tls-server` | ECDSA P-256 + ML-DSA-65 | None | TLS server |
| `hybrid/catalyst/tls-client` | ECDSA P-256 + ML-DSA-44 | None | TLS client |

### Hybrid Composite (IETF Format)

| Name | Signature | Encryption | Use Case |
|------|-----------|------------|----------|
| `hybrid/composite/root-ca` | ECDSA P-384 + ML-DSA-87 | None | Root CA |
| `hybrid/composite/issuing-ca` | ECDSA P-256 + ML-DSA-65 | None | Intermediate CA |
| `hybrid/composite/tls-server` | ECDSA P-256 + ML-DSA-65 | None | TLS server |
| `hybrid/composite/tls-client` | ECDSA P-256 + ML-DSA-44 | None | TLS client |

### PQC (Full Post-Quantum)

| Name | Signature | Encryption | Use Case |
|------|-----------|------------|----------|
| `pqc/root-ca` | ML-DSA-87 | None | Root CA |
| `pqc/issuing-ca` | ML-DSA-65 | None | Intermediate CA |
| `pqc/tls-server` | ML-DSA-65 | ML-KEM-768 | TLS server |
| `pqc/tls-client` | ML-DSA-44 | ML-KEM-768 | TLS client |

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
pki profile show ecdsa/root-ca
```

### Export Profile for Customization

```bash
# Export single profile
pki profile export ecdsa/tls-server ./my-tls-server.yaml

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
pki profile export ecdsa/tls-server ./my-custom.yaml

# Edit the file
vim ./my-custom.yaml

# Use the custom profile
pki enroll --subject "CN=server.example.com" --profile ./my-custom.yaml
```

### Custom Profile Example

```yaml
# my-custom.yaml
name: my-custom-server
description: "Custom policy for internal servers"

signature:
  mode: catalyst
  algorithms:
    - ec-p384
    - ml-dsa-87

encryption:
  algorithms:
    - ml-kem-1024

validity: 180d  # 6 months

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
  basicConstraints:
    critical: true
    ca: false
```

## YAML Schema

```yaml
name: string              # Unique identifier (category/name format)
description: string       # Human-readable description

# Simple signature (single algorithm)
signature:
  algorithms:             # List of algorithm IDs
    - ec-p256             # e.g., ec-p256, rsa-4096, ml-dsa-65
  algo_config:            # Optional - list of configs (by index)
    - scheme: string      # ecdsa | rsassa-pss | pkcs1v15 | ed25519 | ed25519ph
      hash: string        # sha256 | sha384 | sha512 | sha3-256 | sha3-384 | sha3-512
      pss:                # RSA-PSS only
        salt_length: int  # -1 = hash length (recommended)
        mgf: string       # MGF1 hash (defaults to signature hash)

# Hybrid signature (two algorithms)
signature:
  mode: string            # catalyst | composite | separate
  algorithms:
    - ec-p256             # First algorithm (classical)
    - ml-dsa-65           # Second algorithm (PQC)
  algo_config:            # Optional - list of configs
    - scheme: ecdsa       # [0] for first algorithm
      hash: sha256
    - scheme: ...         # [1] for second algorithm (if needed)

# Simple encryption (single algorithm)
encryption:
  algorithms:
    - ml-kem-768          # Algorithm ID

# Hybrid encryption (two algorithms)
encryption:
  mode: string            # catalyst | composite | separate
  algorithms:
    - ec-p256             # First algorithm (classical KEM)
    - ml-kem-768          # Second algorithm (PQC KEM)

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

Profiles can optionally define X.509 extensions with explicit criticality.
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

## Signature Algorithm Configuration

By default, signature algorithms are inferred from the key type:
- EC P-256 → ECDSA with SHA-256
- EC P-384 → ECDSA with SHA-384
- RSA → RSA PKCS#1 v1.5 with SHA-256 (legacy default)

For explicit control over hash algorithms and signature schemes, use `algo_config`:

### Quick Reference

| Key Type | Default Scheme | Default Hash | Recommended |
|----------|----------------|--------------|-------------|
| `ec-p256` | `ecdsa` | `sha256` | ✓ |
| `ec-p384` | `ecdsa` | `sha384` | ✓ |
| `ec-p521` | `ecdsa` | `sha512` | ✓ |
| `rsa-*` | `rsassa-pss` | `sha256` | ✓ |
| `ed25519` | `ed25519` | (none) | ✓ |
| `ml-dsa-*` | (integrated) | SHAKE256 | ✓ |
| `slh-dsa-*` | (integrated) | (in name) | ✓ |

### Signature Schemes

| Scheme | Description | Parameters |
|--------|-------------|------------|
| `ecdsa` | ECDSA standard | hash |
| `pkcs1v15` | RSA PKCS#1 v1.5 (legacy) | hash |
| `rsassa-pss` | RSA-PSS (recommended) | hash, salt_length, mgf |
| `ed25519` | Pure EdDSA | (none) |
| `ed25519ph` | Pre-hashed EdDSA | hash |

### Hash Algorithms

| ID | Algorithm | Size (bits) |
|----|-----------|-------------|
| `sha256` | SHA-256 | 256 |
| `sha384` | SHA-384 | 384 |
| `sha512` | SHA-512 | 512 |
| `sha3-256` | SHA3-256 | 256 |
| `sha3-384` | SHA3-384 | 384 |
| `sha3-512` | SHA3-512 | 512 |

### Example: RSA-PSS with Explicit Configuration

RSA-PSS is the recommended signature scheme for RSA keys (more secure than PKCS#1 v1.5):

```yaml
signature:
  algorithms:
    - rsa-4096
  algo_config:
    - scheme: rsassa-pss      # Use RSA-PSS instead of PKCS#1 v1.5
      hash: sha256
      pss:
        salt_length: -1       # -1 = hash length (recommended)
        # mgf: sha256         # MGF1 hash (default = same as signature hash)
```

### Example: ECDSA with SHA3

For modern deployments preferring SHA-3:

```yaml
signature:
  algorithms:
    - ec-p384
  algo_config:
    - scheme: ecdsa
      hash: sha3-384          # SHA3 instead of SHA2
```

### Example: Legacy RSA PKCS#1 v1.5

For compatibility with legacy systems:

```yaml
signature:
  algorithms:
    - rsa-2048
  algo_config:
    - scheme: pkcs1v15        # Legacy scheme (warning will be shown)
      hash: sha256
```

### RSA-PSS Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `salt_length` | `-1`, `0`, or positive int | Salt length in bytes. `-1` = hash length (recommended), `0` = auto |
| `mgf` | Hash algorithm | Mask Generation Function hash. Defaults to same as signature hash |

### Validation Warnings

Non-standard combinations are allowed but generate warnings:

- `ec-p384` with `sha256` → "non-standard combination: ec-p384 with sha256 (expected sha384)"
- `pkcs1v15` → "pkcs1v15 is legacy; consider rsassa-pss for new deployments"
- `ed25519ph` → "ed25519ph (pre-hashed) is rarely needed; consider pure ed25519"

### PQC Algorithms

PQC algorithms (ML-DSA, SLH-DSA) have integrated hash functions and don't need `algo_config`:

```yaml
signature:
  algorithms:
    - ml-dsa-87               # Uses SHAKE256 internally
```

## Usage Examples

### Enroll with a Profile

```bash
# Enroll using an ECDSA profile
pki enroll --subject "CN=Alice,O=Acme" --profile ecdsa/tls-client --out ./alice

# Enroll using a hybrid profile
pki enroll --subject "CN=server.example.com" --profile hybrid/catalyst/tls-server --out ./server

# Enroll using a PQC profile
pki enroll --subject "CN=Alice" --profile pqc/tls-client --out ./alice-pqc
```

### Recommended Profiles by Use Case

| Use Case | Recommended Profile | Rationale |
|----------|---------------------|-----------|
| Maximum compatibility | `ecdsa/tls-server` | Works with all modern systems |
| Legacy compatibility | `rsa/tls-server` | Works with older systems |
| Future-proof | `hybrid/catalyst/tls-server` | Classical + PQC in one cert |
| Maximum security | `pqc/tls-server` | Full post-quantum |
| IoT/constrained | `pqc/tls-client` | Lightweight PQC only |

## See Also

- [BUNDLES.md](BUNDLES.md) - Certificate bundle management
- [CATALYST.md](CATALYST.md) - Catalyst certificate details
- [PQC.md](PQC.md) - Post-quantum cryptography overview
