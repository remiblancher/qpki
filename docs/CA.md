# CA & Certificate Management

## Table of Contents

- [1. What is a CA?](#1-what-is-a-ca)
- [2. CLI Reference](#2-cli-reference)
- [3. Common Workflows](#3-common-workflows)
- [4. FAQ](#4-faq)
- [See Also](#see-also)

---

This guide covers Certificate Authority operations, certificate issuance, and CRL management.

> **Related documentation:**
> - [CREDENTIALS.md](CREDENTIALS.md) - Credential lifecycle (enroll, rotate, revoke)
> - [KEYS.md](KEYS.md) - Key generation and CSR operations
> - [CLI-REFERENCE.md](CLI-REFERENCE.md) - Complete command reference

## 1. What is a CA?

A **Certificate Authority (CA)** is the trust anchor that signs certificates. QPKI supports root CAs (self-signed) and subordinate CAs (signed by a parent).

### 1.1 CA Structure

```
ca/
├── ca.meta.json           # CA metadata (versions, keys, status)
├── index.txt              # OpenSSL-compatible certificate index
├── serial                 # Current serial number (hex)
├── crlnumber              # Current CRL number
├── certs/                 # Issued certificates
│   ├── 02.crt
│   └── 03.crt
├── crl/                   # Certificate Revocation Lists
│   ├── ca.crl             # PEM format
│   └── ca.crl.der         # DER format
└── versions/              # CA versions (after rotation)
    └── v1/
        ├── keys/
        │   └── ca.ecdsa-p256.key
        └── certs/
            └── ca.ecdsa-p256.pem
```

### 1.2 Versioned CA

After rotation, CAs have multiple versions with status tracking:

```
ca/
├── ca.meta.json           # Points to active version
└── versions/
    ├── v1/                # archived
    │   ├── keys/ca.ecdsa-p256.key
    │   └── certs/ca.ecdsa-p256.pem
    ├── v2/                # active (hybrid)
    │   ├── keys/
    │   │   ├── ca.ecdsa-p256.key
    │   │   └── ca.ml-dsa-65.key
    │   └── certs/
    │       ├── ca.ecdsa-p256.pem
    │       └── ca.ml-dsa-65.pem
    └── v3/                # pending
        └── ...
```

| Status | Description |
|--------|-------------|
| `pending` | Awaiting activation after rotation |
| `active` | Currently in use for signing |
| `archived` | Superseded by newer version |

### 1.3 CA Types

| Type | Description |
|------|-------------|
| Root CA | Self-signed, trust anchor |
| Subordinate CA | Signed by parent, issues end-entity certs |
| Multi-profile CA | Multiple algorithms (crypto-agility) |
| Hybrid CA | Classical + PQC (Catalyst or Composite) |

---

## 2. CLI Reference

### ca init

Initialize a new Certificate Authority.

```bash
qpki ca init [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | "" | CA profile (repeatable for multi-profile CA) |
| `--var` | | [] | Variable value (key=value, repeatable) |
| `--var-file` | | "" | YAML file with variable values |
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--passphrase` | `-p` | "" | Key passphrase |
| `--parent` | | "" | Parent CA directory (creates subordinate CA) |
| `--parent-passphrase` | | "" | Parent CA key passphrase |

> **Note:** Multi-profile subordinate CA is not yet supported. Use a single `--profile` for subordinate CAs.

**Examples:**

```bash
# Using a profile (recommended)
qpki ca init --profile ec/root-ca --ca-dir ./myca --var cn="My Root CA"

# Multi-profile CA (crypto agility)
qpki ca init --profile ec/root-ca --profile ml/root-ca --ca-dir ./multi-ca --var cn="Multi-Algo Root CA"

# Hybrid Catalyst CA (ITU-T - backward compatible)
qpki ca init --profile hybrid/catalyst/root-ca --ca-dir ./catalyst-ca --var cn="Catalyst Root CA"

# Hybrid Composite CA (IETF draft - stricter security)
qpki ca init --profile hybrid/composite/root-ca --ca-dir ./composite-ca --var cn="Composite Root CA"

# Subordinate CA using a profile
qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./rootca --var cn="Issuing CA"

# CA with passphrase-protected key
qpki ca init --profile ec/root-ca --passphrase "mysecret" --ca-dir ./secure-ca --var cn="Secure CA"

# PQC root CA with ML-DSA
qpki ca init --profile ml/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"

# Using a variables file
qpki ca init --profile ec/root-ca --ca-dir ./myca --var-file ca-vars.yaml
```

**Available CA profiles:**

| Profile | Algorithm | Validity | Description |
|---------|-----------|----------|-------------|
| `ec/root-ca` | EC P-384 | 20 years | Root CA with pathLen=1 |
| `ec/issuing-ca` | EC P-256 | 10 years | Issuing CA with pathLen=0 |
| `hybrid/catalyst/root-ca` | EC P-384 + ML-DSA-87 | 20 years | Hybrid root CA (ITU-T extensions) |
| `hybrid/catalyst/issuing-ca` | EC P-384 + ML-DSA-65 | 10 years | Hybrid issuing CA (ITU-T) |
| `hybrid/composite/root-ca` | EC P-384 + ML-DSA-87 | 20 years | Composite root CA (IETF draft) |
| `hybrid/composite/issuing-ca` | EC P-256 + ML-DSA-65 | 10 years | Composite issuing CA (IETF) |
| `rsa/root-ca` | RSA 4096 | 20 years | RSA root CA |
| `ml/root-ca` | ML-DSA-87 | 20 years | Pure PQC root CA |

### ca info

Display information about a Certificate Authority.

```bash
qpki ca info [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki ca info --ca-dir ./myca
```

### ca export

Export CA certificates.

```bash
qpki ca export [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--bundle` | `-b` | ca | Bundle type: ca, chain, root |
| `--out` | `-o` | stdout | Output file |

**Examples:**

```bash
# Export CA certificate
qpki ca export --ca-dir ./myca --out ca.crt

# Export full chain (CA + parent)
qpki ca export --ca-dir ./issuing-ca --bundle chain --out chain.pem

# Export root certificate only
qpki ca export --ca-dir ./issuing-ca --bundle root --out root.crt
```

### ca list

List Certificate Authorities in a directory.

```bash
qpki ca list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | . | Directory to scan |

**Example:**

```bash
qpki ca list --dir /var/lib/pki
```

### ca rotate

Rotate a CA with new keys and algorithm.

```bash
qpki ca rotate [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--profile` | `-P` | | New profile for rotation (repeatable for multi-profile) |
| `--passphrase` | `-p` | "" | Passphrase for new key |
| `--cross-sign` | | auto | Cross-sign strategy: auto, on, off |
| `--dry-run` | | false | Preview rotation plan without executing |

**Examples:**

```bash
# Preview rotation plan (dry-run)
qpki ca rotate --ca-dir ./myca --dry-run

# Rotate to a new profile (crypto migration)
qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

# Multi-profile rotation (crypto agility)
qpki ca rotate --ca-dir ./myca --profile ec/root-ca --profile ml/root-ca

# Rotate with explicit cross-signing
qpki ca rotate --ca-dir ./myca --profile ml/root-ca --cross-sign on
```

### ca activate

Activate a pending CA version after rotation.

```bash
qpki ca activate [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--version` | `-v` | | Version to activate |

**Example:**

```bash
qpki ca activate --ca-dir ./myca --version 2
```

### ca versions

List all versions of a CA.

```bash
qpki ca versions [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki ca versions --ca-dir ./myca
```

### cert issue

Issue a certificate from a Certificate Signing Request (CSR).

```bash
qpki cert issue [flags]
```

**Note:** This command requires a CSR file (`--csr`). For direct issuance with automatic key generation, use `qpki credential enroll` instead. See [CREDENTIALS.md](CREDENTIALS.md).

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--profile` | `-P` | required | Certificate profile (e.g., ec/tls-server) |
| `--csr` | | required | CSR file |
| `--cn` | | "" | Override common name from CSR |
| `--dns` | | "" | DNS SANs (comma-separated) |
| `--ip` | | "" | IP SANs (comma-separated) |
| `--out` | `-o` | "" | Output certificate file |
| `--days` | | 0 | Validity period (overrides profile default) |
| `--hybrid` | | "" | PQC algorithm for hybrid extension |
| `--attest-cert` | | "" | Attestation cert for ML-KEM CSR (RFC 9883) |
| `--ca-passphrase` | | "" | CA key passphrase |

**Examples:**

```bash
# From classical CSR (ECDSA, RSA)
qpki cert issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --out server.crt

# From PQC signature CSR (ML-DSA, SLH-DSA)
qpki cert issue --ca-dir ./myca --profile ml/tls-server-sign \
  --csr mldsa.csr --out server.crt

# From ML-KEM CSR with RFC 9883 attestation
qpki cert issue --ca-dir ./myca --profile ml-kem/client \
  --csr kem.csr --attest-cert sign.crt --out kem.crt

# From hybrid CSR (classical + PQC dual signatures)
qpki cert issue --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --csr hybrid.csr --out server.crt
```

### cert list

List certificates in a CA.

```bash
qpki cert list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--status` | | all | Filter by status (valid, revoked, expired, all) |

**Examples:**

```bash
# List all certificates
qpki cert list --ca-dir ./myca

# List only valid certificates
qpki cert list --ca-dir ./myca --status valid

# List revoked certificates
qpki cert list --ca-dir ./myca --status revoked
```

### cert info

Display information about a certificate.

```bash
qpki cert info <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki cert info 0x03 --ca-dir ./myca
```

### inspect

Display information about certificates or keys.

```bash
qpki inspect <file> [flags]
```

**Examples:**

```bash
# Show certificate details
qpki inspect certificate.crt

# Show key information
qpki inspect private.key

# Show CA certificate
qpki inspect ./myca/ca.crt
```

### cert verify

Verify a certificate's validity and revocation status.

```bash
qpki cert verify <certificate> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca` | | required | CA certificate (PEM) |
| `--crl` | | | CRL file for revocation check (PEM/DER) |
| `--ocsp` | | | OCSP responder URL |

**Checks performed:**
- Certificate signature (signed by CA)
- Validity period (not before / not after)
- Critical extensions
- Revocation status (if --crl or --ocsp provided)

**Examples:**

```bash
# Basic validation
qpki cert verify server.crt --ca ca.crt

# With CRL check
qpki cert verify server.crt --ca ca.crt --crl ca/crl/ca.crl

# With OCSP check
qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

### cert revoke

Revoke a certificate.

```bash
qpki cert revoke <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--reason` | `-r` | unspecified | Revocation reason |
| `--gen-crl` | | false | Generate CRL after revocation |
| `--crl-days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |

**Revocation Reasons:**

| Reason | Description |
|--------|-------------|
| unspecified | No specific reason |
| keyCompromise | Private key was compromised |
| caCompromise | CA key was compromised |
| affiliationChanged | Subject's affiliation changed |
| superseded | Replaced by new certificate |
| cessation | Certificate no longer needed |
| hold | Temporary hold |

**Examples:**

```bash
# Revoke by serial number
qpki cert revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate CRL
qpki cert revoke 02 --ca-dir ./myca --reason keyCompromise --gen-crl

# Revoke with CRL valid for 30 days
qpki cert revoke 02 --ca-dir ./myca --gen-crl --crl-days 30
```

### crl gen

Generate a Certificate Revocation List.

```bash
qpki crl gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |
| `--algo` | | "" | Algorithm family (ec, ml-dsa, etc.) - multi-profile CA only |
| `--all` | | false | Generate CRLs for all algorithm families |

**Examples:**

```bash
# Generate CRL valid for 7 days
qpki crl gen --ca-dir ./myca

# Generate CRL valid for 30 days
qpki crl gen --ca-dir ./myca --days 30

# For multi-profile CA: generate CRL for specific algorithm
qpki crl gen --ca-dir ./myca --algo ec

# For multi-profile CA: generate all CRLs
qpki crl gen --ca-dir ./myca --all
```

### crl info

Display detailed information about a Certificate Revocation List.

```bash
qpki crl info <crl-file>
```

**Output includes:**
- Issuer name
- This Update / Next Update timestamps
- Signature algorithm
- CRL Number (if present)
- Authority Key Identifier
- Number of revoked certificates
- Expiry status
- List of revoked serials with revocation date and reason

**Examples:**

```bash
# Display CRL information
qpki crl info ./ca/crl/ca.crl

# Works with PEM or DER format
qpki crl info /path/to/crl.pem
```

### crl verify

Verify the signature of a Certificate Revocation List.

```bash
qpki crl verify <crl-file> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ca` | (required) | CA certificate (PEM) |
| `--check-expiry` | false | Also check if CRL is expired |

**Examples:**

```bash
# Verify CRL signature
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

# Verify signature and check expiration
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt --check-expiry
```

### crl list

List all CRLs in a CA directory.

```bash
qpki crl list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Output columns:**
- NAME: CRL filename
- THIS UPDATE: When the CRL was generated
- NEXT UPDATE: When the CRL expires
- REVOKED: Number of revoked certificates
- STATUS: valid or EXPIRED

**Example:**

```bash
qpki crl list --ca-dir ./myca
```

---

## 3. Common Workflows

### 3.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
qpki ca init --profile ec/root-ca --ca-dir ./root-ca \
  --var cn="Root CA" --var organization="My Company"

# 2. Create issuing CA (signed by root, with full CA structure)
qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./root-ca --var cn="Issuing CA"

# 3. Issue server certificates from issuing CA
qpki credential enroll --ca-dir ./issuing-ca --cred-dir ./issuing-ca/credentials \
  --profile ec/tls-server \
  --var cn=www.example.com \
  --var dns_names=www.example.com,example.com

# 4. Verify the chain
openssl verify -CAfile ./root-ca/ca.crt ./issuing-ca/ca.crt
```

The `--parent` flag automatically:
- Generates a new key for the subordinate CA
- Issues a CA certificate signed by the parent
- Creates the full CA directory structure
- Generates `chain.crt` with the certificate chain

### 3.2 CA Rotation (Crypto Migration)

```bash
# 1. Preview the rotation plan
qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca --dry-run

# 2. Execute the rotation (creates pending version)
qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

# 3. List versions to see the new pending version
qpki ca versions --ca-dir ./myca

# 4. Activate the new version when ready
qpki ca activate --ca-dir ./myca --version 2
```

---

## 4. FAQ

### Q: How do I create a CA with a custom validity period?

Use the `--validity` flag (in years):
```bash
qpki ca init --profile ec/root-ca --ca-dir ./ca --var cn="Long-lived CA" --validity 30
```

### Q: How do I back up my CA?

Copy the entire CA directory:
```bash
tar -czf ca-backup-$(date +%Y%m%d).tar.gz ./myca
```

### Q: Is the PQC extension compatible with browsers?

The PQC extension is non-critical and will be ignored by browsers. The classical signature is used for TLS. The PQC material is for future use or application-level verification.

---

## See Also

- [CREDENTIALS](CREDENTIALS.md) - Credential management (enroll, rotate, revoke)
- [KEYS](KEYS.md) - Key generation and CSR operations
- [CLI-REFERENCE](CLI-REFERENCE.md) - Complete command reference
- [PROFILES](PROFILES.md) - Certificate profile templates
- [CRYPTO-AGILITY](CRYPTO-AGILITY.md) - Algorithm migration guide
- [OCSP](OCSP.md) - Real-time revocation checking
