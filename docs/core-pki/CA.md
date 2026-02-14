---
title: "Certificate Authority"
description: "CA initialization, configuration, and management"
---

# Certificate Authority

This guide covers Certificate Authority operations: initialization, rotation, and management.

## 1. What is a CA?

A **Certificate Authority (CA)** is the trust anchor that signs certificates. QPKI supports root CAs (self-signed) and subordinate CAs (signed by a parent).

### 1.1 CA Types

| Type | Description |
|------|-------------|
| Root CA | Self-signed, trust anchor |
| Subordinate CA | Signed by parent, issues end-entity certs |
| Multi-profile CA | Multiple algorithms (crypto-agility) |
| Hybrid CA | Classical + PQC (Catalyst or Composite) |

### 1.2 CA Structure

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

### 1.3 Versioned CA

After rotation, CAs have multiple versions with status tracking:

```
ca/
├── ca.meta.json           # Points to active version, stores key refs per version
└── versions/
    ├── v1/                # archived
    │   ├── keys/ca.ecdsa-p256.key    # Software keys only
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

**Key Storage:**
- Each version stores its own key references in `ca.meta.json`
- Software keys: stored as files in `versions/vN/keys/`
- HSM keys: referenced by `label` + `key_id` in metadata (no files)
- This enables proper key rotation with new keys per version

---

## 2. CLI Commands

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
| `--hsm-config` | | "" | HSM configuration file (enables HSM mode) |
| `--key-label` | | "" | Key label in HSM (required with --hsm-config) |
| `--key-id` | | "" | Key ID in HSM (hex, optional) |
| `--use-existing-key` | | false | Use existing key in HSM instead of generating |

> **Note:** Multi-profile subordinate CA is not yet supported. Use a single `--profile` for subordinate CAs.

> **HSM Note:** See [HSM Integration](../operations/HSM.md) for detailed configuration.

**Examples:**

```bash
# Using a profile (recommended)
qpki ca init --profile ec/root-ca --ca-dir ./myca --var cn="My Root CA"

qpki ca init --profile ec/root-ca --profile ml/root-ca --ca-dir ./multi-ca --var cn="Multi-Algo Root CA"

qpki ca init --profile hybrid/catalyst/root-ca --ca-dir ./catalyst-ca --var cn="Catalyst Root CA"

qpki ca init --profile hybrid/composite/root-ca --ca-dir ./composite-ca --var cn="Composite Root CA"

qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./rootca --var cn="Issuing CA"

qpki ca init --profile ec/root-ca --passphrase "mysecret" --ca-dir ./secure-ca --var cn="Secure CA"

qpki ca init --profile ml/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"

qpki ca init --profile ec/root-ca --ca-dir ./myca --var-file ca-vars.yaml

# HSM: generate key in HSM (default behavior)
export HSM_PIN="****"
qpki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
  --hsm-config ./hsm.yaml --key-label "root-ca-key" --var cn="HSM Root CA"

# HSM: use existing key
qpki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
  --hsm-config ./hsm.yaml --key-label "existing-key" --use-existing-key --var cn="HSM Root CA"
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

qpki ca export --ca-dir ./issuing-ca --bundle chain --out chain.pem

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
| `--cross-sign` | | false | Cross-sign new CA with previous CA (see [Crypto-Agility](../migration/CRYPTO-AGILITY.md#25-cross-signing)) |
| `--dry-run` | | false | Preview rotation plan without executing |
| `--hsm-config` | | "" | HSM configuration file (for HSM-based CAs) |
| `--key-label` | | "" | Key label for new HSM keys |

**Examples:**

```bash
# Preview rotation plan (dry-run)
qpki ca rotate --ca-dir ./myca --dry-run

qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

qpki ca rotate --ca-dir ./myca --profile ec/root-ca --profile ml/root-ca

qpki ca rotate --ca-dir ./myca --profile ml/root-ca --cross-sign

# HSM rotation: generates new keys in HSM with versioned key_id
export HSM_PIN="****"
qpki ca rotate --ca-dir ./hsm-ca --profile hybrid/catalyst/root-ca \
  --hsm-config ./hsm.yaml --key-label "my-ca"
```

**HSM Rotation Notes:**
- Each rotation generates new keys in the HSM
- Keys are distinguished by `key_id` (not label) in `ca.meta.json`
- The metadata file tracks which HSM key belongs to which version

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

---

## 3. Common Workflows

### 3.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
qpki ca init --profile ec/root-ca --ca-dir ./root-ca \
  --var cn="Root CA" --var organization="My Company"

qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./root-ca --var cn="Issuing CA"

qpki credential enroll --ca-dir ./issuing-ca --cred-dir ./issuing-ca/credentials \
  --profile ec/tls-server \
  --var cn=www.example.com \
  --var dns_names=www.example.com,example.com

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

qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

qpki ca versions --ca-dir ./myca

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

- [Certificates](CERTIFICATES.md) - Certificate issuance and verification
- [CRL](CRL.md) - Certificate revocation and CRL management
- [Credentials](../end-entities/CREDENTIALS.md) - Credential management
- [Keys & CSR](KEYS.md) - Key generation and CSR operations
- [Profiles](PROFILES.md) - Certificate profile templates
- [Crypto-Agility](../migration/CRYPTO-AGILITY.md) - Algorithm migration guide
