---
title: "Key Management & CSR Operations"
description: "This guide covers private key generation, management, and Certificate Signing Request (CSR) operations."
---

# Key Management & CSR Operations

This guide covers private key generation, management, and Certificate Signing Request (CSR) operations.

## 1. What is a Key?

A **private key** is the cryptographic secret used for signing or decryption. QPKI supports classical (ECDSA, RSA, Ed25519) and post-quantum (ML-DSA, SLH-DSA, ML-KEM) algorithms.

### 1.1 Key Types

| Type | Purpose | Algorithms |
|------|---------|------------|
| Signature | Sign certificates, CMS, OCSP | ECDSA, Ed25519, RSA, ML-DSA, SLH-DSA |
| Key Encapsulation | Encrypt session keys | ML-KEM |

### 1.2 What is a CSR?

A **Certificate Signing Request (CSR)** is a message sent to a CA to request a certificate. It contains the public key and subject information, signed by the corresponding private key.

### 1.3 Key Formats

QPKI stores private keys in **PEM format** (Base64-encoded with headers):

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----
```

| Format | Extension | Description |
|--------|-----------|-------------|
| PEM | .pem, .key | Base64 with headers (default) |
| DER | .der | Binary ASN.1 |
| PKCS#8 | .p8 | Standardized private key format |

**Encrypted keys** use PKCS#8 encryption:

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----
```

Use `qpki key convert` to change formats or add passphrase protection.

---

## 2. CLI Commands

### key gen

Generate a private key file.

The output file contains the private key in PEM format. The public key is mathematically derived from the private key and is not stored separately. To extract the public key, use `qpki key pub`.

```bash
qpki key gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm |
| `--out` | `-o` | required | Output key file |
| `--passphrase` | | "" | Key passphrase |

**Algorithms:**

| Algorithm | Description | Security |
|-----------|-------------|----------|
| ecdsa-p256 | ECDSA with NIST P-256 curve | ~128-bit |
| ecdsa-p384 | ECDSA with NIST P-384 curve | ~192-bit |
| ecdsa-p521 | ECDSA with NIST P-521 curve | ~256-bit |
| ed25519 | Edwards-curve DSA | ~128-bit |
| rsa-2048 | RSA 2048-bit | ~112-bit |
| rsa-4096 | RSA 4096-bit | ~140-bit |
| ml-dsa-44 | ML-DSA (Dilithium) Level 1 | NIST Level 1 |
| ml-dsa-65 | ML-DSA (Dilithium) Level 3 | NIST Level 3 |
| ml-dsa-87 | ML-DSA (Dilithium) Level 5 | NIST Level 5 |

**Examples:**

```bash
# ECDSA P-256 key (default)
qpki key gen --algorithm ecdsa-p256 --out key.pem

qpki key gen --algorithm ed25519 --out ed25519.key

qpki key gen --algorithm ml-dsa-65 --out pqc.key

qpki key gen --algorithm ecdsa-p384 --out secure.key --passphrase "secret"
```

### key pub

Extract the public key from a private key file.

```bash
qpki key pub [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--key` | `-k` | required | Input private key file |
| `--out` | `-o` | required | Output public key file |
| `--passphrase` | | "" | Passphrase for encrypted key |

**Examples:**

```bash
# Extract public key from ECDSA key
qpki key pub --key private.pem --out public.pem

qpki key pub --key encrypted.key --passphrase "secret" --out public.pem

qpki key pub --key mldsa.key --out mldsa.pub
```

### key list

List private keys in a directory or HSM token.

```bash
qpki key list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | . | Directory to scan |
| `--hsm-config` | | | HSM configuration file |

**Examples:**

```bash
# List keys in directory
qpki key list --dir ./keys

qpki key list --hsm-config ./hsm.yaml
```

### key info

Display information about a private key.

```bash
qpki key info <key-file> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--passphrase` | `-p` | "" | Passphrase for encrypted key |

**Example:**

```bash
qpki key info private.key
```

### key convert

Convert a private key to a different format.

```bash
qpki key convert [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--key` | `-k` | required | Input key file |
| `--out` | `-o` | required | Output key file |
| `--format` | `-f` | pem | Output format: pem, der, pkcs8 |
| `--passphrase` | | "" | Passphrase for input key |
| `--out-passphrase` | | "" | Passphrase for output key |

**Examples:**

```bash
# Convert PEM to DER
qpki key convert --key private.pem --out private.der --format der

qpki key convert --key private.pem --out encrypted.pem --out-passphrase "secret"
```

### csr gen

Generate a Certificate Signing Request (CSR) for submission to a CA.

```bash
qpki csr gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--algorithm` | `-a` | "" | Key algorithm for new key |
| `--keyout` | | "" | Output file for new private key |
| `--key` | | "" | Existing private key file |
| `--passphrase` | | "" | Passphrase for existing key |
| `--key-passphrase` | | "" | Passphrase for new key |
| `--out` | `-o` | required | Output CSR file |
| `--cn` | | required | Common Name |
| `--org` | `-O` | "" | Organization |
| `--country` | `-C` | "" | Country (2-letter code) |
| `--dns` | | [] | DNS SANs |
| `--email` | | [] | Email SANs |
| `--ip` | | [] | IP SANs |
| `--hybrid` | | "" | PQC algorithm for hybrid CSR |
| `--hybrid-keyout` | | "" | Output file for hybrid PQC key |
| `--attest-cert` | | "" | Attestation certificate (RFC 9883) |
| `--attest-key` | | "" | Attestation private key (RFC 9883) |

**Modes:**

| Mode | Description | Command |
|------|-------------|---------|
| Classical | RSA, ECDSA, Ed25519 via Go x509 | `--algorithm ecdsa-p256` |
| PQC Signature | ML-DSA, SLH-DSA (custom PKCS#10) | `--algorithm ml-dsa-65` |
| PQC KEM | ML-KEM with RFC 9883 attestation | `--algorithm ml-kem-768 --attest-cert ...` |
| Catalyst | ITU-T X.509 dual signatures | `--algorithm ecdsa-p384 --hybrid ml-dsa-87` |
| Composite | IETF draft-13 combined signature | `--algorithm ecdsa-p384 --composite ml-dsa-87` |

**Examples:**

```bash
# Classical ECDSA CSR
qpki csr gen --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com --out server.csr

qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key \
    --cn alice@example.com --out mldsa.csr

# (requires an existing signature certificate for attestation)
qpki csr gen --algorithm ml-kem-768 --keyout kem.key \
    --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key \
    --out kem.csr

qpki csr gen --algorithm ecdsa-p384 --hybrid ml-dsa-87 \
    --keyout classical.key --hybrid-keyout pqc.key \
    --cn example.com --out catalyst.csr

qpki csr gen --algorithm ecdsa-p384 --composite ml-dsa-87 \
    --keyout classical.key --hybrid-keyout pqc.key \
    --cn example.com --out composite.csr

qpki csr gen --key existing.key --cn server.example.com --out server.csr
```

**Catalyst Combinations (--algorithm + --hybrid):**

Creates a CSR with dual signatures per ITU-T X.509 (2019) Section 9.8.
Both classical and PQC signatures are independent, allowing backward compatibility.

| --algorithm | --hybrid | Security Level |
|-------------|----------|----------------|
| ecdsa-p256 | ml-dsa-44, ml-dsa-65 | 128-bit |
| ecdsa-p384 | ml-dsa-65, ml-dsa-87 | 192-bit |
| ecdsa-p521 | ml-dsa-87 | 256-bit |
| ed25519 | ml-dsa-44, ml-dsa-65 | 128-bit |
| ed448 | ml-dsa-87 | 224-bit |

**Composite Combinations (--algorithm + --composite):**

Creates a CSR with a combined composite signature per IETF draft-ietf-lamps-pq-composite-sigs-13.
The signature is atomic - both components must be verified together.
Only IANA-allocated OIDs are supported.

| --algorithm | --composite | OID | Security Level |
|-------------|-------------|-----|----------------|
| ecdsa-p256 | ml-dsa-65 | 1.3.6.1.5.5.7.6.45 | Level 3 |
| ecdsa-p384 | ml-dsa-65 | 1.3.6.1.5.5.7.6.46 | Level 3 |
| ecdsa-p521 | ml-dsa-87 | 1.3.6.1.5.5.7.6.54 | Level 5 |

**RFC 9883 (ML-KEM Attestation):**

ML-KEM keys cannot sign (they're Key Encapsulation Mechanisms). To prove possession of an ML-KEM private key, RFC 9883 defines the `privateKeyPossessionStatement` attribute. This requires:

1. An existing signature certificate (`--attest-cert`)
2. The corresponding private key (`--attest-key`)

The CSR is signed by the attestation key, and includes a reference to the attestation certificate. The CA verifies the attestation chain before issuing the ML-KEM certificate.

### csr info

Display information about a CSR.

```bash
qpki csr info <csr-file>
```

**Example:**

```bash
qpki csr info server.csr
```

### csr verify

Verify the signature of a CSR.

```bash
qpki csr verify <csr-file>
```

**Example:**

```bash
qpki csr verify server.csr
```

---

## 3. Algorithm Reference

### Classical Algorithms

| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| ecdsa-p256 | Signature | 256-bit | Default, wide compatibility |
| ecdsa-p384 | Signature | 384-bit | Recommended for new deployments |
| ecdsa-p521 | Signature | 521-bit | Maximum classical security |
| ed25519 | Signature | 256-bit | Fast, constant-time |
| rsa-2048 | Signature | 2048-bit | Legacy compatibility |
| rsa-4096 | Signature | 4096-bit | Legacy with higher security |

### Post-Quantum Algorithms

| Algorithm | Type | NIST Level | Use Case |
|-----------|------|------------|----------|
| ml-dsa-44 | Signature | Level 1 | ~AES-128 equivalent |
| ml-dsa-65 | Signature | Level 3 | ~AES-192 equivalent |
| ml-dsa-87 | Signature | Level 5 | ~AES-256 equivalent |
| ml-kem-512 | KEM | Level 1 | Key encapsulation |
| ml-kem-768 | KEM | Level 3 | Key encapsulation |
| ml-kem-1024 | KEM | Level 5 | Key encapsulation |

---

## See Also

- [CA](CA.md) - CA initialization and certificate issuance
- [Credentials](../end-entities/CREDENTIALS.md) - Bundled key + certificate lifecycle
- [HSM](HSM.md) - Hardware Security Module integration
- [Concepts](../getting-started/CONCEPTS.md) - PQC and hybrid certificate concepts
- [CLI Reference](../reference/CLI.md) - Complete command reference
