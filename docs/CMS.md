# CMS Signatures & Encryption

## Table of Contents

- [1. What is CMS?](#1-what-is-cms)
  - [Standards](#standards)
  - [Content Types](#content-types)
- [2. CLI Commands](#2-cli-commands)
  - [cms sign](#cms-sign)
  - [cms verify](#cms-verify)
  - [cms encrypt](#cms-encrypt)
  - [cms decrypt](#cms-decrypt)
  - [cms info](#cms-info)
- [3. Algorithm Support](#3-algorithm-support)
  - [Signature Algorithms](#signature-algorithms)
  - [Key Encapsulation](#key-encapsulation)
  - [Content Encryption](#content-encryption)
- [4. OpenSSL Interoperability](#4-openssl-interoperability)
- [5. Use Cases](#5-use-cases)
  - [Document Signing](#document-signing)
  - [Secure Email (S/MIME)](#secure-email-smime)
  - [Post-Quantum Document Protection](#post-quantum-document-protection)
- [6. Hybrid Encryption (PQC Transition)](#6-hybrid-encryption-pqc-transition)
  - [Concept](#concept)
  - [Usage](#usage)
  - [Security Model](#security-model)
- [See Also](#see-also)

---

This guide covers the Cryptographic Message Syntax (CMS) implementation for signing and encrypting data.

> **Related documentation:**
> - [TSA.md](TSA.md) - Timestamping for long-term validity
> - [CREDENTIALS.md](CREDENTIALS.md) - Signing and encryption credentials

## 1. What is CMS?

**Cryptographic Message Syntax (CMS)** is a standard format (RFC 5652) for signing and encrypting data. It supports classical algorithms (ECDSA, RSA, Ed25519), post-quantum (ML-DSA, SLH-DSA, ML-KEM), and hybrid modes.

### Standards

| Standard | Description |
|----------|-------------|
| RFC 5652 | Cryptographic Message Syntax (CMS) |
| RFC 9629 | Using Key Encapsulation Mechanisms in CMS |
| RFC 9880 | ML-KEM for CMS |
| RFC 9882 | ML-DSA in CMS |
| FIPS 204 | ML-DSA (Dilithium) |
| FIPS 205 | SLH-DSA (SPHINCS+) |
| FIPS 203 | ML-KEM (Kyber) |

### Content Types

| Type | OID | Description |
|------|-----|-------------|
| SignedData | 1.2.840.113549.1.7.2 | Digital signatures |
| EnvelopedData | 1.2.840.113549.1.7.3 | Encrypted data |

---

## 2. CLI Commands

### cms sign

Create a CMS SignedData signature.

```bash
qpki cms sign --data <file> --cert <cert> --key <key> -o <output> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data` | (required) | File to sign |
| `--cert` | (required) | Signer certificate (PEM) |
| `--key` | | Private key (PEM, or use --hsm-config) |
| `--out, -o` | (required) | Output file (.p7s) |
| `--hash` | sha256 | Hash algorithm (sha256, sha384, sha512) |
| `--detached` | true | Create detached signature (content not included) |
| `--include-certs` | true | Include signer certificate in output |
| `--hsm-config` | | HSM configuration file (YAML) |
| `--key-label` | | HSM key label (CKA_LABEL) |
| `--key-id` | | HSM key ID (CKA_ID, hex) |
| `--passphrase` | | Key passphrase |

**Examples:**

```bash
# Detached signature (default)
qpki cms sign --data document.pdf --cert signer.crt --key signer.key -o document.p7s

# Attached signature (content included)
qpki cms sign --data document.pdf --cert signer.crt --key signer.key --detached=false -o document.p7s

# With SHA-512 hash
qpki cms sign --data document.pdf --cert signer.crt --key signer.key --hash sha512 -o document.p7s

# Using HSM key
qpki cms sign --data document.pdf --cert signer.crt \
    --hsm-config ./hsm.yaml --key-label "signing-key" -o document.p7s
```

### cms verify

Verify a CMS SignedData signature.

```bash
qpki cms verify <signature-file> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data` | | Original data file (for detached signatures) |
| `--ca` | | CA certificate for chain verification |

**Examples:**

```bash
# Verify detached signature
qpki cms verify document.p7s --data document.pdf --ca ca.crt

# Verify attached signature (data extracted automatically)
qpki cms verify document.p7s --ca ca.crt

# Verify signature only (no CA check)
qpki cms verify document.p7s --data document.pdf
```

### cms encrypt

Encrypt data using CMS EnvelopedData.

```bash
qpki cms encrypt --recipient <cert> --in <file> --out <file> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--recipient` | `-r` | (required) | Recipient certificate(s), repeatable |
| `--in` | `-i` | (required) | Input file to encrypt |
| `--out` | `-o` | (required) | Output file (.p7m) |
| `--content-enc` | | aes-256-gcm | Content encryption (aes-256-gcm, aes-256-cbc, aes-128-gcm) |

**Supported key types:**
- **RSA**: Uses RSA-OAEP with SHA-256
- **EC**: Uses ECDH with AES Key Wrap
- **ML-KEM**: Uses ML-KEM encapsulation with AES Key Wrap (post-quantum)

**Examples:**

```bash
# Encrypt for a single recipient
qpki cms encrypt --recipient bob.crt --in secret.txt --out secret.p7m

# Encrypt for multiple recipients
qpki cms encrypt --recipient alice.crt --recipient bob.crt --in data.txt --out data.p7m

# Use AES-256-CBC instead of AES-256-GCM
qpki cms encrypt --recipient bob.crt --in data.txt --out data.p7m --content-enc aes-256-cbc
```

### cms decrypt

Decrypt CMS EnvelopedData.

```bash
qpki cms decrypt --key <key> --in <file> --out <file> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--key` | `-k` | (required) | Private key file (PEM) |
| `--cert` | `-c` | | Certificate for recipient matching |
| `--in` | `-i` | (required) | Input file (.p7m) |
| `--out` | `-o` | (required) | Output file |
| `--passphrase` | | | Key passphrase |

**Examples:**

```bash
# Decrypt with private key
qpki cms decrypt --key bob.key --in secret.p7m --out secret.txt

# Decrypt with encrypted private key
qpki cms decrypt --key bob.key --passphrase "secret" --in data.p7m --out data.txt

# Decrypt with certificate matching
qpki cms decrypt --key bob.key --cert bob.crt --in data.p7m --out data.txt
```

### cms info

Display detailed information about a CMS message.

```bash
qpki cms info <file>
```

**Output includes:**
- Content type (SignedData or EnvelopedData)
- Version, algorithms, signature/encryption details
- Signer information (for SignedData)
- Recipient information (for EnvelopedData)
- Embedded certificates

**Examples:**

```bash
# Display SignedData info
qpki cms info signature.p7s

# Display EnvelopedData info
qpki cms info encrypted.p7m
```

---

## 3. Algorithm Support

### Signature Algorithms

| Algorithm | Key Type | Use Case |
|-----------|----------|----------|
| ECDSA-SHA256/384/512 | EC P-256/384/521 | Classical (recommended) |
| RSA-SHA256/384/512 | RSA 2048-4096 | Legacy compatibility |
| Ed25519 | Ed25519 | Modern classical |
| ML-DSA-44/65/87 | ML-DSA | Post-quantum |
| SLH-DSA-* | SLH-DSA | Hash-based PQC |

### Key Encapsulation

| Algorithm | Key Type | Use Case |
|-----------|----------|----------|
| RSA-OAEP | RSA | Classical |
| ECDH + AES-KW | EC | Classical (recommended) |
| ML-KEM-512/768/1024 | ML-KEM | Post-quantum |

### Content Encryption

| Algorithm | Key Size | Mode |
|-----------|----------|------|
| AES-256-GCM | 256-bit | AEAD (default) |
| AES-128-GCM | 128-bit | AEAD |
| AES-256-CBC | 256-bit | CBC |

---

## 4. OpenSSL Interoperability

```bash
# Verify a CMS signature (classical algorithms only)
openssl cms -verify -in signature.p7s -content document.pdf -CAfile ca.crt

# Decrypt CMS (RSA/ECDH/ML-KEM)
openssl cms -decrypt -in encrypted.p7m -inkey recipient.key -out decrypted.txt

# Create signature with OpenSSL
openssl cms -sign -in document.pdf -signer signer.crt -inkey signer.key -out signature.p7s
```

> **Note:** OpenSSL 3.6+ supports ML-KEM for CMS encryption/decryption (RFC 9629). For ML-DSA and SLH-DSA signatures, use `qpki cms` commands.

---

## 5. Use Cases

### Document Signing

```bash
# Sign a contract
qpki cms sign --data contract.pdf --cert signer.crt --key signer.key -o contract.p7s

# Verify the signature
qpki cms verify contract.p7s --data contract.pdf --ca ca.crt
```

### Secure Email (S/MIME)

```bash
# Encrypt for recipient
qpki cms encrypt --recipient alice@example.com.crt --in message.txt --out message.p7m

# Recipient decrypts
qpki cms decrypt --key alice.key --in message.p7m --out message.txt
```

### Post-Quantum Document Protection

```bash
# Encrypt with ML-KEM (quantum-resistant)
# Requires recipient to have an ML-KEM certificate
qpki cms encrypt --recipient bob-mlkem.crt --in sensitive.doc --out sensitive.p7m
```

---

## 6. Hybrid Encryption (PQC Transition)

For quantum-safe encryption during the post-quantum transition, use multiple recipients with different key types. This creates an EnvelopedData with two RecipientInfos, providing defense-in-depth security.

### Concept

```
┌─────────────────────────────────────────────────────────────┐
│                    EnvelopedData                            │
├─────────────────────────────────────────────────────────────┤
│  RecipientInfo[0]: KeyAgreeRecipientInfo (ECDH)             │
│    └─ Wrapped CEK using ECDH + AES-KW                       │
│                                                             │
│  RecipientInfo[1]: KEMRecipientInfo (ML-KEM)                │
│    └─ Wrapped CEK using ML-KEM encapsulation                │
│                                                             │
│  EncryptedContentInfo:                                      │
│    └─ AES-256-GCM(CEK, plaintext)                           │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Create encryption credentials for both algorithms
qpki credential enroll --ca-dir /path/to/ca --profile ec/encryption \
    --var cn="Alice (Classical)"
qpki credential enroll --ca-dir /path/to/pqc-ca --profile ml/encryption \
    --var cn="Alice (PQC)"

# Encrypt with both recipients (hybrid security)
qpki cms encrypt \
    --recipient alice-ec.crt \
    --recipient alice-mlkem.crt \
    --in secret.txt --out secret.p7m

# Recipient can decrypt with EITHER key
qpki cms decrypt --key alice-ec.key --in secret.p7m --out decrypted.txt
# OR
qpki cms decrypt --key alice-mlkem.key --in secret.p7m --out decrypted.txt
```

### Security Model

| Threat | Classical (ECDH) | Post-Quantum (ML-KEM) | Hybrid |
|--------|------------------|----------------------|--------|
| Classical computer | Protected | Protected | Protected |
| Quantum computer | Vulnerable | Protected | Protected |
| Bug in ML-KEM | N/A | Vulnerable | Protected |
| Bug in ECDH | Vulnerable | N/A | Protected |

**Key insight:** An attacker must break BOTH algorithms to decrypt the message, providing "belt and suspenders" security during the PQC transition.

---

## See Also

- [TSA](TSA.md) - Timestamping for long-term validity
- [CREDENTIALS](CREDENTIALS.md) - Signing and encryption credentials
- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) - CMS specification
- [RFC 9880](https://www.rfc-editor.org/rfc/rfc9880) - ML-KEM for CMS
- [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) - ML-DSA in CMS
