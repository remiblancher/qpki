# CMS Signatures & Encryption

## Table of Contents

- [1. What is CMS?](#1-what-is-cms)
- [2. CLI Commands](#2-cli-commands)
- [3. Signing Profiles](#3-signing-profiles)
- [4. Encryption Profiles](#4-encryption-profiles)
- [5. Algorithm Support](#5-algorithm-support)
  - [5.1 RFC 9882 Compliance (ML-DSA)](#51-rfc-9882-compliance-ml-dsa)
  - [5.2 RFC 8419 Compliance (EdDSA)](#52-rfc-8419-compliance-eddsa)
  - [5.3 RFC 9814 Compliance (SLH-DSA)](#53-rfc-9814-compliance-slh-dsa)
- [6. OpenSSL Interoperability](#6-openssl-interoperability)
- [7. Use Cases](#7-use-cases)
- [8. Hybrid Encryption (PQC Transition)](#8-hybrid-encryption-pqc-transition)
- [See Also](#see-also)

---

This guide covers the Cryptographic Message Syntax (CMS) implementation for signing and encrypting data.

> **Related documentation:**
> - [TSA.md](TSA.md) - Timestamping for long-term validity
> - [CREDENTIALS.md](CREDENTIALS.md) - Signing and encryption credentials

## 1. What is CMS?

**Cryptographic Message Syntax (CMS)** is a standard format (RFC 5652) for signing and encrypting data. It supports classical algorithms (ECDSA, RSA, Ed25519, Ed448), post-quantum (ML-DSA, SLH-DSA, ML-KEM), and hybrid modes.

### Standards

| Standard | Description |
|----------|-------------|
| RFC 5652 | Cryptographic Message Syntax (CMS) |
| RFC 8419 | EdDSA (Ed25519/Ed448) in CMS |
| RFC 9629 | Using Key Encapsulation Mechanisms in CMS |
| RFC 9814 | SLH-DSA in CMS |
| RFC 9880 | ML-KEM for CMS |
| RFC 9882 | ML-DSA in CMS |
| FIPS 203 | ML-KEM (Kyber) |
| FIPS 204 | ML-DSA (Dilithium) |
| FIPS 205 | SLH-DSA (SPHINCS+) |

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
qpki cms sign --data <file> --cert <cert> --key <key> --out <output> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data` | (required) | File to sign |
| `--cert` | (required) | Signer certificate (PEM) |
| `--key` | | Private key (PEM, or use --hsm-config) |
| `--out, -o` | (required) | Output file (.p7s) |
| `--hash` | (auto) | Hash algorithm. Auto-selected for ML-DSA per RFC 9882. Options: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 |
| `--detached` | true | Create detached signature (content not included) |
| `--include-certs` | true | Include signer certificate in output |
| `--hsm-config` | | HSM configuration file (YAML) |
| `--key-label` | | HSM key label (CKA_LABEL) |
| `--key-id` | | HSM key ID (CKA_ID, hex) |
| `--passphrase` | | Key passphrase |

**Examples:**

```bash
# Detached signature (default)
qpki cms sign --data document.pdf --cert signer.crt --key signer.key --out document.p7s

# Attached signature (content included)
qpki cms sign --data document.pdf --cert signer.crt --key signer.key --detached=false --out document.p7s

# With SHA-512 hash
qpki cms sign --data document.pdf --cert signer.crt --key signer.key --hash sha512 --out document.p7s

# Using HSM key
qpki cms sign --data document.pdf --cert signer.crt \
    --hsm-config ./hsm.yaml --key-label "signing-key" --out document.p7s
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

## 3. Signing Profiles

Create a signing certificate for CMS signatures.

### Option A: Credential-based

```bash
# ECDSA
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/signing --var cn="Document Signer" --id signer

# ML-DSA (post-quantum)
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/signing --var cn="PQC Signer" --id pqc-signer

# SLH-DSA (hash-based PQC)
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile slh/signing --var cn="Archive Signer" --id archive-signer

# Hybrid Catalyst
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile hybrid/catalyst/signing --var cn="Hybrid Signer" --id hybrid-signer

# Usage
qpki cms sign --data doc.pdf \
    --cert ./credentials/signer/certificates.pem \
    --key ./credentials/signer/private-keys.pem --out doc.p7s
```

### Option B: CSR-based

```bash
# 1. Generate key
qpki key gen --algorithm ecdsa-p256 --out signer.key

# 2. Create CSR
qpki csr gen --key signer.key --cn "Document Signer" --out signer.csr

# 3. Issue certificate
qpki cert issue --ca-dir ./ca --profile ec/signing --csr signer.csr --out signer.crt

# Usage
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --out doc.p7s
```

---

## 4. Encryption Profiles

Create an encryption certificate for CMS EnvelopedData.

### Option A: Credential-based

```bash
# ECDH (classical)
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/encryption --var cn="Recipient" --id recipient

# ML-KEM (post-quantum)
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/encryption --var cn="PQC Recipient" --id pqc-recipient

# Usage
qpki cms encrypt --recipient ./credentials/recipient/certificates.pem \
    --in secret.txt --out secret.p7m
```

### Option B: CSR-based

```bash
# 1. Generate key
qpki key gen --algorithm ecdsa-p384 --out recipient.key

# 2. Create CSR
qpki csr gen --key recipient.key --cn "Recipient" --out recipient.csr

# 3. Issue certificate
qpki cert issue --ca-dir ./ca --profile ec/encryption --csr recipient.csr --out recipient.crt

# Usage
qpki cms encrypt --recipient recipient.crt --in secret.txt --out secret.p7m
```

---

## 5. Algorithm Support

### Signature Algorithms

| Algorithm | Key Type | Use Case |
|-----------|----------|----------|
| ECDSA-SHA256/384/512 | EC P-256/384/521 | Classical (recommended) |
| RSA-SHA256/384/512 | RSA 2048-4096 | Legacy compatibility |
| Ed25519 | Ed25519 | Modern classical (~128-bit security) |
| Ed448 | Ed448 | Modern classical (~224-bit security) |
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

### 5.1 RFC 9882 Compliance (ML-DSA)

QPKI implements RFC 9882 recommendations for ML-DSA in CMS:

#### Automatic Digest Selection

When signing with ML-DSA certificates, the digest algorithm is automatically
selected based on the ML-DSA security level if not explicitly specified:

| ML-DSA Variant | Security Level | Auto-Selected Digest |
|----------------|----------------|---------------------|
| ML-DSA-44 | NIST Level 1 | SHA-256 |
| ML-DSA-65 | NIST Level 3 | SHA-384 |
| ML-DSA-87 | NIST Level 5 | SHA-512 |

**Example:**

```bash
# Sign with ML-DSA (see Section 3 for certificate creation)
# SHA-512 is auto-selected for ML-DSA-87
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --out doc.p7s

# Override with explicit hash (not recommended for ML-DSA-87)
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --hash sha256 --out doc.p7s
```

#### Verification Warnings

During verification, QPKI checks if the digest algorithm matches the ML-DSA
security level and issues warnings for suboptimal combinations:

```bash
# Verify a signature - warning shown if digest doesn't match ML-DSA level
qpki cms verify doc.p7s --data doc.pdf --ca ca.crt

# Example warning:
# WARNING: ML-DSA-87 signature uses SHA-256 (RFC 9882 recommends SHA-512 for NIST Level 5)
```

#### Supported Digest Algorithms

| Algorithm | OID | Notes |
|-----------|-----|-------|
| SHA-256 | 2.16.840.1.101.3.4.2.1 | Default for ML-DSA-44, classical |
| SHA-384 | 2.16.840.1.101.3.4.2.2 | Default for ML-DSA-65 |
| SHA-512 | 2.16.840.1.101.3.4.2.3 | Default for ML-DSA-87 |
| SHA3-256 | 2.16.840.1.101.3.4.2.8 | SHA-3 family |
| SHA3-384 | 2.16.840.1.101.3.4.2.9 | SHA-3 family |
| SHA3-512 | 2.16.840.1.101.3.4.2.10 | SHA-3 family |

### 5.2 RFC 8419 Compliance (EdDSA)

QPKI implements RFC 8419 for EdDSA algorithms (Ed25519 and Ed448) in CMS:

#### Supported Algorithms

| Algorithm | OID | Security Level | Mode |
|-----------|-----|----------------|------|
| Ed25519 | 1.3.101.112 | ~128 bits | Pure (no pre-hash) |
| Ed448 | 1.3.101.113 | ~224 bits | Pure (no pre-hash) |

#### Pure Mode Signing

Both Ed25519 and Ed448 operate in "pure" mode per RFC 8419:
- Data is signed directly without pre-hashing
- Parameters field is absent in AlgorithmIdentifier
- Ed448 uses empty context string (`""`)

**Example:**

```bash
# Sign with Ed448 (see Section 3 for certificate creation)
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --out doc.p7s

# Verify Ed448 signature
qpki cms verify doc.p7s --data doc.pdf --ca ca.crt
```

#### Ed25519 vs Ed448

| Feature | Ed25519 | Ed448 |
|---------|---------|-------|
| Security | ~128 bits | ~224 bits |
| Signature size | 64 bytes | 114 bytes |
| Public key size | 32 bytes | 57 bytes |
| Performance | Faster | Slower |
| Use case | General purpose | Higher security requirements |

---

### 5.3 RFC 9814 Compliance (SLH-DSA)

QPKI implements RFC 9814 for SLH-DSA (SPHINCS+) algorithms in CMS:

#### Supported Algorithms

| Algorithm | OID | Security | Mode |
|-----------|-----|----------|------|
| SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 | NIST Level 1 | Small signatures |
| SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 | NIST Level 1 | Fast signing |
| SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 | NIST Level 3 | Small signatures |
| SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 | NIST Level 3 | Fast signing |
| SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 | NIST Level 5 | Small signatures |
| SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 | NIST Level 5 | Fast signing |
| SLH-DSA-SHAKE-128s | 2.16.840.1.101.3.4.3.26 | NIST Level 1 | Small signatures |
| SLH-DSA-SHAKE-128f | 2.16.840.1.101.3.4.3.27 | NIST Level 1 | Fast signing |
| SLH-DSA-SHAKE-192s | 2.16.840.1.101.3.4.3.28 | NIST Level 3 | Small signatures |
| SLH-DSA-SHAKE-192f | 2.16.840.1.101.3.4.3.29 | NIST Level 3 | Fast signing |
| SLH-DSA-SHAKE-256s | 2.16.840.1.101.3.4.3.30 | NIST Level 5 | Small signatures |
| SLH-DSA-SHAKE-256f | 2.16.840.1.101.3.4.3.31 | NIST Level 5 | Fast signing |

#### Digest Auto-Selection

Per RFC 9814, the digest algorithm is auto-selected based on SLH-DSA security level:

| Security Level | Digest Algorithm |
|----------------|------------------|
| 128-bit (Level 1) | SHA-256 |
| 192-bit (Level 3) | SHA-512 |
| 256-bit (Level 5) | SHA-512 |

#### Pure Mode Signing

All SLH-DSA variants operate in "pure" mode:
- Data is signed directly without pre-hashing
- Parameters field is absent in AlgorithmIdentifier
- Empty context string per RFC 9814

**Example:**

```bash
# Sign with SLH-DSA (see Section 3 for certificate creation)
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --out doc.p7s

# Verify SLH-DSA signature
qpki cms verify doc.p7s --data doc.pdf --ca ca.crt
```

#### SHA2 vs SHAKE Variants

| Feature | SHA2 variants | SHAKE variants |
|---------|---------------|----------------|
| Hash function | SHA-256/SHA-512 | SHAKE128/SHAKE256 |
| Interoperability | Wider support | Newer standard |
| Performance | Similar | Similar |
| Use case | General purpose | SHAKE-based systems |

---

## 6. OpenSSL Interoperability

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

## 7. Use Cases

### Document Signing

```bash
# Sign a contract
qpki cms sign --data contract.pdf --cert signer.crt --key signer.key --out contract.p7s

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

## 8. Hybrid Encryption (PQC Transition)

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
- [RFC 8419](https://www.rfc-editor.org/rfc/rfc8419) - EdDSA (Ed25519/Ed448) in CMS
- [RFC 9880](https://www.rfc-editor.org/rfc/rfc9880) - ML-KEM for CMS
- [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) - ML-DSA in CMS
