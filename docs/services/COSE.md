---
title: "COSE/CWT (CBOR Object Signing)"
description: "This guide covers the COSE (CBOR Object Signing and Encryption) and CWT (CBOR Web Token) implementation with post-quantum algorithm support."
---

# COSE/CWT (CBOR Object Signing)

This guide covers the COSE (CBOR Object Signing and Encryption) and CWT (CBOR Web Token) implementation with post-quantum algorithm support.

## 1. What is COSE/CWT?

**COSE** (CBOR Object Signing and Encryption) is a compact binary format for signed and encrypted messages, analogous to JOSE (JSON Object Signing and Encryption) but using CBOR encoding for efficiency.

**CWT** (CBOR Web Token) is the CBOR equivalent of JWT, using COSE signatures to protect claims in a compact binary format.

QPKI implements COSE/CWT with post-quantum algorithm support.

### Standards

| Standard | Description |
|----------|-------------|
| RFC 9052 | CBOR Object Signing and Encryption (COSE): Structures and Process |
| RFC 9053 | COSE: Initial Algorithms |
| RFC 8392 | CBOR Web Token (CWT) |
| RFC 8949 | Concise Binary Object Representation (CBOR) |
| RFC 9360 | COSE Header Parameters for X.509 Certificates |
| draft-ietf-cose-dilithium-04 | COSE algorithm identifiers for ML-DSA |
| FIPS 204 | ML-DSA (Dilithium) |
| FIPS 205 | SLH-DSA (SPHINCS+) |

### Supported Algorithms

#### Classical Algorithms (IANA Registered)

| Algorithm | COSE ID | Description |
|-----------|---------|-------------|
| ES256 | -7 | ECDSA P-256 with SHA-256 |
| ES384 | -35 | ECDSA P-384 with SHA-384 |
| ES512 | -36 | ECDSA P-521 with SHA-512 |
| EdDSA | -8 | EdDSA (Ed25519/Ed448) |
| PS256 | -37 | RSASSA-PSS with SHA-256 |
| PS384 | -38 | RSASSA-PSS with SHA-384 |
| PS512 | -39 | RSASSA-PSS with SHA-512 |

#### Post-Quantum Algorithms

| Algorithm | COSE ID | Source |
|-----------|---------|--------|
| ML-DSA-44 | -48 | draft-ietf-cose-dilithium-04 |
| ML-DSA-65 | -49 | draft-ietf-cose-dilithium-04 |
| ML-DSA-87 | -50 | draft-ietf-cose-dilithium-04 |
| SLH-DSA-SHA2-128s | -70020 | Private-use range |
| SLH-DSA-SHA2-128f | -70021 | Private-use range |
| SLH-DSA-SHA2-192s | -70022 | Private-use range |
| SLH-DSA-SHA2-192f | -70023 | Private-use range |
| SLH-DSA-SHA2-256s | -70024 | Private-use range |
| SLH-DSA-SHA2-256f | -70025 | Private-use range |
| SLH-DSA-SHAKE-128s | -70026 | Private-use range |
| SLH-DSA-SHAKE-128f | -70027 | Private-use range |
| SLH-DSA-SHAKE-192s | -70028 | Private-use range |
| SLH-DSA-SHAKE-192f | -70029 | Private-use range |
| SLH-DSA-SHAKE-256s | -70030 | Private-use range |
| SLH-DSA-SHAKE-256f | -70031 | Private-use range |

### Architecture

```
+------------------------------------------------------------------+
|                        COSE Message                               |
+------------------------------------------------------------------+
|  +------------------+    +------------------+    +--------------+ |
|  | Protected Header |    |     Payload      |    |  Signature   | |
|  | (alg, kid, x5c)  |    | (CWT claims or   |    |  (bytes)     | |
|  +------------------+    |  arbitrary data) |    +--------------+ |
+------------------------------------------------------------------+
          |                        |                      |
          v                        v                      v
    CBOR Encoded            CBOR Encoded           Signature Bytes
```

**Message Types:**
- **COSE_Sign1** (Tag 18): Single signature
- **COSE_Sign** (Tag 98): Multiple signatures (hybrid mode)
- **CWT**: Sign1 or Sign with claims payload

---

## 2. CLI Commands

### cose sign

Create a signed COSE message or CWT.

```bash
# Create a CWT with ECDSA (default type)
qpki cose sign --cert signer.crt --key signer.key \
    --iss "https://issuer.example.com" \
    --sub "user-123" \
    --aud "https://api.example.com" \
    --exp 1h \
    -o token.cbor

qpki cose sign --cert pqc-signer.crt --key pqc-signer.key \
    --iss "https://issuer.example.com" \
    --sub "device-456" \
    --exp 24h \
    -o pqc-token.cbor

qpki cose sign --cert signer.crt --key signer.key \
    --pqc-key pqc-signer.key \
    --iss "https://issuer.example.com" \
    --sub "hybrid-user" \
    --exp 1h \
    -o hybrid-token.cbor

qpki cose sign --type sign1 --cert signer.crt --key signer.key \
    --data document.pdf \
    -o signed-document.cbor

qpki cose sign --cert signer.crt --key signer.key \
    --iss "https://issuer.example.com" \
    --claim "8=admin" \
    --claim "-65537=custom-value" \
    -o token-with-claims.cbor
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--type` | Message type: `cwt`, `sign1`, `sign` | cwt |
| `--cert` | Signer certificate (PEM) | Required |
| `--key` | Signer private key (PEM) | Required |
| `--pqc-key` | PQC private key for hybrid mode (PEM) | - |
| `--passphrase` | Key passphrase | - |
| `--data` | File to sign (for sign1/sign) | - |
| `-o, --out` | Output file (.cbor) | Required |

**CWT Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--iss` | Issuer claim | - |
| `--sub` | Subject claim | - |
| `--aud` | Audience claim | - |
| `--exp` | Expiration duration (e.g., `1h`, `24h`, `30m`) | - |
| `--claim` | Custom claim: `key=value` (can be repeated) | - |

### cose verify

Verify a COSE message signature.

```bash
# Verify with CA certificate
qpki cose verify token.cbor --ca ca.crt

qpki cose verify hybrid-token.cbor --ca ca.crt --pqc-ca pqc-ca.crt

qpki cose verify token.cbor --ca ca.crt --check-exp

qpki cose verify signed-document.cbor --ca ca.crt --data document.pdf
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--ca` | CA certificate(s) for chain verification | - |
| `--pqc-ca` | PQC CA certificate for hybrid verification | - |
| `--data` | Original data file (for detached signatures) | - |
| `--check-exp` | Verify expiration claims | true |

**Output:**

```
Verification: VALID
  Mode:        hybrid
  Algorithms:  ES256, ML-DSA-65
  Issuer:      https://issuer.example.com
  Subject:     hybrid-user
  Expires:     2025-02-06T12:00:00Z
```

### cose info

Display information about a COSE message.

```bash
qpki cose info token.cbor
```

**Output:**

```
COSE Message Info
=================

Type:         CWT
Mode:         hybrid
Content-Type:
Payload Size: 128 bytes
Payload:      a50166697373...

Signatures (2):
  [0] Algorithm: ES256 (id=-7)
      Key ID:    ab:cd:ef:12:34:...
      Certificate:
        Subject:    CN=signer.example.com
        Issuer:     CN=ca.example.com
        Not Before: 2025-01-01T00:00:00Z
        Not After:  2026-01-01T00:00:00Z
        Serial:     123456
        Thumbprint: ab:cd:ef:...
  [1] Algorithm: ML-DSA-65 (id=-49)
      Key ID:    12:34:56:78:...

CWT Claims:
  Issuer (iss):     https://issuer.example.com
  Subject (sub):    user-123
  Audience (aud):   https://api.example.com
  Expiration (exp): 2025-02-06T12:00:00Z
  Issued At (iat):  2025-02-05T12:00:00Z
  CWT ID (cti):     ab:cd:ef:12:34:56:78:90

  Validation: VALID
```

---

## 3. Signing Modes

### Classical Mode

Uses traditional cryptographic algorithms (ECDSA, EdDSA, RSA-PSS).

```bash
# ECDSA P-256
qpki cose sign --cert ec-signer.crt --key ec-signer.key \
    --iss "issuer" --sub "subject" -o token.cbor

qpki cose sign --cert ed-signer.crt --key ed-signer.key \
    --iss "issuer" --sub "subject" -o token.cbor

qpki cose sign --cert rsa-signer.crt --key rsa-signer.key \
    --iss "issuer" --sub "subject" -o token.cbor
```

### PQC Mode

Uses post-quantum algorithms (ML-DSA, SLH-DSA).

```bash
# ML-DSA-65 (recommended for general use)
qpki cose sign --cert mldsa-signer.crt --key mldsa-signer.key \
    --iss "issuer" --sub "subject" -o pqc-token.cbor

qpki cose sign --cert slhdsa-signer.crt --key slhdsa-signer.key \
    --iss "issuer" --sub "subject" -o slhdsa-token.cbor
```

### Hybrid Mode

Uses both classical and PQC signatures for quantum-safe transition.

```bash
# ECDSA + ML-DSA hybrid
qpki cose sign --cert ec-signer.crt --key ec-signer.key \
    --pqc-key mldsa-signer.key \
    --iss "issuer" --sub "subject" -o hybrid-token.cbor
```

**Hybrid verification requires BOTH signatures to be valid:**

```bash
qpki cose verify hybrid-token.cbor --ca ec-ca.crt --pqc-ca mldsa-ca.crt
```

---

## 4. Message Types

### CWT (CBOR Web Token)

A CWT is a COSE_Sign1 or COSE_Sign message where the payload contains CBOR-encoded claims.

```bash
# Create CWT
qpki cose sign --type cwt \
    --cert signer.crt --key signer.key \
    --iss "https://auth.example.com" \
    --sub "user@example.com" \
    --aud "https://api.example.com" \
    --exp 1h \
    -o access-token.cbor
```

**Structure:**
```
COSE_Sign1 [
  Protected: {alg: ES256, kid: "..."},
  Unprotected: {},
  Payload: CBOR({1: "issuer", 2: "subject", 4: 1738800000, ...}),
  Signature: bytes
]
```

### Sign1 (Single Signature)

A COSE_Sign1 message for signing arbitrary data.

```bash
# Sign a document
qpki cose sign --type sign1 \
    --cert signer.crt --key signer.key \
    --data document.pdf \
    -o signed-document.cbor
```

**CBOR Tag:** 18 (0xd2)

### Sign (Multiple Signatures)

A COSE_Sign message with multiple signatures, used for hybrid mode.

```bash
# Create multi-signature message
qpki cose sign --type sign \
    --cert ec-signer.crt --key ec-signer.key \
    --pqc-key mldsa-signer.key \
    --data document.pdf \
    -o hybrid-signed.cbor
```

**CBOR Tag:** 98 (0xd8 0x62)

**Structure:**
```
COSE_Sign [
  Protected: {},
  Unprotected: {},
  Payload: bytes,
  Signatures: [
    [Protected: {alg: ES256}, Unprotected: {}, Signature: bytes],
    [Protected: {alg: ML-DSA-65}, Unprotected: {}, Signature: bytes]
  ]
]
```

---

## 5. CWT Claims

### Standard Claims (RFC 8392)

| Claim | Key | Type | Description |
|-------|-----|------|-------------|
| iss | 1 | string | Issuer |
| sub | 2 | string | Subject |
| aud | 3 | string | Audience |
| exp | 4 | int | Expiration time (Unix timestamp) |
| nbf | 5 | int | Not before time (Unix timestamp) |
| iat | 6 | int | Issued at time (Unix timestamp) |
| cti | 7 | bytes | CWT ID (unique identifier) |

### Custom Claims

Use integer keys for custom claims. Positive integers are reserved for IANA registration; use negative integers for private claims.

```bash
# Add custom claims
qpki cose sign --cert signer.crt --key signer.key \
    --iss "issuer" \
    --claim "8=admin" \
    --claim "-65537=tenant-id-123" \
    -o token.cbor
```

### Claim Validation

```bash
# Verify with expiration check (default)
qpki cose verify token.cbor --ca ca.crt --check-exp

qpki cose verify token.cbor --ca ca.crt --check-exp=false
```

---

## 6. Use Cases

### IoT Device Attestation

```bash
# Create device credential
qpki credential enroll --profile ml/codesigning \
    --var cn="device-001.iot.example.com" \
    --id device-001

qpki cose sign --cert device-001.crt --key device-001.key \
    --iss "https://manufacturer.example.com" \
    --sub "device-001" \
    --claim "-65537=firmware-v2.1.0" \
    --claim "-65538=$(sha256sum firmware.bin | cut -d' ' -f1)" \
    --exp 8760h \
    -o device-attestation.cbor
```

### API Access Tokens

```bash
# Create access token
qpki cose sign --cert auth-server.crt --key auth-server.key \
    --iss "https://auth.example.com" \
    --sub "user@example.com" \
    --aud "https://api.example.com" \
    --exp 1h \
    --claim "8=read,write" \
    -o access-token.cbor

qpki cose verify access-token.cbor --ca auth-ca.crt
```

### Post-Quantum Transition

Use hybrid mode for quantum-safe transition:

```bash
# Create hybrid credentials
qpki credential enroll --profile ec/codesigning \
    --var cn="signer.example.com" --id ec-signer

qpki credential enroll --profile ml/codesigning \
    --var cn="pqc-signer.example.com" --id pqc-signer

qpki cose sign \
    --cert ec-signer.crt --key ec-signer.key \
    --pqc-key pqc-signer.key \
    --iss "https://issuer.example.com" \
    --sub "hybrid-protected-data" \
    --exp 24h \
    -o hybrid-token.cbor

qpki cose verify hybrid-token.cbor --ca ec-ca.crt --pqc-ca pqc-ca.crt
```

### Document Signing

```bash
# Sign a document with timestamp
qpki cose sign --type sign1 \
    --cert signer.crt --key signer.key \
    --data contract.pdf \
    -o signed-contract.cbor

qpki cose verify signed-contract.cbor --ca ca.crt --data contract.pdf
```

---

## 6. HSM Support

COSE signing supports HSM-stored keys via PKCS#11.

### Sign CWT with HSM Key

```bash
# Generate ML-DSA key in HSM
qpki key gen --algorithm ml-dsa-65 \
    --hsm-config ./hsm.yaml --key-label cose-signer

# Create CA with HSM key
qpki ca init --hsm-config ./hsm.yaml --key-label cose-signer \
    --profile ml/root-ca --var cn="COSE HSM CA" --ca-dir ./ca

# Sign CWT using HSM key
qpki cose sign --type cwt \
    --cert ./ca/ca.crt \
    --hsm-config ./hsm.yaml --key-label cose-signer \
    --iss "https://hsm-issuer.example.com" \
    --sub "user-123" --exp 1h \
    -o token.cbor

# Verify
qpki cose verify token.cbor --ca ./ca/ca.crt
```

### Hybrid Mode with HSM (UTIMACO)

```bash
# Generate both EC and ML-DSA keys with same label
qpki key gen --algorithm ecdsa-p384 \
    --hsm-config ./hsm.yaml --key-label hybrid-signer
qpki key gen --algorithm ml-dsa-65 \
    --hsm-config ./hsm.yaml --key-label hybrid-signer

# Verify both keys exist
qpki key info --hsm-config ./hsm.yaml --key-label hybrid-signer

# Create hybrid CA
qpki ca init --hsm-config ./hsm.yaml --key-label hybrid-signer \
    --profile hybrid/catalyst/root-ca \
    --var cn="Hybrid COSE CA" --ca-dir ./hybrid-ca

# Sign with hybrid mode (COSE_Sign with 2 signatures)
qpki cose sign --type sign \
    --cert ./hybrid-ca/ca.crt \
    --hsm-config ./hsm.yaml --key-label hybrid-signer \
    --data payload.bin -o hybrid-signed.cbor

# Verify
qpki cose verify hybrid-signed.cbor --ca ./hybrid-ca/ca.crt
```

### Supported HSM Algorithms

| Algorithm | SoftHSM | UTIMACO |
|-----------|:-------:|:-------:|
| ECDSA (P-256/384/521) | ✓ | ✓ |
| RSA (2048/4096) | ✓ | ✓ |
| ML-DSA (44/65/87) | ✗ | ✓ |
| Hybrid (EC + ML-DSA) | ✗ | ✓ |

> **Note**: SLH-DSA is not supported by any HSM and only works in software mode.

---

## See Also

- [CMS](CMS.md) - CMS signatures and encryption
- [Credentials](../end-entities/CREDENTIALS.md) - Key and certificate management
- [Crypto-Agility](../migration/CRYPTO-AGILITY.md) - Algorithm transition strategies
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) - COSE: Structures and Process
- [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392) - CBOR Web Token (CWT)
- [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) - ML-DSA for COSE
