---
title: "PKI Fundamentals"
description: "Introduction to Public Key Infrastructure: certificates, keys, CAs, and trust chains."
---

# PKI Fundamentals

This document covers the foundational concepts of Public Key Infrastructure (PKI). If you're new to PKI or need a refresher, start here before diving into QPKI operations.

## 1. What is PKI?

**Public Key Infrastructure (PKI)** is a framework for managing digital identities and securing communications using cryptographic keys and certificates.

PKI answers three fundamental questions:
- **Who are you?** (Authentication)
- **Can I trust you?** (Trust chain verification)
- **Is this message really from you?** (Digital signatures)

### 1.1 The Problem PKI Solves

When two parties communicate over the internet, they face a challenge: how can Alice be sure she's really talking to Bob, and not an imposter?

PKI solves this by introducing a **trusted third party** (the Certificate Authority) that vouches for identities through **digital certificates**.

---

## 2. Certificates

### 2.1 What is a Certificate?

A **digital certificate** is an electronic document that binds a public key to an identity (person, server, organization). Think of it as a digital passport issued by a trusted authority.

A certificate states: *"This public key belongs to this identity, and I (the CA) vouch for it."*

### 2.2 X.509 Structure

Certificates follow the **X.509 standard** (RFC 5280). Key fields:

| Field | Description | Example |
|-------|-------------|---------|
| **Subject** | Who the certificate is issued to | `CN=www.example.com, O=ACME Corp` |
| **Issuer** | Who signed the certificate | `CN=ACME Root CA` |
| **Validity** | When the certificate is valid | `Not Before: 2025-01-01, Not After: 2026-01-01` |
| **Public Key** | The subject's public key | ECDSA P-256, RSA 2048, ML-DSA-65... |
| **Serial Number** | Unique identifier within the CA | `0x03` |
| **Extensions** | Additional constraints and information | Key Usage, SANs, CRL URLs... |
| **Signature** | CA's digital signature over all fields | Proves authenticity |

### 2.3 Certificate Types

| Type | Description | Example |
|------|-------------|---------|
| **Root CA** | Self-signed, trust anchor | Corporate Root CA |
| **Intermediate/Issuing CA** | Signed by Root, issues end-entity certs | Issuing CA |
| **End-Entity** | The final certificate for a service/user | TLS server, code signing |

---

## 3. Keys

### 3.1 Public and Private Keys

PKI uses **asymmetric cryptography** with key pairs:

| Key | Who Has It | Purpose |
|-----|------------|---------|
| **Private Key** | Only the owner (kept secret) | Sign data, decrypt messages |
| **Public Key** | Anyone (in certificate) | Verify signatures, encrypt messages |

The mathematical relationship between the keys ensures:
- Only the private key can create valid signatures
- Only the private key can decrypt messages encrypted with the public key
- The private key cannot be derived from the public key

### 3.2 Key Types

| Type | Purpose | Algorithms |
|------|---------|------------|
| **Signature** | Sign certificates, documents, code | ECDSA, RSA, Ed25519, ML-DSA, SLH-DSA |
| **Key Encapsulation** | Establish shared secrets for encryption | ECDH, RSA, ML-KEM |

### 3.3 Key Storage

Private keys must be protected. Common storage options:

| Storage | Security | Use Case |
|---------|----------|----------|
| File (PEM/DER) | Low | Development, testing |
| Encrypted file (PKCS#8) | Medium | Production with passphrase |
| HSM (PKCS#11) | High | Enterprise, compliance |

---

## 4. Certificate Authority (CA)

### 4.1 What is a CA?

A **Certificate Authority (CA)** is a trusted entity that issues and signs certificates. The CA vouches for the identity of certificate subjects.

### 4.2 CA Hierarchy

Most PKIs use a hierarchical structure:

```
Root CA (offline, trust anchor)
    │
    ├── Issuing CA A (online, issues TLS certs)
    │       ├── www.example.com
    │       └── api.example.com
    │
    └── Issuing CA B (online, issues code signing certs)
            └── Developer certificate
```

| CA Type | Description | Typical Validity |
|---------|-------------|------------------|
| **Root CA** | Self-signed, kept offline, trust anchor | 20+ years |
| **Issuing CA** | Signed by Root, issues end-entity certs | 5-10 years |

### 4.3 Why Hierarchies?

- **Security**: Root CA stays offline (air-gapped), protected from compromise
- **Flexibility**: Multiple Issuing CAs for different purposes
- **Revocation**: Compromise of Issuing CA doesn't require replacing the Root

---

## 5. Certificate Signing Request (CSR)

### 5.1 What is a CSR?

A **Certificate Signing Request (CSR)** is a message sent to a CA to request a certificate. It contains:

1. The subject's **public key**
2. The requested **identity** (subject name, SANs)
3. A **signature** proving the requester owns the private key

### 5.2 CSR Workflow

```
1. Generate key pair         →  private.key + public key
2. Create CSR                →  request.csr (includes public key + identity)
3. Submit CSR to CA          →  CA verifies identity
4. CA issues certificate     →  certificate.crt (signed by CA)
5. Deploy certificate        →  Use with private key
```

The private key never leaves the requester's system.

---

## 6. Trust Chain

### 6.1 Chain of Trust

A **trust chain** connects an end-entity certificate back to a trusted root:

```
End-Entity Certificate (www.example.com)
    ↓ signed by
Issuing CA Certificate
    ↓ signed by
Root CA Certificate (trusted)
```

### 6.2 Certificate Verification

When verifying a certificate, the verifier:

1. Checks the signature on the end-entity cert (using Issuing CA's public key)
2. Checks the signature on the Issuing CA cert (using Root CA's public key)
3. Confirms the Root CA is in the local trust store
4. Validates dates, extensions, and revocation status

If any step fails, the certificate is rejected.

### 6.3 Trust Stores

Operating systems and browsers maintain **trust stores** containing trusted Root CA certificates:

| Platform | Trust Store Location |
|----------|---------------------|
| macOS | Keychain |
| Windows | Certificate Store |
| Linux | `/etc/ssl/certs/` |
| Browsers | Built-in + OS trust store |

---

## 7. Certificate Lifecycle

### 7.1 Lifecycle Stages

```
   Issue           Use             Renew/Revoke         Expire
     │               │                   │                 │
     ▼               ▼                   ▼                 ▼
┌─────────┐    ┌─────────┐         ┌─────────┐       ┌─────────┐
│ Created │───▶│ Active  │────────▶│ Revoked │   or  │ Expired │
└─────────┘    └─────────┘         └─────────┘       └─────────┘
```

### 7.2 Revocation

When a certificate must be invalidated before expiry (key compromise, employee departure):

| Method | Description | Pros | Cons |
|--------|-------------|------|------|
| **CRL** | Signed list of revoked serial numbers | Simple, offline verification | Can grow large, update delay |
| **OCSP** | Real-time status check via HTTP | Current status, small responses | Requires online responder |

---

## 8. File Formats

### 8.1 Encoding Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **PEM** | Base64 with `-----BEGIN/END-----` headers | Text files, human-readable |
| **DER** | Binary ASN.1 | Compact, machine processing |

### 8.2 Common Extensions

| Extension | Content | Format |
|-----------|---------|--------|
| `.crt`, `.cer`, `.pem` | Certificate | PEM or DER |
| `.key` | Private key | PEM |
| `.csr` | Certificate Signing Request | PEM |
| `.p12`, `.pfx` | Certificate + private key bundle | PKCS#12 (binary) |
| `.crl` | Certificate Revocation List | PEM or DER |

### 8.3 PEM Examples

**Certificate:**
```
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPqAOMA0GCSqGSIb3DQEBCwUAMBExDzAN...
-----END CERTIFICATE-----
```

**Private Key:**
```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----
```

---

## See Also

- [Post-Quantum Cryptography](POST-QUANTUM.md) - PQC algorithms and hybrid certificates
- [Glossary](../reference/GLOSSARY.md) - PKI and PQC terminology
- [CA Operations](../build-pki/CA.md) - CA initialization and management
- [Keys & CSR](../build-pki/KEYS.md) - Key generation and CSR operations
