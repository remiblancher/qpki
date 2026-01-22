# Crypto-Agility Guide

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. CA Crypto-Agility](#2-ca-crypto-agility)
- [3. Credential Crypto-Agility](#3-credential-crypto-agility)
- [4. Migration Scenarios](#4-migration-scenarios)
- [5. Best Practices](#5-best-practices)
- [6. Algorithm Reference](#6-algorithm-reference)
- [See Also](#see-also)

---

This guide covers algorithm migration for Certificate Authorities and credentials - transitioning from classical to post-quantum cryptography.

> **Related documentation:**
> - [CREDENTIALS.md](CREDENTIALS.md) - Credential management
> - [CA.md](CA.md) - CA operations and certificate issuance

## 1. Introduction

### 1.1 Why Crypto-Agility?

Crypto-agility is the ability to migrate cryptographic algorithms without redesigning the PKI infrastructure. This is critical for:

- **Quantum threat**: Quantum computers will eventually break RSA and ECC
- **Store Now, Decrypt Later (SNDL)**: Encrypted data captured today can be decrypted later
- **Algorithm deprecation**: Algorithms become weak over time (MD5, SHA-1, RSA-1024)
- **Compliance requirements**: Regulatory changes may require new algorithms

### 1.2 Migration Strategies

| Strategy | Path | Backward Compatibility |
|----------|------|------------------------|
| **Direct** | EC → ML-DSA | None - break with legacy |
| **Via Hybrid** | EC → Catalyst → ML-DSA | Yes - gradual transition |
| **Multi-Profile** | EC + ML-DSA simultaneously | Yes - parallel algorithms |

**Recommended path**: Classical → Hybrid → Post-Quantum

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Classical  │────►│   Hybrid    │────►│     PQC     │
│ (EC/RSA)    │     │  (Catalyst) │     │  (ML-DSA)   │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

## 2. CA Crypto-Agility

### 2.1 CA Rotation Overview

CA rotation creates a new version of the CA with different algorithms while maintaining certificate chain continuity.

```bash
# CA versioning after rotations:
ca/
├── ca.crt           # Symlink to active version
├── ca.key           # Symlink to active version
└── versions/
    ├── v1/          # Original (EC P-384)
    │   ├── ca.crt
    │   └── ca.key
    ├── v2/          # After first rotation (Catalyst)
    │   ├── ca.crt
    │   └── ca.key
    └── v3/          # After second rotation (ML-DSA)
        ├── ca.crt
        └── ca.key
```

### 2.2 ca rotate

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
| `--cross-sign` | | false | Cross-sign new CA with previous CA |
| `--dry-run` | | false | Preview rotation plan without executing |

**Examples:**

```bash
# Preview rotation plan (dry-run)
qpki ca rotate --ca-dir ./myca --dry-run

# Rotate to hybrid Catalyst
qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

# Rotate to pure PQC
qpki ca rotate --ca-dir ./myca --profile ml/root-ca

# Multi-profile rotation (both EC and ML-DSA)
qpki ca rotate --ca-dir ./myca --profile ec/root-ca --profile ml/root-ca

# Rotate with cross-signing
qpki ca rotate --ca-dir ./myca --profile ml/root-ca --cross-sign
```

### 2.3 ca activate

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
qpki ca activate --ca-dir ./myca --version v2
```

### 2.4 ca versions

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

**Output:**

```
CA: My Root CA

VERSION  STATUS    ALGORITHM       CREATED
-------  ------    ---------       -------
v1       archived  EC P-384        2025-01-01
v2       archived  Catalyst        2025-06-01
v3       active    ML-DSA-87       2026-01-01
```

### 2.5 Cross-Signing

Cross-signing creates a certificate chain between old and new CA versions, enabling gradual client migration.

```
┌──────────────────────────────────────────────────────────────────┐
│                    CA Rotation with --cross-sign                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                                                │
│  │  Old CA v1   │                                                │
│  │   (EC)       │──────────────────┐                             │
│  └──────────────┘                  │ signs                       │
│                                    ▼                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      New CA v2 (Catalyst)                 │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  versions/v2/ca.crt              (self-signed)            │   │
│  │  versions/v2/ca_crosssigned_by_v1.crt  (cross-signed)     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

When using `--cross-sign`, the rotation generates **two certificates**:

| File | Description |
|------|-------------|
| `versions/<new>/ca.crt` | Self-signed certificate (new CA signs itself) |
| `versions/<new>/ca_crosssigned_by_<old>.crt` | Cross-signed certificate (old CA signs new CA's public key) |

This allows:
- **New clients**: trust the new CA directly via `ca.crt`
- **Existing clients**: trust the new CA via the cross-signed certificate chain

**Usage:**

```bash
# Without cross-signing (default)
qpki ca rotate --ca-dir ./myca --profile ml/root-ca

# With cross-signing
qpki ca rotate --ca-dir ./myca --profile ml/root-ca --cross-sign
```

---

## 3. Credential Crypto-Agility

### 3.1 Multi-Profile Enrollment

Create credentials with multiple algorithm profiles from the start:

```bash
# Enroll with both EC and ML-DSA
qpki credential enroll --profile ec/tls-server --profile ml/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com
```

This creates a credential with two certificates:
- One EC P-256 certificate
- One ML-DSA certificate

### 3.2 credential rotate with Profile Changes

Modify algorithm profiles during credential rotation:

```bash
# Add a new profile
qpki credential rotate <cred-id> --add-profile ml/tls-client

# Remove an old profile
qpki credential rotate <cred-id> --remove-profile ec/tls-client

# Replace all profiles
qpki credential rotate <cred-id> --profile ml/tls-client
```

**Workflow:**

```bash
# 1. Rotate with profile changes
qpki credential rotate alice-xxx --add-profile ml/client
# Output: Version v20260105_abc123 (PENDING)

# 2. Activate the new version
qpki credential activate alice-xxx --version v20260105_abc123

# 3. Verify the change
qpki credential versions alice-xxx
```

---

## 4. Migration Scenarios

### 4.1 EC → Catalyst → ML-DSA (Full Transition)

The recommended path for organizations needing backward compatibility.

```bash
# Phase 1: Start with EC
qpki ca init --profile ec/root-ca --ca-dir ./ca --var cn="My CA"
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/tls-server --var cn=server.example.com

# Phase 2: Migrate to Catalyst (hybrid)
qpki ca rotate --ca-dir ./ca --profile hybrid/catalyst/root-ca
qpki ca activate --ca-dir ./ca --version v2

qpki credential rotate server-xxx --ca-dir ./ca --cred-dir ./credentials \
    --profile hybrid/catalyst/tls-server
qpki credential activate server-xxx --cred-dir ./credentials --version v2

# Phase 3: Migrate to pure ML-DSA
qpki ca rotate --ca-dir ./ca --profile ml/root-ca
qpki ca activate --ca-dir ./ca --version v3

qpki credential rotate server-xxx --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/tls-server
qpki credential activate server-xxx --cred-dir ./credentials --version v3
```

### 4.2 EC → ML-DSA (Direct Transition)

For environments that can break with legacy clients.

```bash
# Phase 1: Start with EC
qpki ca init --profile ec/root-ca --ca-dir ./ca --var cn="My CA"
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/tls-server --var cn=server.example.com

# Phase 2: Direct migration to ML-DSA
qpki ca rotate --ca-dir ./ca --profile ml/root-ca
qpki ca activate --ca-dir ./ca --version v2

qpki credential rotate server-xxx --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/tls-server
qpki credential activate server-xxx --cred-dir ./credentials --version v2
```

### 4.3 RSA → EC → ML-DSA (Legacy Migration)

For organizations with RSA legacy infrastructure.

```bash
# Phase 1: Legacy RSA (existing)
qpki ca init --profile rsa/root-ca --ca-dir ./ca --var cn="Legacy CA"

# Phase 2: Migrate to EC (modern classical)
qpki ca rotate --ca-dir ./ca --profile ec/root-ca
qpki ca activate --ca-dir ./ca --version v2

# Phase 3: Migrate to ML-DSA (post-quantum)
qpki ca rotate --ca-dir ./ca --profile ml/root-ca
qpki ca activate --ca-dir ./ca --version v3
```

### 4.4 Catalyst → ML-DSA (Hybrid to PQ)

For organizations already using hybrid certificates.

```bash
# Phase 1: Hybrid Catalyst (existing)
qpki ca init --profile hybrid/catalyst/root-ca --ca-dir ./ca --var cn="Hybrid CA"

# Phase 2: Migrate to pure ML-DSA
qpki ca rotate --ca-dir ./ca --profile ml/root-ca
qpki ca activate --ca-dir ./ca --version v2
```

### 4.5 Multi-Profile (Parallel Algorithms)

Run multiple algorithms simultaneously for maximum compatibility.

```bash
# Initialize CA with multiple profiles
qpki ca init --profile ec/root-ca --profile ml/root-ca \
    --ca-dir ./ca --var cn="Multi-Algorithm CA"

# Enroll credentials with multiple profiles
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/tls-server --profile ml/tls-server \
    --var cn=server.example.com

# Generate CRLs for all algorithms
qpki crl gen --ca-dir ./ca --all
```

---

## 5. Best Practices

### 5.1 Planning Migration

1. **Inventory**: List all CAs and credentials
2. **Test**: Set up a test environment
3. **Hybrid first**: Use Catalyst for gradual migration
4. **Rollback plan**: Keep old versions accessible

### 5.2 Timing Considerations

| Component | Migration Timing |
|-----------|------------------|
| Root CA | Rotate during scheduled maintenance |
| Issuing CA | After root CA is stable |
| Server credentials | After issuing CA |
| Client credentials | Last, with user coordination |

### 5.3 Monitoring

```bash
# Check CA versions
qpki ca versions --ca-dir ./ca

# List credential versions
qpki credential versions <cred-id>

# Verify certificates still valid
qpki cert verify server.crt --ca ./ca/ca.crt
```

### 5.4 Rollback

If issues occur, revert to the previous version:

```bash
# Activate previous CA version
qpki ca activate --ca-dir ./ca --version v1

# Activate previous credential version
qpki credential activate <cred-id> --version v1
```

---

## 6. Algorithm Reference

### 6.1 Classical Algorithms

| Algorithm | Security Level | Use Case |
|-----------|----------------|----------|
| EC P-256 | ~128-bit | General purpose |
| EC P-384 | ~192-bit | Root CAs |
| RSA-2048 | ~112-bit | Legacy compatibility |
| RSA-4096 | ~140-bit | Legacy high-security |

### 6.2 Post-Quantum Algorithms

| Algorithm | NIST Level | Use Case |
|-----------|------------|----------|
| ML-DSA-44 | Level 1 | General purpose |
| ML-DSA-65 | Level 3 | Most applications |
| ML-DSA-87 | Level 5 | Root CAs, high security |
| SLH-DSA | Level 1-5 | Hash-based fallback |

### 6.3 Hybrid Algorithms

| Type | Combination | Standard |
|------|-------------|----------|
| Catalyst | EC + ML-DSA | ITU-T X.509 9.8 |
| Composite | EC + ML-DSA | IETF draft |

---

## See Also

- [CA](CA.md) - CA operations and certificate issuance
- [CREDENTIALS](CREDENTIALS.md) - Credential management
- [PROFILES](PROFILES.md) - Certificate profile templates
- [CONCEPTS](CONCEPTS.md) - PQC and hybrid certificate concepts
