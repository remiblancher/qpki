---
title: "Credentials"
description: "Credential management - creating, rotating, and revoking certificate bundles with coupled lifecycle management."
---

# Credentials

This guide covers credential management - creating, rotating, and revoking certificate bundles with coupled lifecycle management.

## 1. What is a Credential?

A **credential** is a managed bundle of **private key(s) + certificate(s)** with coupled lifecycle management. All certificates in a credential are created, renewed, and revoked together.

### Why Credentials?

Traditional PKI tools manage keys and certificates separately, requiring manual coordination for:
- Key generation → CSR → Certificate issuance → Deployment
- Renewal (repeat the full cycle)
- Revocation (track which certs belong together)

**Credentials** encapsulate this end-entity workflow:
- Single command to enroll (key + cert created together)
- Atomic rotation (all certs renewed at once)
- Grouped revocation (all certs added to CRL together)
- Multi-algorithm support (classical + PQC in one bundle)

### 1.1 Credential vs Certificate

| Aspect | Certificate | Credential |
|--------|-------------|------------|
| **Scope** | Single certificate | Bundle of related certificates |
| **Keys** | Separate management | Integrated lifecycle |
| **Renewal** | Manual per-cert | Rotate all at once |
| **Revocation** | Individual | All certs together |
| **Multi-algorithm** | One algorithm | Multiple profiles |

### 1.2 Credential Structure

```
credentials/<credential-id>/
├── credential.meta.json  # Metadata (status, certificates, validity)
├── certificates.pem      # All certificates (PEM, concatenated)
└── private-keys.pem      # All private keys (PEM, encrypted)
```

### 1.3 Versioned Credentials

After rotation, credentials have versions:

```
credentials/<credential-id>/
├── credential.meta.json  # Points to active version
└── versions/
    ├── v20260101_abc123/  # archived
    │   ├── certificates.pem
    │   └── private-keys.pem
    └── v20260105_def456/  # active
        ├── certificates.pem
        └── private-keys.pem
```

| Status | Description |
|--------|-------------|
| `pending` | Awaiting activation after rotation |
| `active` | Currently in use |
| `archived` | Superseded by newer version |

### 1.4 Certificate Roles

| Role | Description |
|------|-------------|
| `signature` | Standard signature certificate |
| `signature-classical` | Classical signature in hybrid-separate mode |
| `signature-pqc` | PQC signature in hybrid-separate mode |
| `encryption` | Standard encryption certificate |
| `encryption-classical` | Classical encryption in hybrid-separate mode |
| `encryption-pqc` | PQC encryption in hybrid-separate mode |

### 1.5 Credential Status

| Status | Description |
|--------|-------------|
| `pending` | Credential created but not yet active |
| `valid` | Credential is active and usable |
| `expired` | Validity period has ended |
| `revoked` | Credential was revoked (all certs added to CRL) |

### 1.6 Lifecycle Workflow

```
┌─────────────┐
│   ENROLL    │
│  (pending)  │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│    VALID    │────►│   EXPIRED   │
│             │     │ (automatic) │
└──────┬──────┘     └─────────────┘
       │
       │ revoke
       ▼
┌─────────────┐
│   REVOKED   │
│  (on CRL)   │
└─────────────┘
```

---

## 2. CLI Commands

### credential enroll

Create a new credential with key(s) and certificate(s).

```bash
qpki credential enroll [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | required | Profile to use (repeatable for multi-profile) |
| `--var` | | | Variable value (e.g., `cn=example.com`). Repeatable. |
| `--var-file` | | | YAML file with variable values |
| `--ca-dir` | `-d` | ./ca | CA directory (for signing) |
| `--cred-dir` | `-c` | ./credentials | Credentials directory |
| `--id` | | auto | Custom credential ID |
| `--passphrase` | `-p` | "" | Passphrase for private keys |

**Output:**

```bash
qpki credential enroll --profile ec/tls-client --var cn=Alice

#   ├── credential.meta.json  # Metadata
#   └── private-keys.pem      # Private key(s)
```

**Examples:**

```bash
# Basic enrollment (single profile)
qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --var email=alice@example.com

qpki credential enroll --profile ec/client --profile ml/client \
    --var cn=alice@example.com

qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --var email=alice@example.com

qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com,www.example.com

qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --id alice-prod

qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --passphrase "secret"

qpki credential enroll --ca-dir ./myca --cred-dir ./myca/credentials \
    --profile ec/tls-server --var cn=server.example.com
```

**ML-KEM (encryption) profiles:**

For ML-KEM profiles, a signature profile must be listed first (RFC 9883 proof of possession):

```bash
# Correct: signature profile before KEM profile
qpki credential enroll --profile ec/client --profile ml-kem/client \
    --var cn=alice@example.com

qpki credential enroll --profile ml-kem/client --var cn=alice@example.com
```

### credential list

List all credentials.

```bash
qpki credential list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cred-dir` | `-c` | ./credentials | Credentials directory |

**Example:**

```bash
qpki credential list
qpki credential list --cred-dir ./myca/credentials
```

### credential info

Show details of a specific credential.

```bash
qpki credential info <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cred-dir` | `-c` | ./credentials | Credentials directory |

**Example:**

```bash
qpki credential info alice-20250115-abc123
```

### credential rotate

Rotate a credential with new certificates. Creates a **PENDING** version that must be activated.

```bash
qpki credential rotate <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory (for signing) |
| `--cred-dir` | `-c` | ./credentials | Credentials directory |
| `--profile` | `-P` | | Replace all profiles (overrides add/remove) |
| `--add-profile` | | | Add profile(s) to current set |
| `--remove-profile` | | | Remove profile(s) from current set |
| `--keep-keys` | | false | Reuse existing keys (certificate renewal only) |
| `--passphrase` | `-p` | "" | Passphrase for private keys |
| `--hsm-config` | | | HSM configuration file for key generation |
| `--key-label` | | | HSM key label prefix |

**Workflow:**

After rotation, the new version must be explicitly activated:

```bash
qpki credential rotate <credential-id>

qpki credential activate <credential-id> --version v20260105_abc123
```

This allows:
- Review before activation
- Gradual rollout
- Rollback possibility

**Examples:**

```bash
# Simple rotation (generates new keys)
qpki credential rotate alice-xxx
# Output: Version v20260105_abc123 (PENDING)

qpki credential rotate alice-xxx --keep-keys

qpki credential rotate alice-xxx --add-profile ml/tls-client

qpki credential rotate alice-xxx --remove-profile ec/tls-client

qpki credential rotate alice-xxx \
    --profile ec/tls-client --profile ml/tls-client

qpki credential rotate alice-xxx --ca-dir ./myca --cred-dir ./myca/credentials
```

### credential activate

Activate a pending credential version after rotation.

```bash
qpki credential activate <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cred-dir` | `-c` | ./credentials | Credentials directory |
| `--version` | | (required) | Version to activate |

**Example:**

```bash
qpki credential activate alice-xxx --version v20260105_abc123
```

### credential versions

List all versions of a credential.

```bash
qpki credential versions <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cred-dir` | `-c` | ./credentials | Credentials directory |

**Example:**

```bash
qpki credential versions alice-xxx
```

**Output:**

```
Credential: alice-xxx

VERSION              STATUS     PROFILES                       CREATED
-------              ------     --------                       -------
v20260101_abc123     archived   ec/tls-client                  2026-01-01
v20260105_def456     active     ec/tls-client, ml/tls-client   2026-01-05
```

### credential revoke

Revoke all certificates in a credential.

```bash
qpki credential revoke <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory (for CRL/index update) |
| `--cred-dir` | `-c` | ./credentials | Credentials directory |
| `--reason` | `-r` | unspecified | Revocation reason |

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

**Example:**

```bash
qpki credential revoke alice-20250115-abc123 --reason keyCompromise
```

### credential export

Export credential certificates.

```bash
qpki credential export <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory (for chain bundle) |
| `--cred-dir` | `-c` | ./credentials | Credentials directory |
| `--out` | `-o` | stdout | Output file |
| `--format` | `-f` | pem | Output format: pem, der |
| `--bundle` | `-b` | cert | Bundle type: cert, chain, all |
| `--version` | `-v` | | Export specific version |
| `--all` | | false | Export all versions |

**Bundle types:**

| Bundle | Description |
|--------|-------------|
| `cert` | Certificate(s) only (default) |
| `chain` | Certificates + issuing CA chain |
| `all` | All certificates from all algorithm families |

**Examples:**

```bash
# Export active certificates as PEM
qpki credential export alice-xxx

qpki credential export alice-xxx --format der --out alice.der

qpki credential export alice-xxx --bundle chain --out alice-chain.pem

qpki credential export alice-xxx --version v20260105_abc123

qpki credential export alice-xxx --all --out alice
```

---

## 3. Common Workflows

### 3.1 TLS Server Certificate

```bash
# 1. Enroll server credential
qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com,www.example.com

cp ./credentials/<id>/certificates.pem /etc/ssl/server.crt
cp ./credentials/<id>/private-keys.pem /etc/ssl/server.key

qpki credential rotate <id>
qpki credential activate <id> --version <new-version>

```

### 3.2 mTLS (Mutual TLS)

```bash
# 1. Create CA
qpki ca init --profile ec/root-ca --ca-dir ./mtls-ca --var cn="mTLS CA"

qpki credential enroll --ca-dir ./mtls-ca --cred-dir ./mtls-ca/credentials \
    --profile ec/tls-server \
    --var cn=server.local --var dns_names=server.local

qpki credential enroll --ca-dir ./mtls-ca --cred-dir ./mtls-ca/credentials \
    --profile ec/tls-client \
    --var cn=client-a@example.com --id client-a

qpki credential enroll --ca-dir ./mtls-ca --cred-dir ./mtls-ca/credentials \
    --profile ec/tls-client \
    --var cn=client-b@example.com --id client-b

# ssl_certificate server.crt;
# ssl_client_certificate mtls-ca/ca.crt;
```

### 3.3 Code Signing

```bash
# 1. Enroll code signing credential
qpki credential enroll --profile ec/code-signing \
    --var cn="My Company Code Signing" \
    --var organization="My Company"

openssl cms -sign -in binary.exe \
    -signer ./credentials/<id>/certificates.pem \
    -inkey ./credentials/<id>/private-keys.pem \
    -out binary.exe.sig -binary

openssl cms -verify -in binary.exe.sig \
    -content binary.exe -CAfile ./ca/ca.crt
```

### 3.4 Certificate Rotation

```bash
# 1. Check credential expiration
qpki credential info <credential-id>

qpki credential rotate <credential-id>

qpki credential versions <credential-id>

qpki credential activate <credential-id> --version v20260105_abc123


qpki credential revoke <old-credential-id> --reason superseded
```

### 3.5 Crypto-Agility Migration

For detailed migration scenarios, see [Crypto-Agility](../migration/CRYPTO-AGILITY.md).

```bash
# Start with classical certificates
qpki credential enroll --profile ec/client --var cn=alice@example.com

qpki credential rotate alice-xxx --add-profile ml/client
qpki credential activate alice-xxx --version <new-version>

qpki credential rotate alice-xxx --remove-profile ec/client
qpki credential activate alice-xxx --version <new-version>
```

---

## 4. Integration with CMS, TSA, OCSP

### 4.1 Signing with Credentials

The `--credential` flag allows loading certificate and key directly from the credential store:

```bash
# CMS signing
qpki cms sign --data doc.pdf --credential signer --out doc.p7s

qpki tsa sign --data doc.pdf --credential tsa --out doc.tsr

qpki ocsp sign --serial 0A1B2C --status good --ca ca.crt \
    --credential ocsp-responder --out response.ocsp
```

### 4.2 Server Mode (TSA/OCSP)

Credentials are particularly well-suited for long-running servers because the **rotate → activate** workflow enables certificate renewal without service interruption:

```bash
# Start server with credential
qpki tsa serve --port 8318 --credential tsa-server
# or
qpki ocsp serve --port 8080 --ca-dir ./ca --credential ocsp-responder

qpki credential rotate tsa-server

qpki credential versions tsa-server
qpki credential activate tsa-server --version v2

```

### 4.3 Multi-Version Decryption

When using `--credential` with `cms decrypt`, QPKI automatically searches **all versions** of the credential to find a matching decryption key. This is essential after key rotation: data encrypted with an old key can still be decrypted.

```bash
# Encrypt with current active key
qpki cms encrypt --recipient ./credentials/bob/certificates.pem \
    --in secret.txt --out secret.p7m

qpki credential rotate bob
qpki credential activate bob --version v2

qpki cms decrypt --credential bob --in secret.p7m --out secret.txt
```

---

## See Also

- [CA](../build-pki/CA.md) - CA initialization and management
- [Keys](../build-pki/KEYS.md) - Key generation and CSR operations
- [CLI Reference](../reference/CLI.md) - Complete command reference
- [Profiles](../build-pki/PROFILES.md) - Certificate profile templates
- [Crypto-Agility](../migration/CRYPTO-AGILITY.md) - Algorithm migration guide
- [Troubleshooting](../reference/TROUBLESHOOTING.md) - Common errors and solutions
