# User Guide

This guide covers installation, CLI usage, and common workflows for Post-Quantum PKI (QPKI).

## 1. Installation

### Download Pre-built Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/remiblancher/post-quantum-pki/releases/latest).

**Linux / macOS:**
```bash
# Download (replace VERSION, OS, and ARCH as needed)
curl -LO https://github.com/remiblancher/post-quantum-pki/releases/latest/download/qpki_VERSION_OS_ARCH.tar.gz

# Extract
tar -xzf qpki_*.tar.gz

# Install
sudo mv qpki /usr/local/bin/

# Verify
qpki --version
```

**Available platforms:**

| OS | Architecture | File |
|----|--------------|------|
| Linux | amd64 | `qpki_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `qpki_VERSION_linux_arm64.tar.gz` |
| macOS | Intel | `qpki_VERSION_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `qpki_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `qpki_VERSION_windows_amd64.zip` |

**Linux packages:**
```bash
# Debian/Ubuntu
sudo dpkg -i qpki_VERSION_linux_amd64.deb

# RHEL/Fedora
sudo rpm -i qpki_VERSION_linux_amd64.rpm
```

### Install via Homebrew (macOS)

```bash
brew tap remiblancher/qpki
brew install qpki
```

### From Source

```bash
git clone https://github.com/remiblancher/post-quantum-pki.git
cd pki
go build -o qpki ./cmd/qpki
sudo mv qpki /usr/local/bin/
```

### Go Install

```bash
go install github.com/remiblancher/post-quantum-pki/cmd/qpki@latest
```

### Verify Installation

```bash
qpki version
qpki --help
```

## 2. CLI Reference

### 2.1 ca init

Initialize a new Certificate Authority.

```bash
qpki ca init [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--name` | `-n` | required | CA common name |
| `--org` | `-o` | "" | Organization name |
| `--country` | `-c` | "" | Country code (2 letters) |
| `--profile` | `-P` | "" | CA profile (e.g., ec/root-ca, hybrid/catalyst/root-ca) |
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm (ignored if --profile is set) |
| `--hybrid-algorithm` | | "" | PQC algorithm for hybrid mode |
| `--dir` | `-d` | ./ca | CA directory |
| `--validity` | | 10 | Validity in years (ignored if --profile is set) |
| `--path-len` | | 1 | Path length constraint (ignored if --profile is set) |
| `--passphrase` | `-p` | "" | Key passphrase |
| `--parent` | | "" | Parent CA directory (creates subordinate CA) |
| `--parent-passphrase` | | "" | Parent CA key passphrase |

**Examples:**

```bash
# Using a profile (recommended)
qpki ca init --name "My Root CA" --profile ec/root-ca --dir ./myca

# Hybrid Catalyst CA (ITU-T - backward compatible)
qpki ca init --name "Catalyst Root CA" --profile hybrid/catalyst/root-ca --dir ./catalyst-ca

# Hybrid Composite CA (IETF draft - stricter security)
qpki ca init --name "Composite Root CA" --profile hybrid/composite/root-ca --dir ./composite-ca

# Subordinate CA using a profile
qpki ca init --name "Issuing CA" --profile ec/issuing-ca \
  --dir ./issuing-ca --parent ./rootca

# CA with passphrase-protected key
qpki ca init --name "Secure CA" --profile ec/root-ca --passphrase "mysecret" --dir ./secure-ca

# PQC root CA with ML-DSA
qpki ca init --name "PQC Root CA" --profile ml-dsa/root-ca --dir ./pqc-ca
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

### 2.2 cert issue

Issue a certificate from a Certificate Signing Request (CSR).

```bash
qpki cert issue [flags]
```

**Note:** This command requires a CSR file (`--csr`). For direct issuance with automatic key generation, use `qpki credential enroll` instead.

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

### 2.3 key gen

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

| Algorithm | Description |
|-----------|-------------|
| ecdsa-p256 | ECDSA with NIST P-256 curve |
| ecdsa-p384 | ECDSA with NIST P-384 curve |
| ecdsa-p521 | ECDSA with NIST P-521 curve |
| ed25519 | Edwards-curve DSA |
| rsa-2048 | RSA 2048-bit |
| rsa-4096 | RSA 4096-bit |
| ml-dsa-44 | ML-DSA (Dilithium) Level 1 |
| ml-dsa-65 | ML-DSA (Dilithium) Level 3 |
| ml-dsa-87 | ML-DSA (Dilithium) Level 5 |

**Examples:**

```bash
# ECDSA P-256 key
qpki key gen --algorithm ecdsa-p256 --out key.pem

# Ed25519 key
qpki key gen --algorithm ed25519 --out ed25519.key

# PQC key (ML-DSA)
qpki key gen --algorithm ml-dsa-65 --out pqc.key

# Encrypted key
qpki key gen --algorithm ecdsa-p384 --out secure.key --passphrase "secret"

# Extract public key from private key
qpki key pub --key key.pem --out key.pub
```

### 2.4 cert csr

Generate a Certificate Signing Request (CSR) for submission to a CA.

```bash
qpki cert csr [flags]
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
| Hybrid | Classical + PQC dual signatures | `--algorithm ecdsa-p256 --hybrid ml-dsa-65` |

**Examples:**

```bash
# Classical ECDSA CSR
qpki cert csr --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com -o server.csr

# PQC ML-DSA CSR (direct signature)
qpki cert csr --algorithm ml-dsa-65 --keyout mldsa.key \
    --cn alice@example.com -o mldsa.csr

# PQC ML-KEM CSR with RFC 9883 attestation
# (requires an existing signature certificate for attestation)
qpki cert csr --algorithm ml-kem-768 --keyout kem.key \
    --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key \
    -o kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
qpki cert csr --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key \
    --cn example.com -o hybrid.csr

# CSR with existing key
qpki cert csr --key existing.key --cn server.example.com -o server.csr
```

**RFC 9883 (ML-KEM Attestation):**

ML-KEM keys cannot sign (they're Key Encapsulation Mechanisms). To prove possession of an ML-KEM private key, RFC 9883 defines the `privateKeyPossessionStatement` attribute. This requires:

1. An existing signature certificate (`--attest-cert`)
2. The corresponding private key (`--attest-key`)

The CSR is signed by the attestation key, and includes a reference to the attestation certificate. The CA verifies the attestation chain before issuing the ML-KEM certificate.

### 2.5 cert revoke

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

### 2.6 cert gen-crl

Generate a Certificate Revocation List.

```bash
qpki cert gen-crl [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |

**Examples:**

```bash
# Generate CRL valid for 7 days
qpki cert gen-crl --ca-dir ./myca

# Generate CRL valid for 30 days
qpki cert gen-crl --ca-dir ./myca --days 30
```

### 2.7 inspect

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

### 2.8 cert list

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

### 2.9 profile

Manage certificate policy templates (profiles).

```bash
qpki profile <subcommand> [flags]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List available profiles |
| `info <name>` | Show details of a profile |
| `validate <file>` | Validate a profile YAML file |
| `install` | Install default profiles to CA |

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--overwrite` | | false | Overwrite existing profiles (install) |

**Examples:**

```bash
# Install default profiles
qpki profile install --dir ./ca

# List available profiles
qpki profile list --dir ./ca

# View profile details
qpki profile info hybrid-catalyst --dir ./ca

# Validate custom profile
qpki profile validate my-profile.yaml
```

### 2.10 credential enroll

A credential is a managed bundle of **private key(s) + certificate(s)** with coupled lifecycle management (enrollment, renewal, revocation).

`credential enroll` generates everything in one command:

```bash
qpki credential enroll --profile ec/tls-client --var cn=Alice --ca-dir ./ca

# Output: ca/credentials/<id>/
#   ├── credential.json     # Metadata
#   ├── certificates.pem    # Certificate(s)
#   └── private-keys.pem    # Private key(s)
```

```bash
qpki credential enroll [flags]
```

**Note:** This is the recommended way to issue certificates. For CSR-based workflows, use `qpki cert issue`.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | required | Profile to use (repeatable for multi-profile) |
| `--var` | | | Variable value (e.g., `cn=example.com`). Repeatable. |
| `--var-file` | | | YAML file with variable values |
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--id` | | auto | Custom credential ID |
| `--passphrase` | `-p` | "" | Passphrase for private keys |

**Examples:**

```bash
# Basic enrollment (single profile)
qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# Multi-profile enrollment (crypto-agility)
qpki credential enroll --profile ec/client --profile ml/client \
    --var cn=alice@example.com --ca-dir ./ca

# Hybrid Catalyst enrollment
qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# TLS server with DNS SANs
qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com,www.example.com --ca-dir ./ca

# With custom credential ID
qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --id alice-prod --ca-dir ./ca

# With passphrase protection
qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --passphrase "secret" --ca-dir ./ca
```

**Important:** For ML-KEM (encryption) profiles, a signature profile must be listed first. This is required by RFC 9883 for proof of possession:

```bash
# Correct: signature profile before KEM profile
qpki credential enroll --profile ec/client --profile ml-kem/client \
    --var cn=alice@example.com --ca-dir ./ca

# Error: KEM profile requires a signature profile first
qpki credential enroll --profile ml-kem/client --var cn=alice@example.com --ca-dir ./ca
# Error: KEM profile "ml-kem/client" requires a signature profile first (RFC 9883)
```

### 2.11 credential (list, info, renew, revoke, export)

Manage certificate credentials.

```bash
qpki credential <subcommand> [flags]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List all credentials |
| `info <credential-id>` | Show credential details |
| `renew <credential-id>` | Renew all certificates in credential |
| `revoke <credential-id>` | Revoke all certificates in credential |
| `export <credential-id>` | Export credential certificates to PEM |

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-c` | ./ca | CA directory |
| `--passphrase` | `-p` | "" | Passphrase for private keys |
| `--reason` | `-r` | unspecified | Revocation reason |
| `--out` | `-o` | stdout | Output file (export) |
| `--keys` | | false | Include private keys (export) |

**Examples:**

```bash
# List credentials
qpki credential list --ca-dir ./ca

# View credential details
qpki credential info alice-20250115-abc123 --ca-dir ./ca

# Renew a credential
qpki credential renew alice-20250115-abc123 --ca-dir ./ca

# Renew with crypto migration (add/change profiles)
qpki credential renew alice-20250115-abc123 \
    --profile ec/client --profile ml/client --ca-dir ./ca

# Revoke a credential
qpki credential revoke alice-20250115-abc123 --ca-dir ./ca --reason keyCompromise

# Export certificates
qpki credential export alice-20250115-abc123 --ca-dir ./ca --out alice.pem

# Export with private keys
qpki credential export alice-20250115-abc123 --ca-dir ./ca \
    --keys --passphrase "secret" --out alice-full.pem
```

### 2.12 verify

Verify a certificate's validity and revocation status.

```bash
qpki verify [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cert` | | required | Certificate to verify (PEM) |
| `--ca` | | required | CA certificate (PEM) |
| `--crl` | | | CRL file for revocation check (PEM/DER) |
| `--ocsp` | | | OCSP responder URL |

**Checks performed:**
- Certificate signature (signed by CA)
- Validity period (not before / not after)
- Revocation status (if --crl or --ocsp provided)

**Examples:**

```bash
# Basic validation
qpki verify --cert server.crt --ca ca.crt

# With CRL check
qpki verify --cert server.crt --ca ca.crt --crl ca/crl/ca.crl

# With OCSP check
qpki verify --cert server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

## 3. Credentials

Credentials group related certificates with a **coupled lifecycle** - all certificates in a credential are created, renewed, and revoked together.

### 3.1 Credential Structure

```
credentials/<credential-id>/
├── credential.json       # Metadata (status, certificates, validity)
├── certificates.pem      # All certificates (PEM, concatenated)
└── private-keys.pem      # All private keys (PEM, encrypted)
```

### 3.2 Certificate Roles

| Role | Description |
|------|-------------|
| `signature` | Standard signature certificate |
| `signature-classical` | Classical signature in hybrid-separate mode |
| `signature-pqc` | PQC signature in hybrid-separate mode |
| `encryption` | Standard encryption certificate |
| `encryption-classical` | Classical encryption in hybrid-separate mode |
| `encryption-pqc` | PQC encryption in hybrid-separate mode |

### 3.3 Credential Status

| Status | Description |
|--------|-------------|
| `pending` | Credential created but not yet active |
| `valid` | Credential is active and usable |
| `expired` | Validity period has ended |
| `revoked` | Credential was revoked (all certs added to CRL) |

### 3.4 Lifecycle Workflow

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

## 4. Common Workflows

### 4.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
qpki ca init --name "Root CA" --org "My Company" \
  --algorithm ecdsa-p384 --validity 20 --pathlen 1 \
  --dir ./root-ca

# 2. Create issuing CA (signed by root, with full CA structure)
qpki ca init --name "Issuing CA" --org "My Company" \
  --dir ./issuing-ca --parent ./root-ca

# 3. Issue server certificates from issuing CA
qpki credential enroll --ca-dir ./issuing-ca --profile ec/tls-server \
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

### 4.2 Set Up mTLS

```bash
# 1. Create CA
qpki ca init --name "mTLS CA" --dir ./mtls-ca

# 2. Issue server certificate
qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-server \
  --var cn=server.local --var dns_names=server.local

# 3. Issue client certificates
qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-a@example.com --id client-a

qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-b@example.com --id client-b

# 4. Configure server (example with nginx)
# ssl_certificate server.crt;
# ssl_certificate_key server.key;
# ssl_client_certificate mtls-ca/ca.crt;
# ssl_verify_client on;
```

### 4.3 Certificate Rotation with Credentials

```bash
# 1. Renew credential before expiration
qpki credential renew <credential-id> --ca-dir ./myca

# 2. Deploy new certificates from credential

# 3. Old certificates expire naturally
# Or revoke if needed:
qpki credential revoke <old-credential-id> --ca-dir ./myca --reason superseded
```

### 4.4 Crypto-Agility Migration

```bash
# Start with classical certificates
qpki credential enroll --profile ec/client --var cn=alice@example.com --ca-dir ./ca

# Later: add PQC during renewal
qpki credential renew alice-20250115-abc123 \
    --profile ec/client --profile ml/client --ca-dir ./ca

# Eventually: remove classical algorithms
qpki credential renew alice-20250615-def456 \
    --profile ml/client --ca-dir ./ca
```

## 5. Troubleshooting

### 5.1 Common Errors

**"CA not found"**
```
Error: CA not found at ./ca
```
Solution: Specify the correct CA directory with `--ca-dir`.

**"Failed to load CA signer"**
```
Error: failed to load CA signer: x509: decryption password incorrect
```
Solution: Provide the correct passphrase with `--ca-passphrase`.

**"Certificate not found"**
```
Error: certificate with serial 05 not found
```
Solution: Check the serial number with `qpki cert list --ca-dir ./myca`.

### 5.2 Verifying Certificates with OpenSSL

```bash
# Verify certificate chain (using chain.crt from subordinate CA)
openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/chain.crt server.crt

# Or verify step by step
openssl verify -CAfile root-ca/ca.crt issuing-ca/ca.crt
openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/ca.crt server.crt

# View certificate details
openssl x509 -in server.crt -text -noout

# Check certificate dates
openssl x509 -in server.crt -dates -noout

# Verify CRL
openssl crl -in ca/crl/ca.crl -text -noout
```

### 5.3 Debugging

Enable verbose output:
```bash
qpki --debug issue --ca-dir ./myca ...
```

Check CA index:
```bash
cat ./myca/index.txt
```

Check serial number:
```bash
cat ./myca/serial
```

## 6. FAQ

### Q: How do I create a CA with a custom validity period?

Use the `--validity` flag (in years for CA, days for end-entity):
```bash
qpki ca init --name "Long-lived CA" --validity 30 --dir ./ca
```

### Q: Can I use my own private key?

Yes, generate a key first, then create a CSR:
```bash
qpki key gen --algorithm ecdsa-p384 --out mykey.pem
openssl req -new -key mykey.pem -out myreq.csr
qpki cert issue --ca-dir ./myca --csr myreq.csr --out mycert.crt
```

### Q: How do I back up my CA?

Simply copy the entire CA directory:
```bash
tar -czf ca-backup-$(date +%Y%m%d).tar.gz ./myca
```

### Q: Is the PQC extension compatible with browsers?

The PQC extension is non-critical and will be ignored by browsers. The classical signature is used for TLS. The PQC material is for future use or application-level verification.

### Q: What's the difference between ml-dsa-44, ml-dsa-65, and ml-dsa-87?

These correspond to NIST security levels:
- **ml-dsa-44**: Level 1 (equivalent to AES-128)
- **ml-dsa-65**: Level 3 (equivalent to AES-192)
- **ml-dsa-87**: Level 5 (equivalent to AES-256)

Higher levels provide more security but produce larger signatures.

## See Also

- [Quick Start](../README.md#quick-start) - Get started in 5 minutes
- [PROFILES](PROFILES.md) - Certificate profile templates
- [CONCEPTS](CONCEPTS.md) - PQC and hybrid certificate concepts
- [OPERATIONS](OPERATIONS.md) - OCSP, TSA, and audit operations
