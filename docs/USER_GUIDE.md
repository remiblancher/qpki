# User Guide

This guide covers installation, CLI usage, and common workflows for the Quantum-Safe PKI.

## 1. Installation

### Download Pre-built Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/remiblancher/pki/releases/latest).

**Linux / macOS:**
```bash
# Download (replace VERSION, OS, and ARCH as needed)
curl -LO https://github.com/remiblancher/pki/releases/latest/download/pki_VERSION_OS_ARCH.tar.gz

# Extract
tar -xzf pki_*.tar.gz

# Install
sudo mv pki /usr/local/bin/

# Verify
pki --version
```

**Available platforms:**

| OS | Architecture | File |
|----|--------------|------|
| Linux | amd64 | `pki_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `pki_VERSION_linux_arm64.tar.gz` |
| macOS | Intel | `pki_VERSION_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `pki_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `pki_VERSION_windows_amd64.zip` |

**Linux packages:**
```bash
# Debian/Ubuntu
sudo dpkg -i pki_VERSION_linux_amd64.deb

# RHEL/Fedora
sudo rpm -i pki_VERSION_linux_amd64.rpm
```

### Install via Homebrew (macOS)

```bash
brew tap remiblancher/pki
brew install pki
```

### From Source

```bash
git clone https://github.com/remiblancher/pki.git
cd pki
go build -o pki ./cmd/pki
sudo mv pki /usr/local/bin/
```

### Go Install

```bash
go install github.com/remiblancher/pki/cmd/pki@latest
```

### Verify Installation

```bash
pki version
pki --help
```

## 2. CLI Reference

### 2.1 init-ca

Initialize a new Certificate Authority.

```bash
pki init-ca [flags]
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
pki init-ca --name "My Root CA" --profile ec/root-ca --dir ./myca

# Hybrid Catalyst CA (ITU-T - backward compatible)
pki init-ca --name "Catalyst Root CA" --profile hybrid/catalyst/root-ca --dir ./catalyst-ca

# Hybrid Composite CA (IETF draft - stricter security)
pki init-ca --name "Composite Root CA" --profile hybrid/composite/root-ca --dir ./composite-ca

# Subordinate CA using a profile
pki init-ca --name "Issuing CA" --profile ec/issuing-ca \
  --dir ./issuing-ca --parent ./rootca

# Manual configuration (without profile)
pki init-ca --name "My Root CA" --org "My Company" --dir ./myca

# High-security CA with P-384
pki init-ca --name "Root CA" --algorithm ecdsa-p384 --validity 20 --dir ./rootca

# Hybrid CA with ML-DSA (manual)
pki init-ca --name "Hybrid CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca

# CA with passphrase-protected key
pki init-ca --name "Secure CA" --passphrase "mysecret" --dir ./secure-ca

# Subordinate CA signed by parent (manual)
pki init-ca --name "Issuing CA" --org "My Company" \
  --dir ./issuing-ca --parent ./rootca
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
| `ml-dsa-kem/root-ca` | ML-DSA-87 | 20 years | Pure PQC root CA |

### 2.2 issue

Issue a certificate from a Certificate Signing Request (CSR).

```bash
pki issue [flags]
```

**Note:** This command requires a CSR file (`--csr`). For direct issuance with automatic key generation, use `pki bundle enroll` instead.

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
pki issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --out server.crt

# From PQC signature CSR (ML-DSA, SLH-DSA)
pki issue --ca-dir ./myca --profile ml-dsa-kem/tls-server-sign \
  --csr mldsa.csr --out server.crt

# From ML-KEM CSR with RFC 9883 attestation
pki issue --ca-dir ./myca --profile ml-kem/client \
  --csr kem.csr --attest-cert sign.crt --out kem.crt

# From hybrid CSR (classical + PQC dual signatures)
pki issue --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --csr hybrid.csr --out server.crt

# Add hybrid extension to classical certificate
pki issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --hybrid ml-dsa-65 --out hybrid.crt
```

**For direct issuance with key generation, use `pki bundle enroll`:**

```bash
# TLS server certificate (direct issuance)
pki bundle enroll --ca-dir ./myca --profile ec/tls-server \
  --var cn=server.example.com \
  --var dns_names=server.example.com,www.example.com

# TLS client certificate
pki bundle enroll --ca-dir ./myca --profile ec/tls-client \
  --var cn=alice@example.com --var email=alice@example.com

# Hybrid certificate
pki bundle enroll --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --var cn=hybrid.example.com --var dns_names=hybrid.example.com
```

### 2.3 genkey

Generate a cryptographic key pair.

```bash
pki genkey [flags]
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
pki genkey --algorithm ecdsa-p256 --out key.pem

# Ed25519 key
pki genkey --algorithm ed25519 --out ed25519.key

# PQC key (ML-DSA)
pki genkey --algorithm ml-dsa-65 --out pqc.key

# Encrypted key
pki genkey --algorithm ecdsa-p384 --out secure.key --passphrase "secret"
```

### 2.4 csr

Generate a Certificate Signing Request (CSR) for submission to a CA.

```bash
pki csr [flags]
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
pki csr --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com -o server.csr

# PQC ML-DSA CSR (direct signature)
pki csr --algorithm ml-dsa-65 --keyout mldsa.key \
    --cn alice@example.com -o mldsa.csr

# PQC ML-KEM CSR with RFC 9883 attestation
# (requires an existing signature certificate for attestation)
pki csr --algorithm ml-kem-768 --keyout kem.key \
    --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key \
    -o kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
pki csr --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key \
    --cn example.com -o hybrid.csr

# CSR with existing key
pki csr --key existing.key --cn server.example.com -o server.csr
```

**RFC 9883 (ML-KEM Attestation):**

ML-KEM keys cannot sign (they're Key Encapsulation Mechanisms). To prove possession of an ML-KEM private key, RFC 9883 defines the `privateKeyPossessionStatement` attribute. This requires:

1. An existing signature certificate (`--attest-cert`)
2. The corresponding private key (`--attest-key`)

The CSR is signed by the attestation key, and includes a reference to the attestation certificate. The CA verifies the attestation chain before issuing the ML-KEM certificate.

### 2.5 revoke

Revoke a certificate.

```bash
pki revoke <serial> [flags]
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
pki revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate CRL
pki revoke 02 --ca-dir ./myca --reason keyCompromise --gen-crl

# Revoke with CRL valid for 30 days
pki revoke 02 --ca-dir ./myca --gen-crl --crl-days 30
```

### 2.6 gen-crl

Generate a Certificate Revocation List.

```bash
pki gen-crl [flags]
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
pki gen-crl --ca-dir ./myca

# Generate CRL valid for 30 days
pki gen-crl --ca-dir ./myca --days 30
```

### 2.7 info

Display information about certificates or keys.

```bash
pki info <file> [flags]
```

**Examples:**

```bash
# Show certificate details
pki info certificate.crt

# Show key information
pki info private.key

# Show CA certificate
pki info ./myca/ca.crt
```

### 2.8 list

List certificates in a CA.

```bash
pki list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--status` | | all | Filter by status (valid, revoked, expired, all) |

**Examples:**

```bash
# List all certificates
pki list --ca-dir ./myca

# List only valid certificates
pki list --ca-dir ./myca --status valid

# List revoked certificates
pki list --ca-dir ./myca --status revoked
```

### 2.8 profile

Manage certificate policy templates (profiles).

```bash
pki profile <subcommand> [flags]
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
pki profile install --dir ./ca

# List available profiles
pki profile list --dir ./ca

# View profile details
pki profile info hybrid-catalyst --dir ./ca

# Validate custom profile
pki profile validate my-profile.yaml
```

### 2.9 bundle enroll

Create a certificate bundle with automatic key generation.

```bash
pki bundle enroll [flags]
```

**Note:** This is the recommended way to issue certificates with automatic key generation. For CSR-based workflows, use `pki issue`.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | required | Profile to use (repeatable for multi-profile) |
| `--var` | | | Variable value (e.g., `cn=example.com`). Repeatable. |
| `--var-file` | | | YAML file with variable values |
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--id` | | auto | Custom bundle ID |
| `--passphrase` | `-p` | "" | Passphrase for private keys |

**Examples:**

```bash
# Basic enrollment (single profile)
pki bundle enroll --profile ec/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# Multi-profile enrollment (crypto-agility)
pki bundle enroll --profile ec/client --profile ml-dsa-kem/client \
    --var cn=alice@example.com --ca-dir ./ca

# Hybrid Catalyst enrollment
pki bundle enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# TLS server with DNS SANs
pki bundle enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com,www.example.com --ca-dir ./ca

# With custom bundle ID
pki bundle enroll --profile ec/tls-client \
    --var cn=alice@example.com --id alice-prod --ca-dir ./ca

# With passphrase protection
pki bundle enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --passphrase "secret" --ca-dir ./ca
```

### 2.10 bundle

Manage certificate bundles.

```bash
pki bundle <subcommand> [flags]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List all bundles |
| `info <bundle-id>` | Show bundle details |
| `renew <bundle-id>` | Renew all certificates in bundle |
| `revoke <bundle-id>` | Revoke all certificates in bundle |
| `export <bundle-id>` | Export bundle certificates to PEM |

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
# List bundles
pki bundle list --ca-dir ./ca

# View bundle details
pki bundle info alice-20250115-abc123 --ca-dir ./ca

# Renew a bundle
pki bundle renew alice-20250115-abc123 --ca-dir ./ca

# Revoke a bundle
pki bundle revoke alice-20250115-abc123 --ca-dir ./ca --reason keyCompromise

# Export certificates
pki bundle export alice-20250115-abc123 --ca-dir ./ca --out alice.pem

# Export with private keys
pki bundle export alice-20250115-abc123 --ca-dir ./ca \
    --keys --passphrase "secret" --out alice-full.pem
```

### 2.11 verify

Verify a certificate's validity and revocation status.

```bash
pki verify [flags]
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
pki verify --cert server.crt --ca ca.crt

# With CRL check
pki verify --cert server.crt --ca ca.crt --crl ca/crl/ca.crl

# With OCSP check
pki verify --cert server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Output examples:**

Valid certificate:
```
✓ Certificate is VALID
  Subject:    server.example.com
  Issuer:     My Root CA
  Serial:     02
  Valid:      2025-01-01 to 2026-01-01
  Revocation: Not checked (use --crl or --ocsp)
```

Revoked certificate:
```
✗ Certificate is REVOKED
  Subject:    server.example.com
  Issuer:     My Root CA
  Serial:     02
  Revoked:    2025-06-15
  Reason:     keyCompromise
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

## 3. Common Workflows

### 3.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
pki init-ca --name "Root CA" --org "My Company" \
  --algorithm ecdsa-p384 --validity 20 --pathlen 1 \
  --dir ./root-ca

# 2. Create issuing CA (signed by root, with full CA structure)
pki init-ca --name "Issuing CA" --org "My Company" \
  --dir ./issuing-ca --parent ./root-ca

# 3. Issue server certificates from issuing CA
pki bundle enroll --ca-dir ./issuing-ca --profile ec/tls-server \
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

### 3.2 Set Up mTLS

```bash
# 1. Create CA
pki init-ca --name "mTLS CA" --dir ./mtls-ca

# 2. Issue server certificate
pki bundle enroll --ca-dir ./mtls-ca --profile ec/tls-server \
  --var cn=server.local --var dns_names=server.local

# 3. Issue client certificates
pki bundle enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-a@example.com --id client-a

pki bundle enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-b@example.com --id client-b

# 4. Configure server (example with nginx)
# ssl_certificate server.crt;
# ssl_certificate_key server.key;
# ssl_client_certificate mtls-ca/ca.crt;
# ssl_verify_client on;
```

### 3.3 Certificate Rotation with Bundles

```bash
# 1. Renew bundle before expiration
pki bundle renew <bundle-id> --ca-dir ./myca

# 2. Deploy new certificates from bundle

# 3. Old certificates expire naturally
# Or revoke if needed:
pki bundle revoke <old-bundle-id> --ca-dir ./myca --reason superseded
```

## 4. Troubleshooting

### 4.1 Common Errors

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
Solution: Check the serial number with `pki list --ca-dir ./myca`.

### 4.2 Verifying Certificates with OpenSSL

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

### 4.3 Debugging

Enable verbose output:
```bash
pki --debug issue --ca-dir ./myca ...
```

Check CA index:
```bash
cat ./myca/index.txt
```

Check serial number:
```bash
cat ./myca/serial
```

## 5. FAQ

### Q: How do I create a CA with a custom validity period?

Use the `--validity` flag (in years for CA, days for end-entity):
```bash
pki init-ca --name "Long-lived CA" --validity 30 --dir ./ca
```

### Q: Can I use my own private key?

Yes, generate a key first, then create a CSR:
```bash
pki genkey --algorithm ecdsa-p384 --out mykey.pem
openssl req -new -key mykey.pem -out myreq.csr
pki issue --ca-dir ./myca --csr myreq.csr --out mycert.crt
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

## 6. OCSP Operations (RFC 6960)

The PKI supports Online Certificate Status Protocol (OCSP) for real-time certificate revocation checking.

### 6.1 ocsp sign

Create an OCSP response for a certificate.

```bash
pki ocsp sign [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--serial` | | required | Certificate serial number (hex) |
| `--status` | | good | Certificate status (good, revoked, unknown) |
| `--revocation-time` | | | Revocation time (RFC3339 format) |
| `--revocation-reason` | | | Revocation reason |
| `--ca` | | required | CA certificate (PEM) |
| `--cert` | | | Responder certificate (PEM, optional) |
| `--key` | | required | Responder private key (PEM) |
| `--passphrase` | | | Key passphrase |
| `--out` | `-o` | required | Output file |
| `--validity` | | 1h | Response validity period |

**Examples:**

```bash
# Create response for good certificate
pki ocsp sign --serial 02 --status good \
  --ca ca.crt --key ca.key -o response.ocsp

# Create response for revoked certificate
pki ocsp sign --serial 02 --status revoked \
  --revocation-time "2025-01-15T10:00:00Z" \
  --revocation-reason keyCompromise \
  --ca ca.crt --key ca.key -o revoked.ocsp

# With dedicated responder certificate
pki ocsp sign --serial 02 --status good \
  --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp
```

### 6.2 ocsp verify

Verify an OCSP response.

```bash
pki ocsp verify [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--response` | | required | OCSP response file |
| `--ca` | | | CA certificate (PEM) |
| `--cert` | | | Certificate to verify (PEM, optional) |

**Examples:**

```bash
# Verify response with CA certificate
pki ocsp verify --response response.ocsp --ca ca.crt

# Verify and check against specific certificate
pki ocsp verify --response response.ocsp --ca ca.crt --cert server.crt
```

### 6.3 ocsp request

Create an OCSP request.

```bash
pki ocsp request [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--issuer` | | required | Issuer certificate (PEM) |
| `--cert` | | required | Certificate to check (PEM) |
| `--nonce` | | false | Include nonce extension |
| `--out` | `-o` | required | Output file |

**Examples:**

```bash
# Create OCSP request
pki ocsp request --issuer ca.crt --cert server.crt -o request.ocsp

# With nonce for replay protection
pki ocsp request --issuer ca.crt --cert server.crt --nonce -o request.ocsp
```

### 6.4 ocsp info

Display information about an OCSP response.

```bash
pki ocsp info <response-file>
```

**Example:**

```bash
pki ocsp info response.ocsp
```

### 6.5 ocsp serve

Start an HTTP OCSP responder server (RFC 6960).

```bash
pki ocsp serve [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | | 8080 | HTTP port |
| `--ca-dir` | | required | CA directory (contains ca.crt, ca.key, index.txt) |
| `--cert` | | | Responder certificate (PEM, optional) |
| `--key` | | | Responder private key (PEM, optional) |
| `--passphrase` | | | Key passphrase |
| `--validity` | | 1h | Response validity period |
| `--copy-nonce` | | true | Copy nonce from request to response |

**Modes:**
- **Delegated:** Use a dedicated OCSP responder certificate (with EKU OCSPSigning)
- **CA-signed:** Use the CA certificate directly (if no responder cert provided)

**Examples:**

```bash
# Start with CA-signed responses
pki ocsp serve --port 8080 --ca-dir ./myca

# Start with delegated responder certificate
pki ocsp serve --port 8080 --ca-dir ./myca \
  --cert responder.crt --key responder.key

# With custom validity period
pki ocsp serve --port 8080 --ca-dir ./myca --validity 2h
```

**Testing with OpenSSL:**

```bash
# Query the OCSP responder
openssl ocsp -issuer ca.crt -cert server.crt \
  -url http://localhost:8080/ -resp_text
```

### 6.6 OCSP Responder Profiles

Use profiles to issue OCSP responder certificates:

```bash
# Issue OCSP responder certificate (ECDSA)
pki bundle enroll --ca-dir ./myca --profile ec/ocsp-responder \
  --var cn=ocsp.example.com --id ocsp-responder

# Issue OCSP responder certificate (ML-DSA)
pki bundle enroll --ca-dir ./myca --profile ml-dsa-kem/ocsp-responder \
  --var cn=pqc-ocsp.example.com --id pqc-ocsp-responder

# Issue hybrid OCSP responder certificate
pki bundle enroll --ca-dir ./myca --profile hybrid/catalyst/ocsp-responder \
  --var cn=hybrid-ocsp.example.com --id hybrid-ocsp-responder
```

The OCSP responder profiles include:
- **ocspSigning** Extended Key Usage (OID 1.3.6.1.5.5.7.3.9)
- **OCSP No Check** extension (RFC 6960 §4.2.2.2.1) to prevent infinite loops
