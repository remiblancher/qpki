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
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm |
| `--hybrid-algorithm` | | "" | PQC algorithm for hybrid mode |
| `--dir` | `-d` | ./ca | CA directory |
| `--validity` | `-v` | 10 | Validity in years |
| `--pathlen` | | 1 | Path length constraint |
| `--passphrase` | | "" | Key passphrase |
| `--parent` | | "" | Parent CA directory (creates subordinate CA) |
| `--parent-passphrase` | | "" | Parent CA key passphrase |

**Examples:**

```bash
# Basic CA with ECDSA P-256
pki init-ca --name "My Root CA" --org "My Company" --dir ./myca

# High-security CA with P-384
pki init-ca --name "Root CA" --algorithm ecdsa-p384 --validity 20 --dir ./rootca

# Hybrid CA with ML-DSA
pki init-ca --name "Hybrid CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca

# CA with passphrase-protected key
pki init-ca --name "Secure CA" --passphrase "$(read -s -p 'Passphrase: ' p && echo $p)" \
  --dir ./secure-ca

# Subordinate CA signed by parent
pki init-ca --name "Issuing CA" --org "My Company" \
  --dir ./issuing-ca --parent ./rootca
```

### 2.2 issue

Issue a certificate.

```bash
pki issue [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--profile` | `-p` | tls-server | Certificate profile |
| `--cn` | | required | Common name |
| `--dns` | | "" | DNS SANs (comma-separated) |
| `--ip` | | "" | IP SANs (comma-separated) |
| `--email` | | "" | Email SANs (comma-separated) |
| `--out` | `-o` | required | Output certificate file |
| `--key-out` | | "" | Output key file (generates new key) |
| `--csr` | | "" | CSR file (instead of generating key) |
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm |
| `--hybrid` | | "" | PQC algorithm for hybrid cert |
| `--validity` | `-v` | 365 | Validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |
| `--passphrase` | | "" | Output key passphrase |

**Profiles:**

| Profile | Description |
|---------|-------------|
| tls-server | TLS server certificate (web servers, APIs) |
| tls-client | TLS client certificate (mutual TLS) |
| issuing-ca | Subordinate CA certificate |

**Examples:**

```bash
# TLS server certificate
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --cn server.example.com \
  --dns server.example.com,www.example.com \
  --out server.crt --key-out server.key

# TLS server with IP SAN
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --cn api.internal \
  --dns api.internal \
  --ip 10.0.0.1,192.168.1.100 \
  --out api.crt --key-out api.key

# TLS client certificate
pki issue --ca-dir ./myca --profile ecdsa/tls-client \
  --cn "alice@example.com" \
  --email alice@example.com \
  --out alice.crt --key-out alice.key

# Issuing CA (subordinate)
pki issue --ca-dir ./rootca --profile ecdsa/issuing-ca \
  --cn "Issuing CA 1" \
  --out issuing-ca.crt --key-out issuing-ca.key \
  --validity 1825

# Hybrid certificate
pki issue --ca-dir ./hybrid-ca --profile ecdsa/tls-server \
  --cn hybrid.example.com \
  --hybrid ml-dsa-65 \
  --out hybrid.crt --key-out hybrid.key

# From CSR
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --csr server.csr \
  --out server.crt
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

### 2.4 revoke

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

### 2.5 gen-crl

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

### 2.6 info

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

### 2.7 list

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

### 2.9 enroll

Enroll a new certificate bundle using a profile.

```bash
pki enroll [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--subject` | `-s` | required | Certificate subject (e.g., "CN=Alice,O=Acme") |
| `--profile` | `-g` | classic | Profile to use |
| `--ca-dir` | `-c` | ./ca | CA directory |
| `--out` | `-o` | . | Output directory |
| `--passphrase` | `-p` | "" | Passphrase for private keys |
| `--dns` | | | DNS SANs (repeatable) |
| `--email` | | | Email SANs (repeatable) |
| `--sig-profile` | | user | Profile for signature certificates |
| `--enc-profile` | | user | Profile for encryption certificates |

**Examples:**

```bash
# Basic enrollment
pki enroll --subject "CN=Alice,O=Acme" --profile ecdsa/tls-client --ca-dir ./ca

# Hybrid Catalyst enrollment
pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/catalyst/tls-client --ca-dir ./ca

# Full hybrid with encryption
pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/catalyst/tls-client --out ./alice

# With DNS SANs
pki enroll --subject "CN=server.example.com" --profile pqc/tls-client \
    --dns server.example.com --dns www.example.com

# With passphrase protection
pki enroll --subject "CN=Alice" --profile hybrid/catalyst/tls-client \
    --passphrase "secret" --out ./alice
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
pki issue --ca-dir ./issuing-ca --profile ecdsa/tls-server \
  --cn www.example.com \
  --dns www.example.com,example.com \
  --out www.crt --key-out www.key

# 4. Verify the chain
openssl verify -CAfile ./root-ca/ca.crt ./issuing-ca/ca.crt
openssl verify -CAfile ./root-ca/ca.crt -untrusted ./issuing-ca/ca.crt www.crt
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
pki issue --ca-dir ./mtls-ca --profile ecdsa/tls-server \
  --cn server.local \
  --dns server.local \
  --out server.crt --key-out server.key

# 3. Issue client certificates
pki issue --ca-dir ./mtls-ca --profile ecdsa/tls-client \
  --cn "Client A" \
  --out client-a.crt --key-out client-a.key

pki issue --ca-dir ./mtls-ca --profile ecdsa/tls-client \
  --cn "Client B" \
  --out client-b.crt --key-out client-b.key

# 4. Configure server (example with nginx)
# ssl_certificate server.crt;
# ssl_certificate_key server.key;
# ssl_client_certificate mtls-ca/ca.crt;
# ssl_verify_client on;
```

### 3.3 Certificate Rotation

```bash
# 1. Issue new certificate before old one expires
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --cn server.example.com \
  --dns server.example.com \
  --out server-new.crt --key-out server-new.key

# 2. Deploy new certificate

# 3. Revoke old certificate
pki revoke 01 --ca-dir ./myca --reason superseded --gen-crl
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
