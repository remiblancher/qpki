# User Guide

This guide covers installation, CLI usage, and common workflows for Post-Quantum PKI (QPKI).

> **Related documentation:**
> - [CREDENTIALS.md](CREDENTIALS.md) - Credential management (enroll, rotate, revoke)
> - [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md) - Algorithm migration guide
> - [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common errors and solutions
> - [OPERATIONS.md](OPERATIONS.md) - OCSP, TSA, CMS operations
> - [PROFILES.md](PROFILES.md) - Certificate profile templates

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

### 2.0 Command Overview

```
qpki [--audit-log PATH]
├── ca                        # Certificate Authority
│   ├── init                  # Initialize CA (root or subordinate)
│   ├── info                  # Display CA information
│   ├── export                # Export CA certificates
│   ├── list                  # List CAs in directory
│   ├── rotate                # Rotate CA with new keys
│   ├── activate              # Activate pending CA version
│   └── versions              # List CA versions
│
├── cert                      # Certificate operations
│   ├── issue                 # Issue certificate from CSR
│   ├── list                  # List issued certificates
│   ├── info                  # Display certificate info
│   ├── revoke                # Revoke a certificate
│   └── verify                # Verify certificate validity
│
├── credential                # Credentials (coupled lifecycle)
│   ├── enroll                # Create new credential
│   ├── list                  # List credentials
│   ├── info                  # Credential details
│   ├── rotate                # Rotate credential
│   ├── activate              # Activate pending version
│   ├── versions              # List credential versions
│   ├── revoke                # Revoke credential
│   └── export                # Export credential
│
├── key                       # Key management
│   ├── gen                   # Generate key pair
│   ├── pub                   # Extract public key
│   ├── list                  # List keys
│   ├── info                  # Key information
│   └── convert               # Convert key format
│
├── profile                   # Certificate profiles
│   ├── list                  # List available profiles
│   ├── info                  # Profile details
│   ├── vars                  # Show profile variables
│   ├── show                  # Display YAML content
│   ├── export                # Export profile to file
│   ├── lint                  # Validate profile YAML
│   └── install               # Install default profiles
│
├── csr                       # CSR operations
│   ├── gen                   # Generate CSR
│   ├── info                  # Display CSR info
│   └── verify                # Verify CSR signature
│
├── crl                       # CRL operations
│   ├── gen                   # Generate CRL
│   ├── info                  # Display CRL info
│   ├── verify                # Verify CRL signature
│   └── list                  # List CRLs
│
├── tsa                       # Timestamping (see OPERATIONS.md)
│   ├── sign                  # Create timestamp token
│   ├── verify                # Verify timestamp token
│   └── serve                 # Start TSA HTTP server
│
├── cms                       # CMS signatures (see OPERATIONS.md)
│   ├── sign                  # Create CMS signature
│   ├── verify                # Verify CMS signature
│   ├── encrypt               # Encrypt with CMS
│   ├── decrypt               # Decrypt CMS
│   └── info                  # Display CMS info
│
├── ocsp                      # OCSP responder (see OPERATIONS.md)
│   ├── sign                  # Create OCSP response
│   ├── verify                # Verify OCSP response
│   ├── request               # Create OCSP request
│   ├── info                  # Display OCSP response info
│   └── serve                 # Start OCSP HTTP server
│
├── hsm                       # HSM integration (see HSM.md)
│   ├── list                  # List HSM slots/tokens
│   ├── test                  # Test HSM connectivity
│   └── info                  # Display HSM token info
│
├── audit                     # Audit logging (see OPERATIONS.md)
│   ├── verify                # Verify audit log integrity
│   └── tail                  # Show recent audit events
│
└── inspect                   # Auto-detect and display file info
```

**Global flags:**
- `--audit-log PATH` - Enable audit logging to file (or set `PKI_AUDIT_LOG` env var)

**Supported algorithms:** ECDSA, Ed25519, RSA, post-quantum (ML-DSA, SLH-DSA, ML-KEM), and hybrid modes (Catalyst, Composite). See [CONCEPTS.md](CONCEPTS.md) for details.

### 2.1 Quick Reference

| Category | Command | Description |
|----------|---------|-------------|
| **Keys** | `key gen` | Generate a private key |
| | `key pub` | Extract public key |
| | `key list` | List keys in directory |
| | `key info` | Display key details |
| | `key convert` | Convert key format |
| **CA** | `ca init` | Initialize a certificate authority |
| | `ca info` | Display CA information |
| | `ca export` | Export CA certificates |
| | `ca list` | List CAs in directory |
| | `ca rotate` | Rotate CA with new keys |
| | `ca activate` | Activate a pending version |
| | `ca versions` | List CA versions |
| **CSR** | `csr gen` | Generate a certificate signing request |
| | `csr info` | Display CSR details |
| | `csr verify` | Verify CSR signature |
| **Certificates** | `cert issue` | Issue certificate from CSR |
| | `cert list` | List certificates in CA |
| | `cert info` | Display certificate details |
| | `cert revoke` | Revoke a certificate |
| | `cert verify` | Verify a certificate |
| **Credentials** | `credential enroll` | Issue key(s) + certificate(s) → [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential list` | List credentials |
| | `credential rotate` | Rotate a credential |
| | `credential revoke` | Revoke a credential |
| **CRL** | `crl gen` | Generate a CRL |
| | `crl info` | Display CRL details |
| | `crl verify` | Verify a CRL |
| | `crl list` | List CRLs in CA |
| **Profiles** | `profile list` | List available profiles |
| | `profile info` | Display profile details |
| | `profile vars` | List profile variables |
| | `profile show` | Display profile YAML |
| | `profile export` | Export a profile |
| | `profile lint` | Validate profile YAML |
| | `profile install` | Install default profiles |
| **Inspection** | `inspect` | Inspect certificate, key, or CRL |
| **CMS** | `cms sign` | Create CMS signature (→ OPERATIONS.md) |
| | `cms verify` | Verify CMS signature |
| | `cms encrypt` | Encrypt with CMS EnvelopedData |
| | `cms decrypt` | Decrypt CMS |
| | `cms info` | Display CMS message details |
| **TSA** | `tsa sign` | Timestamp a file (→ OPERATIONS.md) |
| | `tsa verify` | Verify timestamp token |
| | `tsa serve` | Start TSA HTTP server |
| **OCSP** | `ocsp sign` | Create OCSP response (→ OPERATIONS.md) |
| | `ocsp verify` | Verify OCSP response |
| | `ocsp request` | Create OCSP request |
| | `ocsp info` | Display OCSP response info |
| | `ocsp serve` | Start OCSP HTTP server |
| **HSM** | `hsm list` | List HSM slots/tokens (→ HSM.md) |
| | `hsm test` | Test HSM connectivity |
| | `hsm info` | Display HSM token info |
| **Audit** | `audit verify` | Verify audit log integrity (→ OPERATIONS.md) |
| | `audit tail` | Show recent audit events |

### 2.2 Key Management

#### key gen

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
```

#### key pub

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

# Extract from encrypted key
qpki key pub --key encrypted.key --passphrase "secret" --out public.pem

# Extract from PQC key
qpki key pub --key mldsa.key --out mldsa.pub
```

#### key list

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

# List keys in HSM token
qpki key list --hsm-config ./hsm.yaml
```

#### key info

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

#### key convert

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

# Add passphrase protection
qpki key convert --key private.pem --out encrypted.pem --out-passphrase "secret"
```

### 2.3 CA Management

#### ca init

Initialize a new Certificate Authority.

```bash
qpki ca init [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | "" | CA profile (repeatable for multi-profile CA) |
| `--var` | | [] | Variable value (key=value, repeatable) |
| `--var-file` | | "" | YAML file with variable values |
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm (ignored if --profile is set) |
| `--hybrid-algorithm` | | "" | PQC algorithm for hybrid mode |
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--validity` | | 10 | Validity in years (ignored if --profile is set) |
| `--path-len` | | 1 | Path length constraint (ignored if --profile is set) |
| `--passphrase` | `-p` | "" | Key passphrase |
| `--parent` | | "" | Parent CA directory (creates subordinate CA) |
| `--parent-passphrase` | | "" | Parent CA key passphrase |

**Examples:**

```bash
# Using a profile (recommended)
qpki ca init --profile ec/root-ca --ca-dir ./myca --var cn="My Root CA"

# Multi-profile CA (crypto agility)
qpki ca init --profile ec/root-ca --profile ml/root-ca --ca-dir ./multi-ca --var cn="Multi-Algo Root CA"

# Hybrid Catalyst CA (ITU-T - backward compatible)
qpki ca init --profile hybrid/catalyst/root-ca --ca-dir ./catalyst-ca --var cn="Catalyst Root CA"

# Hybrid Composite CA (IETF draft - stricter security)
qpki ca init --profile hybrid/composite/root-ca --ca-dir ./composite-ca --var cn="Composite Root CA"

# Subordinate CA using a profile
qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./rootca --var cn="Issuing CA"

# CA with passphrase-protected key
qpki ca init --profile ec/root-ca --passphrase "mysecret" --ca-dir ./secure-ca --var cn="Secure CA"

# PQC root CA with ML-DSA
qpki ca init --profile ml/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"

# Using a variables file
qpki ca init --profile ec/root-ca --ca-dir ./myca --var-file ca-vars.yaml
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

#### ca info

Display information about a Certificate Authority.

```bash
qpki ca info [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki ca info --ca-dir ./myca
```

#### ca export

Export CA certificates.

```bash
qpki ca export [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--bundle` | `-b` | ca | Bundle type: ca, chain, root |
| `--out` | `-o` | stdout | Output file |

**Examples:**

```bash
# Export CA certificate
qpki ca export --ca-dir ./myca --out ca.crt

# Export full chain (CA + parent)
qpki ca export --ca-dir ./issuing-ca --bundle chain --out chain.pem

# Export root certificate only
qpki ca export --ca-dir ./issuing-ca --bundle root --out root.crt
```

#### ca list

List Certificate Authorities in a directory.

```bash
qpki ca list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | . | Directory to scan |

**Example:**

```bash
qpki ca list --dir /var/lib/pki
```

#### ca rotate

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
| `--cross-sign` | | auto | Cross-sign strategy: auto, on, off |
| `--dry-run` | | false | Preview rotation plan without executing |

**Examples:**

```bash
# Preview rotation plan (dry-run)
qpki ca rotate --ca-dir ./myca --dry-run

# Rotate to a new profile (crypto migration)
qpki ca rotate --ca-dir ./myca --profile hybrid/catalyst/root-ca

# Multi-profile rotation (crypto agility)
qpki ca rotate --ca-dir ./myca --profile ec/root-ca --profile ml/root-ca

# Rotate with explicit cross-signing
qpki ca rotate --ca-dir ./myca --profile ml/root-ca --cross-sign on
```

#### ca activate

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
qpki ca activate --ca-dir ./myca --version 2
```

#### ca versions

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

### 2.4 Certificate Signing Requests (CSR)

#### csr gen

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
| Catalyst | ITU-T X.509 dual signatures | `--catalyst ecdsa-p384+mldsa87` |
| Composite | IETF draft-13 combined signature | `--composite mldsa87-ecdsa-p384` |
| Hybrid (legacy) | Classical + PQC dual signatures | `--algorithm ecdsa-p256 --hybrid ml-dsa-65` |

**Examples:**

```bash
# Classical ECDSA CSR
qpki csr gen --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com --out server.csr

# PQC ML-DSA CSR (direct signature)
qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key \
    --cn alice@example.com --out mldsa.csr

# PQC ML-KEM CSR with RFC 9883 attestation
# (requires an existing signature certificate for attestation)
qpki csr gen --algorithm ml-kem-768 --keyout kem.key \
    --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key \
    --out kem.csr

# Catalyst hybrid CSR (ITU-T X.509 - recommended for backward compatibility)
qpki csr gen --catalyst ecdsa-p384+mldsa87 --keyout classical.key \
    --hybrid-keyout pqc.key --cn example.com --out catalyst.csr

# Composite CSR (IETF draft-13 - single combined signature)
qpki csr gen --composite mldsa87-ecdsa-p384 --keyout classical.key \
    --hybrid-keyout pqc.key --cn example.com --out composite.csr

# Legacy hybrid CSR (ECDSA + ML-DSA dual signatures)
qpki csr gen --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key \
    --cn example.com --out hybrid.csr

# CSR with existing key
qpki csr gen --key existing.key --cn server.example.com --out server.csr
```

**Catalyst Combinations:**

The `--catalyst` flag creates a CSR with dual signatures per ITU-T X.509 (2019) Section 9.8.
Both classical and PQC signatures are independent, allowing backward compatibility.

| Combination | Classical | PQC | Security Level |
|-------------|-----------|-----|----------------|
| `ecdsa-p256+mldsa44` | ECDSA P-256 | ML-DSA-44 | 128-bit |
| `ecdsa-p256+mldsa65` | ECDSA P-256 | ML-DSA-65 | 128/192-bit |
| `ecdsa-p384+mldsa65` | ECDSA P-384 | ML-DSA-65 | 192-bit |
| `ecdsa-p384+mldsa87` | ECDSA P-384 | ML-DSA-87 | 192/256-bit |
| `ecdsa-p521+mldsa87` | ECDSA P-521 | ML-DSA-87 | 256-bit |
| `ed25519+mldsa44` | Ed25519 | ML-DSA-44 | 128-bit |
| `ed25519+mldsa65` | Ed25519 | ML-DSA-65 | 128/192-bit |
| `ed448+mldsa87` | Ed448 | ML-DSA-87 | 224/256-bit |

**Composite Combinations:**

The `--composite` flag creates a CSR with a combined composite signature per IETF draft-ietf-lamps-pq-composite-sigs-13.
The signature is atomic - both components must be verified together.

| Combination | OID | Security Level |
|-------------|-----|----------------|
| `mldsa44-ecdsa-p256` | 1.3.6.1.5.5.7.6.40 | Level 2 |
| `mldsa65-ecdsa-p256` | 1.3.6.1.5.5.7.6.45 | Level 3 |
| `mldsa87-ecdsa-p384` | 1.3.6.1.5.5.7.6.49 | Level 5 |

**RFC 9883 (ML-KEM Attestation):**

ML-KEM keys cannot sign (they're Key Encapsulation Mechanisms). To prove possession of an ML-KEM private key, RFC 9883 defines the `privateKeyPossessionStatement` attribute. This requires:

1. An existing signature certificate (`--attest-cert`)
2. The corresponding private key (`--attest-key`)

The CSR is signed by the attestation key, and includes a reference to the attestation certificate. The CA verifies the attestation chain before issuing the ML-KEM certificate.

#### csr info

Display information about a CSR.

```bash
qpki csr info <csr-file>
```

**Example:**

```bash
qpki csr info server.csr
```

#### csr verify

Verify the signature of a CSR.

```bash
qpki csr verify <csr-file>
```

**Example:**

```bash
qpki csr verify server.csr
```

### 2.5 Certificate Issuance

#### cert issue

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

### 2.5 Credentials

> **See [CREDENTIALS.md](CREDENTIALS.md)** for the complete credential management guide.

Credentials bundle private key(s) + certificate(s) with coupled lifecycle management.

**Quick reference:**

```bash
# Enroll a new credential
qpki credential enroll --profile ec/tls-server --var cn=server.example.com

# List credentials
qpki credential list

# Rotate a credential
qpki credential rotate <credential-id>
qpki credential activate <credential-id> --version <new-version>

# Revoke a credential
qpki credential revoke <credential-id> --reason keyCompromise
```

### 2.6 Certificate Inspection and Verification

#### cert list

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

#### cert info

Display information about a certificate.

```bash
qpki cert info <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki cert info 0x03 --ca-dir ./myca
```

#### inspect

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

#### cert verify

Verify a certificate's validity and revocation status.

```bash
qpki cert verify <certificate> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca` | | required | CA certificate (PEM) |
| `--crl` | | | CRL file for revocation check (PEM/DER) |
| `--ocsp` | | | OCSP responder URL |

**Checks performed:**
- Certificate signature (signed by CA)
- Validity period (not before / not after)
- Critical extensions
- Revocation status (if --crl or --ocsp provided)

**Examples:**

```bash
# Basic validation
qpki cert verify server.crt --ca ca.crt

# With CRL check
qpki cert verify server.crt --ca ca.crt --crl ca/crl/ca.crl

# With OCSP check
qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

### 2.8 Revocation

#### cert revoke

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

#### crl gen

Generate a Certificate Revocation List.

```bash
qpki crl gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |
| `--algo` | | "" | Algorithm family (ec, ml-dsa, etc.) - multi-profile CA only |
| `--all` | | false | Generate CRLs for all algorithm families |

**Examples:**

```bash
# Generate CRL valid for 7 days
qpki crl gen --ca-dir ./myca

# Generate CRL valid for 30 days
qpki crl gen --ca-dir ./myca --days 30

# For multi-profile CA: generate CRL for specific algorithm
qpki crl gen --ca-dir ./myca --algo ec

# For multi-profile CA: generate all CRLs
qpki crl gen --ca-dir ./myca --all
```

#### crl info

Display detailed information about a Certificate Revocation List.

```bash
qpki crl info <crl-file>
```

**Output includes:**
- Issuer name
- This Update / Next Update timestamps
- Signature algorithm
- CRL Number (if present)
- Authority Key Identifier
- Number of revoked certificates
- Expiry status
- List of revoked serials with revocation date and reason

**Examples:**

```bash
# Display CRL information
qpki crl info ./ca/crl/ca.crl

# Works with PEM or DER format
qpki crl info /path/to/crl.pem
```

#### crl verify

Verify the signature of a Certificate Revocation List.

```bash
qpki crl verify <crl-file> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ca` | (required) | CA certificate (PEM) |
| `--check-expiry` | false | Also check if CRL is expired |

**Examples:**

```bash
# Verify CRL signature
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

# Verify signature and check expiration
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt --check-expiry
```

#### crl list

List all CRLs in a CA directory.

```bash
qpki crl list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Output columns:**
- NAME: CRL filename
- THIS UPDATE: When the CRL was generated
- NEXT UPDATE: When the CRL expires
- REVOKED: Number of revoked certificates
- STATUS: valid or EXPIRED

**Example:**

```bash
qpki crl list --ca-dir ./myca
```

### 2.9 Profiles

#### profile list

List available certificate profiles.

```bash
qpki profile list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki profile list --dir ./ca
```

#### profile info

Show details of a specific profile.

```bash
qpki profile info <name> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki profile info ec/tls-server --dir ./ca
```

#### profile vars

List all variables defined in a profile.

Shows variable names, types, constraints (required, pattern, enum), and default values.

```bash
qpki profile vars <name>
```

**Output columns:**
- NAME: Variable name
- TYPE: Variable type (string, string_list, int, etc.)
- REQUIRED: Whether the variable is required
- DEFAULT: Default value if any
- DESCRIPTION: Variable description

**Examples:**

```bash
# List variables for a builtin profile
qpki profile vars ec/tls-server

# List variables for a custom profile file
qpki profile vars ./my-profile.yaml
```

#### profile show

Display the raw YAML content of a profile.

Useful for exporting profiles via shell redirection.

```bash
qpki profile show <name>
```

**Examples:**

```bash
# Display profile YAML
qpki profile show ec/tls-server

# Export to file via redirection
qpki profile show ec/tls-server > my-tls-server.yaml
```

#### profile export

Export a builtin profile to a YAML file for customization.

```bash
qpki profile export <name> <file>
qpki profile export --all <directory>
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | false | Export all builtin profiles to directory |

**Examples:**

```bash
# Export a single profile
qpki profile export ec/tls-server ./my-tls-server.yaml

# Export all builtin profiles to a directory
qpki profile export --all ./templates/
```

#### profile lint

Validate a profile YAML file for correctness.

```bash
qpki profile lint <file>
```

**Example:**

```bash
qpki profile lint my-profile.yaml
```

#### profile install

Install default profiles to a CA directory.

```bash
qpki profile install [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--overwrite` | | false | Overwrite existing profiles |

**Example:**

```bash
qpki profile install --dir ./ca
```

## 3. Common Workflows

### 3.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
qpki ca init --profile ec/root-ca --ca-dir ./root-ca \
  --var cn="Root CA" --var organization="My Company"

# 2. Create issuing CA (signed by root, with full CA structure)
qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./root-ca --var cn="Issuing CA"

# 3. Issue server certificates from issuing CA
qpki credential enroll --ca-dir ./issuing-ca --cred-dir ./issuing-ca/credentials \
  --profile ec/tls-server \
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

### 3.2 More Workflows

> **See also:**
> - [CREDENTIALS.md](CREDENTIALS.md) - mTLS setup, credential rotation, code signing
> - [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md) - Algorithm migration (EC → Catalyst → ML-DSA)
> - [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common errors and debugging

## 4. FAQ

### Q: How do I create a CA with a custom validity period?

Use the `--validity` flag (in years for CA, days for end-entity):
```bash
qpki ca init --profile ec/root-ca --ca-dir ./ca --var cn="Long-lived CA" --validity 30
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
- [CREDENTIALS](CREDENTIALS.md) - Credential management (enroll, rotate, revoke)
- [CRYPTO-AGILITY](CRYPTO-AGILITY.md) - Algorithm migration guide
- [TROUBLESHOOTING](TROUBLESHOOTING.md) - Common errors and solutions
- [PROFILES](PROFILES.md) - Certificate profile templates
- [CONCEPTS](CONCEPTS.md) - PQC and hybrid certificate concepts
- [OPERATIONS](OPERATIONS.md) - OCSP, TSA, CMS, and audit operations
- [HSM](HSM.md) - Hardware Security Module integration
