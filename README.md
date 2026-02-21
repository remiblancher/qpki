---
title: "Quick Start"
description: "Get started with QPKI - Quantum-Safe X.509 PKI in Go"
---

# QPKI

**Quantum-Safe X.509 PKI in Go**

[![CI](https://github.com/remiblancher/qpki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/qpki/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/remiblancher/qpki/branch/main/graph/badge.svg)](https://codecov.io/gh/remiblancher/qpki)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/qpki)](https://goreportcard.com/report/github.com/remiblancher/qpki)
[![Go Reference](https://pkg.go.dev/badge/github.com/remiblancher/qpki.svg)](https://pkg.go.dev/github.com/remiblancher/qpki)
[![Release](https://img.shields.io/github/v/release/remiblancher/qpki)](https://github.com/remiblancher/qpki/releases)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/remiblancher/qpki/network/updates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

QPKI is a quantum-safe PKI toolkit to help organizations prepare for post-quantum cryptography (PQC) with interoperable, standards-compliant certificates.

> **For education and prototyping** — Learn PKI concepts, experiment with PQC migration, and test crypto-agility. See [Qlab](https://github.com/remiblancher/qlab) for step-by-step tutorials.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA, SLH-DSA and ML-KEM
- **CSR generation** for all algorithms including RFC 9883 ML-KEM attestation
- **Catalyst certificates** (ITU-T X.509 Section 9.8) - dual keys via extensions
- **Composite certificates** (IETF draft-13, **DRAFT**) - dual keys bound together
- **Hybrid certificates** (classical + PQC via combined or separate modes)
- **CMS Signatures & Encryption** (RFC 5652) - sign and encrypt with PQC
- **Crypto-agility** - seamless migration between algorithms (ECDSA → ML-DSA)
- **Profiles** (certificate templates) - define certificate policies in YAML
- **Credentials** - group certificates with coupled lifecycle
- **HSM support** via PKCS#11
- **Cross-validated** with external implementations (OpenSSL, BouncyCastle)
- **CLI-first** - simple, scriptable, no database required
- **PQC via [Cloudflare CIRCL](https://github.com/cloudflare/circl)** — FIPS 203/204/205 implementations, NIST test vectors validated
- **Pure Go by default** - CGO optional (only for HSM/PKCS#11)

## Supported Algorithms

### Classical
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ECDSA (P-256, P-384, P-521) | ~128/192/256-bit | NIST curves, P-384 recommended |
| EdDSA (Ed25519, Ed448) | ~128/224-bit | Fast, constant-time |
| RSA (2048, 4096) | ~112/140-bit | Legacy compatibility |

*EC keys support both ECDSA (signature) and ECDH (key agreement) depending on certificate keyUsage.*

### Post-Quantum
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ML-DSA-44/65/87 | NIST Level 1/3/5 | FIPS 204, lattice-based |
| SLH-DSA-128/192/256 | NIST Level 1/3/5 | FIPS 205, hash-based |
| ML-KEM-512/768/1024 | NIST Level 1/3/5 | FIPS 203, key encapsulation |

*Classical security levels reflect resistance to classical attacks only. Post-quantum algorithms are designed to remain secure against quantum adversaries.*

## Installation

### Requirements

- **Go 1.25** or later (only for building from source)
- No CGO required for standard usage
- CGO required only for HSM/PKCS#11 support (optional)
- No external dependencies (OpenSSL not required)

### Download pre-built binaries (recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/remiblancher/qpki/releases/latest).

**Linux / macOS:**
```bash
# Download (replace VERSION, OS, and ARCH as needed)
curl -LO https://github.com/remiblancher/qpki/releases/latest/download/qpki_VERSION_OS_ARCH.tar.gz

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
| macOS | Universal | `qpki_VERSION_darwin_all.tar.gz` |
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

### Verify release signatures

All releases are signed with GPG. To verify:

```bash
# Import public key
gpg --keyserver keyserver.ubuntu.com --recv-keys 39CD0BF9647E3F56

# Download checksums and signature
curl -LO https://github.com/remiblancher/qpki/releases/download/vX.Y.Z/checksums.txt
curl -LO https://github.com/remiblancher/qpki/releases/download/vX.Y.Z/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt
```

### Build from source

Requires Go 1.25 or later.

```bash
# Clone and build
git clone https://github.com/remiblancher/qpki.git
cd qpki
go build -o qpki ./cmd/qpki

# Or install directly to GOPATH/bin
go install github.com/remiblancher/qpki/cmd/qpki@latest
```

### Verify installation

```bash
qpki version
qpki --help
```

## Quick Start

### Initialize a Root CA

```bash
# Create a CA with ECDSA P-384 (recommended)
qpki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"
# → root-ca/{ca.crt, private/ca.key, certs/, crl/, index.txt, serial}

# Create a hybrid CA (ECDSA + ML-DSA, ITU-T X.509 Section 9.8)
qpki ca init --profile hybrid/catalyst/root-ca --ca-dir ./hybrid-ca --var cn="Hybrid Root CA"

# Create a pure PQC CA (ML-DSA-87)
qpki ca init --profile ml/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"
```

### Create a Subordinate CA

```bash
# Create a subordinate/issuing CA signed by the root
qpki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca \
  --parent ./root-ca --var cn="Issuing CA"
```

This creates a complete CA structure with:
- `ca.crt` - Subordinate CA certificate
- `chain.crt` - Full certificate chain (sub CA + root)
- `private/ca.key` - Subordinate CA private key

### Generate Keys

Generate private key files. The public key is mathematically derived from the private key and can be extracted using `qpki key pub`.

```bash
# Generate an ECDSA key
qpki key generate --algorithm ecdsa-p256 --out key.pem

# Generate an ML-DSA-65 (PQC lattice-based) key
qpki key generate --algorithm ml-dsa-65 --out ml-dsa-key.pem

# Generate an SLH-DSA-128f (PQC hash-based) key
qpki key generate --algorithm slh-dsa-128f --out slh-dsa-key.pem

# Generate with passphrase protection
qpki key generate --algorithm ecdsa-p384 --out key.pem --passphrase mysecret

# Extract public key from private key
qpki key pub --key key.pem --out key.pub
```

### Generate Certificate Signing Requests

When using `--keyout`, the private key is generated alongside the CSR. Use `--key` to create a CSR from an existing key.

```bash
# Generate NEW key pair + CSR
qpki csr gen --algorithm ecdsa-p256 --keyout server.key --cn server.example.com --out server.csr

# CSR from EXISTING key (no key generation)
qpki csr gen --key existing.key --cn server.example.com --out server.csr

# PQC CSR (ML-DSA)
qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key --cn alice@example.com --out mldsa.csr

# ML-KEM CSR with RFC 9883 attestation
qpki csr gen --algorithm ml-kem-768 --keyout kem.key --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key --out kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
qpki csr gen --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com --out hybrid.csr
```

### Issue Certificates

Certificates are always issued from a CSR (Certificate Signing Request).
For direct issuance with key generation, use `qpki credential enroll` instead.

```bash
# From classical CSR with variables
qpki cert issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --out server.crt \
  --var cn=api.example.com \
  --var dns_names=api.example.com,api-v2.example.com

# Using a variables file
qpki cert issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --var-file vars.yaml

# From PQC signature CSR (ML-DSA, SLH-DSA)
qpki cert issue --ca-dir ./myca --profile ml/tls-server-sign \
  --csr mldsa.csr --out server.crt \
  --var cn=pqc.example.com

# From ML-KEM CSR (requires RFC 9883 attestation for verification)
qpki cert issue --ca-dir ./myca --profile ml-kem/client \
  --csr kem.csr --out kem.crt \
  --attest-cert sign.crt --var cn=client@example.com

# From Hybrid CSR (classical + PQC dual signatures)
qpki cert issue --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --csr hybrid.csr --out server.crt \
  --var cn=hybrid.example.com
```

### Inspect & Verify

```bash
# Show certificate details
qpki inspect certificate.crt

# Show key information
qpki inspect private-key.pem

# Verify certificate chain
qpki cert verify server.crt --ca ./myca/ca.crt

# Verify with CRL revocation check
qpki cert verify server.crt --ca ./myca/ca.crt --crl ./myca/crl/ca.crl

# List all issued certificates
qpki cert list --ca-dir ./myca

# List only valid certificates
qpki cert list --ca-dir ./myca --status valid
```

### Sign & Encrypt with CMS

```bash
# Sign a document (detached signature)
qpki cms sign --data doc.pdf --cert signer.crt --key signer.key --out doc.p7s

# Verify signature
qpki cms verify doc.p7s --data doc.pdf --ca ca.crt

# Encrypt for recipient (supports ECDH, RSA, ML-KEM)
qpki cms encrypt --recipient bob.crt --in secret.txt --out secret.p7m

# Decrypt
qpki cms decrypt --key bob.key --in secret.p7m --out secret.txt
```

### Revocation

```bash
# Revoke a certificate by serial number
qpki cert revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate new CRL
qpki cert revoke 02 --ca-dir ./myca --gen-crl

# Generate/update CRL
qpki crl gen --ca-dir ./myca --days 30
```

## Certificate Profiles

Profiles are YAML files that define how certificates are issued. **1 profile = 1 certificate type**.

QPKI includes **50+ built-in profiles** covering common use cases. All examples in this README use these built-in profiles for simplicity.

```bash
# List all built-in profiles
qpki profile list

# View profile details
qpki profile info hybrid/catalyst/tls-server

# Export a profile to customize it
qpki profile export ec/tls-server ./my-tls-server.yaml

# Export all profiles for reference
qpki profile export --all ./templates/
```

You can also create custom profiles from scratch. See [Profiles](docs/core-pki/PROFILES.md) for the full YAML specification.

**Profile Categories:**

| Category | Description |
|----------|-------------|
| `ec/*` | ECDSA profiles (modern classical) |
| `rsa/*` | RSA profiles (legacy compatibility) |
| `ml/*` | ML-DSA and ML-KEM (post-quantum) |
| `slh/*` | SLH-DSA (hash-based post-quantum) |
| `hybrid/catalyst/*` | Catalyst dual-key (ITU-T X.509 9.8) |
| `hybrid/composite/*` | IETF composite signatures |

**Example Profile (catalyst mode):**

```yaml
name: hybrid/catalyst/tls-server
mode: catalyst
algorithms:
  - ecdsa-p256
  - ml-dsa-65
validity: 365d
extensions:
  keyUsage:
    values: [digitalSignature]
  extKeyUsage:
    values: [serverAuth]
```

See [Profiles](docs/core-pki/PROFILES.md) for details.

## Credentials

A credential is a managed bundle of **private key(s) + certificate(s)** with coupled lifecycle management (enrollment, renewal, revocation).

`credential enroll` generates everything in one command:

```bash
qpki credential enroll --ca-dir ./myca --profile ec/tls-client --var cn=Alice
# → credentials/<id>/{credential.meta.json, certificates.pem, private-keys.pem}
```

**Why use credentials?**
- **Coupled lifecycle**: Renew or revoke all certificates at once
- **Multi-certificate**: Use multiple `--profile` flags for crypto-agility (classical + PQC)

```bash
# Create credential with multiple profiles (crypto-agility)
qpki credential enroll --ca-dir ./myca --profile ec/client --profile ml/client --var cn=Alice

# Create credential with custom ID
qpki credential enroll --ca-dir ./myca --profile hybrid/catalyst/tls-client --var cn=Alice --id alice-prod
```

Manage credential lifecycle:

```bash
# List credentials
qpki credential list

# Show credential details
qpki credential info alice-20250115-abc123

# Renew all certificates in a credential
qpki credential rotate alice-20250115-abc123

# Renew with crypto migration (add/change profiles)
qpki credential rotate alice-20250115-abc123 --profile ec/client --profile ml/client

# Revoke all certificates in a credential
qpki credential revoke alice-20250115-abc123 --reason keyCompromise
```

See [Credentials](docs/end-entities/CREDENTIALS.md) for details.

## Interoperability & Compatibility

This project focuses on **real-world Post-Quantum PKI interoperability**.
All artifacts are designed to be compatible with standard PKI tooling and are **cross-tested with external implementations**.

### Standards Compliance

| Standard | Description | Status |
|----------|-------------|--------|
| RFC 5280 | X.509 Certificates and CRL | 🟢 |
| RFC 2986 | PKCS#10 CSR | 🟢 |
| RFC 9883 | ML-KEM CSR Attestation | 🟢 |
| RFC 6960 | OCSP | 🟢 |
| RFC 3161 | TSA Timestamping | 🟢 |
| RFC 5652 | CMS Signed Data | 🟢 |
| RFC 8419 | EdDSA in CMS | 🟢 |
| RFC 9814 | SLH-DSA in CMS | 🟢 |
| RFC 9882 | ML-DSA in CMS | 🟢 |
| FIPS 203 | ML-KEM | 🟢 |
| FIPS 204 | ML-DSA | 🟢 |
| FIPS 205 | SLH-DSA | 🟢 |
| ITU-T X.509 9.8 | Catalyst (dual-key extensions) | 🟢 |
| IETF draft-13 | Composite Signatures | 🟢 |

### Interoperability Matrix

Artifacts are validated using **OpenSSL 3.6+** and **BouncyCastle 1.83+**.

#### Certificates

| Type | QPKI | OpenSSL | BouncyCastle |
|------|------|---------|--------------|
| Classical (ECDSA/RSA) | 🟢 | 🟢 verify | 🟢 verify |
| PQC (ML-DSA, SLH-DSA) | 🟢 | 🟢 verify | 🟢 verify |
| Catalyst Hybrid | 🟢 both sigs | 🟢 ECDSA only | 🟢 both sigs |
| Composite (IETF) | 🟢 both sigs | 🔴 | 🟡 parse only* |

#### CSR (Certificate Signing Requests)

| Type | QPKI | OpenSSL | BouncyCastle |
|------|------|---------|--------------|
| Classical | 🟢 | 🟢 verify | 🟢 verify |
| PQC (ML-DSA) | 🟢 | 🟢 verify | 🟢 verify |
| ML-KEM (RFC 9883) | 🟢 | 🟢 parse | 🟢 verify |
| Hybrid | 🟢 | 🟢 primary | 🟢 both sigs |

#### CRL (Certificate Revocation Lists)

| Type | QPKI | OpenSSL | BouncyCastle |
|------|------|---------|--------------|
| Classical | 🟢 | 🟢 verify | 🟢 verify |
| PQC (ML-DSA, SLH-DSA) | 🟢 | 🟢 verify | 🟢 verify |
| Catalyst Hybrid | 🟢 both sigs | 🟢 ECDSA only | 🟢 both sigs |
| Composite (IETF) | 🟢 both sigs | 🔴 | 🟡 parse only* |

#### OCSP, TSA, CMS

| Artifact | QPKI | OpenSSL | BouncyCastle |
|----------|------|---------|--------------|
| OCSP Response | 🟢 | 🟢 verify | 🟢 verify |
| TSA Timestamp | 🟢 | 🟢 verify | 🟢 verify |
| CMS Signed Data | 🟢 | 🟢 verify | 🟢 verify |
| CMS Enveloped (ML-KEM) | 🟢 | 🟢 decrypt | 🟢 decrypt |

### Known Limitations

| Feature | Status | Notes |
|---------|--------|-------|
| Composite signatures | 🟡 Partial | BC 1.83 uses draft-07 OIDs, we use IETF draft-13 |
| OpenSSL Catalyst | 🟡 Partial | Only ECDSA signature verified, PQC ignored |
| HSM support (PKCS#11) | 🟢 | Tested with SoftHSM; hardware HSM not yet validated |

*\*Composite: BC 1.83 implements draft-07 (Entrust OIDs `2.16.840.1.114027.80.8.1.x`), our implementation uses draft-13 (IETF standard OIDs `1.3.6.1.5.5.7.6.x`). Certificates parse correctly but signature verification requires OID migration in BC.*

### Running Cross-Tests

```bash
make crosstest          # All (OpenSSL + BouncyCastle)
make crosstest-openssl  # OpenSSL only
make crosstest-bc       # BouncyCastle only (requires Java 17+)
```

> OpenSSL and BouncyCastle are used **for interoperability validation only**.
> This project does **not embed nor depend on** these libraries.

See [docs/dev/TESTING.md](docs/dev/TESTING.md) for details on the testing strategy.

## Documentation

### Getting Started

| Document | Description |
|----------|-------------|
| [Installation](docs/getting-started/INSTALLATION.md) | Download binaries, Homebrew, or build from source |
| [Quick Start](docs/getting-started/QUICK-START.md) | Create your first CA and certificate in 5 minutes |
| [Post-Quantum](docs/getting-started/POST-QUANTUM.md) | PQC algorithms and hybrid certificates |

### Core PKI

| Document | Description |
|----------|-------------|
| [CA](docs/core-pki/CA.md) | CA initialization and management |
| [Profiles](docs/core-pki/PROFILES.md) | Certificate profile templates |
| [Keys & CSR](docs/core-pki/KEYS.md) | Key generation and CSR operations |
| [Certificates](docs/core-pki/CERTIFICATES.md) | Certificate issuance |
| [CRL](docs/core-pki/CRL.md) | Revocation lists |

### End Entities

| Document | Description |
|----------|-------------|
| [Credentials](docs/end-entities/CREDENTIALS.md) | Bundled key + certificate lifecycle |

### Services

| Document | Description |
|----------|-------------|
| [OCSP](docs/services/OCSP.md) | Real-time certificate status (RFC 6960) |
| [TSA](docs/services/TSA.md) | Timestamping service (RFC 3161) |
| [CMS](docs/services/CMS.md) | CMS signatures and encryption (RFC 5652) |
| [COSE](docs/services/COSE.md) | CBOR Object Signing (IoT, attestation) |

### Operations

| Document | Description |
|----------|-------------|
| [HSM](docs/operations/HSM.md) | Hardware Security Module integration (PKCS#11) |
| [Audit](docs/operations/AUDIT.md) | Audit logging and SIEM integration |

### Migration

| Document | Description |
|----------|-------------|
| [Crypto-Agility](docs/migration/CRYPTO-AGILITY.md) | Algorithm migration guide |
| [Hybrid](docs/migration/HYBRID.md) | Hybrid certificates |

### Reference

| Document | Description |
|----------|-------------|
| [CLI](docs/reference/CLI.md) | Complete command reference |
| [Troubleshooting](docs/reference/TROUBLESHOOTING.md) | Common errors and solutions |
| [Standards](docs/reference/STANDARDS.md) | OIDs and formats |
| [PKI Basics](docs/reference/PKI-BASICS.md) | Certificates, keys, CAs, trust chains |
| [Glossary](docs/reference/GLOSSARY.md) | PKI and PQC terminology |

### Development

| Document | Description |
|----------|-------------|
| [Architecture](docs/dev/ARCHITECTURE.md) | System architecture overview |
| [Contributing](docs/dev/CONTRIBUTING.md) | Contribution guide |
| [Testing](docs/dev/TESTING.md) | Testing guide |
| [Interoperability](docs/dev/INTEROPERABILITY.md) | Interop testing |

## About

Developed and maintained by **Remi Blancher**, cryptography and PKI specialist with 20+ years of experience in cryptographic infrastructures and post-quantum migration.

For questions, feedback, or professional inquiries:
- Email: remi.blancher@proton.me
- LinkedIn: linkedin.com/in/remiblancher

## License

Apache License 2.0 - See [LICENSE](https://github.com/remiblancher/qpki/blob/main/LICENSE) for details.
