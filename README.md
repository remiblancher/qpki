# Quantum-Safe PKI

[![CI](https://github.com/remiblancher/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/pki/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/pki)](https://goreportcard.com/report/github.com/remiblancher/pki)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A minimalist, quantum-safe Public Key Infrastructure (PKI) implementation in Go.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA, SLH-DSA and ML-KEM
- **CSR generation** for all algorithms including RFC 9883 ML-KEM attestation
- **Catalyst certificates** (ITU-T X.509 Section 9.8) - dual keys in single cert
- **Hybrid certificates** (classical + PQC via combined or separate modes)
- **Profiles** (policy templates) - define enrollment policies in YAML
- **Bundles** - group certificates with coupled lifecycle
- **HSM support** via PKCS#11 (interface ready)
- **CLI-only** - simple, scriptable, no database required
- **Pure Go** - no CGO dependencies, uses cloudflare/circl

## Supported Algorithms

### Classical (Production)
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ECDSA P-256 | ~128-bit | Default, wide compatibility |
| ECDSA P-384 | ~192-bit | Recommended for new deployments |
| ECDSA P-521 | ~256-bit | Maximum classical security |
| Ed25519 | ~128-bit | Fast, constant-time |
| RSA-2048/4096 | ~112/140-bit | Legacy compatibility |

### Post-Quantum (Experimental)
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ML-DSA-44/65/87 | NIST Level 1/3/5 | FIPS 204, lattice-based |
| SLH-DSA-128/192/256 | NIST Level 1/3/5 | FIPS 205, hash-based |
| ML-KEM-512/768/1024 | NIST Level 1/3/5 | FIPS 203, key encapsulation |

## Installation

### Download pre-built binaries (recommended)

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

### Verify release signatures

All releases are signed with GPG. To verify:

```bash
# Import public key
gpg --keyserver keyserver.ubuntu.com --recv-keys 39CD0BF9647E3F56

# Download checksums and signature
curl -LO https://github.com/remiblancher/pki/releases/download/vX.Y.Z/checksums.txt
curl -LO https://github.com/remiblancher/pki/releases/download/vX.Y.Z/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt
```

### Build from source

Requires Go 1.21 or later.

```bash
# Clone and build
git clone https://github.com/remiblancher/pki.git
cd pki
go build -o pki ./cmd/pki

# Or install directly to GOPATH/bin
go install github.com/remiblancher/pki/cmd/pki@latest
```

## Requirements

- **Go 1.21** or later (only for building from source)
- No CGO required (pure Go)
- No external dependencies (OpenSSL not required)

## Dependencies

This project uses minimal, well-maintained dependencies:

| Dependency | Version | Purpose |
|------------|---------|---------|
| [cloudflare/circl](https://github.com/cloudflare/circl) | v1.6.1 | Post-quantum cryptography (ML-DSA, ML-KEM) |
| [spf13/cobra](https://github.com/spf13/cobra) | v1.10.2 | CLI framework |

### PQC Implementation

Post-quantum algorithms are provided by **Cloudflare's CIRCL** library:
- **ML-DSA** (FIPS 204) - Digital signatures (Dilithium)
- **SLH-DSA** (FIPS 205) - Hash-based digital signatures (SPHINCS+)
- **ML-KEM** (FIPS 203) - Key encapsulation (Kyber)

CIRCL is tested against official NIST test vectors and is used in production at Cloudflare. We rely on their implementation rather than re-implementing PQC algorithms.

## Quick Start

### Initialize a Root CA

```bash
# Create a CA with ECDSA P-256 (default)
pki init-ca --name "My Root CA" --org "My Organization" --dir ./root-ca

# Create a CA with P-384 (higher security)
pki init-ca --name "My Root CA" --algorithm ecdsa-p384 --dir ./root-ca

# Create a hybrid CA (ECDSA + ML-DSA)
pki init-ca --name "Hybrid Root CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca
```

### Create a Subordinate CA

```bash
# Create a subordinate/issuing CA signed by the root
pki init-ca --name "Issuing CA" --org "My Organization" \
  --dir ./issuing-ca --parent ./root-ca

# The subordinate CA can then issue end-entity certificates
pki issue --ca-dir ./issuing-ca --profile ecdsa/tls-server \
  --cn server.example.com --out server.crt --key-out server.key
```

This creates a complete CA structure with:
- `ca.crt` - Subordinate CA certificate
- `chain.crt` - Full certificate chain (sub CA + root)
- `private/ca.key` - Subordinate CA private key

### Generate Keys

```bash
# Generate an ECDSA key
pki genkey --algorithm ecdsa-p256 --out key.pem

# Generate an ML-DSA-65 (PQC lattice-based) key
pki genkey --algorithm ml-dsa-65 --out ml-dsa-key.pem

# Generate an SLH-DSA-128f (PQC hash-based) key
pki genkey --algorithm slh-dsa-128f --out slh-dsa-key.pem

# Generate with passphrase protection
pki genkey --algorithm ecdsa-p384 --out key.pem --passphrase mysecret
```

### Generate Certificate Signing Requests

```bash
# Classical CSR (ECDSA)
pki csr --algorithm ecdsa-p256 --keyout server.key --cn server.example.com -o server.csr

# PQC CSR (ML-DSA - direct signature)
pki csr --algorithm ml-dsa-65 --keyout mldsa.key --cn alice@example.com -o mldsa.csr

# ML-KEM CSR with RFC 9883 attestation
# (requires existing signature certificate to attest KEM key possession)
pki csr --algorithm ml-kem-768 --keyout kem.key --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key -o kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
pki csr --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com -o hybrid.csr

# CSR with existing key
pki csr --key existing.key --cn server.example.com -o server.csr
```

### Issue Certificates

```bash
# Direct issuance (auto-generates key)
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --cn server.example.com \
  --dns server.example.com,www.example.com \
  --out server.crt --key-out server.key

# From CSR (traditional PKI workflow)
pki issue --ca-dir ./myca --profile ecdsa/tls-server \
  --csr server.csr \
  --out server.crt
```

### Inspect Certificates

```bash
# Show certificate details
pki info certificate.crt

# Show key information
pki info private-key.pem

# List all issued certificates
pki list --ca-dir ./myca

# List only valid certificates
pki list --ca-dir ./myca --status valid
```

### Revocation

```bash
# Revoke a certificate by serial number
pki revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate new CRL
pki revoke 02 --ca-dir ./myca --gen-crl

# Generate/update CRL
pki gen-crl --ca-dir ./myca --days 30
```

## Certificate Profiles

| Profile | Description |
|---------|-------------|
| tls-server | TLS server authentication |
| tls-client | TLS client authentication |
| root-ca | Root CA certificate |
| issuing-ca | Subordinate/issuing CA |

## Hybrid PQC Certificates

The PKI supports hybrid certificates that combine classical signatures with post-quantum material.

### Catalyst Certificates (Recommended)

Catalyst certificates follow ITU-T X.509 Section 9.8, embedding dual keys and signatures in a single certificate:

```bash
# Enroll with Catalyst profile
pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/catalyst/tls-client --ca-dir ./ca
```

### Separate Linked Certificates

Two certificates linked via the RelatedCertificate extension:

```bash
# Enroll with separate certificates
pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/composite/tls-client --ca-dir ./ca
```

### Direct Issuance

```bash
# Create CA with hybrid support
pki init-ca --name "Hybrid CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca

# Issue hybrid certificate
pki issue --ca-dir ./hybrid-ca --profile ecdsa/tls-server \
  --cn server.example.com \
  --hybrid ml-dsa-65 \
  --out hybrid-server.crt
```

## Profiles (Policy Templates)

Profiles define certificate enrollment policies in YAML:

```bash
# Install default profiles
pki profile install --dir ./ca

# List available profiles
pki profile list --dir ./ca

# View profile details
pki profile info hybrid-catalyst --dir ./ca
```

**Default Profiles:**

| Name | Signature | Encryption | Certificates |
|------|-----------|------------|--------------|
| `classic` | ECDSA P-256 | None | 1 |
| `pqc-basic` | ML-DSA-65 | None | 1 |
| `pqc-full` | ML-DSA-65 | ML-KEM-768 | 2 |
| `hybrid-catalyst` | ECDSA + ML-DSA (Catalyst) | None | 1 |
| `hybrid-separate` | ECDSA + ML-DSA (linked) | None | 2 |
| `hybrid-full` | ECDSA + ML-DSA (Catalyst) | ML-KEM-768 | 2 |

See [docs/PROFILES.md](docs/PROFILES.md) for details.

## Bundles

Bundles group related certificates with coupled lifecycle:

```bash
# Enroll creates a bundle
pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/catalyst/tls-client --out ./alice

# List bundles
pki bundle list --ca-dir ./ca

# Renew all certificates in a bundle
pki bundle renew alice-20250115-abc123 --ca-dir ./ca

# Revoke all certificates in a bundle
pki bundle revoke alice-20250115-abc123 --reason keyCompromise --ca-dir ./ca
```

See [docs/BUNDLES.md](docs/BUNDLES.md) for details.

## CA Directory Structure

```
ca/
├── ca.crt           # CA certificate (PEM)
├── chain.crt        # Certificate chain (subordinate CA only)
├── private/
│   └── ca.key       # CA private key (PEM, optionally encrypted)
├── certs/           # Issued certificates by serial
│   ├── 01.crt
│   └── 02.crt
├── crl/
│   ├── ca.crl       # Current CRL (PEM)
│   └── ca.crl.der   # Current CRL (DER)
├── profiles/          # Certificate policy templates
│   ├── classic.yaml
│   ├── hybrid-catalyst.yaml
│   └── ...
├── bundles/         # Certificate bundles
│   └── <bundle-id>/
│       ├── bundle.json
│       ├── certificates.pem
│       └── private-keys.pem
├── index.txt        # Certificate database
├── serial           # Next serial number
└── crlnumber        # Next CRL number
```

## Development

```bash
# Run tests
make test

# Run tests with coverage
make coverage

# Lint code
make lint

# Build binary
make build
```

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Get started in 5 minutes |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Complete user guide with CLI reference |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and design |
| [SPECIFICATION.md](docs/SPECIFICATION.md) | Formal requirements and OID registry |
| [PROFILES.md](docs/PROFILES.md) | Certificate profile configuration |
| [BUNDLES.md](docs/BUNDLES.md) | Certificate bundle management |
| [OCSP.md](docs/OCSP.md) | OCSP responder (RFC 6960) |
| [TSA.md](docs/TSA.md) | Timestamping authority (RFC 3161) |
| [CATALYST.md](docs/CATALYST.md) | Catalyst hybrid certificates |
| [PQC.md](docs/PQC.md) | Post-quantum cryptography |
| [HSM.md](docs/HSM.md) | HSM/PKCS#11 integration |
| [AUDIT.md](docs/AUDIT.md) | Audit logging configuration |
| [TEST_STRATEGY.md](docs/TEST_STRATEGY.md) | Testing strategy |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute |
| [ROADMAP.md](docs/ROADMAP.md) | Future improvements |

## Project Status

| Component | Status |
|-----------|--------|
| Classical CA (ECDSA/RSA/Ed25519) | ✅ Production |
| X.509 certificate issuance | ✅ Production |
| CSR generation (all algorithms, RFC 9883) | ✅ Production |
| Certificate profiles | ✅ Production |
| CRL generation | ✅ Production |
| OCSP Responder (RFC 6960) | ✅ Production |
| TSA Timestamping (RFC 3161) | ✅ Production |
| CMS Signed Data (RFC 5652) | ✅ Production |
| PQC algorithms (ML-DSA, SLH-DSA, ML-KEM) | 🧪 Experimental |
| Catalyst certificates (ITU-T X.509 9.8) | 🧪 Experimental |
| Hybrid PQC certificates | 🧪 Experimental |
| Profiles (policy templates) | 🧪 Experimental |
| Bundles (certificate groups) | 🧪 Experimental |
| Audit logging | ✅ Production |
| HSM via PKCS#11 | 🚧 Not implemented |

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Pure PQC certificates are not yet supported by Go's crypto/x509 package. The hybrid approach allows classical-signed certificates that transport PQC material via X.509 extensions, providing a migration path to quantum-safe cryptography.
