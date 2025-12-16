# Quantum-Safe PKI

[![CI](https://github.com/remiblancher/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/pki/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/pki)](https://goreportcard.com/report/github.com/remiblancher/pki)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A minimalist, quantum-safe Public Key Infrastructure (PKI) implementation in Go.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA and ML-KEM
- **Hybrid certificates** (classical signature + PQC via X.509 extensions)
- **HSM support** via PKCS#11 (interface ready)
- **CLI-only** - simple, scriptable, no database required
- **Pure Go** - no CGO dependencies, uses cloudflare/circl

## Supported Algorithms

### Classical (Production)
| Algorithm | Usage |
|-----------|-------|
| ECDSA P-256 | Default, maximum compatibility |
| ECDSA P-384 | High security |
| ECDSA P-521 | Ultra security |
| Ed25519 | Modern, fast |
| RSA-2048/4096 | Legacy support |

### Post-Quantum (Experimental)
| Algorithm | Standard | Security Level | Type |
|-----------|----------|----------------|------|
| ML-DSA-44 | FIPS 204 | NIST Level 1 | Signature |
| ML-DSA-65 | FIPS 204 | NIST Level 3 | Signature |
| ML-DSA-87 | FIPS 204 | NIST Level 5 | Signature |
| SLH-DSA-128s/f | FIPS 205 | NIST Level 1 | Signature (hash-based) |
| SLH-DSA-192s/f | FIPS 205 | NIST Level 3 | Signature (hash-based) |
| SLH-DSA-256s/f | FIPS 205 | NIST Level 5 | Signature (hash-based) |
| ML-KEM-512 | FIPS 203 | NIST Level 1 | Key encapsulation |
| ML-KEM-768 | FIPS 203 | NIST Level 3 | Key encapsulation |
| ML-KEM-1024 | FIPS 203 | NIST Level 5 | Key encapsulation |

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
pki issue --ca-dir ./issuing-ca --profile tls-server \
  --cn server.example.com --out server.crt --key-out server.key
```

This creates a complete CA structure with:
- `ca.crt` - Subordinate CA certificate
- `chain.crt` - Full certificate chain (sub CA + root)
- `private/ca.key` - Subordinate CA private key

### Issue Certificates

```bash
# Issue a TLS server certificate (auto-generates key)
pki issue --ca-dir ./myca --profile tls-server \
  --cn server.example.com \
  --dns server.example.com,www.example.com \
  --out server.crt --key-out server.key

# Issue a TLS client certificate
pki issue --ca-dir ./myca --profile tls-client \
  --cn "user@example.com" \
  --out client.crt --key-out client.key

# Issue a subordinate/issuing CA
pki issue --ca-dir ./myca --profile issuing-ca \
  --cn "Issuing CA" \
  --out issuing-ca.crt --key-out issuing-ca.key
```

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

The PKI supports hybrid certificates that combine classical signatures with post-quantum material. This approach:

1. Uses classical algorithm (ECDSA/RSA) for the X.509 signature (compatibility)
2. Embeds PQC public key in a non-critical extension (future-proofing)

```bash
# Create CA with hybrid support
pki init-ca --name "Hybrid CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca

# Issue hybrid certificate
pki issue --ca-dir ./hybrid-ca --profile tls-server \
  --cn server.example.com \
  --hybrid ml-dsa-65 \
  --out hybrid-server.crt
```

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

## Project Status

| Component | Status |
|-----------|--------|
| Classical CA (ECDSA/RSA/Ed25519) | ✅ Production |
| X.509 certificate issuance | ✅ Production |
| Certificate profiles | ✅ Production |
| CRL generation | ✅ Production |
| PQC algorithms (ML-DSA, SLH-DSA, ML-KEM) | 🧪 Experimental |
| Hybrid PQC certificates | 🧪 Experimental |
| Audit logging | ✅ Production |
| HSM via PKCS#11 | 🚧 Not implemented |

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Pure PQC certificates are not yet supported by Go's crypto/x509 package. The hybrid approach allows classical-signed certificates that transport PQC material via X.509 extensions, providing a migration path to quantum-safe cryptography.
