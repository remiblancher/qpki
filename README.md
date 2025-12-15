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
| Algorithm | Standard | Security Level |
|-----------|----------|----------------|
| ML-DSA-44 | FIPS 204 | NIST Level 1 |
| ML-DSA-65 | FIPS 204 | NIST Level 3 |
| ML-DSA-87 | FIPS 204 | NIST Level 5 |
| ML-KEM-512 | FIPS 203 | NIST Level 1 |
| ML-KEM-768 | FIPS 203 | NIST Level 3 |
| ML-KEM-1024 | FIPS 203 | NIST Level 5 |

## Requirements

- **Go 1.21** or later
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
- **ML-KEM** (FIPS 203) - Key encapsulation (Kyber)

CIRCL is tested against official NIST test vectors and is used in production at Cloudflare. We rely on their implementation rather than re-implementing PQC algorithms.

## Installation

```bash
# From source
git clone https://github.com/remiblancher/pki.git
cd pki
go build -o pki ./cmd/pki

# Or install directly
go install github.com/remiblancher/pki/cmd/pki@latest
```

## Quick Start

### Initialize a Root CA

```bash
# Create a CA with ECDSA P-256 (default)
pki init-ca --name "My Root CA" --org "My Organization" --dir ./myca

# Create a CA with P-384 (higher security)
pki init-ca --name "My Root CA" --algorithm ecdsa-p384 --dir ./myca

# Create a hybrid CA (ECDSA + ML-DSA)
pki init-ca --name "Hybrid Root CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca
```

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

# Generate an ML-DSA-65 (PQC) key
pki genkey --algorithm ml-dsa-65 --out pqc-key.pem

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
| Hybrid PQC extension | 🧪 Experimental |
| HSM via PKCS#11 | 📝 Interface ready |

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Pure PQC certificates are not yet supported by Go's crypto/x509 package. The hybrid approach allows classical-signed certificates that transport PQC material via X.509 extensions, providing a migration path to quantum-safe cryptography.
