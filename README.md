# Quantum-Safe PKI

[![CI](https://github.com/remiblancher/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/pki/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/pki)](https://goreportcard.com/report/github.com/remiblancher/pki)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A minimalist, quantum-safe Public Key Infrastructure (PKI) implementation in Go.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA and ML-KEM
- **Hybrid certificates** (classical + PQC via X.509 extensions)
- **HSM support** via PKCS#11
- **CLI-only** - simple, scriptable, no database required
- **Triple validation** - tested with Go, OpenSSL, and Bouncy Castle

## Supported Algorithms

### Classical (Production)
| Algorithm | Usage |
|-----------|-------|
| ECDSA P-256 | Default, maximum compatibility |
| ECDSA P-384 | High security |
| ECDSA P-521 | Ultra security |
| Ed25519 | Modern, fast |
| Ed448 | High security |
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

## Quick Start

### Installation

```bash
go install github.com/remiblancher/pki/cmd/pki@latest
```

### Create a PKI

```bash
# Initialize Root CA
pki init root \
  --name "My Root CA" \
  --alg ecdsa-p384 \
  --out ./pki/root

# Initialize Issuing CA
pki init issuing \
  --parent ./pki/root \
  --name "My Issuing CA" \
  --alg ecdsa-p256 \
  --out ./pki/issuing

# Issue a TLS server certificate
pki issue \
  --ca ./pki/issuing \
  --profile tls-server \
  --cn example.com \
  --san DNS:example.com,DNS:www.example.com \
  --out cert.pem

# Issue a hybrid certificate (classical + PQC)
pki issue \
  --ca ./pki/issuing \
  --profile tls-server \
  --cn example.com \
  --hybrid-alg ml-kem-768 \
  --out hybrid-cert.pem
```

### Revocation

```bash
# Revoke a certificate
pki revoke --ca ./pki/issuing --serial 0002 --reason keyCompromise

# Generate CRL
pki crl --ca ./pki/issuing --out crl.pem
```

### Inspect

```bash
pki inspect --cert cert.pem
pki inspect --crl crl.pem
pki inspect --ca ./pki/issuing
```

## HSM Support

The PKI supports Hardware Security Modules via PKCS#11:

```bash
pki init issuing \
  --parent ./pki/root \
  --name "HSM Issuing CA" \
  --signer pkcs11 \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token CA \
  --pkcs11-pin env:PKCS11_PIN \
  --pkcs11-key-label issuing-key
```

## Documentation

- [Specification](docs/SPECIFICATION.md) - Formal requirements and formats
- [Architecture](docs/ARCHITECTURE.md) - Technical design
- [User Guide](docs/USER_GUIDE.md) - Installation and usage
- [Test Strategy](docs/TEST_STRATEGY.md) - Testing approach
- [PQC Guide](docs/PQC.md) - Post-quantum cryptography details
- [HSM Guide](docs/HSM.md) - PKCS#11 integration

## Project Status

| Component | Status |
|-----------|--------|
| Classical CA (ECDSA/RSA/Ed25519) | Production |
| X.509 certificate issuance | Production |
| CRL generation | Production |
| HSM via PKCS#11 | Production |
| PQC hybrid extension | Experimental |
| Pure PQC certificates | Experimental |

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Most HSMs do not yet support ML-DSA/ML-KEM. The hybrid approach allows HSM-protected classical CA keys while transporting PQC material via X.509 extensions.
