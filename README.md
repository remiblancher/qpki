# Quantum-Safe PKI

[![CI](https://github.com/remiblancher/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/pki/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/pki)](https://goreportcard.com/report/github.com/remiblancher/pki)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A minimalist, quantum-safe Public Key Infrastructure (PKI) implementation in Go.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA, SLH-DSA and ML-KEM
- **CSR generation** for all algorithms including RFC 9883 ML-KEM attestation
- **Catalyst certificates** (ITU-T X.509 Section 9.8) - dual keys via extensions
- **Composite certificates** (IETF draft-13, **DRAFT**) - dual keys bound together
- **Hybrid certificates** (classical + PQC via combined or separate modes)
- **Profiles** (certificate templates) - define certificate policies in YAML
- **Credentials** - group certificates with coupled lifecycle
- **HSM support** via PKCS#11 (interface ready)
- **Cross-validated** - certificates verified by OpenSSL and BouncyCastle
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
# Create a CA with ECDSA P-384 (recommended)
pki ca init --name "My Root CA" --profile ec/root-ca --dir ./root-ca

# Create a hybrid CA (ECDSA + ML-DSA, ITU-T X.509 Section 9.8)
pki ca init --name "Hybrid Root CA" --profile hybrid/catalyst/root-ca --dir ./hybrid-ca

# Create a pure PQC CA (ML-DSA-87)
pki ca init --name "PQC Root CA" --profile ml-dsa-kem/root-ca --dir ./pqc-ca
```

### Create a Subordinate CA

```bash
# Create a subordinate/issuing CA signed by the root
pki ca init --name "Issuing CA" --profile ec/issuing-ca \
  --dir ./issuing-ca --parent ./root-ca
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
pki cert csr --algorithm ecdsa-p256 --keyout server.key --cn server.example.com -o server.csr

# PQC CSR (ML-DSA - direct signature)
pki cert csr --algorithm ml-dsa-65 --keyout mldsa.key --cn alice@example.com -o mldsa.csr

# ML-KEM CSR with RFC 9883 attestation
# (requires existing signature certificate to attest KEM key possession)
pki cert csr --algorithm ml-kem-768 --keyout kem.key --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key -o kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
pki cert csr --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com -o hybrid.csr

# CSR with existing key
pki cert csr --key existing.key --cn server.example.com -o server.csr
```

### Issue Certificates

Certificates are always issued from a CSR (Certificate Signing Request).
For direct issuance with key generation, use `pki credential enroll` instead.

```bash
# From classical CSR with variables
pki cert issue --profile ec/tls-server --csr server.csr --out server.crt \
  --var cn=api.example.com \
  --var dns_names=api.example.com,api-v2.example.com

# Using a variables file
pki cert issue --profile ec/tls-server --csr server.csr --var-file vars.yaml

# From PQC signature CSR (ML-DSA, SLH-DSA)
pki cert issue --profile ml-dsa-kem/tls-server-sign --csr mldsa.csr --out server.crt \
  --var cn=pqc.example.com

# From ML-KEM CSR (requires RFC 9883 attestation for verification)
pki cert issue --profile ml-kem/client --csr kem.csr --out kem.crt \
  --attest-cert sign.crt --var cn=client@example.com

# From Hybrid CSR (classical + PQC dual signatures)
pki cert issue --profile hybrid/catalyst/tls-server --csr hybrid.csr --out server.crt \
  --var cn=hybrid.example.com
```

### Inspect Certificates

```bash
# Show certificate details
pki inspect certificate.crt

# Show key information
pki inspect private-key.pem

# List all issued certificates
pki cert list --ca-dir ./myca

# List only valid certificates
pki cert list --ca-dir ./myca --status valid
```

### Revocation

```bash
# Revoke a certificate by serial number
pki cert revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate new CRL
pki cert revoke 02 --ca-dir ./myca --gen-crl

# Generate/update CRL
pki cert gen-crl --ca-dir ./myca --days 30
```

## Profiles (Certificate Templates)

Profiles define certificate enrollment policies in YAML. **1 profile = 1 certificate**.

```bash
# List available profiles
pki profile list

# View profile details
pki profile info hybrid/catalyst/tls-server
```

**Profile Categories:**

| Category | Description |
|----------|-------------|
| `ec/*` | ECDSA profiles (modern classical) |
| `rsa/*` | RSA profiles (legacy compatibility) |
| `ml-dsa-kem/*` | ML-DSA and ML-KEM (post-quantum) |
| `slh-dsa/*` | SLH-DSA (hash-based post-quantum) |
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

See [docs/PROFILES.md](docs/PROFILES.md) for details.

## Credentials

Credentials provide coupled lifecycle management (renewal, revocation) for certificates issued together. Common use cases:
- **Single certificate**: Catalyst (dual keys), classical, or PQC
- **Multiple certificates**: Signature + encryption (using multiple profiles)

Use `pki credential enroll` to create credentials:

```bash
# Create credential with a single profile
pki credential enroll --profile ec/tls-client --var cn=Alice --ca-dir ./ca

# Create credential with multiple profiles (crypto-agility)
pki credential enroll --profile ec/client --profile ml-dsa-kem/client \
    --var cn=Alice --ca-dir ./ca

# Create credential with custom ID
pki credential enroll --profile hybrid/catalyst/tls-client --var cn=Alice \
    --id alice-prod --ca-dir ./ca
```

Manage credential lifecycle:

```bash
# List credentials
pki credential list --ca-dir ./ca

# Show credential details
pki credential info alice-20250115-abc123 --ca-dir ./ca

# Renew all certificates in a credential
pki credential renew alice-20250115-abc123 --ca-dir ./ca

# Renew with crypto migration (add/change profiles)
pki credential renew alice-20250115-abc123 --profile ec/client --profile ml-dsa-kem/client --ca-dir ./ca

# Revoke all certificates in a credential
pki credential revoke alice-20250115-abc123 --reason keyCompromise --ca-dir ./ca
```

See [docs/CREDENTIALS.md](docs/CREDENTIALS.md) for details.

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
├── profiles/          # Certificate templates
│   ├── classic.yaml
│   ├── hybrid-catalyst.yaml
│   └── ...
├── bundles/         # Certificate credentials
│   └── <credential-id>/
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

## Cross-Validation

All certificate types are verified by **at least 2 independent implementations**:

| Certificate Type | PKI Tool | OpenSSL 3.x | BouncyCastle 1.83 |
|-----------------|----------|-------------|-------------------|
| Classical (ECDSA/RSA) | ✅ | ✅ verify | ✅ verify |
| PQC (ML-DSA, SLH-DSA) | ✅ | ⚠️ 3.5+ only | ✅ verify |
| Catalyst Hybrid | ✅ both | ✅ classical | ✅ classical + ext |
| Composite (IETF) | ✅ both | ❌ | ⚠️ parse only* |

**Version requirements:**
- **OpenSSL 3.0+**: Classical certificates (Ubuntu 24.04 default)
- **OpenSSL 3.5+**: Native PQC support (April 2025)
- **BouncyCastle 1.83+**: Full PQC support (December 2024)

*\*Composite: BC 1.83 implements draft-07 (Entrust OIDs), our implementation uses draft-13 (IETF standard OIDs). Certificates parse correctly but signature verification requires OID migration in BC.*

Run cross-tests locally:
```bash
make crosstest        # All cross-tests (OpenSSL + BouncyCastle)
make crosstest-bc     # BouncyCastle only (requires Java 17+)
```

See [docs/TESTING.md](docs/TESTING.md) for details on the testing strategy.

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Get started in 5 minutes |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Complete user guide with CLI reference |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and design |
| [SPECIFICATION.md](docs/SPECIFICATION.md) | Formal requirements and OID registry |
| [PROFILES.md](docs/PROFILES.md) | Certificate profile configuration |
| [CREDENTIALS.md](docs/CREDENTIALS.md) | Certificate credential management |
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
| Profiles (certificate templates) | 🧪 Experimental |
| Credentials (certificate groups) | 🧪 Experimental |
| Audit logging | ✅ Production |
| HSM via PKCS#11 | 🚧 Not implemented |

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Pure PQC certificates are not yet supported by Go's crypto/x509 package. The hybrid approach allows classical-signed certificates that transport PQC material via X.509 extensions, providing a migration path to quantum-safe cryptography.
