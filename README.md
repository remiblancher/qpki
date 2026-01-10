# Post-Quantum PKI (QPKI)

[![CI](https://github.com/remiblancher/post-quantum-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/remiblancher/post-quantum-pki/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/remiblancher/post-quantum-pki)](https://goreportcard.com/report/github.com/remiblancher/post-quantum-pki)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A minimal, modular, post-quantum-ready Public Key Infrastructure (PKI) supporting both classical and Post-Quantum Cryptography (PQC) algorithms. QPKI enables quantum-safe migration with hybrid certificates, CSR workflows, and NIST-standard PQC algorithms.

> **For education and prototyping** — Learn PKI concepts, experiment with PQC migration, and test crypto-agility.

## Features

- **State-of-the-art X.509 certificates** (RFC 5280 compliant)
- **Post-Quantum Cryptography (PQC)** support via ML-DSA, SLH-DSA and ML-KEM
- **CSR generation** for all algorithms including RFC 9883 ML-KEM attestation
- **Catalyst certificates** (ITU-T X.509 Section 9.8) - dual keys via extensions
- **Composite certificates** (IETF draft-13, **DRAFT**) - dual keys bound together
- **Hybrid certificates** (classical + PQC via combined or separate modes)
- **Crypto-agility** - seamless migration between algorithms (ECDSA → ML-DSA)
- **Profiles** (certificate templates) - define certificate policies in YAML
- **Credentials** - group certificates with coupled lifecycle
- **HSM support** via PKCS#11
- **Cross-validated** with external implementations (OpenSSL, BouncyCastle)
- **CLI-only** - simple, scriptable, no database required
- **Pure Go by default** - CGO optional (only for HSM/PKCS#11)

## Supported Algorithms

### Classical
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ECDSA P-256 | ~128-bit | Default, wide compatibility |
| ECDSA P-384 | ~192-bit | Recommended for new deployments |
| ECDSA P-521 | ~256-bit | Maximum classical security |
| Ed25519 | ~128-bit | Fast, constant-time |
| RSA-2048/4096 | ~112/140-bit | Legacy compatibility |

### Post-Quantum
| Algorithm | Security | Notes |
|-----------|----------|-------|
| ML-DSA-44/65/87 | NIST Level 1/3/5 | FIPS 204, lattice-based |
| SLH-DSA-128/192/256 | NIST Level 1/3/5 | FIPS 205, hash-based |
| ML-KEM-512/768/1024 | NIST Level 1/3/5 | FIPS 203, key encapsulation |

*Classical security levels reflect resistance to classical attacks only. Post-quantum algorithms are designed to remain secure against quantum adversaries.*

## Installation

### Download pre-built binaries (recommended)

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
curl -LO https://github.com/remiblancher/post-quantum-pki/releases/download/vX.Y.Z/checksums.txt
curl -LO https://github.com/remiblancher/post-quantum-pki/releases/download/vX.Y.Z/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt
```

### Build from source

Requires Go 1.25 or later.

```bash
# Clone and build
git clone https://github.com/remiblancher/post-quantum-pki.git
cd pki
go build -o qpki ./cmd/qpki

# Or install directly to GOPATH/bin
go install github.com/remiblancher/post-quantum-pki/cmd/qpki@latest
```

## Requirements

- **Go 1.25** or later (only for building from source)
- No CGO required for standard usage
- CGO required only for HSM/PKCS#11 support (optional)
- No external dependencies (OpenSSL not required)

## Dependencies

This project uses minimal, well-maintained dependencies:

| Dependency | Version | Purpose |
|------------|---------|---------|
| [cloudflare/circl](https://github.com/cloudflare/circl) | v1.6.1 | Post-quantum cryptography (ML-DSA, ML-KEM) |
| [spf13/cobra](https://github.com/spf13/cobra) | v1.10.2 | CLI framework |
| [miekg/pkcs11](https://github.com/miekg/pkcs11) | v1.1.1 | HSM/PKCS#11 support (optional, requires CGO) |

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
qpki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"

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
qpki key gen --algorithm ecdsa-p256 --out key.pem

# Generate an ML-DSA-65 (PQC lattice-based) key
qpki key gen --algorithm ml-dsa-65 --out ml-dsa-key.pem

# Generate an SLH-DSA-128f (PQC hash-based) key
qpki key gen --algorithm slh-dsa-128f --out slh-dsa-key.pem

# Generate with passphrase protection
qpki key gen --algorithm ecdsa-p384 --out key.pem --passphrase mysecret

# Extract public key from private key
qpki key pub --key key.pem --out key.pub
```

### Generate Certificate Signing Requests

```bash
# Classical CSR (ECDSA)
qpki csr gen --algorithm ecdsa-p256 --keyout server.key --cn server.example.com -o server.csr

# PQC CSR (ML-DSA - direct signature)
qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key --cn alice@example.com -o mldsa.csr

# ML-KEM CSR with RFC 9883 attestation
# (requires existing signature certificate to attest KEM key possession)
qpki csr gen --algorithm ml-kem-768 --keyout kem.key --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key -o kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
qpki csr gen --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com -o hybrid.csr

# CSR with existing key
qpki csr gen --key existing.key --cn server.example.com -o server.csr
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
qpki verify --cert server.crt --ca ./myca/ca.crt

# Verify with CRL revocation check
qpki verify --cert server.crt --ca ./myca/ca.crt --crl ./myca/crl/ca.crl

# List all issued certificates
qpki cert list --ca-dir ./myca

# List only valid certificates
qpki cert list --ca-dir ./myca --status valid
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

## Profiles (Certificate Templates)

Profiles define certificate enrollment policies in YAML. **1 profile = 1 certificate**.

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

You can also create custom profiles from scratch. See [docs/PROFILES.md](docs/PROFILES.md) for the full YAML specification.

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

See [docs/PROFILES.md](docs/PROFILES.md) for details.

## Credentials

A credential is a managed bundle of **private key(s) + certificate(s)** with coupled lifecycle management (enrollment, renewal, revocation).

`credential enroll` generates everything in one command:

```bash
qpki credential enroll --ca-dir ./myca --profile ec/tls-client --var cn=Alice

# Output: credentials/<id>/
#   ├── credential.meta.json  # Metadata
#   ├── certificates.pem      # Certificate(s)
#   └── private-keys.pem      # Private key(s)
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

See [docs/CREDENTIALS.md](docs/CREDENTIALS.md) for details.

## Directory Structure

### CA Directory (`--ca-dir`, default: `./ca`)

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
├── profiles/        # Certificate templates
│   ├── classic.yaml
│   ├── hybrid-catalyst.yaml
│   └── ...
├── index.txt        # Certificate database
├── serial           # Next serial number
└── crlnumber        # Next CRL number
```

### Credentials Directory (`--cred-dir`, default: `./credentials`)

```
credentials/
└── <credential-id>/
    ├── credential.meta.json  # Metadata (status, profiles, validity)
    ├── certificates.pem      # Certificate(s) (PEM)
    └── private-keys.pem      # Private key(s) (PEM, optionally encrypted)
```

Credentials are stored separately from the CA, enabling End Entity (EE) autonomy.

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

All artifacts are verified by **at least 2 independent implementations**:

### Certificates

| Type | QPKI | OpenSSL 3.6 | BouncyCastle 1.83 |
|------|------|-------------|-------------------|
| Classical (ECDSA/RSA) | ✅ | ✅ verify | ✅ verify |
| PQC (ML-DSA, SLH-DSA) | ✅ | ✅ verify | ✅ verify |
| Catalyst Hybrid | ✅ both sigs | ✅ ECDSA only | ✅ both sigs |
| Composite (IETF) | ✅ both sigs | ❌ | ⚠️ parse only* |

**Cross-tested with:**
- **OpenSSL 3.6+** (full PQC support)
- **BouncyCastle 1.83+** (full PQC support)

*\*Composite: BC 1.83 implements draft-07 (Entrust OIDs), our implementation uses draft-13 (IETF standard OIDs). Certificates parse correctly but signature verification requires OID migration in BC.*

Run cross-tests locally:
```bash
make crosstest        # All cross-tests (OpenSSL + BouncyCastle)
make crosstest-bc     # BouncyCastle only (requires Java 17+)
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for details on the testing strategy.

## Documentation

| Document | Description |
|----------|-------------|
| [GUIDE.md](docs/GUIDE.md) | Core CLI reference (CA, keys, CSR, certificates, CRL) |
| [CREDENTIALS.md](docs/CREDENTIALS.md) | Credential management (enroll, rotate, revoke) |
| [CRYPTO-AGILITY.md](docs/CRYPTO-AGILITY.md) | Algorithm migration guide (EC → Catalyst → ML-DSA) |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors and solutions |
| [PROFILES.md](docs/PROFILES.md) | Certificate profile configuration |
| [OPERATIONS.md](docs/OPERATIONS.md) | OCSP, TSA, CMS, and audit logging |
| [CONCEPTS.md](docs/CONCEPTS.md) | PQC, hybrid certificates (Catalyst, Composite) |
| [HSM.md](docs/HSM.md) | HSM/PKCS#11 integration |
| [GLOSSARY.md](docs/GLOSSARY.md) | PKI and PQC terminology |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and design |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Contributing, testing, CI/CD |

## Project Status

> ⚠️ **Minimalist PKI toolkit for education** — Prototyping and PQC experiments.

| Component | Standard | Status |
|-----------|----------|--------|
| Certificate Authority (ECDSA/RSA/Ed25519) | RFC 5280 | ✅ |
| X.509 certificate issuance | RFC 5280 | ✅ |
| CSR generation | RFC 2986, RFC 9883 | ✅ |
| CRL generation | RFC 5280 | ✅ |
| OCSP Responder | RFC 6960 | ✅ |
| TSA Timestamping | RFC 3161 | ✅ |
| CMS Signed Data | RFC 5652 | ✅ |
| PQC (ML-DSA, SLH-DSA, ML-KEM) | FIPS 203/204/205 | ✅ |
| Catalyst certificates | ITU-T X.509 9.8 | ✅ |
| Composite certificates | IETF draft-13 | ✅ |
| Credentials | — | ✅ |
| HSM support | PKCS#11 | ✅ |
| Audit logging | — | ✅ |

## About

Developed and maintained by **Rémi Blancher**, cryptography and PKI specialist with 20+ years of experience in cryptographic infrastructures and post-quantum migration.

For questions, feedback, or professional inquiries:
- Email: remi.blancher@proton.me
- LinkedIn: linkedin.com/in/remiblancher

## AI Usage

See [AI_USAGE.md](AI_USAGE.md) for details on AI-assisted development.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Note:** PQC features are experimental. Pure PQC certificates are not yet supported by Go's crypto/x509 package. The hybrid approach allows classical-signed certificates that transport PQC material via X.509 extensions, providing a migration path to Post-Quantum Cryptography.
