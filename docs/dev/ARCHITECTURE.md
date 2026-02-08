---
title: "Architecture"
description: "This document describes the technical design, component structure, and data flow of QPKI (Post-Quantum PKI)."
---

# Architecture

This document describes the technical design, component structure, and data flow of QPKI (Post-Quantum PKI).

## 1. Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   CLI Layer                                      │
│  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌─────┐ ┌─────────┐ ┌─────┐ ┌─────┐    │
│  │   ca   │ │   cert   │ │ credential │ │ key │ │ profile │ │ csr │ │ crl │    │
│  └────┬───┘ └────┬─────┘ └─────┬──────┘ └──┬──┘ └────┬────┘ └──┬──┘ └──┬──┘    │
│       │          │             │           │         │         │       │        │
│  ┌────┴──────────┴─────────────┴───────────┴─────────┴─────────┴───────┴────┐  │
│  │                           Shared CLI Utilities                            │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌─────────┐ ┌─────┐ ┌─────┐                  │
│  │  tsa  │ │  ocsp │ │  cms  │ │ inspect │ │ hsm │ │audit│                  │
│  └───┬───┘ └───┬───┘ └───┬───┘ └────┬────┘ └──┬──┘ └──┬──┘                  │
│      │         │         │          │         │       │                     │
└───────┼────────────┼────────────┼────────────┼──────────┼─────────┼───────┼────┘
        │            │            │            │          │
        v            v            v            v          v
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  CA Layer                                        │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                                  CA                                        │  │
│  │  Initialize()  Issue()  Revoke()  GenerateCRL()  Rotate()                 │  │
│  │  Enroll()  RenewCredential()  RevokeCredential()                          │  │
│  └─────────────────────────────────────┬─────────────────────────────────────┘  │
│                                        │                                         │
│  ┌─────────────────────────────────────┴─────────────────────────────────────┐  │
│  │                               Store + Metadata                             │  │
│  │  CAMetadata  CredentialStore  CertificateIndex  CRL                       │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
        │                    │                    │                    │
        v                    v                    v                    v
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Crypto Layer   │  │  Profile Layer  │  │ Credential Layer│  │  X509Util Layer │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │  Signer   │  │  │  │  Profile  │  │  │  │Credential │  │  │  │Extensions │  │
│  │HybridSign │  │  │  │ Variables │  │  │  │  Store    │  │  │  │  Builder  │  │
│  │KeyProvider │  │  │  │   Modes   │  │  │  │ Lifecycle │  │  │  │   CSR     │  │
│  └─────┬─────┘  │  │  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
│        │        │  └─────────────────┘  └─────────────────┘  └─────────────────┘
│  ┌─────┴─────┐  │
│  │ Software  │  │           ┌───────────────────────────────────────────────────────┐
│  │  PKCS#11  │  │           │                   Standards Support                    │
│  └───────────┘  │           │  ┌────────┐  ┌───────┐  ┌────────┐  ┌───────┐         │
└─────────────────┘           │  │  X.509 │  │  TSA  │  │  OCSP  │  │  CMS  │         │
                              │  │RFC 5280│  │RFC3161│  │RFC 6960│  │RFC5652│         │
                              │  └────────┘  └───────┘  └────────┘  └───────┘         │
                              └───────────────────────────────────────────────────────┘
```

## 2. Package Structure

```
pki/
├── cmd/qpki/                    # CLI entry point
│   ├── main.go                  # Root command and global flags
│   ├── ca.go                    # ca init, info, export, list
│   ├── ca_activate.go           # ca activate, ca versions
│   ├── ca_rotate.go             # ca rotate - CA key rotation
│   ├── cert.go                  # cert command group
│   ├── cert_info.go             # cert info - Certificate details
│   ├── cert_verify.go           # cert verify - Chain verification
│   ├── credential.go            # credential enroll, list, info, rotate, revoke, export, import
│   ├── credential_activate.go   # credential activate, credential versions
│   ├── key.go                   # key gen, list, info, convert
│   ├── profile.go               # profile list, info, show, export, lint, install, vars
│   ├── csr.go                   # csr gen, info, verify
│   ├── crl.go                   # crl gen, info, verify, list
│   ├── issue.go                 # cert issue - Issue certificates from CSRs
│   ├── list.go                  # cert list - List issued certificates
│   ├── revoke.go                # cert revoke - Revoke certificates
│   ├── tsa.go                   # tsa request, sign, verify, info, serve
│   ├── ocsp.go                  # ocsp request, sign, verify, info, serve
│   ├── cms.go                   # cms sign, verify, encrypt, decrypt
│   ├── hsm.go                   # hsm list, test, info
│   ├── audit.go                 # audit verify, tail
│   └── inspect.go               # Auto-detect file type and display info
│
├── internal/
│   ├── audit/                   # Audit logging with cryptographic chaining
│   │   ├── audit.go             # Core audit functionality
│   │   ├── event.go             # Event types and definitions
│   │   ├── writer.go            # Writer interface
│   │   └── file_writer.go       # File-based audit writer
│   │
│   ├── ca/                      # Certificate Authority operations
│   │   │                        # -- Core --
│   │   ├── ca.go                # CA type and core operations
│   │   ├── info.go              # CAInfo unified metadata (versions, keys, subject)
│   │   ├── store.go             # FileStore implementation
│   │   ├── store_crl.go         # CRL storage operations
│   │   ├── errors.go            # Structured error handling
│   │   ├── signer_loader.go     # CA signer loading (HSM/software)
│   │   │                        # -- Initialization --
│   │   ├── init.go              # Single-algorithm CA initialization
│   │   ├── init_pqc.go          # Pure PQC CA initialization (ML-DSA, SLH-DSA)
│   │   ├── init_hybrid.go       # Catalyst CA initialization
│   │   ├── init_composite.go    # IETF composite CA initialization
│   │   ├── init_multi.go        # Multi-algorithm CA initialization
│   │   │                        # -- Certificate Issuance --
│   │   ├── issue.go             # Certificate issuance entry point
│   │   ├── issue_pqc.go         # PQC certificate issuance (manual DER)
│   │   ├── issue_catalyst.go    # Catalyst certificate issuance
│   │   ├── issue_composite.go   # Composite certificate issuance
│   │   ├── issue_crosssign.go   # Cross-signing support
│   │   │                        # -- CRL Generation --
│   │   ├── crl.go               # CRL generation entry point
│   │   ├── crl_pqc.go           # PQC CRL generation
│   │   ├── crl_catalyst.go      # Catalyst CRL generation
│   │   ├── crl_composite.go     # Composite CRL generation
│   │   ├── crl_multi.go         # Multi-algorithm CRL
│   │   │                        # -- Lifecycle --
│   │   ├── revoke.go            # Certificate revocation
│   │   ├── rotate.go            # CA key rotation
│   │   ├── rotate_crosssign.go  # Cross-signing during rotation
│   │   ├── rotate_multi.go      # Multi-algorithm rotation
│   │   │                        # -- Verification --
│   │   ├── verify.go            # Chain and signature verification
│   │   └── composite_verify.go  # Composite signature verification
│   │
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── algorithm.go         # Algorithm definitions and metadata
│   │   ├── signer.go            # Signer interface
│   │   ├── signer_opts.go       # Signing options
│   │   ├── keyprovider.go       # KeyProvider interface
│   │   ├── software.go          # Software signing implementation
│   │   ├── software_kp.go       # Software KeyProvider
│   │   ├── hybrid.go            # HybridSigner (classical + PQC)
│   │   ├── keygen.go            # Key generation
│   │   ├── context.go           # Context utilities
│   │   ├── hsmconfig.go         # HSM configuration loading
│   │   ├── pkcs11.go            # PKCS#11 signer
│   │   ├── pkcs11_kp.go         # PKCS#11 KeyProvider
│   │   ├── pkcs11_pool.go       # Session pooling for HSM
│   │   ├── pkcs11_nocgo.go      # No-CGO stubs
│   │   └── pkcs11_kp_nocgo.go   # No-CGO KeyProvider stubs
│   │
│   ├── profile/                 # Certificate profiles (templates)
│   │   ├── profile.go           # Profile struct and modes
│   │   ├── loader.go            # YAML loading
│   │   ├── compiled.go          # Compiled profile cache
│   │   ├── variable.go          # Profile variables
│   │   ├── types.go             # Type validators
│   │   ├── extensions.go        # X.509 extension configuration
│   │   ├── crl_profile.go       # CRL profile support
│   │   ├── defaults.go          # Default values
│   │   ├── errors.go            # Profile errors
│   │   ├── helpers.go           # Utility functions
│   │   ├── signature_algo.go    # Signature algorithm mapping
│   │   ├── template.go          # Certificate template building
│   │   └── validator.go         # Profile validation
│   │
│   ├── credential/              # Certificate credentials
│   │   ├── credential.go        # Credential struct and lifecycle
│   │   ├── store.go             # Credential storage
│   │   ├── pem.go               # PEM encoding/decoding
│   │   ├── enrollment.go        # Credential enrollment
│   │   ├── rotate.go            # Credential rotation
│   │   ├── keygen.go            # Key generation
│   │   └── info.go              # Credential info display
│   │
│   ├── ocsp/                    # OCSP responder (RFC 6960)
│   │   ├── request.go           # OCSP request parsing
│   │   ├── response.go          # OCSP response generation
│   │   ├── responder.go         # Responder logic
│   │   └── verify.go            # Response verification
│   │
│   ├── tsa/                     # Timestamping Authority (RFC 3161)
│   │   ├── request.go           # TimeStampReq parsing
│   │   ├── response.go          # TimeStampResp generation
│   │   ├── token.go             # Token generation
│   │   └── verify.go            # Token verification
│   │
│   ├── cms/                     # CMS/PKCS#7 (RFC 5652)
│   │   ├── signer.go            # CMS signing
│   │   ├── verify.go            # Signature verification
│   │   ├── encrypt.go           # Encryption (EnvelopedData)
│   │   └── decrypt.go           # Decryption
│   │
│   └── x509util/                # X.509 utilities
│       ├── builder.go           # Certificate template builder
│       ├── csr.go               # CSR utilities
│       ├── csr_pqc.go           # PQC CSR support
│       ├── extensions.go        # Custom extensions (Catalyst, hybrid)
│       └── oids.go              # OID definitions
│
├── profiles/                    # Built-in certificate profiles
│   ├── profiles.go              # Embedded profile loading
│   ├── ec/                      # ECDSA profiles
│   ├── rsa/                     # RSA profiles
│   ├── rsa-pss/                 # RSA-PSS profiles
│   ├── ml/                      # ML-DSA and ML-KEM profiles
│   ├── slh/                     # SLH-DSA profiles
│   ├── hybrid/                  # Hybrid profiles (catalyst, composite)
│   └── examples/                # Example profiles
│
└── docs/                        # Documentation
```

## 3. Core Abstractions

### Interfaces

| Interface | Package | Role |
|-----------|---------|------|
| `Signer` | crypto | Unified signing interface for all algorithm types (extends `crypto.Signer`) |
| `HybridSigner` | crypto | Dual-algorithm signing for Catalyst certificates (classical + PQC) |
| `KeyProvider` | crypto | Pluggable key storage abstraction (software files or PKCS#11 HSM) |
| `Store` | ca | Storage interface for certificates and CRLs (FileStore implementation) |

### Data Types

| Type | Package | Role |
|------|---------|------|
| `Profile` | profile | Certificate policy template (algorithm, validity, extensions, variables) |
| `CAInfo` | ca | Unified CA metadata (versions, keys, subject) - replaces legacy metadata |
| `CAVersion` | ca | Version lifecycle tracking (active/pending/archived) |
| `KeyRef` | ca | Key reference abstraction (HSM or software storage) |
| `Credential` | credential | Grouped certificates with coupled lifecycle (rotation, revocation) |

## 4. Algorithm Support

### Classical Algorithms
| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| ecdsa-p256 | ECDSA | 256-bit | TLS, general signing |
| ecdsa-p384 | ECDSA | 384-bit | CA, high security |
| ecdsa-p521 | ECDSA | 521-bit | Maximum security |
| ed25519 | EdDSA | 256-bit | Fast signing |
| rsa-2048 | RSA | 2048-bit | Legacy compatibility |
| rsa-4096 | RSA | 4096-bit | High security RSA |

### Post-Quantum Algorithms (NIST FIPS)
| Algorithm | Standard | Security Level | Notes |
|-----------|----------|----------------|-------|
| ml-dsa-44 | FIPS 204 | 1 | Signature, smallest |
| ml-dsa-65 | FIPS 204 | 3 | Signature, balanced |
| ml-dsa-87 | FIPS 204 | 5 | Signature, highest |
| slh-dsa-* | FIPS 205 | 1-5 | Stateless hash-based |
| ml-kem-512 | FIPS 203 | 1 | Key encapsulation |
| ml-kem-768 | FIPS 203 | 3 | Key encapsulation |
| ml-kem-1024 | FIPS 203 | 5 | Key encapsulation |

### Hybrid Combinations
| Hybrid ID | Classical | PQC | Mode |
|-----------|-----------|-----|------|
| hybrid-p256-mldsa44 | ECDSA P-256 | ML-DSA-44 | Catalyst/Composite |
| hybrid-p384-mldsa65 | ECDSA P-384 | ML-DSA-65 | Catalyst/Composite |

## 5. Certificate Modes

### 5.1 Simple Mode
Single algorithm per certificate. Standard X.509.

```yaml
mode: simple
algorithm: ecdsa-p384
```

### 5.2 Catalyst Mode
Dual-key certificate with classical + PQC in a single X.509 certificate.
PQC signature stored in non-critical extension for backward compatibility.

```yaml
mode: catalyst
algorithms:
  - ecdsa-p384
  - ml-dsa-65
```

### 5.3 Composite Mode (IETF)
IETF composite format where both signatures must validate.

```yaml
mode: composite
algorithms:
  - ecdsa-p384
  - ml-dsa-65
```

## 6. CLI Overview

QPKI provides a comprehensive CLI organized into command groups:

| Command | Purpose |
|---------|---------|
| `ca` | CA management (init, info, export, list, activate, versions, rotate) |
| `cert` | Certificate operations (issue, list, info, revoke, verify) |
| `credential` | Credential lifecycle (enroll, list, info, rotate, revoke, activate, versions) |
| `key` | Key generation and management |
| `profile` | Certificate profile management |
| `csr` | Certificate Signing Requests |
| `crl` | Certificate Revocation Lists |
| `tsa` | Timestamping (RFC 3161) |
| `ocsp` | OCSP responder (RFC 6960) |
| `cms` | CMS operations (RFC 5652) |
| `hsm` | HSM/PKCS#11 diagnostics |
| `audit` | Audit log management |
| `inspect` | Auto-detect and display file info |

For detailed CLI usage, see [CA](../build-pki/CA.md) and [CLI Reference](../reference/CLI.md).

## 7. Data Flow

### 7.1 Certificate Issuance Flow

```
User Request (qpki credential enroll)
     │
     v
┌─────────────────┐
│  Load Profile   │
│  (YAML → struct)│
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Load CA        │
│  (meta + signer)│
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Generate Key    │
│ (KeyProvider)    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Apply Profile  │
│  (vars → cert)  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Build Template │
│  (extensions)   │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Sign with CA   │
│  (Signer)       │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Store          │
│  (credential +  │
│   certificate)  │
└─────────────────┘
```

### 7.2 HSM Key Loading Flow

```
CLI Request (--hsm-config)
     │
     v
┌─────────────────┐
│  Load HSM Config│
│  (YAML)         │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Get PIN        │
│  (env var)      │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Create         │
│  KeyStorageConfig│
└────────┬────────┘
         │
         v
┌─────────────────┐
│  NewKeyProvider  │
│  → PKCS11KP     │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Load/Generate  │
│  → PKCS11Signer │
└─────────────────┘
```

## 8. Security Model

### 8.1 Key Protection

| Storage | Protection | Use Case |
|---------|------------|----------|
| Software (file) | Optional passphrase (PKCS#8) | Development, testing |
| PKCS#11 (HSM) | PIN + hardware security | Production |

### 8.2 HSM Integration

QPKI supports Hardware Security Modules via PKCS#11 for key protection:

- Classical algorithms only (EC, RSA) - PQC keys software-only
- Hybrid mode: classical key in HSM, PQC key in software
- Session pooling for high-throughput operations

For configuration and usage details, see [HSM.md](../build-pki/HSM.md).

### 8.3 Trust Model

```
                    Root CA (offline, HSM recommended)
                         │
                         │ signs
                         v
                    Issuing CA (online)
                         │
                         │ signs
                         v
               End-Entity Certificates
                    (credentials)
```

## 9. Design Decisions

### 9.1 Pure Go (with optional CGO)
- Default build: Pure Go, PQC via cloudflare/circl
- CGO build: PKCS#11 HSM support
- Cross-compilation friendly

### 9.2 File-Based Storage
- OpenSSL-compatible directory structure
- JSON metadata files
- PEM encoding for certificates/keys
- No database dependency

### 9.3 Profile-Driven Issuance
- Declarative YAML profiles
- Variables with type validation
- Reproducible certificate generation
- Policy enforcement

### 9.4 Credential Lifecycle
- Grouped certificates with coupled validity
- Multiple profiles per credential (crypto-agility)
- Rotation with key regeneration
- Revocation propagates to all certificates

## 10. External Dependencies

### Core Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/cloudflare/circl` - PQC algorithms
- `gopkg.in/yaml.v3` - Profile parsing
- Standard Go crypto (x509, tls, etc.)

### Optional (with CGO)
- PKCS#11 libraries (SoftHSM2, Eviden Proteccio, Thales Luna, etc.)

## See Also

- [CA](../build-pki/CA.md) - CA operations and certificate issuance
- [Post-Quantum](../getting-started/POST-QUANTUM.md) - Post-quantum cryptography and hybrid certificates
- [Profiles](../build-pki/PROFILES.md) - Certificate profile templates
- [OCSP](../services/OCSP.md) - Online Certificate Status Protocol
- [TSA](../services/TSA.md) - Time-Stamp Authority
- [Audit](../services/AUDIT.md) - Audit logging
- [HSM](../build-pki/HSM.md) - Hardware Security Module integration
- [Contributing](CONTRIBUTING.md) - Contributing, testing, and CI/CD
