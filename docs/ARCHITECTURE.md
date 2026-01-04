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
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌─────────┐ ┌────────┐ ┌─────┐ ┌─────┐        │
│  │  tsa  │ │  ocsp │ │  cms  │ │ inspect │ │ verify │ │ hsm │ │audit│        │
│  └───┬───┘ └───┬───┘ └───┬───┘ └────┬────┘ └───┬────┘ └──┬──┘ └──┬──┘        │
│      │         │         │          │          │         │       │           │
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
│   ├── cert.go                  # cert issue, list, info, revoke
│   ├── credential.go            # credential enroll, list, info, rotate, revoke, export, import
│   ├── key.go                   # key gen, list, info, convert
│   ├── profile.go               # profile list, info, show, export, lint, install, vars
│   ├── csr_cmd.go               # csr gen, info, verify
│   ├── crl.go                   # crl gen, info, verify, list
│   ├── tsa.go                   # tsa request, sign, verify, info, serve
│   ├── ocsp.go                  # ocsp request, sign, verify, info, serve
│   ├── cms.go                   # cms sign, verify, encrypt, decrypt
│   ├── hsm.go                   # hsm list, test, info
│   ├── audit.go                 # audit verify, tail
│   ├── inspect.go               # Auto-detect file type and display info
│   └── verify.go                # Certificate chain verification
│
├── internal/
│   ├── audit/                   # Audit logging with cryptographic chaining
│   │   ├── audit.go             # Core audit functionality
│   │   ├── event.go             # Event types and definitions
│   │   ├── writer.go            # Writer interface
│   │   └── file_writer.go       # File-based audit writer
│   │
│   ├── ca/                      # Certificate Authority operations
│   │   ├── ca.go                # CA type, certificate lifecycle
│   │   ├── metadata.go          # CA metadata and key references
│   │   ├── store.go             # File-based certificate storage
│   │   ├── enrollment.go        # Credential enrollment
│   │   ├── revocation.go        # Revocation and CRL generation
│   │   ├── rotate.go            # CA key rotation
│   │   ├── composite.go         # Composite certificate support (IETF)
│   │   └── pqc_cert.go          # PQC certificate handling
│   │
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── algorithm.go         # Algorithm definitions and metadata
│   │   ├── signer.go            # Signer interface
│   │   ├── keyprovider.go       # KeyProvider interface
│   │   ├── software.go          # Software signing implementation
│   │   ├── hybrid.go            # HybridSigner (classical + PQC)
│   │   ├── pkcs11.go            # PKCS#11 HSM integration
│   │   └── keygen.go            # Key generation
│   │
│   ├── profile/                 # Certificate profiles (templates)
│   │   ├── profile.go           # Profile struct and modes
│   │   ├── loader.go            # YAML loading
│   │   ├── compiled.go          # Compiled profile cache
│   │   ├── variable.go          # Profile variables
│   │   ├── types.go             # Type validators
│   │   └── extensions.go        # X.509 extension configuration
│   │
│   ├── credential/              # Certificate credentials
│   │   ├── credential.go        # Credential struct and lifecycle
│   │   ├── store.go             # Credential storage
│   │   └── pem.go               # PEM encoding/decoding
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
│   ├── ec/                      # ECDSA profiles
│   ├── rsa/                     # RSA profiles
│   ├── ml/                      # ML-DSA and ML-KEM profiles
│   ├── slh/                     # SLH-DSA profiles
│   └── hybrid/                  # Hybrid profiles (catalyst, composite)
│
└── docs/                        # Documentation
```

## 3. Core Interfaces

### 3.1 Signer Interface

```go
// Signer extends crypto.Signer with algorithm metadata.
type Signer interface {
    crypto.Signer
    Algorithm() AlgorithmID
}
```

### 3.2 HybridSigner Interface

```go
// HybridSigner combines classical and PQC signers (for Catalyst certificates).
type HybridSigner interface {
    Signer
    ClassicalSigner() Signer
    PQCSigner() Signer
    SignHybrid(rand io.Reader, message []byte) (classical, pqc []byte, err error)
}
```

### 3.3 KeyProvider Interface

```go
// KeyProvider provides unified key management for software and HSM keys.
type KeyProvider interface {
    Load(cfg KeyStorageConfig) (Signer, error)
    Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error)
}

// KeyStorageConfig holds configuration for key storage/retrieval.
type KeyStorageConfig struct {
    Type             KeyProviderType  // "software" or "pkcs11"

    // Software key storage
    KeyPath          string
    Passphrase       string

    // PKCS#11 (HSM) key storage
    PKCS11Lib        string
    PKCS11Token      string
    PKCS11Pin        string
    PKCS11KeyLabel   string
    PKCS11KeyID      string
    PKCS11ConfigPath string
}
```

### 3.4 Profile Structure

```go
// Profile defines certificate characteristics via YAML configuration.
type Profile struct {
    Name        string
    Description string
    Algorithm   AlgorithmID           // For simple mode
    Algorithms  []AlgorithmID         // For catalyst/composite (exactly 2)
    Mode        Mode                  // simple, catalyst, composite
    Validity    time.Duration
    Extensions  *ExtensionsConfig
    Variables   map[string]*Variable  // Declarative inputs with validation
    Signature   *SignatureAlgoConfig
}
```

## 4. Data Structures

### 4.1 CA Metadata

```go
// CAMetadata stores CA configuration and key references.
type CAMetadata struct {
    Profile string     `json:"profile"`
    Created time.Time  `json:"created"`
    Keys    []KeyRef   `json:"keys"`
}

// KeyRef references a CA key (software or HSM).
type KeyRef struct {
    ID        string      `json:"id"`        // "default", "classical", "pqc"
    Algorithm AlgorithmID `json:"algorithm"`
    Storage   StorageRef  `json:"storage"`
}

// StorageRef references where a key is stored.
type StorageRef struct {
    Type   string `json:"type"`              // "software" or "pkcs11"
    Path   string `json:"path,omitempty"`    // Software: key file path
    Config string `json:"config,omitempty"`  // HSM: hsm-config.yaml path
    Label  string `json:"label,omitempty"`   // HSM: CKA_LABEL
    KeyID  string `json:"key_id,omitempty"`  // HSM: CKA_ID (hex)
}
```

### 4.2 Credential

```go
// Credential groups related certificates with coupled lifecycle.
type Credential struct {
    ID           string           `json:"id"`
    Subject      Subject          `json:"subject"`
    Profiles     []string         `json:"profiles"`
    Status       Status           `json:"status"`  // valid, revoked, expired, pending
    Created      time.Time        `json:"created"`
    NotBefore    time.Time        `json:"not_before"`
    NotAfter     time.Time        `json:"not_after"`
    Certificates []CertificateRef `json:"certificates"`
    RevokedAt    *time.Time       `json:"revoked_at,omitempty"`
}

// CertificateRef references a certificate within a credential.
type CertificateRef struct {
    Serial      string     `json:"serial"`
    Role        CertRole   `json:"role"`       // signature, encryption, etc.
    Profile     string     `json:"profile"`
    Algorithm   string     `json:"algorithm"`
    Fingerprint string     `json:"fingerprint"`
    Storage     StorageRef `json:"storage,omitempty"`
}
```

## 5. Algorithm Support

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

## 6. Certificate Modes

### 6.1 Simple Mode
Single algorithm per certificate. Standard X.509.

```yaml
mode: simple
algorithm: ecdsa-p384
```

### 6.2 Catalyst Mode
Dual-key certificate with classical + PQC in a single X.509 certificate.
PQC signature stored in non-critical extension for backward compatibility.

```yaml
mode: catalyst
algorithms:
  - ecdsa-p384
  - ml-dsa-65
```

### 6.3 Composite Mode (IETF)
IETF composite format where both signatures must validate.

```yaml
mode: composite
algorithms:
  - ecdsa-p384
  - ml-dsa-65
```

## 7. CLI Overview

QPKI provides a comprehensive CLI organized into command groups:

| Command | Purpose |
|---------|---------|
| `ca` | Certificate Authority management |
| `cert` | Certificate operations (CSR workflow) |
| `credential` | Credential lifecycle management |
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
| `verify` | Certificate chain verification |

For detailed CLI usage, see [GUIDE.md](GUIDE.md).

## 8. Data Flow

### 8.1 Certificate Issuance Flow

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

### 8.2 HSM Key Loading Flow

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

## 9. Security Model

### 9.1 Key Protection

| Storage | Protection | Use Case |
|---------|------------|----------|
| Software (file) | Optional passphrase (PKCS#8) | Development, testing |
| PKCS#11 (HSM) | PIN + hardware security | Production |

### 9.2 HSM Integration

QPKI supports Hardware Security Modules via PKCS#11 for key protection:

- Classical algorithms only (EC, RSA) - PQC keys software-only
- Hybrid mode: classical key in HSM, PQC key in software
- Session pooling for high-throughput operations

For configuration and usage details, see [HSM.md](HSM.md).

### 9.3 Trust Model

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

## 10. Design Decisions

### 10.1 Pure Go (with optional CGO)
- Default build: Pure Go, PQC via cloudflare/circl
- CGO build: PKCS#11 HSM support
- Cross-compilation friendly

### 10.2 File-Based Storage
- OpenSSL-compatible directory structure
- JSON metadata files
- PEM encoding for certificates/keys
- No database dependency

### 10.3 Profile-Driven Issuance
- Declarative YAML profiles
- Variables with type validation
- Reproducible certificate generation
- Policy enforcement

### 10.4 Credential Lifecycle
- Grouped certificates with coupled validity
- Multiple profiles per credential (crypto-agility)
- Rotation with key regeneration
- Revocation propagates to all certificates

## 11. External Dependencies

### Core Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/cloudflare/circl` - PQC algorithms
- `gopkg.in/yaml.v3` - Profile parsing
- Standard Go crypto (x509, tls, etc.)

### Optional (with CGO)
- PKCS#11 libraries (SoftHSM2, YubiHSM, Thales Luna, etc.)

## See Also

- [GUIDE.md](GUIDE.md) - CLI reference and common workflows
- [CONCEPTS.md](CONCEPTS.md) - Post-quantum cryptography and hybrid certificates
- [PROFILES.md](PROFILES.md) - Certificate profile templates
- [OPERATIONS.md](OPERATIONS.md) - OCSP, TSA, and audit operations
- [HSM.md](HSM.md) - Hardware Security Module integration
- [DEVELOPMENT.md](DEVELOPMENT.md) - Contributing, testing, and CI/CD
