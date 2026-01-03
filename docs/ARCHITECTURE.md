# Architecture

This document describes the technical design, component structure, and data flow of QPKI (Post-Quantum PKI).

## 1. Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   CLI Layer                                      │
│  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌─────┐ ┌─────────┐ ┌─────┐ ┌─────┐    │
│  │   ca   │ │   cert   │ │ credential │ │ key │ │ profile │ │ hsm │ │audit│    │
│  └────┬───┘ └────┬─────┘ └─────┬──────┘ └──┬──┘ └────┬────┘ └──┬──┘ └──┬──┘    │
│       │          │             │           │         │         │       │        │
│  ┌────┴──────────┴─────────────┴───────────┴─────────┴─────────┴───────┴────┐  │
│  │                           Shared CLI Utilities                            │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐                  │
│  │   tsa    │ │   ocsp   │ │   cms    │ │ inspect │ │ verify │                  │
│  │ RFC 3161 │ │ RFC 6960 │ │ RFC 5652 │ └────┬────┘ └───┬────┘                  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘      │          │                       │
└───────┼────────────┼────────────┼────────────┼──────────┼───────────────────────┘
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
│  │ Software  │  │           ┌─────────────────────────────────────────────┐
│  │  PKCS#11  │  │           │              Standards Support               │
│  └───────────┘  │           │  ┌───────┐  ┌────────┐  ┌───────┐           │
└─────────────────┘           │  │  TSA  │  │  OCSP  │  │  CMS  │           │
                              │  │RFC3161│  │RFC6960 │  │RFC5652│           │
                              │  └───────┘  └────────┘  └───────┘           │
                              └─────────────────────────────────────────────┘
```

## 2. Package Structure

```
pki/
├── cmd/qpki/                    # CLI entry point (38 files)
│   ├── main.go                  # Root command and global flags
│   ├── ca.go                    # ca init, info
│   ├── ca_activate.go           # ca activate (subordinate CA)
│   ├── ca_rotate.go             # ca rotate (key rotation)
│   ├── cert.go                  # cert list, info, revoke
│   ├── csr.go                   # csr create (classical, PQC, hybrid)
│   ├── issue.go                 # cert issue (from CSR)
│   ├── credential.go            # credential enroll, list, info, rotate, revoke
│   ├── key.go                   # key gen, list, info, convert
│   ├── profile.go               # profile list, info, lint, install, show
│   ├── tsa.go                   # tsa sign, verify, serve (RFC 3161)
│   ├── ocsp.go                  # ocsp sign, verify, serve (RFC 6960)
│   ├── cms.go                   # cms sign, verify, encrypt, decrypt (RFC 5652)
│   ├── hsm.go                   # hsm list, test (diagnostics)
│   ├── audit.go                 # audit log inspection
│   ├── inspect.go               # certificate/CSR inspection
│   └── verify.go                # certificate chain verification
│
├── internal/
│   ├── ca/                      # CA operations (22 files)
│   │   ├── ca.go                # CA type, certificate issuance
│   │   ├── metadata.go          # CAMetadata struct with key references
│   │   ├── store.go             # File-based certificate storage
│   │   ├── enrollment.go        # Credential enrollment and renewal
│   │   ├── revocation.go        # Revocation and CRL generation
│   │   ├── rotate.go            # CA key rotation
│   │   ├── composite.go         # Composite certificate support
│   │   ├── pqc_cert.go          # PQC certificate handling
│   │   └── version.go           # Version management
│   │
│   ├── crypto/                  # Cryptographic primitives (18 files)
│   │   ├── algorithm.go         # Algorithm definitions and metadata
│   │   ├── signer.go            # Signer and HybridSigner interfaces
│   │   ├── keyprovider.go        # KeyProvider interface + KeyStorageConfig
│   │   ├── software.go          # Software key generation and signing
│   │   ├── software_kp.go       # SoftwareKeyProvider implementation
│   │   ├── hybrid.go            # HybridSigner implementation
│   │   ├── pkcs11.go            # PKCS#11 HSM signer (with CGO)
│   │   ├── pkcs11_kp.go         # PKCS11KeyProvider implementation
│   │   ├── pkcs11_nocgo.go      # Stub when CGO disabled
│   │   ├── hsmconfig.go         # HSM configuration loading
│   │   └── keygen.go            # Key generation for all algorithms
│   │
│   ├── profile/                 # Certificate profiles (20 files)
│   │   ├── profile.go           # Profile struct (modes: simple, catalyst, composite)
│   │   ├── types.go             # Type validators for variables
│   │   ├── variable.go          # Profile variable declarations
│   │   ├── loader.go            # YAML loading
│   │   ├── compiled.go          # Compiled profile cache
│   │   ├── extensions.go        # X.509 extension configuration
│   │   └── signature_algo.go    # Signature algorithm configuration
│   │
│   ├── credential/              # Certificate credentials (4 files)
│   │   ├── credential.go        # Credential struct with lifecycle
│   │   ├── store.go             # FileStore for persistence
│   │   └── pem.go               # PEM encoding/decoding
│   │
│   ├── ocsp/                    # OCSP responder (10 files)
│   │   ├── request.go           # OCSP request parsing
│   │   ├── response.go          # OCSP response generation
│   │   ├── responder.go         # Responder logic
│   │   └── verify.go            # Response verification
│   │
│   ├── tsa/                     # Timestamping Authority (6 files)
│   │   ├── request.go           # RFC 3161 TimeStampReq
│   │   ├── response.go          # RFC 3161 TimeStampResp
│   │   ├── token.go             # Token generation
│   │   └── verify.go            # Token verification
│   │
│   ├── cms/                     # CMS/PKCS#7 (15 files)
│   │   ├── signed.go            # SignedData handling
│   │   ├── signer.go            # CMS signing
│   │   ├── verify.go            # Signature verification
│   │   ├── enveloped.go         # EnvelopedData (encryption)
│   │   ├── encrypt.go           # Encryption operations
│   │   └── decrypt.go           # Decryption operations
│   │
│   ├── audit/                   # Audit logging (5 files)
│   │   ├── audit.go             # Audit event recording
│   │   ├── event.go             # Event types
│   │   └── file_writer.go       # File-based writer
│   │
│   ├── x509util/                # X.509 utilities (10 files)
│   │   ├── builder.go           # Certificate template builder
│   │   ├── extensions.go        # Custom X.509 extensions
│   │   ├── csr.go               # CSR utilities
│   │   ├── csr_pqc.go           # PQC CSR support
│   │   └── oids.go              # OID definitions
│   │
│   └── store/                   # Storage interface
│
├── docs/                        # Documentation
│   ├── ARCHITECTURE.md          # This file
│   ├── HSM.md                   # HSM integration guide
│   ├── PROFILES.md              # Profile documentation
│   └── ...
│
└── .github/workflows/           # CI/CD
    └── ci.yml                   # Build, test, cross-verification
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

## 7. CLI Command Reference

### CA Commands
```bash
qpki ca init          # Initialize CA (root or issuing)
qpki ca info          # Display CA information
qpki ca activate      # Activate subordinate CA
qpki ca rotate        # Rotate CA key
qpki crl gen          # Generate CRL
```

### Certificate Commands
```bash
qpki cert issue       # Issue certificate from CSR
qpki cert list        # List issued certificates
qpki cert info        # Show certificate details
qpki cert revoke      # Revoke certificate
qpki csr gen          # Generate CSR
```

### Credential Commands
```bash
qpki credential enroll   # Create credential from profile(s)
qpki credential list     # List all credentials
qpki credential info     # Show credential details
qpki credential rotate   # Rotate credential keys
qpki credential revoke   # Revoke credential
qpki credential export   # Export credential certificates
```

### Key Commands
```bash
qpki key gen          # Generate key (software or HSM)
qpki key list         # List HSM keys
qpki key info         # Display key information
qpki key convert      # Convert key format
```

### RFC Standards Commands
```bash
# RFC 3161 - Timestamping
qpki tsa sign         # Create timestamp token
qpki tsa verify       # Verify timestamp token
qpki tsa serve        # Start TSA HTTP server

# RFC 6960 - OCSP
qpki ocsp sign        # Create OCSP response
qpki ocsp verify      # Verify OCSP response
qpki ocsp serve       # Start OCSP responder

# RFC 5652 - CMS
qpki cms sign         # Sign data (SignedData)
qpki cms verify       # Verify signature
qpki cms encrypt      # Encrypt data (EnvelopedData)
qpki cms decrypt      # Decrypt data
```

### HSM & Utility Commands
```bash
qpki hsm list         # List HSM slots/tokens
qpki hsm test         # Test HSM connectivity
qpki profile list     # List available profiles
qpki profile info     # Show profile details
qpki inspect          # Inspect certificate/CSR
qpki verify           # Verify certificate chain
qpki audit            # Inspect audit log
```

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

- Supported via PKCS#11 interface
- Classical algorithms only (EC, RSA)
- PQC keys always software (HSM roadmap)
- Hybrid mode: classical in HSM, PQC in software

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

## 12. CI/CD Pipeline

| Job | Purpose | Algorithms |
|-----|---------|------------|
| build | Compile + smoke tests | All |
| pki-test | All PKI commands | EC, RSA, PQC, Hybrid |
| hsm-test | PKCS#11 integration | EC, RSA (SoftHSM2) |
| ocsp-test | OCSP functional | All |
| tsa-test | TSA functional | All |
| cms-test | CMS functional | All |
| crosstest-openssl | Interop verification | EC, RSA |
| crosstest-bc | Interop verification | PQC, Hybrid |
