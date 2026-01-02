# Architecture

This document describes the technical design, component structure, and data flow of Post-Quantum PKI (QPKI).

## 1. Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                CLI Layer                                     │
│  ┌────────┐ ┌───────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌───────┐ ┌─────────┐ │
│  │init-ca │ │ issue │ │ revoke │ │gen-crl │ │ info │ │ profile │ │ enroll  │ │
│  └───┬────┘ └───┬───┘ └───┬────┘ └───┬────┘ └──┬───┘ └───┬───┘ └────┬────┘ │
│      │          │         │          │         │         │          │       │
│  ┌───┴──────────┴─────────┴──────────┴─────────┴─────────┘          │       │
│  │                                                      ┌───────────┴─────┐ │
│  │                                                      │   credential    │ │
│  │                                                      │ list/info/renew │ │
│  │                                                      └────────┬────────┘ │
└──┼───────────────────────────────────────────────────────────────┼──────────┘
   │                                                               │
   v                                                               v
┌─────────────────────────────────────────────────────────────────────────────┐
│                               CA Layer                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                              CA                                      │    │
│  │  • Initialize()      • Issue()           • Enroll()                 │    │
│  │  • IssueCatalyst()   • IssueLinked()     • RenewCredential()       │    │
│  │  • Revoke()          • RevokeCredential()• GenerateCRL()           │    │
│  └────────────────────────────────┬────────────────────────────────────┘    │
│                                   │                                          │
│  ┌────────────────────────────────┴────────────────────────────────────┐    │
│  │                            Store                                     │    │
│  │  • SaveCertificate()   • NextSerial()   • ReadIndex()               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
        │                    │                              │
        v                    v                              v
┌─────────────────┐  ┌─────────────────┐          ┌─────────────────────────┐
│  Profiles Layer │  │   Policy Layer  │          │      Crypto Layer       │
│  ┌───────────┐  │  │  ┌───────────┐  │          │  ┌─────────────────┐    │
│  │ RootCA    │  │  │  │   Profile   │  │          │  │ Signer Interface│    │
│  │ IssuingCA │  │  │  │   Store   │  │          │  │ • Sign()        │    │
│  │ TLSServer │  │  │  │   Loader  │  │          │  │ • SignHybrid()  │    │
│  │ TLSClient │  │  │  │   Defaults│  │          │  └────────┬────────┘    │
│  └───────────┘  │  │  └───────────┘  │          │           │             │
└─────────────────┘  └─────────────────┘          │  ┌────────┴────────┐    │
                                                  │  │ SoftwareSigner  │    │
        │                    │                    │  │ HybridSigner    │    │
        v                    v                    │  │ PKCS11Signer    │    │
┌─────────────────────────────────────────────┐  │  └─────────────────┘    │
│            Credential Layer                  │  └─────────────────────────┘
│  ┌─────────────────────────────────────┐    │
│  │          Credential                  │    │            │
│  │  • Create()   • Revoke()            │    │            v
│  │  • Renew()    • Status              │    │  ┌─────────────────────────┐
│  └─────────────────┬───────────────────┘    │  │     X509Util Layer      │
│  ┌─────────────────┴───────────────────┐    │  │  ┌─────────────────┐    │
│  │           FileStore                  │    │  │  │   Extensions    │    │
│  │  • Save()    • Load()   • List()    │    │  │  │  • Catalyst     │    │
│  │  • PEM encoding/decoding            │    │  │  │  • Related      │    │
│  └─────────────────────────────────────┘    │  │  │  • SKI/AKI      │    │
└─────────────────────────────────────────────┘  │  └─────────────────┘    │
                                                  └─────────────────────────┘
```

## 2. Package Structure

```
pki/
├── cmd/
│   └── qpki/                   # CLI entry point
│       ├── main.go             # Root command
│       ├── init.go             # init-ca command
│       ├── issue.go            # issue command
│       ├── revoke.go           # revoke, gen-crl commands
│       ├── key.go              # key gen command
│       ├── info.go             # info command
│       ├── list.go             # list command
│       ├── profile.go            # profile command (list, info, validate, install)
│       ├── enroll.go           # enroll command
│       └── credential.go       # credential command (list, info, renew, revoke, export)
│
├── internal/
│   ├── ca/                     # CA operations
│   │   ├── ca.go               # CA type and core operations
│   │   ├── store.go            # File-based storage
│   │   ├── revocation.go       # Revocation and CRL
│   │   ├── enrollment.go       # Credential enrollment and renewal
│   │   └── *_test.go           # Tests
│   │
│   ├── crypto/                 # Cryptographic primitives
│   │   ├── algorithms.go       # Algorithm definitions
│   │   ├── keygen.go           # Key generation
│   │   ├── signer.go           # Signer interface
│   │   ├── software.go         # Software signer implementation
│   │   ├── pkcs11.go           # PKCS#11 signer (placeholder)
│   │   ├── hybrid.go           # Hybrid signer (Catalyst support)
│   │   ├── pem.go              # PEM encoding/decoding
│   │   └── *_test.go           # Tests
│   │
│   ├── profiles/               # Certificate profiles
│   │   ├── profile.go          # Profile interface
│   │   ├── ca.go               # CA profiles (root, issuing)
│   │   ├── tls_server.go       # TLS server profile
│   │   ├── tls_client.go       # TLS client profile
│   │   └── *_test.go           # Tests
│   │
│   ├── policy/                 # Policy templates (Profiles)
│   │   ├── profile.go            # Profile structure and validation
│   │   ├── loader.go           # YAML loading and ProfileStore
│   │   ├── defaults.go         # Embedded default profiles
│   │   ├── defaults/           # YAML profile files
│   │   │   ├── classic.yaml
│   │   │   ├── pqc-basic.yaml
│   │   │   ├── pqc-full.yaml
│   │   │   ├── hybrid-catalyst.yaml
│   │   │   ├── hybrid-separate.yaml
│   │   │   └── hybrid-full.yaml
│   │   └── *_test.go           # Tests
│   │
│   ├── credential/             # Certificate credentials
│   │   ├── credential.go       # Credential structure and lifecycle
│   │   ├── pem.go              # PEM encoding/decoding for credentials
│   │   ├── store.go            # FileStore for credential persistence
│   │   └── *_test.go           # Tests
│   │
│   └── x509util/               # X.509 utilities
│       ├── builder.go          # Certificate builder
│       ├── extensions.go       # Custom extensions (Catalyst, Related)
│       ├── oids.go             # OID definitions
│       ├── csr.go              # CSR utilities (dual-signature)
│       └── *_test.go           # Tests
│
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md         # This file
│   ├── USER_GUIDE.md           # CLI usage guide
│   ├── PQC.md                  # Post-quantum cryptography
│   ├── PROFILES.md               # Profile documentation
│   ├── CREDENTIALS.md          # Credential documentation
│   └── CATALYST.md             # Catalyst certificate documentation
│
└── test/                       # Integration tests
```

## 3. Interfaces

### 3.1 Signer Interface

```go
// Signer extends crypto.Signer with algorithm metadata.
type Signer interface {
    crypto.Signer
    Algorithm() AlgorithmID
}
```

### 3.2 KeyManager Interface

```go
// KeyManager provides a unified interface for key management operations.
// It abstracts the differences between software keys and HSM-based keys.
type KeyManager interface {
    Load(cfg KeyStorageConfig) (Signer, error)
    Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error)
}
```

### 3.3 HybridSigner Interface

```go
// HybridSigner combines classical and PQC signers.
type HybridSigner interface {
    Signer
    ClassicalSigner() Signer
    PQCSigner() Signer
    SignHybrid(rand io.Reader, message []byte) (classical, pqc []byte, err error)
}
```

### 3.4 Profile Interface

```go
// Profile defines certificate characteristics.
type Profile interface {
    Name() string
    Apply(template *x509.Certificate) error
    Validate(cert *x509.Certificate) error
}
```

## 4. Data Flow

### 4.1 Certificate Issuance Flow

```
User Request
     │
     v
┌─────────────────┐
│  Parse CLI Args │
│  (cn, dns, ip)  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Load CA        │
│  (cert + signer)│
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Generate Key   │
│  (if not CSR)   │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Apply Profile  │
│  (KU, EKU, BC)  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Build Cert     │
│  Template       │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Sign with CA   │
│  Private Key    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Store Cert     │
│  Update Index   │
└────────┬────────┘
         │
         v
    Output Files
    (cert.pem, key.pem)
```

### 4.2 CRL Generation Flow

```
User Request
     │
     v
┌─────────────────┐
│  Load CA        │
│  (cert + signer)│
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Read Index     │
│  Filter Revoked │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Build CRL      │
│  Template       │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Sign CRL       │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Save CRL       │
│  (PEM + DER)    │
└─────────────────┘
```

## 5. Design Decisions

### 5.1 Pure Go Implementation

**Decision**: No CGO dependencies.

**Rationale**:
- Simplified cross-compilation
- No external library dependencies
- Easier deployment (static binary)
- cloudflare/circl provides PQC without CGO

**Trade-offs**:
- Cannot use liboqs (requires CGO)
- HSM support requires CGO in production

### 5.2 File-Based Storage

**Decision**: Use file system instead of database.

**Rationale**:
- OpenSSL-compatible directory structure
- Simple deployment
- Easy backup/restore
- No database administration

**Trade-offs**:
- No concurrent access protection
- Index file can grow large
- No query capabilities

### 5.3 Hybrid PQC Extension

**Decision**: Store PQC material in non-critical X.509 extension.

**Rationale**:
- Backward compatibility (ignored by non-PQC parsers)
- Go's crypto/x509 doesn't support pure PQC certificates
- Allows gradual migration

**Trade-offs**:
- Not a standard extension (private OID)
- Larger certificate size
- Requires custom parsing

### 5.4 Profile-Based Issuance

**Decision**: Use predefined profiles for certificate types.

**Rationale**:
- Consistent certificate generation
- Reduced configuration errors
- Clear separation of concerns

**Trade-offs**:
- Less flexible than full template control
- May need new profiles for edge cases

## 6. Security Model

### 6.1 Key Protection

| Key Type | Storage | Protection |
|----------|---------|------------|
| CA Private Key | File system | Optional passphrase encryption (PKCS#8) |
| End-entity Key | File system | Optional passphrase encryption |
| HSM Key | Hardware | PKCS#11 PIN + hardware security |

### 6.2 Trust Model

```
                    Root CA (offline)
                         │
                         │ signs
                         v
                    Issuing CA (online)
                         │
                         │ signs
                         v
                   End Certificates
```

### 6.3 Revocation Model

- CRL-based revocation (RFC 5280)
- No OCSP support (future enhancement)
- CRL Distribution Points in certificates (optional)

## 7. Extension Points

### 7.1 Adding New Algorithms

1. Add algorithm constant to `internal/crypto/algorithms.go`
2. Add OID to `internal/x509util/oids.go`
3. Update key generation in `internal/crypto/keygen.go`
4. Add signing support in `internal/crypto/software.go`
5. Add tests

### 7.2 Adding New Profiles

1. Create new file in `internal/profiles/`
2. Implement `Profile` interface
3. Register profile in profile registry
4. Add CLI support in `cmd/qpki/issue.go`
5. Add tests

### 7.3 Adding HSM Support

1. Implement `Signer` interface for HSM
2. Implement `KeyManager` for HSM (PKCS11KeyManager)
3. Add PKCS#11 library binding
4. Add CLI flags for HSM configuration
5. Add integration tests with SoftHSM2
