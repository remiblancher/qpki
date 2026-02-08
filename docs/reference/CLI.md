---
title: "CLI Reference"
description: "Complete command reference for QPKI."
---

# CLI Reference

Complete command reference for QPKI.

## Command Tree

```
qpki [--audit-log PATH]
├── ca                        # Certificate Authority → CA.md
│   ├── init                  # Initialize CA (root or subordinate)
│   ├── info                  # Display CA information
│   ├── export                # Export CA certificates
│   ├── list                  # List CAs in directory
│   ├── rotate                # Rotate CA with new keys
│   ├── activate              # Activate pending CA version
│   └── versions              # List CA versions
│
├── cert                      # Certificate operations → CA.md
│   ├── issue                 # Issue certificate from CSR
│   ├── list                  # List issued certificates
│   ├── info                  # Display certificate info
│   ├── revoke                # Revoke a certificate
│   └── verify                # Verify certificate validity
│
├── credential                # Credentials → CREDENTIALS.md
│   ├── enroll                # Create new credential
│   ├── list                  # List credentials
│   ├── info                  # Credential details
│   ├── rotate                # Rotate credential
│   ├── activate              # Activate pending version
│   ├── versions              # List credential versions
│   ├── revoke                # Revoke credential
│   └── export                # Export credential
│
├── key                       # Key management → KEYS.md
│   ├── gen                   # Generate key pair
│   ├── pub                   # Extract public key
│   ├── list                  # List keys
│   ├── info                  # Key information
│   └── convert               # Convert key format
│
├── csr                       # CSR operations → KEYS.md
│   ├── gen                   # Generate CSR
│   ├── info                  # Display CSR info
│   └── verify                # Verify CSR signature
│
├── crl                       # CRL operations → CA.md
│   ├── gen                   # Generate CRL
│   ├── info                  # Display CRL info
│   ├── verify                # Verify CRL signature
│   └── list                  # List CRLs
│
├── profile                   # Certificate profiles → PROFILES.md
│   ├── list                  # List available profiles
│   ├── info                  # Profile details
│   ├── vars                  # Show profile variables
│   ├── show                  # Display YAML content
│   ├── export                # Export profile to file
│   ├── lint                  # Validate profile YAML
│   └── install               # Install default profiles
│
├── tsa                       # Timestamping → TSA.md
│   ├── sign                  # Create timestamp token
│   ├── verify                # Verify timestamp token
│   └── serve                 # Start TSA HTTP server
│
├── cms                       # CMS signatures → CMS.md
│   ├── sign                  # Create CMS signature
│   ├── verify                # Verify CMS signature
│   ├── encrypt               # Encrypt with CMS
│   ├── decrypt               # Decrypt CMS
│   └── info                  # Display CMS info
│
├── ocsp                      # OCSP responder → OCSP.md
│   ├── sign                  # Create OCSP response
│   ├── verify                # Verify OCSP response
│   ├── request               # Create OCSP request
│   ├── info                  # Display OCSP response info
│   └── serve                 # Start OCSP HTTP server
│
├── hsm                       # HSM integration → HSM.md
│   ├── list                  # List HSM slots/tokens
│   ├── test                  # Test HSM connectivity
│   └── info                  # Display HSM token info
│
├── audit                     # Audit logging → AUDIT.md
│   ├── verify                # Verify audit log integrity
│   └── tail                  # Show recent audit events
│
└── inspect                   # Auto-detect and display file info
```

---

## Quick Reference

| Category | Command | Description | Documentation |
|----------|---------|-------------|---------------|
| **Keys** | `key gen` | Generate a private key | [KEYS](../build-pki/KEYS.md) |
| | `key pub` | Extract public key | [KEYS](../build-pki/KEYS.md) |
| | `key list` | List keys in directory | [KEYS](../build-pki/KEYS.md) |
| | `key info` | Display key details | [KEYS](../build-pki/KEYS.md) |
| | `key convert` | Convert key format | [KEYS](../build-pki/KEYS.md) |
| **CA** | `ca init` | Initialize a certificate authority | [CA](../build-pki/CA.md) |
| | `ca info` | Display CA information | [CA](../build-pki/CA.md) |
| | `ca export` | Export CA certificates | [CA](../build-pki/CA.md) |
| | `ca list` | List CAs in directory | [CA](../build-pki/CA.md) |
| | `ca rotate` | Rotate CA with new keys | [CA](../build-pki/CA.md) |
| | `ca activate` | Activate a pending version | [CA](../build-pki/CA.md) |
| | `ca versions` | List CA versions | [CA](../build-pki/CA.md) |
| **CSR** | `csr gen` | Generate a certificate signing request | [KEYS](../build-pki/KEYS.md) |
| | `csr info` | Display CSR details | [KEYS](../build-pki/KEYS.md) |
| | `csr verify` | Verify CSR signature | [KEYS](../build-pki/KEYS.md) |
| **Certificates** | `cert issue` | Issue certificate from CSR | [Certificates](../build-pki/CERTIFICATES.md) |
| | `cert list` | List certificates in CA | [Certificates](../build-pki/CERTIFICATES.md) |
| | `cert info` | Display certificate details | [Certificates](../build-pki/CERTIFICATES.md) |
| | `cert revoke` | Revoke a certificate | [CRL](../build-pki/CRL.md) |
| | `cert verify` | Verify a certificate | [Certificates](../build-pki/CERTIFICATES.md) |
| **Credentials** | `credential enroll` | Issue key(s) + certificate(s) | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential list` | List credentials | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential info` | Credential details | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential rotate` | Rotate a credential | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential activate` | Activate pending version | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential versions` | List credential versions | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential revoke` | Revoke a credential | [Credentials](../end-entities/CREDENTIALS.md) |
| | `credential export` | Export credential | [Credentials](../end-entities/CREDENTIALS.md) |
| **CRL** | `crl gen` | Generate a CRL | [CRL](../build-pki/CRL.md) |
| | `crl info` | Display CRL details | [CRL](../build-pki/CRL.md) |
| | `crl verify` | Verify a CRL | [CRL](../build-pki/CRL.md) |
| | `crl list` | List CRLs in CA | [CRL](../build-pki/CRL.md) |
| **Profiles** | `profile list` | List available profiles | [Profiles](../build-pki/PROFILES.md) |
| | `profile info` | Display profile details | [Profiles](../build-pki/PROFILES.md) |
| | `profile vars` | List profile variables | [Profiles](../build-pki/PROFILES.md) |
| | `profile show` | Display profile YAML | [Profiles](../build-pki/PROFILES.md) |
| | `profile export` | Export a profile | [Profiles](../build-pki/PROFILES.md) |
| | `profile lint` | Validate profile YAML | [Profiles](../build-pki/PROFILES.md) |
| | `profile install` | Install default profiles | [Profiles](../build-pki/PROFILES.md) |
| **Inspection** | `inspect` | Inspect certificate, key, or CRL | - |
| **CMS** | `cms sign` | Create CMS signature | [CMS](../services/CMS.md) |
| | `cms verify` | Verify CMS signature | [CMS](../services/CMS.md) |
| | `cms encrypt` | Encrypt with CMS | [CMS](../services/CMS.md) |
| | `cms decrypt` | Decrypt CMS | [CMS](../services/CMS.md) |
| | `cms info` | Display CMS message details | [CMS](../services/CMS.md) |
| **TSA** | `tsa sign` | Timestamp a file | [TSA](../services/TSA.md) |
| | `tsa verify` | Verify timestamp token | [TSA](../services/TSA.md) |
| | `tsa serve` | Start TSA HTTP server | [TSA](../services/TSA.md) |
| **OCSP** | `ocsp sign` | Create OCSP response | [OCSP](../services/OCSP.md) |
| | `ocsp verify` | Verify OCSP response | [OCSP](../services/OCSP.md) |
| | `ocsp request` | Create OCSP request | [OCSP](../services/OCSP.md) |
| | `ocsp info` | Display OCSP response info | [OCSP](../services/OCSP.md) |
| | `ocsp serve` | Start OCSP HTTP server | [OCSP](../services/OCSP.md) |
| **HSM** | `hsm list` | List HSM slots/tokens | [HSM](../build-pki/HSM.md) |
| | `hsm test` | Test HSM connectivity | [HSM](../build-pki/HSM.md) |
| | `hsm info` | Display HSM token info | [HSM](../build-pki/HSM.md) |
| **Audit** | `audit verify` | Verify audit log integrity | [Audit](../services/AUDIT.md) |
| | `audit tail` | Show recent audit events | [Audit](../services/AUDIT.md) |

---

## Global Flags

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--audit-log PATH` | `PKI_AUDIT_LOG` | Enable audit logging to file |

---

## Supported Algorithms

**Classical:**
- `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`
- `ed25519`
- `rsa-2048`, `rsa-4096`

**Post-Quantum (FIPS 204/205/203):**
- `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (signature)
- `slh-dsa-128s`, `slh-dsa-192s`, `slh-dsa-256s` (signature, hash-based)
- `ml-kem-512`, `ml-kem-768`, `ml-kem-1024` (key encapsulation)

**Hybrid modes:**
- Catalyst (ITU-T X.509 Section 9.8)
- Composite (IETF draft-13)

See [Post-Quantum](../getting-started/POST-QUANTUM.md) for algorithm details.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid input, operation failed, etc.) |

---

## See Also

- [CA](../build-pki/CA.md) - CA and certificate operations
- [Certificates](../build-pki/CERTIFICATES.md) - Certificate issuance
- [CRL](../build-pki/CRL.md) - Certificate revocation
- [Keys](../build-pki/KEYS.md) - Key and CSR operations
- [Credentials](../end-entities/CREDENTIALS.md) - Credential lifecycle
- [Profiles](../build-pki/PROFILES.md) - Certificate profiles
- [OCSP](../services/OCSP.md) - OCSP responder
- [TSA](../services/TSA.md) - Timestamping
- [CMS](../services/CMS.md) - CMS signatures and encryption
- [Audit](../services/AUDIT.md) - Audit logging
- [HSM](../build-pki/HSM.md) - HSM integration
