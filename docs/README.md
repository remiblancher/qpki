---
title: "QPKI Documentation"
description: "Welcome to the Post-Quantum PKI documentation. This guide will help you find the right information based on your needs."
---

# QPKI Documentation

Welcome to the Post-Quantum PKI documentation. This guide will help you find the right information based on your needs.

## Quick Start

New to QPKI? Start here:

| Document | Description |
|----------|-------------|
| [PKI Fundamentals](reference/PKI-BASICS.md) | Certificates, keys, CAs, trust chains |
| [Post-Quantum](getting-started/POST-QUANTUM.md) | PQC algorithms and hybrid certificates |
| [Quick Start](getting-started/QUICK-START.md#quick-start) | Create your first CA and certificate in 5 minutes |

## Core Operations

For day-to-day PKI operations:

| Document | Description |
|----------|-------------|
| [CA](core-pki/CA.md) | CA initialization, certificates, CRL management |
| [Keys](core-pki/KEYS.md) | Key generation and CSR operations |
| [Credentials](end-entities/CREDENTIALS.md) | Bundled key + certificate lifecycle |
| [Profiles](core-pki/PROFILES.md) | Certificate profile templates (YAML configuration) |

## Services

Running QPKI services:

| Document | Description |
|----------|-------------|
| [OCSP](services/OCSP.md) | Real-time certificate status (RFC 6960) |
| [TSA](services/TSA.md) | Timestamping service (RFC 3161) |
| [CMS](services/CMS.md) | CMS signatures and encryption (RFC 5652) |
| [COSE](services/COSE.md) | CBOR Object Signing (IoT, attestation) |

## Reference

Understanding the system:

| Document | Description |
|----------|-------------|
| [Post-Quantum](getting-started/POST-QUANTUM.md) | Post-quantum cryptography, hybrid certificates |
| [Crypto-Agility](migration/CRYPTO-AGILITY.md) | Algorithm migration guide |
| [CLI Reference](reference/CLI.md) | Complete command reference |
| [HSM](operations/HSM.md) | Hardware Security Module integration (PKCS#11) |
| [Architecture](dev/ARCHITECTURE.md) | System architecture overview |
| [Audit](operations/AUDIT.md) | Audit logging and SIEM integration |
| [Troubleshooting](reference/TROUBLESHOOTING.md) | Common errors and solutions |
| [Glossary](reference/GLOSSARY.md) | PKI and PQC terminology |

---

## Standards Compliance

| Standard | Description | Status |
|----------|-------------|--------|
| RFC 5280 | X.509 PKI Certificates | Implemented |
| RFC 6960 | OCSP | Implemented |
| RFC 3161 | TSA Timestamping | Implemented |
| RFC 5652 | CMS Signed Data | Implemented |
| RFC 9883 | ML-KEM in CMS (CSR Attestation) | Implemented |
| FIPS 204 | ML-DSA (Dilithium) | Implemented |
| FIPS 205 | SLH-DSA (SPHINCS+) | Implemented |
| FIPS 203 | ML-KEM (Kyber) | Implemented |
| ITU-T X.509 9.8 | Catalyst Hybrid Certificates | Implemented |
| IETF draft-13 | Composite Signatures | Implemented |

## Document Map

```
docs/
├── README.md              ← You are here
│
├── getting-started/       # Getting Started
│   ├── INSTALLATION.md    Installation guide
│   ├── POST-QUANTUM.md    PQC & hybrid certificates
│   └── QUICK-START.md     Quick start guide
│
├── core-pki/             # Core PKI
│   ├── CA.md              CA, certificates, CRL
│   ├── CERTIFICATES.md    Certificate issuance
│   ├── CRL.md             Revocation lists
│   ├── KEYS.md            Key generation, CSR
│   └── PROFILES.md        Certificate templates
│
├── end-entities/          # End Entities
│   └── CREDENTIALS.md     Credential lifecycle
│
├── services/              # Services
│   ├── OCSP.md            Real-time revocation
│   ├── TSA.md             Timestamping
│   ├── CMS.md             Signatures & encryption
│   └── COSE.md            CBOR Object Signing
│
├── operations/            # Operations
│   ├── HSM.md             PKCS#11 integration
│   └── AUDIT.md           Audit logging
│
├── migration/             # Migration
│   ├── CRYPTO-AGILITY.md  Algorithm migration
│   └── HYBRID.md          Hybrid certificates
│
├── reference/             # Reference
│   ├── CLI.md             Command reference
│   ├── PKI-BASICS.md      PKI fundamentals
│   ├── STANDARDS.md       OIDs and formats
│   ├── TROUBLESHOOTING.md Common errors
│   └── GLOSSARY.md        Terminology
│
└── dev/                   # Development
    ├── ARCHITECTURE.md    System architecture
    ├── CONTRIBUTING.md    Contribution guide
    ├── TESTING.md         Testing guide
    └── INTEROPERABILITY.md Interop testing
```
