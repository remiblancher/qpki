# QPKI Documentation

Welcome to the Post-Quantum PKI documentation. This guide will help you find the right information based on your needs.

## Quick Start

New to QPKI? Start here:

| Document | Description |
|----------|-------------|
| [Quick Start](../README.md#quick-start) | Create your first CA and certificate in 5 minutes |
| [GLOSSARY](GLOSSARY.md) | PKI and post-quantum cryptography terminology |

## Core Operations

For day-to-day PKI operations:

| Document | Description |
|----------|-------------|
| [CA](CA.md) | CA initialization, certificates, CRL management |
| [KEYS](KEYS.md) | Key generation and CSR operations |
| [CREDENTIALS](CREDENTIALS.md) | Bundled key + certificate lifecycle |
| [PROFILES](PROFILES.md) | Certificate profile templates (YAML configuration) |

## Services

Running QPKI services:

| Document | Description |
|----------|-------------|
| [OCSP](OCSP.md) | Real-time certificate status (RFC 6960) |
| [TSA](TSA.md) | Timestamping service (RFC 3161) |
| [CMS](CMS.md) | CMS signatures and encryption (RFC 5652) |

## Concepts & Reference

Understanding the system:

| Document | Description |
|----------|-------------|
| [CONCEPTS](CONCEPTS.md) | Post-quantum cryptography, hybrid certificates |
| [CRYPTO-AGILITY](CRYPTO-AGILITY.md) | Algorithm migration guide |
| [CLI-REFERENCE](CLI-REFERENCE.md) | Complete command reference |
| [HSM](HSM.md) | Hardware Security Module integration (PKCS#11) |
| [AUDIT](AUDIT.md) | Audit logging and SIEM integration |
| [TROUBLESHOOTING](TROUBLESHOOTING.md) | Common errors and solutions |

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
├── # Core Operations
├── CA.md                  CA, certificates, CRL
├── KEYS.md                Key generation, CSR
├── CREDENTIALS.md         Credential lifecycle
├── PROFILES.md            Certificate templates
│
├── # Services
├── OCSP.md                Real-time revocation
├── TSA.md                 Timestamping
├── CMS.md                 Signatures & encryption
│
├── # Reference
├── CONCEPTS.md            PQC & hybrid certificates
├── CRYPTO-AGILITY.md      Algorithm migration
├── CLI-REFERENCE.md       Command reference
├── HSM.md                 PKCS#11 integration
├── AUDIT.md               Audit logging
├── TROUBLESHOOTING.md     Common errors
└── GLOSSARY.md            Terminology
```
