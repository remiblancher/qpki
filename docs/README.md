# QPKI Documentation

Welcome to the Post-Quantum PKI documentation. This guide will help you find the right information based on your needs.

## Quick Start

New to QPKI? Start here:

| Document | Description |
|----------|-------------|
| [Quick Start](../README.md#quick-start) | Create your first CA and certificate in 5 minutes |
| [GLOSSARY](GLOSSARY.md) | PKI and post-quantum cryptography terminology |

## User Guide

For day-to-day operations and CLI usage:

| Document | Description |
|----------|-------------|
| [GUIDE](GUIDE.md) | Complete CLI reference and workflows |
| [PROFILES](PROFILES.md) | Certificate profile templates (YAML configuration) |

## Concepts

Understanding the system design and cryptography:

| Document | Description |
|----------|-------------|
| [CONCEPTS](CONCEPTS.md) | Post-quantum cryptography, hybrid certificates (Catalyst, Composite) |
| [ARCHITECTURE](ARCHITECTURE.md) | System components and design decisions |

## Operations

Running QPKI services in production:

| Document | Description |
|----------|-------------|
| [OPERATIONS](OPERATIONS.md) | OCSP responder, TSA timestamping, audit logging |
| [HSM](HSM.md) | Hardware Security Module integration (PKCS#11) |

## Development

Contributing to QPKI:

| Document | Description |
|----------|-------------|
| [DEVELOPMENT](DEVELOPMENT.md) | Contributing guidelines, testing strategy, CI/CD |

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
├── README.md          ← You are here
├── GLOSSARY.md        Terminology reference
├── GUIDE.md           CLI reference & workflows
├── PROFILES.md        Certificate templates
├── CONCEPTS.md        PQC & hybrid certificates
├── ARCHITECTURE.md    System design
├── OPERATIONS.md      OCSP, TSA, Audit
├── HSM.md             PKCS#11 integration
└── DEVELOPMENT.md     Contributing & testing
```
