# QPKI Documentation

## Quick Links

| Document | Description |
|----------|-------------|
| [QUICKSTART](QUICKSTART.md) | Get started in 5 minutes |
| [USER_GUIDE](USER_GUIDE.md) | Complete CLI reference |

## Documentation Index

### Getting Started

- **[QUICKSTART](QUICKSTART.md)** - Create your first CA and certificate
- **[USER_GUIDE](USER_GUIDE.md)** - Complete CLI commands reference

### Architecture & Design

- **[ARCHITECTURE](ARCHITECTURE.md)** - System components and design decisions
- **[SPECIFICATION](SPECIFICATION.md)** - Formal requirements and OID registry

### Certificate Management

- **[PROFILES](PROFILES.md)** - Certificate policy templates (YAML)
- **[BUNDLES](BUNDLES.md)** - Certificate lifecycle management
- **[CATALYST](CATALYST.md)** - Hybrid certificates (ITU-T X.509 9.8)
- **[PQC](PQC.md)** - Post-quantum cryptography (ML-DSA, ML-KEM)

### Protocols

- **[OCSP](OCSP.md)** - Online Certificate Status Protocol (RFC 6960)
- **[TSA](TSA.md)** - Time-Stamp Authority (RFC 3161)

### Operations & Security

- **[AUDIT](AUDIT.md)** - Audit logging and compliance
- **[HSM](HSM.md)** - Hardware Security Module integration

### Development

- **[CONTRIBUTING](CONTRIBUTING.md)** - How to contribute
- **[TEST_STRATEGY](TEST_STRATEGY.md)** - Testing approach and coverage
- **[ROADMAP](ROADMAP.md)** - Future improvements

## Standards Compliance

| Standard | Description | Status |
|----------|-------------|--------|
| RFC 5280 | X.509 PKI Certificates | Implemented |
| RFC 6960 | OCSP | Implemented |
| RFC 3161 | TSA Timestamping | Implemented |
| RFC 5652 | CMS Signed Data | Implemented |
| FIPS 204 | ML-DSA (Dilithium) | Implemented |
| FIPS 205 | SLH-DSA (SPHINCS+) | Implemented |
| FIPS 203 | ML-KEM (Kyber) | Implemented |
| ITU-T X.509 9.8 | Catalyst Hybrid Certificates | Implemented |

## Language

Most documentation is in English. Some operational documents (AUDIT, OCSP) include French content.
