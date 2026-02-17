---
title: "REST API"
description: "Complete REST API for DevOps automation and PKI integration"
---

# REST API

QPKI exposes a complete REST API enabling automation of all PKI operations. The API is designed for DevOps integration, CI/CD pipelines, and certificate management systems.

## Quick Start

```bash
# Start the API server
qpki serve --port 8443 --ca-dir ./pki

# Verify the server is running
curl http://localhost:8443/health
```

## Features

- **RESTful**: Standardized endpoints with appropriate HTTP verbs
- **JSON**: Uniform exchange format for all operations
- **OpenAPI 3.1**: Complete specification available at `/api/openapi.yaml`
- **Post-quantum**: Native support for ML-DSA, SLH-DSA, ML-KEM and hybrid modes
- **RFC compliant**: Native OCSP (RFC 6960) and TSA (RFC 3161) endpoints

## Interactive Documentation

Explore the API interactively:

- **[Swagger UI](/api-reference/)** - Interactive API explorer
- **[OpenAPI Spec](/openapi.yaml)** - Raw OpenAPI 3.1 specification (YAML)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    qpki serve                           │
├─────────────────────────────────────────────────────────┤
│  /api/v1/*          │  /ocsp        │  /tsa            │
│  REST API           │  RFC 6960     │  RFC 3161        │
│  (JSON)             │  (DER)        │  (DER)           │
├─────────────────────┴───────────────┴──────────────────┤
│                    Chi Router                          │
├─────────────────────────────────────────────────────────┤
│  Middleware: Logging, Recovery, CORS, Auth (future)    │
├─────────────────────────────────────────────────────────┤
│                 Service Layer                          │
│  ca_service │ cert_service │ cms_service │ ...         │
├─────────────────────────────────────────────────────────┤
│               Internal Packages                        │
│  internal/ca │ internal/cms │ internal/ocsp │ ...      │
└─────────────────────────────────────────────────────────┘
```

## Endpoint Groups

| Group | Base URL | Description |
|-------|----------|-------------|
| [CA](/qpki/api/endpoints#ca) | `/api/v1/ca` | Certificate Authority management |
| [Certificates](/qpki/api/endpoints#certificates) | `/api/v1/certs` | Issuance, revocation, verification |
| [Credentials](/qpki/api/endpoints#credentials) | `/api/v1/credentials` | Key + certificate management |
| [CMS](/qpki/api/endpoints#cms) | `/api/v1/cms` | CMS signatures and encryption |
| [COSE/CWT](/qpki/api/endpoints#cose) | `/api/v1/cose`, `/api/v1/cwt` | CBOR signatures and tokens |
| [TSA](/qpki/api/endpoints#tsa) | `/api/v1/tsa` | RFC 3161 timestamping |
| [OCSP](/qpki/api/endpoints#ocsp) | `/api/v1/ocsp` | RFC 6960 certificate status |
| [Profiles](/qpki/api/endpoints#profiles) | `/api/v1/profiles` | Certificate templates |
| [CRL](/qpki/api/endpoints#crl) | `/api/v1/crl` | Revocation lists |
| [CSR](/qpki/api/endpoints#csr) | `/api/v1/csr` | Certificate Signing Requests |
| [Keys](/qpki/api/endpoints#keys) | `/api/v1/keys` | Key generation |

## Data Formats

### Binary Data

Binary data (certificates, keys, signatures) is Base64-encoded:

```json
{
  "data": "MIIBkTCB+wIBADBTMQswCQYDVQQGEwJGUjEOMAwGA1UE...",
  "encoding": "base64"
}
```

Or PEM-encoded:

```json
{
  "data": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIBAD...",
  "encoding": "pem"
}
```

### Errors

Errors follow a standardized format:

```json
{
  "code": "CERT_NOT_FOUND",
  "message": "Certificate with serial ABC123 not found",
  "details": {
    "serial": "ABC123"
  }
}
```

| HTTP Code | Meaning |
|-----------|---------|
| 400 | Invalid request (malformed JSON, missing parameters) |
| 404 | Resource not found (CA, certificate, credential) |
| 409 | Conflict (certificate already revoked) |
| 410 | Resource expired |
| 412 | Precondition failed (CA not initialized) |
| 422 | Processing error (verification failed) |
| 501 | Not implemented |

## OpenAPI Specification

The complete OpenAPI 3.1 specification is available:

```bash
# Download the spec
curl http://localhost:8443/api/openapi.yaml > openapi.yaml

# View with Redoc
npx @redocly/cli preview-docs openapi.yaml

# Import into Postman/Insomnia
# File > Import > openapi.yaml
```

## Next Steps

- [Server Configuration](/qpki/api/server) - Startup options
- [Endpoint Reference](/qpki/api/endpoints) - Detailed documentation
- [Examples](/qpki/api/examples) - Complete scenarios
