---
title: REST API Overview
description: QPKI Enterprise REST API for post-quantum PKI operations
---

The QPKI Enterprise REST API provides a complete interface for managing post-quantum PKI operations, including certificate issuance, cryptographic signing, and protocol services.

## Features

- **Post-Quantum Support**: ML-DSA, SLH-DSA, ML-KEM, and hybrid algorithms
- **RFC Compliance**: CMS (RFC 5652), COSE (RFC 9052), CWT (RFC 8392), TSA (RFC 3161), OCSP (RFC 6960)
- **Profile-Based Issuance**: Template-based certificate generation
- **Audit Logging**: Full operation tracking

## Interactive Documentation

Explore the API interactively with [Swagger UI](/api-reference/).

Download the [OpenAPI specification](/openapi.yaml) for code generation.

## Quick Start

```bash
# Health check
curl http://localhost:8443/health

# Initialize a CA
curl -X POST http://localhost:8443/api/v1/ca/init \
  -H "Content-Type: application/json" \
  -d '{"name": "root-ca", "profile": "root-ca"}'
```
