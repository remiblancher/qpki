---
title: API Endpoints
description: Complete reference of QPKI Enterprise REST API endpoints
---

## CA Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ca/init` | Initialize a new CA |
| GET | `/api/v1/ca/` | List all CAs |
| GET | `/api/v1/ca/{id}` | Get CA information |
| POST | `/api/v1/ca/{id}/rotate` | Rotate CA keys |
| POST | `/api/v1/ca/{id}/activate` | Activate a key version |
| GET | `/api/v1/ca/{id}/export` | Export CA certificate |

## Certificates

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/certs/issue` | Issue a certificate |
| GET | `/api/v1/certs/` | List certificates |
| GET | `/api/v1/certs/{serial}` | Get certificate details |
| POST | `/api/v1/certs/{serial}/revoke` | Revoke a certificate |
| POST | `/api/v1/certs/verify` | Verify certificate chain |

## Credentials

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/credentials/enroll` | Enroll new credential |
| GET | `/api/v1/credentials/` | List credentials |
| GET | `/api/v1/credentials/{id}` | Get credential |
| POST | `/api/v1/credentials/{id}/rotate` | Rotate credential |
| POST | `/api/v1/credentials/{id}/revoke` | Revoke credential |
| GET | `/api/v1/credentials/{id}/export` | Export (PEM/PKCS12/JKS) |

## CMS (RFC 5652)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cms/sign` | Create SignedData |
| POST | `/api/v1/cms/verify` | Verify SignedData |
| POST | `/api/v1/cms/encrypt` | Create EnvelopedData |
| POST | `/api/v1/cms/decrypt` | Decrypt EnvelopedData |
| POST | `/api/v1/cms/info` | Parse CMS message |

## COSE (RFC 9052)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cose/sign` | Create COSE Sign1/Sign |
| POST | `/api/v1/cose/verify` | Verify COSE message |
| POST | `/api/v1/cose/info` | Parse COSE message |

## CWT (RFC 8392)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cwt/issue` | Issue CBOR Web Token |
| POST | `/api/v1/cwt/verify` | Verify CWT |

## TSA (RFC 3161)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/tsa/sign` | Create timestamp token |
| POST | `/api/v1/tsa/verify` | Verify timestamp |
| POST | `/api/v1/tsa/info` | Parse timestamp |
| POST | `/tsa` | RFC 3161 binary protocol |

## OCSP (RFC 6960)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ocsp/query` | Query certificate status |
| POST | `/api/v1/ocsp/verify` | Verify OCSP response |
| GET/POST | `/ocsp` | RFC 6960 binary protocol |

## CRL

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/crl/generate` | Generate CRL |
| GET | `/api/v1/crl/` | List CRLs |
| GET | `/api/v1/crl/{id}` | Get specific CRL |
| POST | `/api/v1/crl/verify` | Verify CRL signature |

## CSR

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/csr/generate` | Generate CSR |
| POST | `/api/v1/csr/info` | Parse CSR |
| POST | `/api/v1/csr/verify` | Verify CSR signature |

## Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/keys/generate` | Generate key pair |
| POST | `/api/v1/keys/info` | Get key information |

## Profiles

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/profiles/` | List profiles |
| GET | `/api/v1/profiles/{name}` | Get profile details |
| GET | `/api/v1/profiles/{name}/vars` | Get profile variables |
| POST | `/api/v1/profiles/validate` | Validate profile YAML |

## Audit

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit/logs` | Get audit logs |
| POST | `/api/v1/audit/verify` | Verify log integrity |

## Inspect

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/inspect/` | Auto-detect and parse any crypto object |

See the [interactive API documentation](/api-reference/) for request/response schemas.
