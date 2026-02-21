---
title: API Examples
description: Practical examples using the QPKI Enterprise REST API
---

## Initialize a Root CA

```bash
curl -X POST http://localhost:8443/api/v1/ca/init \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca",
    "profile": "root-ca",
    "algorithm": "ml-dsa-65"
  }'
```

## Issue a Certificate

```bash
# From CSR
curl -X POST http://localhost:8443/api/v1/certs/issue \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "root-ca",
    "csr": {
      "data": "-----BEGIN CERTIFICATE REQUEST-----\n...",
      "encoding": "pem"
    },
    "profile": "end-entity"
  }'

# Direct issuance with profile
curl -X POST http://localhost:8443/api/v1/certs/issue \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "root-ca",
    "profile": "server",
    "subject": {
      "cn": "api.example.com",
      "o": "Example Corp"
    }
  }'
```

## Sign Data with CMS

```bash
curl -X POST http://localhost:8443/api/v1/cms/sign \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "signer-1",
    "data": {
      "data": "SGVsbG8gV29ybGQ=",
      "encoding": "base64"
    },
    "detached": false
  }'
```

## Create a Timestamp

```bash
curl -X POST http://localhost:8443/api/v1/tsa/sign \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "data": "SGVsbG8gV29ybGQ=",
      "encoding": "base64"
    },
    "hash_algorithm": "sha256"
  }'
```

## Query Certificate Status (OCSP)

```bash
curl -X POST http://localhost:8443/api/v1/ocsp/query \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": {
      "data": "-----BEGIN CERTIFICATE-----\n...",
      "encoding": "pem"
    },
    "issuer": {
      "data": "-----BEGIN CERTIFICATE-----\n...",
      "encoding": "pem"
    }
  }'
```

## COSE Sign1 Message

```bash
curl -X POST http://localhost:8443/api/v1/cose/sign \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "cose-signer",
    "payload": {
      "data": "eyJoZWxsbyI6IndvcmxkIn0=",
      "encoding": "base64"
    },
    "mode": "sign1"
  }'
```

## Issue a CWT

```bash
curl -X POST http://localhost:8443/api/v1/cwt/issue \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "cwt-issuer",
    "claims": {
      "iss": "https://issuer.example.com",
      "sub": "user-123",
      "aud": "https://api.example.com",
      "exp": 1735689600
    }
  }'
```

## Inspect Unknown Object

```bash
# Auto-detect certificate, CSR, CRL, CMS, COSE, etc.
curl -X POST http://localhost:8443/api/v1/inspect/ \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "data": "-----BEGIN CERTIFICATE-----\n...",
      "encoding": "pem"
    }
  }'
```

## Using Binary Protocols

### RFC 3161 TSA
```bash
openssl ts -query -data file.txt -out request.tsq
curl -X POST http://localhost:8443/tsa \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  -o response.tsr
```

### RFC 6960 OCSP
```bash
openssl ocsp -issuer issuer.pem -cert cert.pem \
  -url http://localhost:8443/ocsp \
  -resp_text
```
