---
title: "API Reference"
description: "Complete REST API endpoint documentation for QPKI"
---

# Endpoint Reference

Complete documentation of the QPKI REST API. All endpoints use the `/api/v1` prefix.

## CA {#ca}

Certificate Authority management.

### Initialize a CA

```http
POST /api/v1/ca/init
```

Creates a new CA (root or intermediate).

**Request**
```json
{
  "profile": "pq/root-ca",
  "variables": {
    "cn": "My Root CA",
    "o": "My Organization",
    "c": "US"
  },
  "passphrase": "secret",
  "output_dir": "./my-ca"
}
```

**Response** `201 Created`
```json
{
  "id": "my-ca",
  "certificate": {
    "data": "MIIB...",
    "encoding": "base64"
  },
  "subject": {
    "cn": "My Root CA",
    "o": "My Organization"
  },
  "validity": {
    "not_before": "2024-01-15T00:00:00Z",
    "not_after": "2034-01-15T00:00:00Z"
  },
  "algorithm": {
    "id": "ml-dsa-65",
    "name": "ML-DSA-65",
    "type": "signature",
    "security_level": 3
  }
}
```

### List CAs

```http
GET /api/v1/ca
```

**Response** `200 OK`
```json
{
  "cas": [
    {
      "id": "root-ca",
      "subject": "CN=Root CA,O=Org",
      "algorithm": "ml-dsa-65",
      "expires_at": "2034-01-15T00:00:00Z",
      "is_root": true
    }
  ]
}
```

### Get CA Information

```http
GET /api/v1/ca/{id}
```

**Response** `200 OK`
```json
{
  "id": "root-ca",
  "subject": { "cn": "Root CA", "o": "Org" },
  "issuer": { "cn": "Root CA", "o": "Org" },
  "serial": "01",
  "validity": { "not_before": "...", "not_after": "..." },
  "algorithm": { "id": "ml-dsa-65" },
  "is_root": true,
  "path_len": 2,
  "versions": [
    { "version": 1, "algorithms": ["ml-dsa-65"], "active": true }
  ],
  "certificate": "-----BEGIN CERTIFICATE-----\n..."
}
```

### Rotate CA Keys

```http
POST /api/v1/ca/{id}/rotate
```

**Request**
```json
{
  "passphrase": "current-secret",
  "new_passphrase": "new-secret",
  "algorithms": ["ml-dsa-87"]
}
```

### Activate CA Version

```http
POST /api/v1/ca/{id}/activate
```

**Request**
```json
{
  "version": 2
}
```

### Export CA Certificates

```http
GET /api/v1/ca/{id}/export?format=pem&include_chain=true
```

---

## Certificates {#certificates}

Certificate issuance and management.

### Issue a Certificate

```http
POST /api/v1/certs/issue
```

**Request**
```json
{
  "profile": "pq/tls-server",
  "variables": {
    "cn": "server.example.com",
    "dns_names": "server.example.com,www.example.com"
  },
  "csr": {
    "data": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "encoding": "pem"
  },
  "ca_passphrase": "ca-secret",
  "validity_days": 365
}
```

**Response** `201 Created`
```json
{
  "serial": "02",
  "certificate": { "data": "...", "encoding": "base64" },
  "chain": [{ "data": "...", "encoding": "base64" }],
  "subject": { "cn": "server.example.com" },
  "validity": { "not_before": "...", "not_after": "..." }
}
```

### List Certificates

```http
GET /api/v1/certs?status=valid&offset=0&limit=20
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | `valid`, `revoked`, `expired` |
| `offset` | int | Pagination offset |
| `limit` | int | Pagination limit (max 100) |

### Get Certificate

```http
GET /api/v1/certs/{serial}
```

### Revoke Certificate

```http
POST /api/v1/certs/{serial}/revoke
```

**Request**
```json
{
  "reason": "keyCompromise",
  "ca_passphrase": "ca-secret"
}
```

| Reason | Description |
|--------|-------------|
| `unspecified` | Unspecified reason |
| `keyCompromise` | Key compromised |
| `caCompromise` | CA compromised |
| `affiliationChanged` | Affiliation changed |
| `superseded` | Superseded |
| `cessationOfOperation` | Cessation of operation |

### Verify Certificate

```http
POST /api/v1/certs/verify
```

**Request**
```json
{
  "certificate": { "data": "...", "encoding": "pem" },
  "chain": [{ "data": "...", "encoding": "pem" }],
  "check_revocation": true
}
```

**Response**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "chain_verified": true,
  "revocation_checked": true
}
```

---

## Credentials {#credentials}

Key + certificate bundle management.

### Enroll Credential

```http
POST /api/v1/credentials/enroll
```

**Request**
```json
{
  "profile": "pq/tls-client",
  "variables": {
    "cn": "alice@example.com"
  },
  "passphrase": "key-secret",
  "ca_passphrase": "ca-secret"
}
```

### List Credentials

```http
GET /api/v1/credentials
```

### Get Credential

```http
GET /api/v1/credentials/{id}
```

### Rotate Credential

```http
POST /api/v1/credentials/{id}/rotate
```

### Revoke Credential

```http
POST /api/v1/credentials/{id}/revoke
```

### Export Credential

```http
GET /api/v1/credentials/{id}/export?format=pkcs12
```

| Format | Description |
|--------|-------------|
| `pem` | Separate PEM files |
| `pkcs12` | PKCS#12 bundle |
| `jks` | Java KeyStore |

---

## CMS {#cms}

CMS signatures and encryption (RFC 5652).

### Sign

```http
POST /api/v1/cms/sign
```

**Request**
```json
{
  "data": { "data": "SGVsbG8gV29ybGQ=", "encoding": "base64" },
  "credential_id": "signer-credential",
  "passphrase": "key-secret",
  "detached": false,
  "include_chain": true
}
```

**Response**
```json
{
  "signed_data": { "data": "...", "encoding": "base64" },
  "content_type": "application/pkcs7-mime"
}
```

### Verify

```http
POST /api/v1/cms/verify
```

**Request**
```json
{
  "signed_data": { "data": "...", "encoding": "base64" },
  "content": { "data": "...", "encoding": "base64" },
  "trusted_certs": [{ "data": "...", "encoding": "pem" }]
}
```

### Encrypt

```http
POST /api/v1/cms/encrypt
```

**Request**
```json
{
  "data": { "data": "...", "encoding": "base64" },
  "recipients": [
    { "data": "...", "encoding": "pem" }
  ]
}
```

### Decrypt

```http
POST /api/v1/cms/decrypt
```

**Request**
```json
{
  "enveloped_data": { "data": "...", "encoding": "base64" },
  "credential_id": "recipient",
  "passphrase": "key-secret"
}
```

### CMS Info

```http
POST /api/v1/cms/info
```

---

## COSE/CWT {#cose}

CBOR Object Signing and Encryption (RFC 9052).

### Sign COSE

```http
POST /api/v1/cose/sign
```

**Request**
```json
{
  "payload": { "data": "...", "encoding": "base64" },
  "credential_id": "signer",
  "passphrase": "secret",
  "sign_type": "sign1"
}
```

### Verify COSE

```http
POST /api/v1/cose/verify
```

### Issue CWT

```http
POST /api/v1/cwt/issue
```

**Request**
```json
{
  "credential_id": "issuer",
  "passphrase": "secret",
  "claims": {
    "iss": "https://issuer.example.com",
    "sub": "user123",
    "aud": "https://api.example.com",
    "exp": 1735689600,
    "custom": {
      "role": "admin"
    }
  }
}
```

### Verify CWT

```http
POST /api/v1/cwt/verify
```

---

## TSA {#tsa}

Time-Stamp Authority (RFC 3161).

### Create Timestamp Token

```http
POST /api/v1/tsa/sign
```

**Request**
```json
{
  "data": { "data": "...", "encoding": "base64" },
  "hash_algorithm": "sha256",
  "credential_id": "tsa-credential",
  "passphrase": "secret",
  "include_cert": true
}
```

**Response**
```json
{
  "token": { "data": "...", "encoding": "base64" },
  "timestamp": "2024-01-15T10:30:45Z",
  "serial": "12345"
}
```

### Verify Token

```http
POST /api/v1/tsa/verify
```

### Token Info

```http
POST /api/v1/tsa/info
```

### RFC 3161 Endpoint

```http
POST /tsa
Content-Type: application/timestamp-query

<binary TSA request>
```

---

## OCSP {#ocsp}

Online Certificate Status Protocol (RFC 6960).

### Query Status

```http
POST /api/v1/ocsp/query
```

**Request**
```json
{
  "serial": "02",
  "ca_id": "root-ca",
  "ca_passphrase": "secret"
}
```

**Response**
```json
{
  "response": { "data": "...", "encoding": "base64" },
  "status": "good",
  "this_update": "2024-01-15T10:00:00Z",
  "next_update": "2024-01-15T11:00:00Z"
}
```

### Verify OCSP Response

```http
POST /api/v1/ocsp/verify
```

### RFC 6960 Endpoint

```http
POST /ocsp
Content-Type: application/ocsp-request

<binary OCSP request>
```

```http
GET /ocsp/{base64-encoded-request}
```

---

## Profiles {#profiles}

Certificate templates.

### List Profiles

```http
GET /api/v1/profiles
```

**Response**
```json
{
  "profiles": [
    {
      "name": "pq/root-ca",
      "description": "Post-quantum root CA",
      "category": "pq",
      "algorithm": "ml-dsa-65",
      "is_ca": true
    },
    {
      "name": "pq/tls-server",
      "description": "Post-quantum TLS server",
      "category": "pq",
      "algorithm": "ml-dsa-65",
      "is_ca": false
    }
  ]
}
```

### Get Profile

```http
GET /api/v1/profiles/{name}
```

### Get Profile Variables

```http
GET /api/v1/profiles/{name}/vars
```

### Validate Profile YAML

```http
POST /api/v1/profiles/validate
```

**Request**
```json
{
  "yaml": "name: custom-profile\nalgorithm: ml-dsa-65\n..."
}
```

---

## CRL {#crl}

Certificate Revocation Lists.

### Generate CRL

```http
POST /api/v1/crl/generate
```

**Request**
```json
{
  "ca_id": "root-ca",
  "ca_passphrase": "secret",
  "validity_days": 7
}
```

### List CRLs

```http
GET /api/v1/crl
```

### Get CRL

```http
GET /api/v1/crl/{id}
```

### Verify CRL

```http
POST /api/v1/crl/verify
```

---

## CSR {#csr}

Certificate Signing Requests.

### Generate CSR

```http
POST /api/v1/csr/generate
```

**Request**
```json
{
  "algorithm": "ml-dsa-65",
  "subject": {
    "cn": "server.example.com",
    "o": "My Organization"
  },
  "san": {
    "dns_names": ["server.example.com", "www.example.com"],
    "ip_addresses": ["192.168.1.1"]
  },
  "passphrase": "key-secret"
}
```

### CSR Info

```http
POST /api/v1/csr/info
```

### Verify CSR

```http
POST /api/v1/csr/verify
```

---

## Keys {#keys}

Key generation and inspection.

### Generate Key Pair

```http
POST /api/v1/keys/generate
```

**Request**
```json
{
  "algorithm": "ml-dsa-65",
  "passphrase": "secret",
  "output_format": "pem"
}
```

**Response**
```json
{
  "public_key": { "data": "...", "encoding": "pem" },
  "private_key": { "data": "...", "encoding": "pem" },
  "algorithm": {
    "id": "ml-dsa-65",
    "name": "ML-DSA-65",
    "type": "signature",
    "security_level": 3
  }
}
```

### Key Info

```http
POST /api/v1/keys/info
```

---

## Audit {#audit}

Audit logs.

### Get Logs

```http
GET /api/v1/audit/logs?from=2024-01-01&to=2024-01-31&operation=cert.issue
```

### Verify Integrity

```http
POST /api/v1/audit/verify
```

---

## Inspect {#inspect}

Auto-detect and inspect cryptographic objects.

```http
POST /api/v1/inspect
```

**Request**
```json
{
  "data": { "data": "...", "encoding": "base64" }
}
```

**Response**
```json
{
  "type": "certificate",
  "details": {
    "subject": "CN=server.example.com",
    "issuer": "CN=CA",
    "serial": "02",
    "algorithm": "ml-dsa-65",
    "valid_from": "2024-01-15T00:00:00Z",
    "valid_to": "2025-01-15T00:00:00Z"
  }
}
```

Detected types: `certificate`, `csr`, `crl`, `cms`, `cose`, `cwt`, `tsa_token`, `ocsp_request`, `ocsp_response`, `public_key`, `private_key`.
