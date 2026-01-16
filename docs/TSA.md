# Time-Stamp Authority (TSA)

## Table of Contents

- [1. What is a TSA?](#1-what-is-a-tsa)
- [2. CLI Commands](#2-cli-commands)
- [3. OpenSSL Interoperability](#3-openssl-interoperability)
- [4. Use Cases](#4-use-cases)
- [See Also](#see-also)

---

This guide covers the RFC 3161 compliant timestamping server implementation.

> **Related documentation:**
> - [CMS.md](CMS.md) - CMS signatures and encryption
> - [CREDENTIALS.md](CREDENTIALS.md) - TSA credentials

## 1. What is a TSA?

A **Time-Stamp Authority (TSA)** provides cryptographic proof that data existed at a specific time. QPKI implements an RFC 3161 compliant timestamping server with post-quantum algorithm support via RFC 9882.

### Standards

| Standard | Description |
|----------|-------------|
| RFC 3161 | Time-Stamp Protocol (TSP) |
| RFC 5652 | Cryptographic Message Syntax (CMS) |
| RFC 5816 | ESSCertIDv2 Update for RFC 3161 |
| RFC 9882 | ML-DSA in CMS |
| FIPS 204 | ML-DSA (Dilithium) |
| FIPS 205 | SLH-DSA (SPHINCS+) |

### Supported Formats

| Format | Extension | Content-Type |
|--------|-----------|--------------|
| TimeStampReq | `.tsq` | `application/timestamp-query` |
| TimeStampResp | `.tsr` | `application/timestamp-reply` |

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TSA Server                                    │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │  HTTP Handler    │────│    Timestamper   │────│   Signing    │  │
│  │  (POST)          │    │    (RFC 3161)    │    │   Key        │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Token Contents:**
- Serial number (unique identifier)
- Generation time (UTC)
- Message imprint (hash of timestamped data)
- TSA policy OID
- Optional: nonce, accuracy

---

## 2. CLI Commands

### Issue a TSA Certificate

```bash
# ECDSA (classical)
qpki credential enroll --profile ec/timestamping \
    --var cn=tsa.example.com --id tsa

# ML-DSA (post-quantum)
qpki credential enroll --profile ml/timestamping \
    --var cn=pqc-tsa.example.com --id pqc-tsa

# SLH-DSA (hash-based, long-term)
qpki credential enroll --profile slh/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa

# Hybrid (PQC transition)
qpki credential enroll --profile hybrid/catalyst/timestamping \
    --var cn=hybrid-tsa.example.com --id hybrid-tsa
```

### tsa sign

Sign a file with a timestamp.

```bash
qpki tsa sign --data document.pdf --cert tsa.crt --key tsa.key --out token.tsr

# Options
#   --hash sha256|sha384|sha512   Hash algorithm (default: sha256)
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --include-tsa                 Include TSA name in token
```

### tsa verify

Verify a timestamp token.

```bash
qpki tsa verify --token token.tsr --data document.pdf --ca ca.crt

# Without data verification (signature only)
qpki tsa verify --token token.tsr --ca ca.crt
```

### inspect

Display token information.

```bash
qpki inspect token.tsr
```

Output:
```
Timestamp Response:
  Status:         granted
Timestamp Token:
  Version:        1
  Serial Number:  123456789012345678901234567890
  Gen Time:       2025-01-15T10:30:00Z
  Policy:         1.3.6.1.4.1.99999.2.1
  Message Imprint:
    Hash Alg:     2.16.840.1.101.3.4.2.1
    Hash:         AB:CD:EF:...
  Accuracy:       1s 0ms 0us
  Nonce:          12345
```

### tsa request

Create a timestamp request.

```bash
qpki tsa request --data document.pdf --out request.tsq

# With nonce (recommended for replay protection)
qpki tsa request --data document.pdf --nonce --out request.tsq

# With specific hash algorithm
qpki tsa request --data document.pdf --hash sha384 --out request.tsq
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--data` | File to timestamp | Required |
| `--hash` | Hash algorithm (sha256, sha384, sha512) | sha256 |
| `--nonce` | Include random nonce | false |
| `-o, --out` | Output file | Required |

### tsa info

Display timestamp token information.

```bash
qpki tsa info token.tsr
```

**Output:**

```
Timestamp Token:
  Version:        1
  Serial Number:  123456789012345678901234567890
  Gen Time:       2025-01-15T10:30:00Z
  Policy:         1.3.6.1.4.1.99999.2.1
  Message Imprint:
    Hash Alg:     SHA-256
    Hash:         AB:CD:EF:...
  Accuracy:       1s
  Signer:         CN=tsa.example.com
```

### tsa serve

Start an HTTP TSA server.

```bash
# Start the server
qpki tsa serve --port 8318 --cert tsa.crt --key tsa.key

# Options
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --accuracy 1                   Accuracy in seconds
#   --tls-cert server.crt          TLS certificate (HTTPS)
#   --tls-key server.key           TLS key (HTTPS)
```

### HTTP Protocol

| Element | Value |
|---------|-------|
| Method | POST |
| Endpoint | / |
| Content-Type (request) | `application/timestamp-query` |
| Content-Type (response) | `application/timestamp-reply` |

---

## 3. OpenSSL Interoperability

```bash
# Generate a request
openssl ts -query -data document.pdf -sha256 -out request.tsq

# Submit to server
curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     http://localhost:8318/ -o response.tsr

# Verify the response (ECDSA/RSA only)
openssl ts -verify -in response.tsr -data document.pdf -CAfile ca.crt
```

> **Note:** OpenSSL does not support ML-DSA/SLH-DSA. Use `qpki tsa verify` for PQC tokens.

---

## 4. Use Cases

### Code Signing

```bash
# 1. Sign the code
codesign --sign "Developer ID" myapp.app

# 2. Timestamp the signature
qpki tsa sign --data myapp.app/Contents/_CodeSignature/CodeResources \
    --cert tsa.crt --key tsa.key --out myapp.tsr
```

### Legal Archiving

```bash
# Use SLH-DSA for maximum quantum resistance
qpki credential enroll --profile slh/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa

# Timestamp documents
for doc in *.pdf; do
    qpki tsa sign --data "$doc" --cert archive-tsa.crt --key archive-tsa.key \
        --out "${doc%.pdf}.tsr"
done
```

---

## See Also

- [CMS](CMS.md) - CMS signatures and encryption
- [CREDENTIALS](CREDENTIALS.md) - TSA credentials
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) - Time-Stamp Protocol
- [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) - ML-DSA in CMS
