---
title: "Time-Stamp Authority (TSA)"
description: "This guide covers the RFC 3161 compliant timestamping server implementation."
---

# Time-Stamp Authority (TSA)

This guide covers the RFC 3161 compliant timestamping server implementation.

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
| eIDAS | EU 910/2014 Electronic Identification and Trust Services |
| ETSI EN 319 422 | Time-stamping protocol profiles for eIDAS |

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

### tsa sign

Sign a file with a timestamp.

```bash
# Sign with credential (recommended)
qpki tsa sign --data document.pdf --credential tsa --out token.tsr

qpki tsa sign --data document.pdf --cert tsa.crt --key tsa.key --out token.tsr

#   --credential <id>             Credential ID (alternative to --cert/--key)
#   --hash sha256|sha384|sha512   Hash algorithm (default: sha256)
#   --include-tsa                 Include TSA name in token
```

### tsa verify

Verify a timestamp token.

```bash
qpki tsa verify --token token.tsr --data document.pdf --ca ca.crt

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

qpki tsa request --data document.pdf --nonce --out request.tsq

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
# Start the server with credential (recommended)
qpki tsa serve --port 8318 --credential tsa

qpki tsa serve --port 8318 --cert tsa.crt --key tsa.key

qpki tsa serve --port 8318 --cert tsa.crt --key tsa.key --pid-file /var/run/tsa.pid

#   --credential <id>             Credential ID (alternative to --cert/--key)
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --tls-cert server.crt          TLS certificate (HTTPS)
#   --pid-file /path/to/file.pid   PID file path
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | HTTP port | 8318 |
| `--cert` | TSA certificate | Required |
| `--key` | TSA private key | Required |
| `--policy` | TSA policy OID | 1.3.6.1.4.1.99999.2.1 |
| `--accuracy` | Accuracy in seconds | 1 |
| `--tls-cert` | TLS certificate (HTTPS) | - |
| `--tls-key` | TLS key (HTTPS) | - |
| `--pid-file` | PID file path | `/tmp/qpki-tsa-{port}.pid` |

### tsa stop

Stop a running TSA server.

```bash
# Stop using default PID file (based on port)
qpki tsa stop --port 8318

qpki tsa stop --pid-file /var/run/tsa.pid
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Port to derive default PID file | 8318 |
| `--pid-file` | PID file path | `/tmp/qpki-tsa-{port}.pid` |

> **Note:** The stop command sends a SIGTERM signal to the process. This works on Unix-like systems (Linux, macOS) but not on Windows.

### HTTP Protocol

| Element | Value |
|---------|-------|
| Method | POST |
| Endpoint | / |
| Content-Type (request) | `application/timestamp-query` |
| Content-Type (response) | `application/timestamp-reply` |

---

## 3. TSA Profiles

### Option A: Credential-based

```bash
# ECDSA
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/timestamping --var cn=tsa.example.com --id tsa

qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/timestamping --var cn=pqc-tsa.example.com --id pqc-tsa

qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile slh/timestamping --var cn=archive-tsa.example.com --id archive-tsa

qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile hybrid/catalyst/timestamping --var cn=hybrid-tsa.example.com --id hybrid-tsa

qpki tsa serve --port 8318 \
    --cert ./credentials/tsa/tsa.crt --key ./credentials/tsa/tsa.key
```

### Option B: CSR-based

```bash
# 1. Generate key
qpki key gen --algo ecdsa-p256 --out tsa.key

qpki csr create --key tsa.key --cn tsa.example.com --out tsa.csr

qpki cert issue --ca-dir ./ca --profile ec/timestamping --csr tsa.csr --out tsa.crt

qpki tsa serve --port 8318 --cert tsa.crt --key tsa.key
```

### Server Mode with Credentials

Using credentials for `tsa serve` enables **zero-downtime certificate rotation** via the rotate → activate workflow:

```bash
# 1. Start server with credential
qpki tsa serve --port 8318 --credential tsa

qpki credential rotate tsa

qpki credential versions tsa

qpki credential activate tsa --version v2

```

The server always uses the **active** version of the credential. This workflow allows:
- Certificate renewal without service interruption
- Gradual rollout with rollback capability
- Crypto-agility migration (add/remove algorithm profiles)

---

## 4. OpenSSL Interoperability

```bash
# Generate a request
openssl ts -query -data document.pdf -sha256 -out request.tsq

curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     http://localhost:8318/ -o response.tsr

openssl ts -verify -in response.tsr -data document.pdf -CAfile ca.crt
```

> **Note:** OpenSSL does not support ML-DSA/SLH-DSA. Use `qpki tsa verify` for PQC tokens.

---

## 5. Use Cases

### Code Signing

```bash
# 1. Sign the code
codesign --sign "Developer ID" myapp.app

qpki tsa sign --data myapp.app/Contents/_CodeSignature/CodeResources \
    --cert tsa.crt --key tsa.key --out myapp.tsr
```

### Legal Archiving

```bash
# Use SLH-DSA for maximum quantum resistance
qpki credential enroll --profile slh/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa

for doc in *.pdf; do
    qpki tsa sign --data "$doc" --cert archive-tsa.crt --key archive-tsa.key \
        --out "${doc%.pdf}.tsr"
done
```

---

## 6. eIDAS Qualified Timestamps

QPKI supports **eIDAS qualified electronic timestamps** (EU Regulation 910/2014).

### Standards

| Standard | Description |
|----------|-------------|
| eIDAS | EU Regulation 910/2014 on electronic identification and trust services |
| ETSI EN 319 422 | Time-stamping protocol and token profiles |
| ETSI EN 319 412-5 | QCStatements extension for qualified certificates |

### Qualified Timestamp Requirements

For a timestamp to be considered **qualified** under eIDAS:

1. **TSA Certificate**: Must contain QCStatements with `qcCompliance`
2. **Token Extension**: Must include `esi4-qtstStatement-1` (OID 0.4.0.19422.1.1)
3. **SigningCertificateV2**: Must include ESSCertIDv2 attribute (RFC 5816)

### Automatic Qualified Token Generation

When the TSA certificate contains the `qcCompliance` QCStatement, QPKI automatically adds the `esi4-qtstStatement-1` extension to the TSTInfo:

```
TSTInfo:
  version         1
  policy          0.4.0.2042.1.3
  messageImprint  ...
  serialNumber    ...
  genTime         2025-01-21T10:30:00Z
  extensions:
    - esi4-qtstStatement-1 (0.4.0.19422.1.1)   <-- Added automatically
```

### Issue a Qualified TSA Certificate

```bash
# Create eIDAS qualified TSA certificate
qpki credential enroll --profile eidas/qc-tsa \
    --var cn="ACME Qualified TSA" \
    --var organization="ACME Corporation" \
    --var country="FR" \
    --id qualified-tsa
```

The `eidas/qc-tsa` profile includes:
- QCStatements with `qcCompliance`
- extKeyUsage: timeStamping (critical, exclusive per RFC 3161)
- ETSI policy OID 0.4.0.2042.1.3

### Create Qualified Timestamps

```bash
# Start qualified TSA server
qpki tsa serve --port 8318 \
    --cert qualified-tsa.crt \
    --key qualified-tsa.key \
    --policy "0.4.0.2042.1.3"

curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     http://localhost:8318/ -o qualified-response.tsr
```

### Verify Qualified Timestamp

```bash
# Inspect token to verify esi4-qtstStatement-1 extension
qpki inspect qualified-response.tsr
```

Expected output includes:
```
Extensions:
  - OID: 0.4.0.19422.1.1 (esi4-qtstStatement-1)
    Critical: false
```

---

## See Also

- [CMS](CMS.md) - CMS signatures and encryption
- [Credentials](../end-entities/CREDENTIALS.md) - TSA credentials
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) - Time-Stamp Protocol
- [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) - ML-DSA in CMS
