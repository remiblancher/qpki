# Operations

This document covers operational services: OCSP responder, TSA timestamping, and audit logging.

## 1. OCSP Responder (RFC 6960)

The OCSP implementation is compliant with **RFC 6960** (X.509 Internet PKI OCSP) and **RFC 5019** (Lightweight OCSP Profile). It supports classical algorithms (ECDSA, RSA, Ed25519), post-quantum (ML-DSA), and hybrid (Catalyst).

### 1.1 OCSP vs CRL

| Criterion | CRL | OCSP |
|-----------|-----|------|
| Latency | Full download | Per-certificate query |
| Bandwidth | High (complete list) | Low (single response) |
| Real-time | No (update interval) | Yes |
| Privacy | No leakage | Responder sees queries |
| TLS Stapling | No | Yes |

### 1.2 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OCSP Responder                               │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │  HTTP Handler    │────│    Responder     │────│   CA Store   │  │
│  │  (GET + POST)    │    │    (RFC 6960)    │    │   (index)    │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Operation Modes:**

1. **Delegated Responder** (recommended)
   - Responder certificate with EKU `ocspSigning` (OID 1.3.6.1.5.5.7.3.9)
   - OCSP No Check extension to prevent recursion
   - Separate key from CA

2. **CA-Signed**
   - CA signs responses directly
   - Simpler but less flexible

### 1.3 CLI Commands

#### ocsp sign

Create a signed OCSP response.

```bash
# Response "good" for valid certificate
qpki ocsp sign --serial 0A1B2C3D --status good \
  --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

# Response "revoked" with reason
qpki ocsp sign --serial 0A1B2C3D --status revoked \
  --revocation-time "2024-01-15T10:00:00Z" \
  --revocation-reason keyCompromise \
  --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

# Response "unknown"
qpki ocsp sign --serial 0A1B2C3D --status unknown \
  --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--serial` | Serial number (hex) | Required |
| `--status` | good, revoked, unknown | Required |
| `--ca` | CA certificate | Required |
| `--cert` | Responder certificate | Required |
| `--key` | Responder private key | Required |
| `--validity` | Response validity period | 1h |
| `--revocation-time` | Revocation date (RFC 3339) | - |
| `--revocation-reason` | CRL reason | - |
| `-o, --out` | Output file | stdout |

#### ocsp verify

Verify an OCSP response.

```bash
# Basic verification
qpki ocsp verify --response response.ocsp --ca ca.crt

# With target certificate
qpki ocsp verify --response response.ocsp --ca ca.crt --cert server.crt

# With nonce (replay protection)
qpki ocsp verify --response response.ocsp --ca ca.crt --nonce 0102030405060708
```

#### ocsp request

Create an OCSP request.

```bash
# Simple request
qpki ocsp request --ca ca.crt --cert server.crt -o request.ocsp

# With nonce (recommended)
qpki ocsp request --ca ca.crt --cert server.crt --nonce -o request.ocsp

# By serial number
qpki ocsp request --ca ca.crt --serial 0A1B2C3D -o request.ocsp
```

#### ocsp serve

Start an HTTP OCSP responder server.

```bash
# Delegated mode (dedicated responder cert)
qpki ocsp serve --port 8080 --ca-dir /path/to/ca \
  --cert responder.crt --key responder.key

# With custom validity
qpki ocsp serve --port 8080 --ca-dir /path/to/ca \
  --cert responder.crt --key responder.key --validity 24h
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | HTTP port | 8080 |
| `--addr` | Full listen address | :8080 |
| `--ca-dir` | CA directory (with index.txt) | Required |
| `--cert` | Responder certificate | Required |
| `--key` | Responder private key | Required |
| `--validity` | Response validity | 1h |

### 1.4 Responder Profiles

```bash
# ECDSA (classical)
qpki credential enroll --profile ec/ocsp-responder \
    --var cn=ocsp.example.com --id ocsp-responder --ca-dir ./ca

# ML-DSA (post-quantum)
qpki credential enroll --profile ml/ocsp-responder \
    --var cn=pqc-ocsp.example.com --id pqc-ocsp-responder --ca-dir ./ca

# Hybrid Catalyst
qpki credential enroll --profile hybrid/catalyst/ocsp-responder \
    --var cn=hybrid-ocsp.example.com --id hybrid-ocsp-responder --ca-dir ./ca
```

### 1.5 OpenSSL Interoperability

```bash
# Create request with OpenSSL
openssl ocsp -issuer ca.crt -cert server.crt -reqout request.ocsp -no_nonce

# Query the server
openssl ocsp -issuer ca.crt -cert server.crt \
  -url http://localhost:8080 -resp_text

# Verify a response
openssl ocsp -respin response.ocsp -CAfile ca.crt -resp_text
```

> **Note:** OpenSSL does not support ML-DSA. Use `qpki ocsp verify` for PQC responses.

### 1.6 OCSP No Check Extension

The `id-pkix-ocsp-nocheck` extension (OID 1.3.6.1.5.5.7.48.1.5) indicates the responder certificate should not be checked via OCSP, avoiding infinite loops. This extension is automatically added to `ocsp-responder` profiles.

---

## 2. Time-Stamp Authority (RFC 3161)

The TSA module implements an RFC 3161 compliant timestamping server with post-quantum algorithm support via RFC 9882.

### 2.1 Standards

| Standard | Description |
|----------|-------------|
| RFC 3161 | Time-Stamp Protocol (TSP) |
| RFC 5652 | Cryptographic Message Syntax (CMS) |
| RFC 5816 | ESSCertIDv2 Update for RFC 3161 |
| RFC 9882 | ML-DSA in CMS |
| FIPS 204 | ML-DSA (Dilithium) |
| FIPS 205 | SLH-DSA (SPHINCS+) |

### 2.2 Supported Formats

| Format | Extension | Content-Type |
|--------|-----------|--------------|
| TimeStampReq | `.tsq` | `application/timestamp-query` |
| TimeStampResp | `.tsr` | `application/timestamp-reply` |

### 2.3 CLI Commands

#### Issue a TSA Certificate

```bash
# ECDSA (classical)
qpki credential enroll --profile ec/timestamping \
    --var cn=tsa.example.com --id tsa --ca-dir ./ca

# ML-DSA (post-quantum)
qpki credential enroll --profile ml/timestamping \
    --var cn=pqc-tsa.example.com --id pqc-tsa --ca-dir ./ca

# SLH-DSA (hash-based, long-term)
qpki credential enroll --profile slh/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa --ca-dir ./ca

# Hybrid (PQC transition)
qpki credential enroll --profile hybrid/catalyst/timestamping \
    --var cn=hybrid-tsa.example.com --id hybrid-tsa --ca-dir ./ca
```

#### Sign a File

```bash
qpki tsa sign --data document.pdf --cert tsa.crt --key tsa.key -o token.tsr

# Options
#   --hash sha256|sha384|sha512   Hash algorithm (default: sha256)
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --include-tsa                 Include TSA name in token
```

#### Verify a Token

```bash
qpki tsa verify --token token.tsr --data document.pdf --ca ca.crt

# Without data verification (signature only)
qpki tsa verify --token token.tsr --ca ca.crt
```

#### Display Token Information

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

#### HTTP Server

```bash
# Start the server
qpki tsa serve --port 8318 --cert tsa.crt --key tsa.key

# Options
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --accuracy 1                   Accuracy in seconds
#   --tls-cert server.crt          TLS certificate (HTTPS)
#   --tls-key server.key           TLS key (HTTPS)
```

### 2.4 HTTP Protocol

| Element | Value |
|---------|-------|
| Method | POST |
| Endpoint | / |
| Content-Type (request) | `application/timestamp-query` |
| Content-Type (response) | `application/timestamp-reply` |

### 2.5 OpenSSL Interoperability

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

### 2.6 Use Cases

#### Code Signing

```bash
# 1. Sign the code
codesign --sign "Developer ID" myapp.app

# 2. Timestamp the signature
qpki tsa sign --data myapp.app/Contents/_CodeSignature/CodeResources \
    --cert tsa.crt --key tsa.key -o myapp.tsr
```

#### Legal Archiving

```bash
# Use SLH-DSA for maximum quantum resistance
qpki credential enroll --profile slh/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa --ca-dir ./ca

# Timestamp documents
for doc in *.pdf; do
    qpki tsa sign --data "$doc" --cert archive-tsa.crt --key archive-tsa.key \
        -o "${doc%.pdf}.tsr"
done
```

---

## 3. Audit Logging

The audit system is designed for compliance (eIDAS, ETSI EN 319 401) and SIEM integration.

### 3.1 Core Principles

1. **Strict separation**: Audit logs are distinct from technical logs
2. **Write guarantee**: If audit fails → operation fails
3. **Cryptographic chaining**: Detects any modification or deletion
4. **No secrets**: No private keys or passphrases in logs

### 3.2 Activation

Via CLI flag:
```bash
qpki --audit-log /var/log/pki/audit.jsonl ca init --name "Root CA"
```

Via environment variable:
```bash
export PKI_AUDIT_LOG=/var/log/pki/audit.jsonl
qpki ca init --name "Root CA"
```

### 3.3 Event Format

Each event is stored in JSON Lines (JSONL), one line per event:

```json
{
  "event_type": "CERT_ISSUED",
  "timestamp": "2025-01-15T14:30:22Z",
  "actor": {
    "type": "user",
    "id": "admin",
    "host": "ca-server"
  },
  "object": {
    "type": "certificate",
    "serial": "0x03",
    "subject": "CN=server.example.com"
  },
  "context": {
    "profile": "tls-server",
    "ca": "/var/lib/pki/issuing-ca",
    "algorithm": "ECDSA-SHA256"
  },
  "result": "success",
  "hash_prev": "sha256:abc123...",
  "hash": "sha256:def456..."
}
```

### 3.4 Event Types

| Type | Trigger |
|------|---------|
| `CA_CREATED` | New CA created (root or issuing) |
| `CA_LOADED` | Existing CA loaded |
| `KEY_ACCESSED` | CA private key accessed |
| `CERT_ISSUED` | Certificate issued |
| `CERT_REVOKED` | Certificate revoked |
| `CRL_GENERATED` | CRL generated |
| `AUTH_FAILED` | Authentication failed (wrong passphrase) |
| `OCSP_SIGN` | OCSP response created |
| `OCSP_REQUEST` | OCSP request received |
| `TSA_SIGN` | Timestamp token created |
| `TSA_REQUEST` | Timestamp request received |

### 3.5 Cryptographic Chaining

Each event is linked to the previous by SHA-256 hash:

```
H(n) = SHA256( canonical_json(event_n) || H(n-1) )
```

- First event: `hash_prev = "sha256:genesis"`
- Hash is calculated on canonical JSON (without `hash` field)

**Detects:**
- **Modification**: Recalculated hash doesn't match
- **Deletion**: Chain is broken
- **Insertion**: hash_prev doesn't match

### 3.6 Verification

```bash
# Verify log integrity
qpki audit verify --log /var/log/pki/audit.jsonl

# Display last events
qpki audit tail --log /var/log/pki/audit.jsonl -n 20

# JSON output
qpki audit tail --log /var/log/pki/audit.jsonl --json
```

**Verification output:**
```
Verifying audit log: /var/log/pki/audit.jsonl

VERIFICATION PASSED
  Total events: 42
  Hash chain: VALID
```

### 3.7 SIEM Integration

#### Splunk

Configuration `inputs.conf`:
```ini
[monitor:///var/log/pki/audit.jsonl]
sourcetype = pki:audit
index = security
```

Query example:
```spl
index=security sourcetype=pki:audit event_type=AUTH_FAILED
| stats count by actor.id, actor.host
```

#### Elastic (Filebeat)

Configuration `filebeat.yml`:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/pki/audit.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: pki_audit
    fields_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "pki-audit-%{+yyyy.MM.dd}"
```

Query example:
```
event_type: "CERT_REVOKED" AND context.reason: "keyCompromise"
```

### 3.8 ETSI EN 319 401 Compliance

| Requirement | Implementation |
|-------------|----------------|
| 7.5.1 Logging | All CA events are logged |
| 7.5.2 Integrity | SHA-256 hash chain |
| 7.5.3 Protection | File with fsync, permissions 0600 |
| 7.5.4 Retention | JSONL file, SIEM archiving |

### 3.9 Best Practices

#### File Permissions

```bash
# Create directory with restrictive permissions
sudo mkdir -p /var/log/pki
sudo chmod 700 /var/log/pki
```

#### Log Rotation (logrotate)

```
/var/log/pki/audit.jsonl {
    daily
    rotate 365
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        # Verify integrity before archiving
        qpki audit verify --log /var/log/pki/audit.jsonl.1
    endscript
}
```

#### Archiving

```bash
qpki audit verify --log /var/log/pki/audit.jsonl
cp /var/log/pki/audit.jsonl /archive/pki/$(date +%Y%m%d)-audit.jsonl
```

### 3.10 Security

**What is NEVER logged:**
- Private keys
- Passphrases
- Encryption secrets
- Sensitive certificate data beyond DN

**File protection:**
- Permissions 0600 (root read/write only)
- fsync after each write
- Hash chain for integrity

---

## 4. References

- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) - OCSP
- [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) - Lightweight OCSP Profile
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) - Time-Stamp Protocol
- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) - CMS
- [ETSI EN 319 401](https://www.etsi.org/deliver/etsi_en/319400_319499/319401/) - Trust Service Providers

## See Also

- [GUIDE](GUIDE.md) - CLI reference
- [HSM](HSM.md) - Hardware security module integration
- [CONCEPTS](CONCEPTS.md) - PQC and hybrid certificates
