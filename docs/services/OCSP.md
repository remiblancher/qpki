---
title: "OCSP Responder"
description: "This guide covers the Online Certificate Status Protocol (OCSP) responder implementation."
---

# OCSP Responder

This guide covers the Online Certificate Status Protocol (OCSP) responder implementation.

## 1. What is OCSP?

**Online Certificate Status Protocol (OCSP)** provides real-time certificate revocation checking. The QPKI implementation is compliant with **RFC 6960** (X.509 Internet PKI OCSP) and **RFC 5019** (Lightweight OCSP Profile). It supports classical algorithms (ECDSA, RSA, Ed25519), post-quantum (ML-DSA), and hybrid (Catalyst).

### OCSP vs CRL

| Criterion | CRL | OCSP |
|-----------|-----|------|
| Latency | Full download | Per-certificate query |
| Bandwidth | High (complete list) | Low (single response) |
| Real-time | No (update interval) | Yes |
| Privacy | No leakage | Responder sees queries |
| TLS Stapling | No | Yes |

### Architecture

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

---

## 2. CLI Commands

### ocsp sign

Create a signed OCSP response.

```bash
# Sign with credential (recommended)
qpki ocsp sign --serial 0A1B2C3D --status good \
  --ca ca.crt --credential ocsp-responder --out response.ocsp

qpki ocsp sign --serial 0A1B2C3D --status good \
  --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

qpki ocsp sign --serial 0A1B2C3D --status revoked \
  --revocation-time "2024-01-15T10:00:00Z" \
  --revocation-reason keyCompromise \
  --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

qpki ocsp sign --serial 0A1B2C3D --status unknown \
  --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--serial` | Serial number (hex) | Required |
| `--status` | good, revoked, unknown | Required |
| `--ca` | CA certificate | Required |
| `--cert` | Responder certificate | - |
| `--key` | Responder private key | - |
| `--credential` | Credential ID (alternative to --cert/--key) | - |
| `--cred-dir` | Credentials directory | ./credentials |
| `--hsm-config` | HSM configuration file | - |
| `--key-label` | HSM key label (CKA_LABEL) | - |
| `--key-id` | HSM key ID (CKA_ID, hex) | - |
| `--validity` | Response validity period | 1h |
| `--revocation-time` | Revocation date (RFC 3339) | - |
| `--revocation-reason` | CRL reason | - |
| `-o, --out` | Output file | stdout |

### ocsp verify

Verify an OCSP response.

```bash
# Basic verification
qpki ocsp verify --response response.ocsp --ca ca.crt

qpki ocsp verify --response response.ocsp --ca ca.crt --cert server.crt

qpki ocsp verify --response response.ocsp --ca ca.crt --nonce 0102030405060708
```

### ocsp request

Create an OCSP request.

```bash
# Simple request
qpki ocsp request --ca ca.crt --cert server.crt --out request.ocsp

qpki ocsp request --ca ca.crt --cert server.crt --nonce --out request.ocsp

qpki ocsp request --ca ca.crt --serial 0A1B2C3D --out request.ocsp
```

### ocsp info

Display OCSP response information.

```bash
qpki ocsp info response.ocsp
```

### ocsp serve

Start an HTTP OCSP responder server.

```bash
# Serve with credential (recommended)
qpki ocsp serve --port 8080 --ca-dir /path/to/ca --credential ocsp-responder

qpki ocsp serve --port 8080 --ca-dir /path/to/ca \
  --cert responder.crt --key responder.key

qpki ocsp serve --port 8080 --ca-dir /path/to/ca \
  --cert responder.crt --key responder.key --validity 24h

qpki ocsp serve --port 8080 --ca-dir /path/to/ca \
  --cert responder.crt --key responder.key --pid-file /var/run/ocsp.pid
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | HTTP port | 8080 |
| `--addr` | Full listen address | :8080 |
| `--ca-dir` | CA directory (with index.txt) | Required |
| `--cert` | Responder certificate | - |
| `--key` | Responder private key | - |
| `--credential` | Credential ID (alternative to --cert/--key) | - |
| `--cred-dir` | Credentials directory | ./credentials |
| `--hsm-config` | HSM configuration file | - |
| `--key-label` | HSM key label (CKA_LABEL) | - |
| `--key-id` | HSM key ID (CKA_ID, hex) | - |
| `--validity` | Response validity | 1h |
| `--pid-file` | PID file path | `/tmp/qpki-ocsp-{port}.pid` |

### ocsp stop

Stop a running OCSP responder server.

```bash
# Stop using default PID file (based on port)
qpki ocsp stop --port 8080

qpki ocsp stop --pid-file /var/run/ocsp.pid
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Port to derive default PID file | 8080 |
| `--pid-file` | PID file path | `/tmp/qpki-ocsp-{port}.pid` |

> **Note:** The stop command sends a SIGTERM signal to the process. This works on Unix-like systems (Linux, macOS) but not on Windows.

---

## 3. Responder Profiles

### Option A: Credential-based

```bash
# ECDSA
qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ec/ocsp-responder --var cn=ocsp.example.com --id ocsp-responder

qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile ml/ocsp-responder --var cn=pqc-ocsp.example.com --id pqc-ocsp-responder

qpki credential enroll --ca-dir ./ca --cred-dir ./credentials \
    --profile hybrid/catalyst/ocsp-responder --var cn=hybrid-ocsp.example.com --id hybrid-ocsp-responder

qpki ocsp serve --port 8080 --ca-dir ./ca \
    --cert ./credentials/ocsp-responder/ocsp-responder.crt \
    --key ./credentials/ocsp-responder/ocsp-responder.key
```

### Option B: CSR-based

```bash
# 1. Generate key
qpki key gen --algo ecdsa-p256 --out ocsp-responder.key

qpki csr create --key ocsp-responder.key --cn ocsp.example.com --out ocsp-responder.csr

qpki cert issue --ca-dir ./ca --profile ec/ocsp-responder --csr ocsp-responder.csr --out ocsp-responder.crt

qpki ocsp serve --port 8080 --ca-dir ./ca \
    --cert ocsp-responder.crt --key ocsp-responder.key
```

### Server Mode with Credentials

Using credentials for `ocsp serve` enables **zero-downtime certificate rotation** via the rotate → activate workflow:

```bash
# 1. Start server with credential
qpki ocsp serve --port 8080 --ca-dir ./ca --credential ocsp-responder

qpki credential rotate ocsp-responder

qpki credential versions ocsp-responder

qpki credential activate ocsp-responder --version v2

```

The server always uses the **active** version of the credential. This workflow allows:
- Certificate renewal without service interruption
- Gradual rollout with rollback capability
- Crypto-agility migration (add/remove algorithm profiles)

---

## 4. OpenSSL Interoperability

```bash
# Create request with OpenSSL
openssl ocsp -issuer ca.crt -cert server.crt -reqout request.ocsp -no_nonce

openssl ocsp -issuer ca.crt -cert server.crt \
  -url http://localhost:8080 -resp_text

openssl ocsp -respin response.ocsp -CAfile ca.crt -resp_text
```

> **Note:** OpenSSL does not support ML-DSA. Use `qpki ocsp verify` for PQC responses.

---

## 5. OCSP No Check Extension

The `id-pkix-ocsp-nocheck` extension (OID 1.3.6.1.5.5.7.48.1.5) indicates the responder certificate should not be checked via OCSP, avoiding infinite loops. This extension is automatically added to `ocsp-responder` profiles.

---

## 6. HSM Support

OCSP signing operations support HSM-stored keys.

```bash
export HSM_PIN="****"

# Sign OCSP response with HSM key
qpki ocsp sign --serial 0A1B2C3D --status good \
  --ca ca.crt --cert responder.crt \
  --hsm-config ./hsm.yaml --key-label "ocsp-key" --out response.ocsp

# Start OCSP server with HSM key
qpki ocsp serve --port 8080 --ca-dir ./ca --cert responder.crt \
  --hsm-config ./hsm.yaml --key-label "ocsp-key"
```

See [HSM Integration](../operations/HSM.md) for configuration details.

---

## See Also

- [CRL](../core-pki/CRL.md) - Certificate revocation with CRL
- [Credentials](../end-entities/CREDENTIALS.md) - OCSP responder credentials
- [HSM](../operations/HSM.md) - Hardware Security Module integration
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) - OCSP specification
- [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) - Lightweight OCSP Profile
