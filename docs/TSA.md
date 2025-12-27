# Time-Stamp Authority (TSA)

The TSA module implements an RFC 3161 compliant timestamping server with post-quantum algorithm support via RFC 9882.

## Standards

| Standard | Description | Link |
|----------|-------------|------|
| RFC 3161 | Time-Stamp Protocol (TSP) | https://www.rfc-editor.org/rfc/rfc3161 |
| RFC 5652 | Cryptographic Message Syntax (CMS) | https://www.rfc-editor.org/rfc/rfc5652 |
| RFC 5816 | ESSCertIDv2 Update for RFC 3161 | https://www.rfc-editor.org/rfc/rfc5816 |
| RFC 9882 | ML-DSA in CMS | https://www.rfc-editor.org/rfc/rfc9882 |
| FIPS 204 | ML-DSA (Dilithium) | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 | SLH-DSA (SPHINCS+) | https://csrc.nist.gov/pubs/fips/205/final |

## Supported Formats

| Format | Extension | Content-Type | Description |
|--------|-----------|--------------|-------------|
| TimeStampReq | `.tsq` | `application/timestamp-query` | DER-encoded request (RFC 3161 §2.4.1) |
| TimeStampResp | `.tsr` | `application/timestamp-reply` | DER-encoded response (RFC 3161 §2.4.2) |
| TSTInfo | - | - | Encapsulated in CMS SignedData (OID 1.2.840.113549.1.9.16.1.4) |

### File Format Details

- **Input**: Binary DER encoding (not PEM)
- **Output**: Binary DER encoding (not PEM)
- **CMS wrapper**: SignedData (OID 1.2.840.113549.1.7.2)
- **Content type**: id-ct-TSTInfo (OID 1.2.840.113549.1.9.16.1.4)

## Commands

### Issue a TSA Certificate

```bash
# ECDSA (classical)
pki credential enroll --profile ec/timestamping \
    --var cn=tsa.example.com --id tsa --ca-dir ./ca

# ML-DSA (post-quantum)
pki credential enroll --profile ml-dsa-kem/timestamping \
    --var cn=pqc-tsa.example.com --id pqc-tsa --ca-dir ./ca

# SLH-DSA (hash-based, long-term)
pki credential enroll --profile slh-dsa/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa --ca-dir ./ca

# Hybrid (PQC transition)
pki credential enroll --profile hybrid/catalyst/timestamping \
    --var cn=hybrid-tsa.example.com --id hybrid-tsa --ca-dir ./ca
```

### Sign a File (CLI Mode)

```bash
pki tsa sign --data document.pdf --cert tsa.crt --key tsa.key -o token.tsr

# Options
#   --hash sha256|sha384|sha512   Hash algorithm (default: sha256)
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --include-tsa                 Include TSA name in token
```

### Verify a Token

```bash
pki tsa verify --token token.tsr --data document.pdf --ca ca.crt

# Without data verification (signature only)
pki tsa verify --token token.tsr --ca ca.crt
```

### Display Token Information

```bash
pki inspect token.tsr
```

Example output:
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
  Accuracy:       1s 0ms 0µs
  Nonce:          12345
```

### HTTP Server (RFC 3161)

```bash
# Start the server
pki tsa serve --port 8318 --cert tsa.crt --key tsa.key

# Options
#   --policy "1.3.6.1.4.1.X.Y.Z"  TSA policy OID
#   --accuracy 1                   Accuracy in seconds
#   --tls-cert server.crt          TLS certificate (HTTPS)
#   --tls-key server.key           TLS key (HTTPS)
```

## HTTP Protocol

| Element | Value |
|---------|-------|
| Method | POST |
| Endpoint | / |
| Content-Type (request) | `application/timestamp-query` |
| Content-Type (response) | `application/timestamp-reply` |

### Status Codes

- **200 OK** - TimeStampResp returned (even if rejected)
- **400 Bad Request** - Malformed request
- **405 Method Not Allowed** - Method other than POST

## Available Profiles

| Profile | Algorithm | Security Level | Use Case |
|---------|-----------|----------------|----------|
| `ec/timestamping` | ECDSA P-256 | Classical | Legacy compatibility |
| `rsa/timestamping` | RSA-2048 | Classical | Legacy compatibility |
| `ml-dsa-kem/timestamping` | ML-DSA-65 | NIST 3 | Post-quantum |
| `slh-dsa/timestamping` | SLH-DSA-256s | NIST 5 | Long-term archives |
| `hybrid/catalyst/timestamping` | ECDSA P-384 + ML-DSA-65 | Hybrid | PQC transition |
| `hybrid/composite/timestamping` | IETF Composite | Hybrid | Dual validation |

## OpenSSL Interoperability

### Generate a Request

```bash
openssl ts -query -data document.pdf -sha256 -out request.tsq
```

### Submit to Server

```bash
curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     http://localhost:8318/ -o response.tsr
```

### Verify the Response (ECDSA/RSA only)

```bash
# Display contents
openssl ts -reply -in response.tsr -text

# Verify the token
openssl ts -verify -in response.tsr -data document.pdf -CAfile ca.crt
```

> **Note:** OpenSSL does not support ML-DSA/SLH-DSA. To verify PQC tokens, use `pki tsa verify`.

## Supported Hash Algorithms

| Algorithm | OID | Size | Reference |
|-----------|-----|------|-----------|
| SHA-256 | 2.16.840.1.101.3.4.2.1 | 32 bytes | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| SHA-384 | 2.16.840.1.101.3.4.2.2 | 48 bytes | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| SHA-512 | 2.16.840.1.101.3.4.2.3 | 64 bytes | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| SHA3-256 | 2.16.840.1.101.3.4.2.8 | 32 bytes | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) |
| SHA3-384 | 2.16.840.1.101.3.4.2.9 | 48 bytes | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) |
| SHA3-512 | 2.16.840.1.101.3.4.2.10 | 64 bytes | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) |
| SHAKE256 | 2.16.840.1.101.3.4.2.12 | 32 bytes | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) |

## Signature Algorithms

| Algorithm | OID | Reference |
|-----------|-----|-----------|
| ECDSA P-256 | 1.2.840.10045.4.3.2 | [RFC 5758](https://www.rfc-editor.org/rfc/rfc5758) |
| ECDSA P-384 | 1.2.840.10045.4.3.3 | [RFC 5758](https://www.rfc-editor.org/rfc/rfc5758) |
| ECDSA P-521 | 1.2.840.10045.4.3.4 | [RFC 5758](https://www.rfc-editor.org/rfc/rfc5758) |
| Ed25519 | 1.3.101.112 | [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) |
| RSA-SHA256 | 1.2.840.113549.1.1.11 | [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055) |
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |
| SLH-DSA-128s | 2.16.840.1.101.3.4.3.20 | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) |
| SLH-DSA-256s | 2.16.840.1.101.3.4.3.24 | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) |

## ASN.1 Structures

### TimeStampReq (RFC 3161 §2.4.1)

```asn1
TimeStampReq ::= SEQUENCE {
   version          INTEGER { v1(1) },
   messageImprint   MessageImprint,
   reqPolicy        TSAPolicyId OPTIONAL,
   nonce            INTEGER OPTIONAL,
   certReq          BOOLEAN DEFAULT FALSE,
   extensions       [0] IMPLICIT Extensions OPTIONAL
}

MessageImprint ::= SEQUENCE {
   hashAlgorithm    AlgorithmIdentifier,
   hashedMessage    OCTET STRING
}
```

### TSTInfo (RFC 3161 §2.4.2)

```asn1
TSTInfo ::= SEQUENCE {
   version          INTEGER { v1(1) },
   policy           TSAPolicyId,
   messageImprint   MessageImprint,
   serialNumber     INTEGER,
   genTime          GeneralizedTime,
   accuracy         Accuracy OPTIONAL,
   ordering         BOOLEAN DEFAULT FALSE,
   nonce            INTEGER OPTIONAL,
   tsa              [0] GeneralName OPTIONAL,
   extensions       [1] IMPLICIT Extensions OPTIONAL
}
```

### TimeStampResp (RFC 3161 §2.4.2)

```asn1
TimeStampResp ::= SEQUENCE {
   status           PKIStatusInfo,
   timeStampToken   TimeStampToken OPTIONAL
}

PKIStatusInfo ::= SEQUENCE {
   status        PKIStatus,
   statusString  PKIFreeText OPTIONAL,
   failInfo      PKIFailureInfo OPTIONAL
}
```

## Audit Logging

All TSA operations are logged:

| Event | Description |
|-------|-------------|
| `TSA_SIGN` | Token created in CLI mode |
| `TSA_VERIFY` | Token verified |
| `TSA_REQUEST` | Request received by server |
| `TSA_RESPONSE` | Response sent by server |
| `TSA_SERVE` | Server started |

Example log entry:
```json
{
  "event_type": "TSA_SIGN",
  "timestamp": "2025-01-15T10:30:00Z",
  "actor": {"type": "user", "id": "alice", "host": "workstation"},
  "object": {"type": "token", "serial": "123456", "path": "token.tsr"},
  "context": {"algorithm": "sha256", "policy": "1.3.6.1.4.1.99999.2.1"},
  "result": "success"
}
```

## Use Cases

### Code Signing

```bash
# 1. Sign the code
codesign --sign "Developer ID" myapp.app

# 2. Timestamp the signature
pki tsa sign --data myapp.app/Contents/_CodeSignature/CodeResources \
    --cert tsa.crt --key tsa.key -o myapp.tsr
```

### Legal Archiving

```bash
# Use SLH-DSA for maximum quantum resistance
pki credential enroll --profile slh-dsa/timestamping \
    --var cn=archive-tsa.example.com --id archive-tsa --ca-dir ./ca

# Timestamp documents (using certificates from credential)
for doc in *.pdf; do
    pki tsa sign --data "$doc" --cert archive-tsa.crt --key archive-tsa.key \
        -o "${doc%.pdf}.tsr"
done
```

### Production Timestamping Service

```bash
# Start with HTTPS and audit logging
pki tsa serve --port 443 \
    --cert tsa.crt --key tsa.key \
    --tls-cert server.crt --tls-key server.key \
    --policy "1.3.6.1.4.1.99999.2.1" \
    --accuracy 1 \
    --audit-log /var/log/pki/tsa.log
```
