---
title: "API Examples"
description: "Complete usage scenarios for the QPKI REST API"
---

# Usage Examples

Complete scenarios with curl for common use cases.

## Prerequisites

```bash
# Start the server
qpki serve --port 8443 --ca-dir ./pki

# Variable for examples
API="http://localhost:8443/api/v1"
```

## Complete PKI Setup

### 1. Create a Root CA

```bash
curl -X POST "$API/ca/init" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "pq/root-ca",
    "variables": {
      "cn": "My Root CA",
      "o": "My Organization",
      "c": "US"
    },
    "passphrase": "root-ca-secret",
    "output_dir": "root-ca"
  }' | jq
```

### 2. Create an Intermediate CA

```bash
curl -X POST "$API/ca/init" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "pq/intermediate-ca",
    "variables": {
      "cn": "My Intermediate CA",
      "o": "My Organization"
    },
    "passphrase": "int-ca-secret",
    "parent_ca": "root-ca",
    "parent_passphrase": "root-ca-secret",
    "output_dir": "intermediate-ca"
  }' | jq
```

### 3. Issue a Server Certificate

```bash
# Generate a CSR
curl -X POST "$API/csr/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "ml-dsa-65",
    "subject": {
      "cn": "server.example.com",
      "o": "My Organization"
    },
    "san": {
      "dns_names": ["server.example.com", "www.example.com"]
    },
    "passphrase": "server-key-secret"
  }' > server-csr.json

# Extract the CSR
CSR=$(jq -r '.csr.data' server-csr.json)

# Issue the certificate
curl -X POST "$API/certs/issue" \
  -H "Content-Type: application/json" \
  -d "{
    \"profile\": \"pq/tls-server\",
    \"csr\": {
      \"data\": \"$CSR\",
      \"encoding\": \"base64\"
    },
    \"ca_passphrase\": \"int-ca-secret\",
    \"validity_days\": 365
  }" | jq
```

### 4. Verify the Certificate

```bash
CERT=$(cat server-cert.pem | base64)

curl -X POST "$API/certs/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"certificate\": {
      \"data\": \"$CERT\",
      \"encoding\": \"base64\"
    },
    \"check_revocation\": true
  }" | jq
```

---

## CMS Signatures

### Sign a Document

```bash
# Create a signing credential
curl -X POST "$API/credentials/enroll" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "pq/document-signer",
    "variables": {
      "cn": "Document Signer",
      "email": "signer@example.com"
    },
    "passphrase": "signer-secret",
    "ca_passphrase": "int-ca-secret"
  }' | jq '.id' -r > signer-id.txt

# Sign the document
DOCUMENT=$(echo "Hello World" | base64)
SIGNER_ID=$(cat signer-id.txt)

curl -X POST "$API/cms/sign" \
  -H "Content-Type: application/json" \
  -d "{
    \"data\": {
      \"data\": \"$DOCUMENT\",
      \"encoding\": \"base64\"
    },
    \"credential_id\": \"$SIGNER_ID\",
    \"passphrase\": \"signer-secret\",
    \"include_chain\": true
  }" | jq '.signed_data.data' -r | base64 -d > document.p7m
```

### Verify a Signature

```bash
SIGNED=$(cat document.p7m | base64)

curl -X POST "$API/cms/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"signed_data\": {
      \"data\": \"$SIGNED\",
      \"encoding\": \"base64\"
    }
  }" | jq
```

---

## Timestamping (TSA)

### Timestamp a Document

```bash
# Hash the document
HASH=$(sha256sum document.pdf | cut -d' ' -f1 | xxd -r -p | base64)

curl -X POST "$API/tsa/sign" \
  -H "Content-Type: application/json" \
  -d "{
    \"data\": {
      \"data\": \"$HASH\",
      \"encoding\": \"base64\"
    },
    \"hash_algorithm\": \"sha256\",
    \"credential_id\": \"tsa-credential\",
    \"passphrase\": \"tsa-secret\"
  }" | jq '.token.data' -r | base64 -d > document.tsr
```

### Verify a Timestamp

```bash
TOKEN=$(cat document.tsr | base64)
HASH=$(sha256sum document.pdf | cut -d' ' -f1 | xxd -r -p | base64)

curl -X POST "$API/tsa/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": {
      \"data\": \"$TOKEN\",
      \"encoding\": \"base64\"
    },
    \"data\": {
      \"data\": \"$HASH\",
      \"encoding\": \"base64\"
    }
  }" | jq
```

---

## OCSP

### Check Certificate Status

```bash
curl -X POST "$API/ocsp/query" \
  -H "Content-Type: application/json" \
  -d '{
    "serial": "02",
    "ca_id": "intermediate-ca",
    "ca_passphrase": "int-ca-secret"
  }' | jq
```

### Use RFC 6960 Endpoint

```bash
# Create an OCSP request with OpenSSL
openssl ocsp -issuer ca.crt -cert server.crt -url http://localhost:8443/ocsp
```

---

## COSE/CWT

### Issue a CWT Token

```bash
curl -X POST "$API/cwt/issue" \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "token-issuer",
    "passphrase": "issuer-secret",
    "claims": {
      "iss": "https://issuer.example.com",
      "sub": "user123",
      "aud": "https://api.example.com",
      "exp": 1735689600,
      "custom": {
        "role": "admin",
        "permissions": ["read", "write"]
      }
    }
  }' | jq '.cwt.data' -r | base64 -d > token.cwt
```

### Verify a CWT Token

```bash
TOKEN=$(cat token.cwt | base64)

curl -X POST "$API/cwt/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"cwt\": {
      \"data\": \"$TOKEN\",
      \"encoding\": \"base64\"
    }
  }" | jq
```

---

## Lifecycle Management

### CA Key Rotation

```bash
# Check current versions
curl "$API/ca/root-ca" | jq '.versions'

# Perform rotation
curl -X POST "$API/ca/root-ca/rotate" \
  -H "Content-Type: application/json" \
  -d '{
    "passphrase": "root-ca-secret",
    "new_passphrase": "new-root-ca-secret",
    "algorithms": ["ml-dsa-87"]
  }' | jq

# Activate the new version
curl -X POST "$API/ca/root-ca/activate" \
  -H "Content-Type: application/json" \
  -d '{"version": 2}' | jq
```

### Certificate Revocation

```bash
# Revoke
curl -X POST "$API/certs/02/revoke" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "keyCompromise",
    "ca_passphrase": "int-ca-secret"
  }' | jq

# Generate a new CRL
curl -X POST "$API/crl/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "intermediate-ca",
    "ca_passphrase": "int-ca-secret",
    "validity_days": 7
  }' | jq
```

---

## Automation Scripts

### Bash: Automatic Renewal

```bash
#!/bin/bash
API="http://localhost:8443/api/v1"
CRED_ID="server-credential"
THRESHOLD_DAYS=30

# Check expiration
EXPIRES=$(curl -s "$API/credentials/$CRED_ID" | jq -r '.validity.not_after')
EXPIRES_TS=$(date -d "$EXPIRES" +%s)
NOW_TS=$(date +%s)
DAYS_LEFT=$(( (EXPIRES_TS - NOW_TS) / 86400 ))

if [ $DAYS_LEFT -lt $THRESHOLD_DAYS ]; then
  echo "Credential expires in $DAYS_LEFT days, rotating..."

  curl -X POST "$API/credentials/$CRED_ID/rotate" \
    -H "Content-Type: application/json" \
    -d '{
      "passphrase": "current-secret",
      "new_passphrase": "new-secret",
      "ca_passphrase": "ca-secret"
    }'

  echo "Rotation complete"
else
  echo "Credential valid for $DAYS_LEFT days"
fi
```

### Python: API Client

```python
import requests
import base64

class QPKIClient:
    def __init__(self, base_url="http://localhost:8443/api/v1"):
        self.base_url = base_url

    def init_ca(self, profile, cn, passphrase):
        return requests.post(f"{self.base_url}/ca/init", json={
            "profile": profile,
            "variables": {"cn": cn},
            "passphrase": passphrase
        }).json()

    def issue_cert(self, profile, csr_pem, ca_passphrase):
        return requests.post(f"{self.base_url}/certs/issue", json={
            "profile": profile,
            "csr": {"data": csr_pem, "encoding": "pem"},
            "ca_passphrase": ca_passphrase
        }).json()

    def sign_cms(self, data, credential_id, passphrase):
        b64_data = base64.b64encode(data).decode()
        return requests.post(f"{self.base_url}/cms/sign", json={
            "data": {"data": b64_data, "encoding": "base64"},
            "credential_id": credential_id,
            "passphrase": passphrase
        }).json()

# Usage
client = QPKIClient()
ca = client.init_ca("pq/root-ca", "My CA", "secret")
print(f"CA created: {ca['id']}")
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Issue TLS Certificate

on:
  workflow_dispatch:
    inputs:
      domain:
        description: 'Domain name'
        required: true

jobs:
  issue-cert:
    runs-on: ubuntu-latest
    steps:
      - name: Generate CSR
        run: |
          curl -X POST "${{ secrets.QPKI_API }}/csr/generate" \
            -H "Content-Type: application/json" \
            -d '{
              "algorithm": "ml-dsa-65",
              "subject": {"cn": "${{ inputs.domain }}"},
              "san": {"dns_names": ["${{ inputs.domain }}"]}
            }' > csr.json

      - name: Issue Certificate
        run: |
          CSR=$(jq -r '.csr.data' csr.json)
          curl -X POST "${{ secrets.QPKI_API }}/certs/issue" \
            -H "Content-Type: application/json" \
            -d "{
              \"profile\": \"pq/tls-server\",
              \"csr\": {\"data\": \"$CSR\", \"encoding\": \"base64\"},
              \"ca_passphrase\": \"${{ secrets.CA_PASSPHRASE }}\"
            }" > cert.json

      - name: Upload Certificate
        uses: actions/upload-artifact@v3
        with:
          name: certificate
          path: cert.json
```

### Terraform Provider (concept)

```hcl
resource "qpki_certificate" "web_server" {
  profile = "pq/tls-server"

  subject {
    common_name  = "web.example.com"
    organization = "Example Corp"
  }

  san {
    dns_names = ["web.example.com", "www.example.com"]
  }

  validity_days = 365
}

output "certificate_pem" {
  value = qpki_certificate.web_server.certificate_pem
}
```
