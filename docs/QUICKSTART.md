# Quick Start Guide

Get your PKI running in 5 minutes.

## 1. Create a Root CA

```bash
pki init-ca --name "My Root CA" --org "My Organization" --dir ./ca
```

This creates a CA directory with:
- `ca.crt` - CA certificate
- `private/ca.key` - CA private key (encrypted)
- `index.txt` - Certificate database

## 2. Issue a TLS Server Certificate

```bash
pki issue --ca-dir ./ca --profile ec/tls-server \
  --cn "server.example.com" \
  --dns server.example.com,www.example.com \
  --out server.crt --key-out server.key
```

## 3. Issue a TLS Client Certificate

```bash
pki issue --ca-dir ./ca --profile ec/tls-client \
  --cn "user@example.com" \
  --out client.crt --key-out client.key
```

## 4. Verify Certificates

```bash
# Verify certificate validity and chain
pki verify --cert server.crt --ca ./ca/ca.crt

# Verify with CRL revocation check
pki verify --cert server.crt --ca ./ca/ca.crt --crl ./ca/crl/ca.crl

# Show certificate details
pki info server.crt

# List all issued certificates
pki list --ca-dir ./ca
```

## 5. Revoke a Certificate

```bash
# Revoke by serial number
pki revoke 02 --ca-dir ./ca --reason keyCompromise

# Generate updated CRL
pki gen-crl --ca-dir ./ca
```

## Common Profiles

| Profile | Use Case |
|---------|----------|
| `ec/tls-server` | HTTPS servers |
| `ec/tls-client` | Client authentication |
| `ec/code-signing` | Sign software |
| `ec/timestamping` | TSA service |
| `ec/ocsp-responder` | OCSP service |

## Post-Quantum (Experimental)

```bash
# Create hybrid CA (ECDSA + ML-DSA)
pki init-ca --name "Hybrid CA" --algorithm ecdsa-p384 \
  --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca

# Issue hybrid certificate
pki issue --ca-dir ./hybrid-ca --profile hybrid/catalyst/tls-server \
  --cn "pqc.example.com" --out pqc.crt --key-out pqc.key
```

## Next Steps

- **[USER_GUIDE](USER_GUIDE.md)** - All CLI commands and options
- **[PROFILES](PROFILES.md)** - Certificate policy templates
- **[PQC](PQC.md)** - Post-quantum cryptography details
- **[OCSP](OCSP.md)** - Real-time revocation checking
- **[TSA](TSA.md)** - Timestamping service
