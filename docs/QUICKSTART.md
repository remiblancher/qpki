# Quick Start Guide

Get your PKI running in 5 minutes.

## 1. Create a Root CA

```bash
# Using a profile (recommended)
pki ca init --name "My Root CA" --profile ec/root-ca --dir ./ca

# Or with manual configuration
pki ca init --name "My Root CA" --org "My Organization" --dir ./ca
```

This creates a CA directory with:
- `ca.crt` - CA certificate
- `private/ca.key` - CA private key
- `index.txt` - Certificate database

## 2. Issue a TLS Server Certificate

```bash
# Using credential enroll (generates key + certificate)
pki credential enroll --ca-dir ./ca --profile ec/tls-server \
  --var cn=server.example.com \
  --var dns_names=server.example.com,www.example.com

# Or using CSR workflow
pki cert csr --algorithm ecdsa-p256 --keyout server.key \
  --cn server.example.com --dns server.example.com -o server.csr
pki cert issue --ca-dir ./ca --profile ec/tls-server --csr server.csr --out server.crt
```

## 3. Issue a TLS Client Certificate

```bash
pki credential enroll --ca-dir ./ca --profile ec/tls-client \
  --var cn=user@example.com --var email=user@example.com
```

## 4. Verify Certificates

```bash
# Verify certificate validity and chain
pki verify --cert server.crt --ca ./ca/ca.crt

# Verify with CRL revocation check
pki verify --cert server.crt --ca ./ca/ca.crt --crl ./ca/crl/ca.crl

# Show certificate details
pki inspect server.crt

# List all issued certificates
pki cert list --ca-dir ./ca
```

## 5. Revoke a Certificate

```bash
# Revoke by serial number
pki cert revoke 02 --ca-dir ./ca --reason keyCompromise

# Generate updated CRL
pki cert gen-crl --ca-dir ./ca
```

## Common Profiles

**CA Profiles:**

| Profile | Use Case |
|---------|----------|
| `ec/root-ca` | Root CA (EC P-384, 20 years) |
| `ec/issuing-ca` | Issuing CA (EC P-256, 10 years) |
| `hybrid/catalyst/root-ca` | Hybrid root CA (EC + ML-DSA) |

**Certificate Profiles:**

| Profile | Use Case |
|---------|----------|
| `ec/tls-server` | HTTPS servers |
| `ec/tls-client` | Client authentication |
| `ec/code-signing` | Sign software |
| `ec/timestamping` | TSA service |
| `ec/ocsp-responder` | OCSP service |

## Post-Quantum (Experimental)

```bash
# Create hybrid CA using profile
pki ca init --name "Hybrid CA" --profile hybrid/catalyst/root-ca --dir ./hybrid-ca

# Issue hybrid certificate using credential enroll
pki credential enroll --ca-dir ./hybrid-ca --profile hybrid/catalyst/tls-server \
  --var cn=pqc.example.com --var dns_names=pqc.example.com
```

## Next Steps

- **[USER_GUIDE](USER_GUIDE.md)** - All CLI commands and options
- **[PROFILES](PROFILES.md)** - Certificate policy templates
- **[PQC](PQC.md)** - Post-quantum cryptography details
- **[OCSP](OCSP.md)** - Real-time revocation checking
- **[TSA](TSA.md)** - Timestamping service
