---
title: "Certificates"
description: "Certificate issuance, listing, and verification"
---

# Certificates

This guide covers certificate operations: issuance, listing, inspection, and verification.

## 1. CLI Reference

### cert issue

Issue a certificate from a Certificate Signing Request (CSR).

```bash
qpki cert issue [flags]
```

**Note:** This command requires a CSR file (`--csr`). For direct issuance with automatic key generation, use `qpki credential enroll` instead. See [Credentials](../end-entities/CREDENTIALS.md).

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--profile` | `-P` | required | Certificate profile (e.g., ec/tls-server) |
| `--csr` | | required | CSR file |
| `--cn` | | "" | Override common name from CSR |
| `--dns` | | "" | DNS SANs (comma-separated) |
| `--ip` | | "" | IP SANs (comma-separated) |
| `--out` | `-o` | "" | Output certificate file |
| `--days` | | 0 | Validity period (overrides profile default) |
| `--hybrid` | | "" | PQC algorithm for hybrid extension |
| `--attest-cert` | | "" | Attestation cert for ML-KEM CSR (RFC 9883) |
| `--ca-passphrase` | | "" | CA key passphrase |

**Examples:**

```bash
# From classical CSR (ECDSA, RSA)
qpki cert issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --out server.crt

qpki cert issue --ca-dir ./myca --profile ml/tls-server-sign \
  --csr mldsa.csr --out server.crt

qpki cert issue --ca-dir ./myca --profile ml-kem/client \
  --csr kem.csr --attest-cert sign.crt --out kem.crt

qpki cert issue --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --csr hybrid.csr --out server.crt
```

### cert list

List certificates in a CA.

```bash
qpki cert list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--status` | | all | Filter by status (valid, revoked, expired, all) |

**Examples:**

```bash
# List all certificates
qpki cert list --ca-dir ./myca

qpki cert list --ca-dir ./myca --status valid

qpki cert list --ca-dir ./myca --status revoked
```

### cert info

Display information about a certificate.

```bash
qpki cert info <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki cert info 0x03 --ca-dir ./myca
```

### inspect

Display information about certificates or keys.

```bash
qpki inspect <file> [flags]
```

**Examples:**

```bash
# Show certificate details
qpki inspect certificate.crt

qpki inspect private.key

qpki inspect ./myca/ca.crt
```

### cert verify

Verify a certificate's validity and revocation status.

```bash
qpki cert verify <certificate> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca` | | required | CA certificate (PEM) |
| `--crl` | | | CRL file for revocation check (PEM/DER) |
| `--ocsp` | | | OCSP responder URL |

**Checks performed:**
- Certificate signature (signed by CA)
- Validity period (not before / not after)
- Critical extensions
- Revocation status (if --crl or --ocsp provided)

**Examples:**

```bash
# Basic validation
qpki cert verify server.crt --ca ca.crt

qpki cert verify server.crt --ca ca.crt --crl ca/crl/ca.crl

qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

---

## 2. Certificate Profiles

See [Profiles](PROFILES.md) for the complete list of certificate profiles. Common end-entity profiles:

| Profile | Algorithm | Validity | Description |
|---------|-----------|----------|-------------|
| `ec/tls-server` | EC P-256 | 1 year | TLS server certificate |
| `ec/tls-client` | EC P-256 | 1 year | TLS client certificate |
| `ml/tls-server-sign` | ML-DSA-65 | 1 year | PQC TLS server (signing) |
| `hybrid/catalyst/tls-server` | EC + ML-DSA | 1 year | Hybrid TLS server |

---

## See Also

- [CA](CA.md) - Certificate Authority management
- [CRL](CRL.md) - Certificate revocation and CRL management
- [Credentials](../end-entities/CREDENTIALS.md) - Credential lifecycle
- [Keys & CSR](KEYS.md) - Key generation and CSR operations
- [Profiles](PROFILES.md) - Certificate profile templates
