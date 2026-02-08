---
title: "CRL"
description: "Certificate revocation and CRL management"
---

# CRL

This guide covers certificate revocation and Certificate Revocation List (CRL) operations.

## 1. What is a CRL?

A **Certificate Revocation List (CRL)** is a signed list of revoked certificates published by the CA. Relying parties download the CRL to check if a certificate has been revoked.

### 1.1 CRL Structure in CA Directory

```
ca/
└── crl/
    ├── ca.crl              # PEM format
    └── ca.crl.der          # DER format (for LDAP/HTTP distribution)
```

For multi-profile CAs, each algorithm family has its own CRL:

```
ca/
└── crl/
    ├── ca.ecdsa-p384.crl       # EC-signed CRL
    ├── ca.ecdsa-p384.crl.der
    ├── ca.ml-dsa-87.crl        # ML-DSA-signed CRL
    └── ca.ml-dsa-87.crl.der
```

---

## 2. CLI Commands

### cert revoke

Revoke a certificate.

```bash
qpki cert revoke <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--reason` | `-r` | unspecified | Revocation reason |
| `--gen-crl` | | false | Generate CRL after revocation |
| `--crl-days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |

**Revocation Reasons:**

| Reason | Description |
|--------|-------------|
| unspecified | No specific reason |
| keyCompromise | Private key was compromised |
| caCompromise | CA key was compromised |
| affiliationChanged | Subject's affiliation changed |
| superseded | Replaced by new certificate |
| cessation | Certificate no longer needed |
| hold | Temporary hold |

**Examples:**

```bash
# Revoke by serial number
qpki cert revoke 02 --ca-dir ./myca --reason superseded

qpki cert revoke 02 --ca-dir ./myca --reason keyCompromise --gen-crl

qpki cert revoke 02 --ca-dir ./myca --gen-crl --crl-days 30
```

### crl gen

Generate a Certificate Revocation List.

```bash
qpki crl gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |
| `--algo` | | "" | Algorithm family (ec, ml-dsa, etc.) - multi-profile CA only |
| `--all` | | false | Generate CRLs for all algorithm families |

**Examples:**

```bash
# Generate CRL valid for 7 days
qpki crl gen --ca-dir ./myca

qpki crl gen --ca-dir ./myca --days 30

qpki crl gen --ca-dir ./myca --algo ec

qpki crl gen --ca-dir ./myca --all
```

### crl info

Display detailed information about a Certificate Revocation List.

```bash
qpki crl info <crl-file>
```

**Output includes:**
- Issuer name
- This Update / Next Update timestamps
- Signature algorithm
- CRL Number (if present)
- Authority Key Identifier
- Number of revoked certificates
- Expiry status
- List of revoked serials with revocation date and reason

**Examples:**

```bash
# Display CRL information
qpki crl info ./ca/crl/ca.crl

qpki crl info /path/to/crl.pem
```

### crl verify

Verify the signature of a Certificate Revocation List.

```bash
qpki crl verify <crl-file> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ca` | (required) | CA certificate (PEM) |
| `--check-expiry` | false | Also check if CRL is expired |

**Examples:**

```bash
# Verify CRL signature
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt --check-expiry
```

### crl list

List all CRLs in a CA directory.

```bash
qpki crl list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Output columns:**
- NAME: CRL filename
- THIS UPDATE: When the CRL was generated
- NEXT UPDATE: When the CRL expires
- REVOKED: Number of revoked certificates
- STATUS: valid or EXPIRED

**Example:**

```bash
qpki crl list --ca-dir ./myca
```

---

## 3. Best Practices

### 3.1 CRL Validity Period

| Environment | Recommended Validity |
|-------------|---------------------|
| Development | 7 days |
| Production | 1-7 days |
| High-security | 1 day or less |

Shorter validity periods mean faster revocation propagation but more frequent CRL regeneration.

### 3.2 CRL Distribution

Publish CRLs via:
- HTTP (recommended): `http://crl.example.com/ca.crl`
- LDAP: `ldap://ldap.example.com/cn=CA,dc=example,dc=com?certificateRevocationList`

### 3.3 CRL vs OCSP

| Feature | CRL | OCSP |
|---------|-----|------|
| Freshness | Periodic | Real-time |
| Bandwidth | Higher (full list) | Lower (per-cert) |
| Availability | Cacheable | Requires responder |
| Privacy | Client reveals nothing | Client reveals cert |

For real-time revocation checking, see [OCSP](../services/OCSP.md).

---

## See Also

- [CA](CA.md) - Certificate Authority management
- [Certificates](CERTIFICATES.md) - Certificate issuance and verification
- [OCSP](../services/OCSP.md) - Real-time revocation checking
- [Credentials](../end-entities/CREDENTIALS.md) - Credential lifecycle
