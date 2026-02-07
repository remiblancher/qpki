---
title: "Troubleshooting Guide"
description: "This guide covers common errors and diagnostic procedures for QPKI."
---

# Troubleshooting Guide

This guide covers common errors and diagnostic procedures for QPKI.

## 1. Common Errors

### 1.1 CA Errors

#### "CA not found" / "CA directory not found"

```
Error: CA not found at ./ca
Error: failed to load CA: directory not found
```

**Cause**: The `--ca-dir` flag points to a non-existent or invalid CA directory.

**Solution**:
```bash
qpki ca list --dir .

qpki cert issue --ca-dir ./myca --profile ec/tls-server --csr request.csr
```

#### "Failed to load CA signer"

```
Error: failed to load CA signer: x509: decryption password incorrect
```

**Cause**: The CA private key is encrypted and the passphrase is wrong or missing.

**Solution**:
```bash
qpki cert issue --ca-dir ./myca --ca-passphrase "correct-password" --profile ec/tls-server --csr request.csr
```

#### "Version not found"

```
Error: version v5 not found
```

**Cause**: Attempting to activate a non-existent CA version.

**Solution**:
```bash
qpki ca versions --ca-dir ./myca

qpki ca activate --ca-dir ./myca --version v2
```

---

### 1.2 Credential Errors

#### "Credential not found"

```
Error: credential alice-xxx not found
```

**Cause**: The `--cred-dir` flag points to wrong directory or credential ID is incorrect.

**Solution**:
```bash
qpki credential list --cred-dir ./credentials

qpki credential info alice-xxx --cred-dir ./myca/credentials
```

#### "KEM profile requires a signature profile first"

```
Error: KEM profile "ml-kem/client" requires a signature profile first (RFC 9883)
```

**Cause**: ML-KEM (encryption) profiles require a signature profile for proof of possession.

**Solution**:
```bash
qpki credential enroll --profile ec/client --profile ml-kem/client \
    --var cn=alice@example.com
```

#### "Credential version is PENDING"

```
Error: cannot use credential - version v2 is PENDING
```

**Cause**: Credential was rotated but not activated.

**Solution**:
```bash
qpki credential activate alice-xxx --version v2
```

---

### 1.3 Profile Errors

#### "Profile not found"

```
Error: profile "ec/custom-server" not found
```

**Cause**: Profile doesn't exist in CA profiles directory or built-in profiles.

**Solution**:
```bash
qpki profile list --dir ./myca

qpki profile install --dir ./myca

qpki credential enroll --profile ec/tls-server --var cn=server.example.com
```

#### "Variable required"

```
Error: variable "cn" is required but not provided
```

**Cause**: Required profile variable was not provided.

**Solution**:
```bash
qpki profile vars ec/tls-server

qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com
```

---

### 1.4 Certificate Errors

#### "Certificate not found"

```
Error: certificate with serial 05 not found
```

**Cause**: Serial number doesn't exist in CA index.

**Solution**:
```bash
qpki cert list --ca-dir ./myca

qpki cert info 0x03 --ca-dir ./myca
```

#### "Certificate verification failed"

```
Error: certificate verification failed: x509: certificate signed by unknown authority
```

**Cause**: CA certificate chain is incomplete or wrong CA used for verification.

**Solution**:
```bash
qpki cert verify server.crt --ca ./issuing-ca/ca.crt

qpki cert verify server.crt --ca ./issuing-ca/chain.crt

openssl verify -CAfile ./root-ca/ca.crt ./issuing-ca/ca.crt
openssl verify -CAfile ./root-ca/ca.crt -untrusted ./issuing-ca/ca.crt server.crt
```

---

### 1.5 CRL/OCSP Errors

#### "CRL is expired"

```
Warning: CRL has expired (Next Update: 2025-01-01)
```

**Cause**: CRL validity period has passed.

**Solution**:
```bash
qpki crl gen --ca-dir ./myca --days 30
```

#### "OCSP responder unreachable"

```
Error: OCSP request failed: connection refused
```

**Cause**: OCSP server is not running or wrong URL.

**Solution**:
```bash
qpki ocsp serve --ca-dir ./myca --listen :8080 &

qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080
```

---

## 2. Diagnostic Commands

### 2.1 CA Diagnostics

```bash
# CA information
qpki ca info --ca-dir ./myca

qpki ca versions --ca-dir ./myca

qpki ca list --dir /var/lib/pki

qpki ca export --ca-dir ./myca --out ca.crt
```

### 2.2 Credential Diagnostics

```bash
# List all credentials
qpki credential list --cred-dir ./credentials

qpki credential info alice-xxx --cred-dir ./credentials

qpki credential versions alice-xxx --cred-dir ./credentials

qpki credential export alice-xxx --cred-dir ./credentials
```

### 2.3 Certificate Diagnostics

```bash
# List certificates in CA
qpki cert list --ca-dir ./myca

qpki cert info 0x03 --ca-dir ./myca

qpki inspect certificate.crt
qpki inspect private.key
qpki inspect request.csr
```

### 2.4 Profile Diagnostics

```bash
# List available profiles
qpki profile list --dir ./myca

qpki profile info ec/tls-server --dir ./myca

qpki profile vars ec/tls-server

qpki profile lint ./my-profile.yaml
```

### 2.5 CRL Diagnostics

```bash
# List CRLs
qpki crl list --ca-dir ./myca

qpki crl info ./myca/crl/ca.crl

qpki crl verify ./myca/crl/ca.crl --ca ./myca/ca.crt
```

---

## 3. OpenSSL Verification

### 3.1 Certificate Verification

```bash
# Verify single certificate
openssl verify -CAfile ca.crt server.crt

openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/ca.crt server.crt

openssl x509 -in server.crt -text -noout

openssl x509 -in server.crt -dates -noout

openssl x509 -in server.crt -subject -issuer -noout
```

### 3.2 Key Verification

```bash
# View key details
openssl ec -in key.pem -text -noout
openssl rsa -in key.pem -text -noout

openssl x509 -in cert.crt -noout -modulus | openssl md5
openssl rsa -in key.pem -noout -modulus | openssl md5
```

### 3.3 CSR Verification

```bash
# View CSR details
openssl req -in request.csr -text -noout

openssl req -in request.csr -verify -noout
```

### 3.4 CRL Verification

```bash
# View CRL details
openssl crl -in ca.crl -text -noout

openssl crl -in ca.crl -CAfile ca.crt -verify
```

---

## 4. HSM/PKCS#11 Issues

### 4.1 Token Not Found

```
Error: PKCS#11: token not found
```

**Causes**:
- HSM/token not connected
- Wrong PKCS#11 library path
- Token not initialized

**Solutions**:
```bash
qpki hsm list --hsm-config ./hsm.yaml

qpki hsm test --hsm-config ./hsm.yaml

```

### 4.2 PIN Incorrect

```
Error: PKCS#11: CKR_PIN_INCORRECT
```

**Solution**: Verify PIN in HSM configuration file.

### 4.3 Slot Unavailable

```
Error: PKCS#11: slot 0 not found
```

**Solution**:
```bash
qpki hsm list --hsm-config ./hsm.yaml

```

---

## 5. File System Issues

### 5.1 Permission Denied

```
Error: open ./ca/ca.key: permission denied
```

**Solution**:
```bash
ls -la ./ca/

chmod 600 ./ca/ca.key
chmod 644 ./ca/ca.crt
```

### 5.2 Directory Structure

Expected CA directory structure:
```
ca/
├── ca.crt           # CA certificate
├── ca.key           # CA private key (protect!)
├── chain.crt        # Certificate chain (if subordinate)
├── serial           # Next serial number
├── index.txt        # Certificate database
├── crl/             # CRL directory
│   └── ca.crl
├── certs/           # Issued certificates
│   ├── 01.pem
│   └── 02.pem
└── profiles/        # Custom profiles (optional)
```

---

## 6. Debug Mode

Enable verbose output for troubleshooting:

```bash
# Run with debug flag
qpki --debug ca info --ca-dir ./myca

cat ./myca/index.txt

cat ./myca/serial
```

---

## 7. Getting Help

### 7.1 Built-in Help

```bash
# General help
qpki --help

qpki ca --help
qpki credential enroll --help
```

### 7.2 Documentation

- [CA](../build-pki/CA.md) - CA operations and certificate issuance
- [Credentials](../end-entities/CREDENTIALS.md) - Credential management
- [Crypto-Agility](../migration/CRYPTO-AGILITY.md) - Algorithm migration
- [Profiles](../build-pki/PROFILES.md) - Certificate profiles
- [HSM](../build-pki/HSM.md) - Hardware Security Module integration
- [OCSP](../services/OCSP.md) - Online Certificate Status Protocol
- [TSA](../services/TSA.md) - Time-Stamp Authority
- [CMS](../services/CMS.md) - Cryptographic Message Syntax

### 7.3 Reporting Issues

Report issues at: https://github.com/remiblancher/post-quantum-pki/issues

Include:
- QPKI version (`qpki version`)
- Operating system
- Full error message
- Command that caused the error
- Relevant configuration (without secrets)
