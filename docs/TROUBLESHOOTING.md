# Troubleshooting Guide

## Table of Contents

- [1. Common Errors](#1-common-errors)
- [2. Diagnostic Commands](#2-diagnostic-commands)
- [3. OpenSSL Verification](#3-openssl-verification)
- [4. HSM/PKCS#11 Issues](#4-hsmpkcs11-issues)
- [5. File System Issues](#5-file-system-issues)
- [6. Debug Mode](#6-debug-mode)
- [7. Getting Help](#7-getting-help)

---

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
# List CAs in current directory
qpki ca list --dir .

# Specify correct CA directory
qpki cert issue --ca-dir ./myca --profile ec/tls-server --csr request.csr
```

#### "Failed to load CA signer"

```
Error: failed to load CA signer: x509: decryption password incorrect
```

**Cause**: The CA private key is encrypted and the passphrase is wrong or missing.

**Solution**:
```bash
# Provide correct passphrase
qpki cert issue --ca-dir ./myca --ca-passphrase "correct-password" --profile ec/tls-server --csr request.csr
```

#### "Version not found"

```
Error: version v5 not found
```

**Cause**: Attempting to activate a non-existent CA version.

**Solution**:
```bash
# List available versions
qpki ca versions --ca-dir ./myca

# Activate existing version
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
# List credentials in directory
qpki credential list --cred-dir ./credentials

# Use correct directory
qpki credential info alice-xxx --cred-dir ./myca/credentials
```

#### "KEM profile requires a signature profile first"

```
Error: KEM profile "ml-kem/client" requires a signature profile first (RFC 9883)
```

**Cause**: ML-KEM (encryption) profiles require a signature profile for proof of possession.

**Solution**:
```bash
# Correct: signature profile before KEM profile
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
# Activate the pending version
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
# List available profiles
qpki profile list --dir ./myca

# Install default profiles
qpki profile install --dir ./myca

# Or use a built-in profile
qpki credential enroll --profile ec/tls-server --var cn=server.example.com
```

#### "Variable required"

```
Error: variable "cn" is required but not provided
```

**Cause**: Required profile variable was not provided.

**Solution**:
```bash
# List profile variables
qpki profile vars ec/tls-server

# Provide required variables
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
# List certificates in CA
qpki cert list --ca-dir ./myca

# Use correct serial (hex format)
qpki cert info 0x03 --ca-dir ./myca
```

#### "Certificate verification failed"

```
Error: certificate verification failed: x509: certificate signed by unknown authority
```

**Cause**: CA certificate chain is incomplete or wrong CA used for verification.

**Solution**:
```bash
# Verify with correct CA
qpki cert verify server.crt --ca ./issuing-ca/ca.crt

# For subordinate CA, use chain
qpki cert verify server.crt --ca ./issuing-ca/chain.crt

# Or verify step by step
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
# Regenerate CRL
qpki crl gen --ca-dir ./myca --days 30
```

#### "OCSP responder unreachable"

```
Error: OCSP request failed: connection refused
```

**Cause**: OCSP server is not running or wrong URL.

**Solution**:
```bash
# Start OCSP server
qpki ocsp serve --ca-dir ./myca --listen :8080 &

# Verify with correct URL
qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080
```

---

## 2. Diagnostic Commands

### 2.1 CA Diagnostics

```bash
# CA information
qpki ca info --ca-dir ./myca

# List CA versions
qpki ca versions --ca-dir ./myca

# List CAs in directory
qpki ca list --dir /var/lib/pki

# Export CA certificate
qpki ca export --ca-dir ./myca --out ca.crt
```

### 2.2 Credential Diagnostics

```bash
# List all credentials
qpki credential list --cred-dir ./credentials

# Credential details
qpki credential info alice-xxx --cred-dir ./credentials

# Credential versions
qpki credential versions alice-xxx --cred-dir ./credentials

# Export certificates
qpki credential export alice-xxx --cred-dir ./credentials
```

### 2.3 Certificate Diagnostics

```bash
# List certificates in CA
qpki cert list --ca-dir ./myca

# Certificate details
qpki cert info 0x03 --ca-dir ./myca

# Inspect any file
qpki inspect certificate.crt
qpki inspect private.key
qpki inspect request.csr
```

### 2.4 Profile Diagnostics

```bash
# List available profiles
qpki profile list --dir ./myca

# Profile details
qpki profile info ec/tls-server --dir ./myca

# Profile variables
qpki profile vars ec/tls-server

# Validate custom profile
qpki profile lint ./my-profile.yaml
```

### 2.5 CRL Diagnostics

```bash
# List CRLs
qpki crl list --ca-dir ./myca

# CRL details
qpki crl info ./myca/crl/ca.crl

# Verify CRL signature
qpki crl verify ./myca/crl/ca.crl --ca ./myca/ca.crt
```

---

## 3. OpenSSL Verification

### 3.1 Certificate Verification

```bash
# Verify single certificate
openssl verify -CAfile ca.crt server.crt

# Verify certificate chain
openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/ca.crt server.crt

# View certificate details
openssl x509 -in server.crt -text -noout

# Check certificate dates
openssl x509 -in server.crt -dates -noout

# Check certificate subject/issuer
openssl x509 -in server.crt -subject -issuer -noout
```

### 3.2 Key Verification

```bash
# View key details
openssl ec -in key.pem -text -noout
openssl rsa -in key.pem -text -noout

# Verify key matches certificate
openssl x509 -in cert.crt -noout -modulus | openssl md5
openssl rsa -in key.pem -noout -modulus | openssl md5
```

### 3.3 CSR Verification

```bash
# View CSR details
openssl req -in request.csr -text -noout

# Verify CSR signature
openssl req -in request.csr -verify -noout
```

### 3.4 CRL Verification

```bash
# View CRL details
openssl crl -in ca.crl -text -noout

# Verify CRL signature
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
# List available tokens
qpki hsm list --hsm-config ./hsm.yaml

# Test HSM connectivity
qpki hsm test --hsm-config ./hsm.yaml

# Verify PKCS#11 library path in hsm.yaml
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
# List available slots
qpki hsm list --hsm-config ./hsm.yaml

# Update slot number in hsm.yaml
```

---

## 5. File System Issues

### 5.1 Permission Denied

```
Error: open ./ca/ca.key: permission denied
```

**Solution**:
```bash
# Check file permissions
ls -la ./ca/

# Fix permissions (careful with private keys)
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

# Check CA index file
cat ./myca/index.txt

# Check serial number
cat ./myca/serial
```

---

## 7. Getting Help

### 7.1 Built-in Help

```bash
# General help
qpki --help

# Command-specific help
qpki ca --help
qpki credential enroll --help
```

### 7.2 Documentation

- [CA](CA.md) - CA operations and certificate issuance
- [CREDENTIALS](CREDENTIALS.md) - Credential management
- [CRYPTO-AGILITY](CRYPTO-AGILITY.md) - Algorithm migration
- [PROFILES](PROFILES.md) - Certificate profiles
- [HSM](HSM.md) - Hardware Security Module integration
- [OCSP](OCSP.md) - Online Certificate Status Protocol
- [TSA](TSA.md) - Time-Stamp Authority
- [CMS](CMS.md) - Cryptographic Message Syntax

### 7.3 Reporting Issues

Report issues at: https://github.com/remiblancher/post-quantum-pki/issues

Include:
- QPKI version (`qpki version`)
- Operating system
- Full error message
- Command that caused the error
- Relevant configuration (without secrets)
