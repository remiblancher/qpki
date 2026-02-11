---
title: "Feature Test Coverage"
description: "Test coverage by feature for QPKI."
generated: true
---

# Feature Test Coverage

> **Note**: This file is auto-generated from `specs/tests/feature-coverage.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document tracks test coverage by feature, identifying what is tested and what gaps exist.

## Summary

| Metric | Value |
|--------|-------|
| Total Features | 17 |
| Covered | 7 |
| Partial | 8 |
| **Gap** | **2** |
| Last Updated | 2026-02-11 |

## Coverage Matrix

| Feature | Status | Tests | Gaps |
|---------|--------|-------|------|
| Post-Quantum Algorithms | covered | 3 | 0 |
| Classical Algorithms | covered | 2 | 0 |
| Hybrid Certificates | partial | 2 | 2 |
| Crypto Agility | partial | 2 | 2 |
| OCSP Responder | partial | 1 | 2 |
| Timestamp Authority | partial | 1 | 2 |
| CMS SignedData | partial | 2 | 2 |
| CMS EnvelopedData | partial | 1 | 2 |
| COSE/CWT | partial | 1 | 2 |
| HSM Support | partial | 1 | 4 |
| Certificate Profiles | covered | 8 | 0 |
| Credential Management | covered | 7 | 0 |
| Certificate Verification | covered | 7 | 0 |
| Custom X.509 Extensions | covered | 8 | 0 |
| Audit Logging | covered | 1 | 0 |
| OpenSSL Interoperability | gap | 0 | 2 |
| BouncyCastle Interoperability | gap | 0 | 3 |


## Feature Details

### Post-Quantum Algorithms

**ID**: `pqc-algorithms`

**Status**: covered

NIST FIPS 203/204/205 algorithm support

**Tests**:
- `TestU_Key_Generate_* (all PQC algorithms)`
- `TestF_CA_Initialize_MLDSA*`
- `TestF_CMS_Sign_MLDSA*`

**Gaps**:


---

### Classical Algorithms

**ID**: `classical-algorithms`

**Status**: covered

ECDSA, RSA, Ed25519 support

**Tests**:
- `TestU_Key_Generate_ECDSA`
- `TestF_CA_Initialize_ECDSA`

**Gaps**:


---

### Hybrid Certificates

**ID**: `hybrid-certificates`

**Status**: partial

Catalyst and Composite hybrid certificates

**Tests**:
- `TestF_Hybrid_* (internal tests)`
- `TestA_Credential_Export_Chain_HybridCA`

**Gaps**:
- Composite cross-validation with BouncyCastle (OID mismatch)
- No acceptance tests for hybrid CA initialization

---

### Crypto Agility

**ID**: `crypto-agility`

**Status**: partial

Algorithm migration and CA rotation

**Tests**:
- `TestCrossSign_* (cross-signing during rotation)`
- `TestF_CA_Rotate_*`

**Gaps**:
- No acceptance tests for CA rotation via CLI
- Algorithm migration path not fully tested

---

### OCSP Responder

**ID**: `ocsp`

**Status**: partial

Online Certificate Status Protocol

**Tests**:
- `TestF_OCSP_* (internal tests)`

**Gaps**:
- No acceptance tests for OCSP server
- OCSP with PQC algorithms cross-validation needed

---

### Timestamp Authority

**ID**: `tsa`

**Status**: partial

RFC 3161 timestamping

**Tests**:
- `TestF_TSA_* (internal tests)`

**Gaps**:
- No acceptance tests for TSA CLI
- TSA with PQC algorithms cross-validation needed

---

### CMS SignedData

**ID**: `cms-signed`

**Status**: partial

RFC 5652 signed messages

**Tests**:
- `TestF_CMS_Sign_* (internal tests)`
- `FuzzCMSParser`

**Gaps**:
- No acceptance tests for CMS sign/verify CLI
- Cross-validation with OpenSSL/BC needed

---

### CMS EnvelopedData

**ID**: `cms-enveloped`

**Status**: partial

RFC 5652 encrypted messages with ML-KEM

**Tests**:
- `TestF_CMS_Encrypt_* (internal tests)`

**Gaps**:
- No acceptance tests for CMS encrypt/decrypt CLI
- Cross-validation with OpenSSL/BC needed

---

### COSE/CWT

**ID**: `cose`

**Status**: partial

CBOR Object Signing and Encryption

**Tests**:
- `TestU_COSE_* (unit tests)`

**Gaps**:
- No acceptance tests for COSE CLI
- COSE with PQC algorithms limited testing

---

### HSM Support

**ID**: `hsm`

**Status**: partial

PKCS#11 hardware security module integration

**Tests**:
- `TestF_HSM_* (with SoftHSM mock)`

**Gaps**:
- No acceptance tests for HSM CLI commands
- HSM key import not tested
- HSM CA rotation not tested
- Real HSM integration testing not automated

---

### Certificate Profiles

**ID**: `profiles`

**Status**: covered

YAML-based certificate profile system

**Tests**:
- `TestU_Profile_* (parsing tests)`
- `TestF_Profile_List`
- `TestF_Profile_Info*`
- `TestF_Profile_Show`
- `TestF_Profile_Lint*`
- `TestF_Profile_Export*`
- `TestF_Profile_Install*`
- `FuzzProfileParser`

**Gaps**:


---

### Credential Management

**ID**: `credential-management`

**Status**: covered

End-entity credential lifecycle management

**Tests**:
- `TestF_Credential_Enroll`
- `TestF_Credential_List*`
- `TestF_Credential_Info*`
- `TestF_Credential_Rotate*`
- `TestF_Credential_Revoke*`
- `TestF_Credential_Export*`
- `TestF_Credential_Versions*`

**Gaps**:


---

### Certificate Verification

**ID**: `certificate-verification`

**Status**: covered

Certificate chain validation and revocation checking

**Tests**:
- `TestF_Verify_ValidCertificate`
- `TestF_Verify_SubordinateCA`
- `TestF_Verify_WithCRL`
- `TestF_Verify_RevokedCertificate`
- `TestF_VerifyCatalystSignatures*`
- `TestF_VerifyCompositeCRL*`
- `TestF_VerifyPQCCertificateRaw*`

**Gaps**:


---

### Custom X.509 Extensions

**ID**: `custom-extensions`

**Status**: covered

User-defined X.509 extensions via profile YAML

**Tests**:
- `TestU_CustomExtension_ToExtension_Hex`
- `TestU_CustomExtension_ToExtension_Base64`
- `TestU_CustomExtension_Validate_*`
- `TestU_CustomExtension_RealASN1_*`
- `TestU_CustomExtension_InCertificate`
- `TestU_CustomExtension_LoadFromYAML`
- `TestU_CustomExtension_MultipleInCertificate`
- `TestU_CustomExtension_CriticalFlagInCertificate`

**Gaps**:


---

### Audit Logging

**ID**: `audit-logging`

**Status**: covered

Security audit trail

**Tests**:
- `TestU_Audit_* (comprehensive)`

**Gaps**:


---

### OpenSSL Interoperability

**ID**: `openssl-interop`

**Status**: gap

Cross-validation with OpenSSL 3.6+

**Tests**:


**Gaps**:
- No automated TestC_OpenSSL_* tests
- Manual validation only

---

### BouncyCastle Interoperability

**ID**: `bouncycastle-interop`

**Status**: gap

Cross-validation with BouncyCastle 1.83+

**Tests**:


**Gaps**:
- No automated TestC_BouncyCastle_* tests
- Manual validation only
- Composite OID mismatch (draft-07 vs draft-13)

---


## Gap Summary

Features requiring immediate attention:

- **OpenSSL Interoperability**: No automated TestC_OpenSSL_* tests; Manual validation only
- **BouncyCastle Interoperability**: No automated TestC_BouncyCastle_* tests; Manual validation only; Composite OID mismatch (draft-07 vs draft-13)

Features with partial coverage:

- **Hybrid Certificates**: Composite cross-validation with BouncyCastle (OID mismatch); No acceptance tests for hybrid CA initialization
- **Crypto Agility**: No acceptance tests for CA rotation via CLI; Algorithm migration path not fully tested
- **OCSP Responder**: No acceptance tests for OCSP server; OCSP with PQC algorithms cross-validation needed
- **Timestamp Authority**: No acceptance tests for TSA CLI; TSA with PQC algorithms cross-validation needed
- **CMS SignedData**: No acceptance tests for CMS sign/verify CLI; Cross-validation with OpenSSL/BC needed
- **CMS EnvelopedData**: No acceptance tests for CMS encrypt/decrypt CLI; Cross-validation with OpenSSL/BC needed
- **COSE/CWT**: No acceptance tests for COSE CLI; COSE with PQC algorithms limited testing
- **HSM Support**: No acceptance tests for HSM CLI commands; HSM key import not tested; HSM CA rotation not tested; Real HSM integration testing not automated

## See Also

- [CLI Coverage](CLI-COVERAGE.md) - CLI command test coverage
- [Test Strategy](STRATEGY.md) - Testing philosophy
- [specs/tests/feature-coverage.yaml](../../../specs/tests/feature-coverage.yaml) - Source data
