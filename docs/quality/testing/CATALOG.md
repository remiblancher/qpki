---
title: "Test Catalog"
description: "Exhaustive list of QPKI test cases following ISO/IEC 29119-3."
generated: true
---

# QPKI Test Catalog

> **Note**: This file is auto-generated from `specs/tests/test-catalog.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This catalog documents all test cases following ISO/IEC 29119-3 Test Documentation standard.

## TC-ID Format

```
TC-<TYPE>-<DOMAIN>-<SEQ>

TYPE:   U (Unit), F (Functional), A (Acceptance), C (Crossval), Z (fuZz)
DOMAIN: KEY, CA, CERT, CRL, EXT, CRED, PROFILE, LIST, REVOKE, INFO, VERIFY, OCSP, TSA, CMS, HSM
SEQ:    001-999
```

## Summary

| Metric | Value |
|--------|-------|
| Test Types | 5 (U, F, A, C, Z) |
| Domains | 15 |
| Last Updated | 2026-02-11 |

---

## Unit Tests (TC-U-*)

Unit tests validate individual functions in isolation.

### TC-U-KEY - Key Generation

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-U-KEY-001 | ECDSA P-256 key generation | `TestU_Key_Generate_ECDSA_P256` | FIPS 186-5 |
| TC-U-KEY-002 | ECDSA P-384 key generation | `TestU_Key_Generate_ECDSA_P384` | FIPS 186-5 |
| TC-U-KEY-003 | ML-DSA-44 key generation | `TestU_Key_Generate_MLDSA44` | FIPS 204 |
| TC-U-KEY-004 | ML-DSA-65 key generation | `TestU_Key_Generate_MLDSA65` | FIPS 204 |
| TC-U-KEY-005 | ML-DSA-87 key generation | `TestU_Key_Generate_MLDSA87` | FIPS 204 |
| TC-U-KEY-006 | SLH-DSA-128f key generation | `TestU_Key_Generate_SLHDSA` | FIPS 205 |
| TC-U-KEY-007 | ML-KEM-768 key generation | `TestU_Key_Generate_MLKEM768` | FIPS 203 |

### TC-U-EXT - X.509 Extensions

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-U-EXT-001 | Custom extension hex value | `TestU_CustomExtension_ToExtension_Hex` | X.509 |
| TC-U-EXT-002 | Custom extension base64 value | `TestU_CustomExtension_ToExtension_Base64` | X.509 |
| TC-U-EXT-003 | Custom extension validation | `TestU_CustomExtension_Validate_*` | X.509 |
| TC-U-EXT-004 | Custom extension in certificate | `TestU_CustomExtension_RealASN1_InCertificate` | X.509 |
| TC-U-EXT-005 | Custom extension YAML loading | `TestU_CustomExtension_LoadFromYAML` | Profile |
| TC-U-EXT-006 | Custom extension ASN.1 encoding | `TestU_CustomExtension_RealASN1_*` | X.509, ASN.1 |
| TC-U-EXT-007 | Multiple custom extensions | `TestU_CustomExtension_MultipleInCertificate` | X.509 |
| TC-U-EXT-008 | Custom extension critical flag | `TestU_CustomExtension_CriticalFlagInCertificate` | X.509 |

---

## Functional Tests (TC-F-*)

Functional tests validate internal workflows and APIs.

### TC-F-CA - Certificate Authority

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CA-001 | ECDSA CA initialization | `TestF_CA_Initialize_ECDSA` | RFC 5280 |
| TC-F-CA-002 | ML-DSA-65 CA initialization | `TestF_CA_Initialize_MLDSA65` | RFC 5280, FIPS 204 |
| TC-F-CA-003 | Catalyst hybrid CA | `TestF_CA_Initialize_Catalyst` | ITU-T X.509 9.8 |
| TC-F-CA-004 | Composite hybrid CA | `TestF_CA_Initialize_Composite` | IETF draft-13 |
| TC-F-CA-005 | SLH-DSA CA initialization | `TestF_SLHDSACA_Initialize` | RFC 5280, FIPS 205 |

### TC-F-CERT - Certificate Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CERT-001 | ECDSA certificate from CSR | `TestF_Cert_Issue_ECDSA` | RFC 5280, RFC 2986 |
| TC-F-CERT-002 | ML-DSA certificate issuance | `TestF_Cert_Issue_MLDSA` | RFC 5280, FIPS 204 |
| TC-F-CERT-003 | ML-KEM certificate | `TestF_Cert_Issue_MLKEM` | RFC 9883 |
| TC-F-CERT-004 | SLH-DSA certificate from CSR | `TestF_IssueFromSLHDSACSR` | RFC 5280, RFC 2986, FIPS 205 |
| TC-F-CERT-005 | SLH-DSA certificate issuance | `TestF_SLHDSACA_IssueCertificate` | RFC 5280, FIPS 205 |

### TC-F-CRL - CRL Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CRL-001 | ECDSA CRL generation | `TestF_CRL_Generate_ECDSA` | RFC 5280 |
| TC-F-CRL-002 | ML-DSA CRL generation | `TestF_CRL_Generate_MLDSA` | RFC 5280, FIPS 204 |

### TC-F-OCSP - OCSP Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-OCSP-001 | ECDSA OCSP response | `TestF_OCSP_Response_ECDSA` | RFC 6960 |
| TC-F-OCSP-002 | ML-DSA OCSP response | `TestF_OCSP_Response_MLDSA` | RFC 6960, FIPS 204 |

### TC-F-TSA - TSA Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-TSA-001 | ECDSA timestamp | `TestF_TSA_Timestamp_ECDSA` | RFC 3161 |
| TC-F-TSA-002 | ML-DSA timestamp | `TestF_TSA_Timestamp_MLDSA` | RFC 3161, FIPS 204 |
| TC-F-TSA-003 | SLH-DSA timestamp | `TestF_Token_SLHDSAAlgorithms` | RFC 3161, FIPS 205 |

### TC-F-CMS - CMS Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CMS-001 | ECDSA CMS SignedData | `TestF_CMS_Sign_ECDSA` | RFC 5652 |
| TC-F-CMS-002 | ML-DSA CMS SignedData | `TestF_CMS_Sign_MLDSA` | RFC 5652, RFC 9882 |
| TC-F-CMS-003 | ML-KEM CMS EnvelopedData | `TestF_CMS_Encrypt_MLKEM` | RFC 5652, FIPS 203 |
| TC-F-CMS-004 | SLH-DSA CMS SignedData fast | `TestF_Sign_SLHDSA_FastVariants` | RFC 5652, RFC 9814, FIPS 205 |
| TC-F-CMS-005 | SLH-DSA CMS RFC 9814 SHA2 | `TestF_RFC9814_SLHDSA_SHA2_AllVariants` | RFC 5652, RFC 9814, FIPS 205 |
| TC-F-CMS-006 | SLH-DSA CMS RFC 9814 SHAKE | `TestF_RFC9814_SLHDSA_SHAKE_AllVariants` | RFC 5652, RFC 9814, FIPS 205 |

### TC-F-CRED - Credential Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CRED-001 | Credential enrollment | `TestF_Credential_Enroll` | RFC 5280 |
| TC-F-CRED-002 | Credential list | `TestF_Credential_List*` | - |
| TC-F-CRED-003 | Credential info | `TestF_Credential_Info*` | - |
| TC-F-CRED-004 | Credential rotation | `TestF_Credential_Rotate*` | - |
| TC-F-CRED-005 | Credential revocation | `TestF_Credential_Revoke*` | RFC 5280 |
| TC-F-CRED-006 | Credential export | `TestF_Credential_Export*` | - |

### TC-F-PROFILE - Profile Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-PROFILE-001 | Profile list | `TestF_Profile_List` | - |
| TC-F-PROFILE-002 | Profile info | `TestF_Profile_Info*` | - |
| TC-F-PROFILE-003 | Profile show | `TestF_Profile_Show` | - |
| TC-F-PROFILE-004 | Profile lint | `TestF_Profile_Lint*` | - |
| TC-F-PROFILE-005 | Profile export | `TestF_Profile_Export*` | - |
| TC-F-PROFILE-006 | Profile install | `TestF_Profile_Install*` | - |

### TC-F-LIST - Certificate Listing

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-LIST-001 | List certificates empty | `TestF_Cert_List_Empty` | - |
| TC-F-LIST-002 | List certificates | `TestF_Cert_List_WithCertificates` | - |
| TC-F-LIST-003 | Filter valid certs | `TestF_Cert_List_FilterValid` | - |
| TC-F-LIST-004 | Filter revoked certs | `TestF_Cert_List_FilterRevoked` | - |
| TC-F-LIST-005 | List verbose | `TestF_Cert_List_Verbose*` | - |

### TC-F-REVOKE - Certificate Revocation

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-REVOKE-001 | Revoke certificate | `TestF_Cert_Revoke_Certificate` | RFC 5280 |
| TC-F-REVOKE-002 | Revoke with reason | `TestF_Cert_Revoke_WithReason` | RFC 5280 |
| TC-F-REVOKE-003 | Revoke with CRL | `TestF_Cert_Revoke_WithCRLGeneration` | RFC 5280 |

### TC-F-INFO - Certificate Info

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-INFO-001 | Certificate info | `TestF_Cert_Info_Basic` | - |
| TC-F-INFO-002 | Missing serial error | `TestF_Cert_Info_MissingSerial` | - |
| TC-F-INFO-003 | Not found error | `TestF_Cert_Info_CertNotFound` | - |

### TC-F-KEY - Key CLI Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-KEY-001 | Key generation | `TestF_Key_Gen` | FIPS 186-5, FIPS 204 |
| TC-F-KEY-002 | Key with passphrase | `TestF_Key_Gen_WithPassphrase` | - |
| TC-F-KEY-003 | Key info | `TestF_Key_Info*` | - |

### TC-F-VERIFY - Certificate Verification

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-VERIFY-001 | Verify valid certificate | `TestF_Verify_ValidCertificate` | RFC 5280 |
| TC-F-VERIFY-002 | Verify subordinate CA | `TestF_Verify_SubordinateCA` | RFC 5280 |
| TC-F-VERIFY-003 | Verify with CRL | `TestF_Verify_WithCRL` | RFC 5280 |
| TC-F-VERIFY-004 | Verify revoked cert | `TestF_Verify_RevokedCertificate` | RFC 5280 |

---

## Acceptance Tests (TC-A-*)

Acceptance tests validate CLI commands end-to-end (black box).

**Location**: `test/acceptance/`

| ID | Name | Go Test | Command |
|----|------|---------|---------|
| TC-A-CA-001 | CA init with profile | `TestA_CA_Init_WithProfile` | `qpki ca init` |
| TC-A-CA-002 | CA init with HSM | `TestA_CA_Init_WithHSM` | `qpki ca init --hsm` |
| TC-A-CERT-001 | Certificate from CSR | `TestA_Cert_Issue_FromCSR` | `qpki cert issue` |
| TC-A-CMS-001 | CMS sign ML-DSA | `TestA_CMS_Sign_MLDSA` | `qpki cms sign` |

> **Note**: See [CLI-COVERAGE.md](CLI-COVERAGE.md) for complete CLI test coverage.

---

## Cross-Validation Tests (TC-C-*)

Cross-validation tests verify interoperability with external implementations.

**Location**: `test/bouncycastle/`, `test/openssl/`

### TC-C-OSL - OpenSSL 3.6+

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-OSL-001 | Verify ECDSA certificate | OpenSSL | Certificate |
| TC-C-OSL-002 | Verify ML-DSA certificate | OpenSSL | Certificate |
| TC-C-OSL-003 | Verify ML-DSA CMS | OpenSSL | CMS SignedData |
| TC-C-OSL-004 | Decrypt ML-KEM CMS | OpenSSL | CMS EnvelopedData |

### TC-C-BC - BouncyCastle 1.83+

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-BC-001 | Verify ECDSA certificate | BouncyCastle | Certificate |
| TC-C-BC-002 | Verify ML-DSA certificate | BouncyCastle | Certificate |
| TC-C-BC-003 | Verify Catalyst certificate | BouncyCastle | Certificate |
| TC-C-BC-004 | Verify Composite certificate | BouncyCastle | Certificate |

---

## Fuzzing Tests (TC-Z-*)

Fuzzing tests ensure parsers handle malformed input without panicking.

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-Z-CMS-001 | CMS parser fuzzing | `FuzzCMSParser` | internal/cms/fuzz_test.go |
| TC-Z-OCSP-001 | OCSP request fuzzing | `FuzzOCSPRequest` | internal/ocsp/fuzz_test.go |
| TC-Z-PROFILE-001 | Profile YAML fuzzing | `FuzzProfileParser` | internal/profile/fuzz_test.go |
| TC-Z-CSR-001 | PQC CSR fuzzing | `FuzzCSRParser` | internal/x509util/fuzz_test.go |

---

## Priority Definitions

| Priority | Description | CI Blocking |
|----------|-------------|-------------|
| P1 | Critical - Must pass for release | true |
| P2 | High - Should pass, may have known limitations | false |
| P3 | Medium - Nice to have | false |

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [Test Naming](NAMING.md) - Naming conventions
- [CLI Coverage](CLI-COVERAGE.md) - CLI command coverage
- [Feature Coverage](FEATURES.md) - Feature coverage
- [specs/tests/test-mapping.yaml](../../../specs/tests/test-mapping.yaml) - TC-ID mapping
