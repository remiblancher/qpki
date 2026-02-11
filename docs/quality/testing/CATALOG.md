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
DOMAIN: KEY, CA, CERT, CRL, EXT, CRED, PROFILE, LIST, REVOKE, INFO, VERIFY, OCSP, TSA, CMS, HSM, AGILITY
SEQ:    001-999
```

## Summary

| Metric | Value |
|--------|-------|
| Total Test Cases | 196 |
| Test Types | 5 (U, F, A, C, Z) |
| Last Updated | 2026-02-11 |

---

## Unit Tests (TC-U-*)

Unit tests validate individual functions in isolation.

### TC-KEY - Key Generation Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-U-KEY-001 | ECDSA P-256 key generation | \`TestU_GenerateKey_ECDSA_P256\` | FIPS 186-5 |
| TC-U-KEY-002 | ECDSA P-384 key generation | \`TestU_GenerateKey_ECDSA_P384\` | FIPS 186-5 |
| TC-U-KEY-003 | ML-DSA-44 key generation | \`TestU_GenerateKey_MLDSA44\` | FIPS 204 |
| TC-U-KEY-004 | ML-DSA-65 key generation | \`TestU_GenerateKey_MLDSA65\` | FIPS 204 |
| TC-U-KEY-005 | ML-DSA-87 key generation | \`TestU_GenerateKey_MLDSA87\` | FIPS 204 |
| TC-U-KEY-006 | SLH-DSA-128f key generation | \`TestU_GenerateKey_SLHDSA128f\` | FIPS 205 |
| TC-U-KEY-007 | ML-KEM-768 key generation | \`TestU_GenerateKey_MLKEM768\` | FIPS 203 |

### TC-EXT - X.509 Extensions Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-U-EXT-001 | Custom extension with hex value | \`TestU_CustomExtension_ToExtension_Hex\` | X.509 |
| TC-U-EXT-002 | Custom extension with base64 value | \`TestU_CustomExtension_ToExtension_Base64\` | X.509 |
| TC-U-EXT-003 | Custom extension validation | \`TestU_CustomExtension_Validate_*\` | X.509 |
| TC-U-EXT-004 | Custom extension in certificate | \`TestU_CustomExtension_RealASN1_InCertificate\` | X.509 |
| TC-U-EXT-005 | Custom extension YAML loading | \`TestU_CustomExtension_LoadFromYAML\` | Profile YAML |
| TC-U-EXT-006 | Custom extension ASN.1 encoding | \`TestU_CustomExtension_RealASN1_*\` | X.509, ASN.1 |
| TC-U-EXT-007 | Multiple custom extensions | \`TestU_CustomExtension_MultipleInCertificate\` | X.509 |
| TC-U-EXT-008 | Custom extension critical flag | \`TestU_CustomExtension_CriticalFlagInCertificate\` | X.509 |

---

## Functional Tests (TC-F-*)

Functional tests validate internal workflows and APIs.

### TC-CA - Certificate Authority Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CA-001 | ECDSA P-256 CA initialization | \`TestF_CA_Initialize_ECDSA_P256\` | RFC 5280 |
| TC-F-CA-002 | ML-DSA-65 CA initialization | \`TestF_CA_Initialize_MLDSA65\` | RFC 5280, FIPS 204 |
| TC-F-CA-003 | Catalyst hybrid CA initialization | \`TestF_CA_Initialize_Catalyst\` | ITU-T X.509 9.8 |
| TC-F-CA-004 | Composite hybrid CA initialization | \`TestF_CA_Initialize_Composite\` | IETF draft-ounsworth-pq-composite-sigs-13 |
| TC-F-CA-005 | SLH-DSA CA initialization | \`TestF_SLHDSACA_Initialize\` | RFC 5280, FIPS 205 |

### TC-CERT - X.509 Certificate Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CERT-001 | ECDSA certificate issuance from CSR | \`TestF_CA_Issue_ECDSA\` | RFC 5280, RFC 2986 |
| TC-F-CERT-002 | ML-DSA-65 certificate issuance | \`TestF_CA_Issue_MLDSA65\` | RFC 5280, FIPS 204 |
| TC-F-CERT-003 | ML-KEM certificate with attestation | \`TestF_CA_Issue_MLKEM_Attestation\` | RFC 9883 |
| TC-F-CERT-004 | SLH-DSA certificate from CSR | \`TestF_IssueFromSLHDSACSR\` | RFC 5280, RFC 2986, FIPS 205 |
| TC-F-CERT-005 | SLH-DSA certificate issuance | \`TestF_SLHDSACA_IssueCertificate\` | RFC 5280, FIPS 205 |
| TC-F-CERT-006 | ML-DSA certificate from CSR | \`TestF_IssueFromMLDSACSR\` | RFC 5280, RFC 2986, FIPS 204 |

### TC-CRL - CRL Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CRL-001 | ECDSA CRL generation | \`TestF_CA_CRL_Generate_ECDSA\` | RFC 5280 |
| TC-F-CRL-002 | ML-DSA CRL generation | \`TestF_CA_CRL_Generate_MLDSA\` | RFC 5280, FIPS 204 |
| TC-F-CRL-003 | SLH-DSA CRL generation | \`TestF_CA_GenerateCRL_SLHDSA\` | RFC 5280, FIPS 205 |

### TC-CRED - Credential Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CRED-001 | Credential enrollment | \`TestF_Credential_Enroll\` | RFC 5280 |
| TC-F-CRED-002 | Credential list | \`TestF_Credential_List*\` |  |
| TC-F-CRED-003 | Credential info | \`TestF_Credential_Info*\` |  |
| TC-F-CRED-004 | Credential rotation | \`TestF_Credential_Rotate*\` |  |
| TC-F-CRED-005 | Credential revocation | \`TestF_Credential_Revoke*\` | RFC 5280 |
| TC-F-CRED-006 | Credential export | \`TestF_Credential_Export*\` |  |

### TC-PROFILE - Profile Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-PROFILE-001 | Profile list | \`TestF_Profile_List\` |  |
| TC-F-PROFILE-002 | Profile info | \`TestF_Profile_Info*\` |  |
| TC-F-PROFILE-003 | Profile show | \`TestF_Profile_Show\` |  |
| TC-F-PROFILE-004 | Profile lint | \`TestF_Profile_Lint*\` |  |
| TC-F-PROFILE-005 | Profile export | \`TestF_Profile_Export*\` |  |
| TC-F-PROFILE-006 | Profile install | \`TestF_Profile_Install*\` |  |

### TC-LIST - Certificate Listing Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-LIST-001 | List certificates empty | \`TestF_Cert_List_Empty\` |  |
| TC-F-LIST-002 | List certificates with results | \`TestF_Cert_List_WithCertificates\` |  |
| TC-F-LIST-003 | List certificates filter valid | \`TestF_Cert_List_FilterValid\` |  |
| TC-F-LIST-004 | List certificates filter revoked | \`TestF_Cert_List_FilterRevoked\` |  |
| TC-F-LIST-005 | List certificates verbose | \`TestF_Cert_List_Verbose*\` |  |

### TC-REVOKE - Certificate Revocation Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-REVOKE-001 | Revoke certificate | \`TestF_Cert_Revoke_Certificate\` | RFC 5280 |
| TC-F-REVOKE-002 | Revoke with reason | \`TestF_Cert_Revoke_WithReason\` | RFC 5280 |
| TC-F-REVOKE-003 | Revoke with CRL generation | \`TestF_Cert_Revoke_WithCRLGeneration\` | RFC 5280 |

### TC-INFO - Certificate Information Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-INFO-001 | Certificate info basic | \`TestF_Cert_Info_Basic\` |  |
| TC-F-INFO-002 | Certificate info missing serial | \`TestF_Cert_Info_MissingSerial\` |  |
| TC-F-INFO-003 | Certificate info not found | \`TestF_Cert_Info_CertNotFound\` |  |

### TC-KEY-CLI - Key CLI Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-KEY-001 | Key generation via CLI | \`TestF_Key_Gen\` | FIPS 186-5, FIPS 204 |
| TC-F-KEY-002 | Key generation with passphrase | \`TestF_Key_Gen_WithPassphrase\` |  |
| TC-F-KEY-003 | Key info | \`TestF_Key_Info*\` |  |

### TC-VERIFY - Certificate Verification Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-VERIFY-001 | Verify valid certificate | \`TestF_Verify_ValidCertificate\` | RFC 5280 |
| TC-F-VERIFY-002 | Verify subordinate CA | \`TestF_Verify_SubordinateCA\` | RFC 5280 |
| TC-F-VERIFY-003 | Verify with CRL | \`TestF_Verify_WithCRL\` | RFC 5280 |
| TC-F-VERIFY-004 | Verify revoked certificate | \`TestF_Verify_RevokedCertificate\` | RFC 5280 |

### TC-OCSP - OCSP Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-OCSP-001 | ECDSA OCSP response signing | \`TestF_OCSP_Sign_ECDSA\` | RFC 6960 |
| TC-F-OCSP-002 | ML-DSA OCSP response signing | \`TestF_OCSP_Sign_MLDSA\` | RFC 6960, FIPS 204 |
| TC-F-OCSP-003 | SLH-DSA OCSP response signing | \`TestU_ResponseBuilder_SLHDSA\` | RFC 6960, FIPS 205 |

### TC-TSA - TSA Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-TSA-001 | ECDSA timestamp signing | \`TestF_TSA_Sign_ECDSA\` | RFC 3161 |
| TC-F-TSA-002 | ML-DSA timestamp signing | \`TestF_TSA_Sign_MLDSA\` | RFC 3161, FIPS 204 |
| TC-F-TSA-003 | SLH-DSA timestamp signing | \`TestF_Token_SLHDSAAlgorithms\` | RFC 3161, FIPS 205 |

### TC-CMS - CMS Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CMS-001 | ECDSA CMS SignedData | \`TestF_CMS_Sign_ECDSA\` | RFC 5652 |
| TC-F-CMS-002 | ML-DSA CMS SignedData | \`TestF_CMS_Sign_MLDSA\` | RFC 5652, RFC 9882 |
| TC-F-CMS-003 | ML-KEM CMS EnvelopedData | \`TestF_CMS_Encrypt_MLKEM\` | RFC 5652, FIPS 203 |
| TC-F-CMS-004 | SLH-DSA CMS SignedData fast variants | \`TestF_Sign_SLHDSA_FastVariants\` | RFC 5652, RFC 9814, FIPS 205 |
| TC-F-CMS-005 | SLH-DSA CMS RFC 9814 SHA2 variants | \`TestF_RFC9814_SLHDSA_SHA2_AllVariants\` | RFC 5652, RFC 9814, FIPS 205 |
| TC-F-CMS-006 | SLH-DSA CMS RFC 9814 SHAKE variants | \`TestF_RFC9814_SLHDSA_SHAKE_AllVariants\` | RFC 5652, RFC 9814, FIPS 205 |

---

## Acceptance Tests (TC-A-*)

Acceptance tests validate CLI commands end-to-end (black box).

**Location**: `test/acceptance/`

### TC-A-PKI - PKI CLI Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-KEY-001 | EC key generation algorithms | \`TestA_Key_Gen_EC_Algorithms\` | test/acceptance/pki_test.go |
| TC-A-KEY-002 | RSA key generation algorithms | \`TestA_Key_Gen_RSA_Algorithms\` | test/acceptance/pki_test.go |
| TC-A-KEY-003 | ML-DSA key generation algorithms | \`TestA_Key_Gen_MLDSA_Algorithms\` | test/acceptance/pki_test.go |
| TC-A-KEY-004 | SLH-DSA key generation algorithms | \`TestA_Key_Gen_SLHDSA_Algorithms\` | test/acceptance/pki_test.go |
| TC-A-KEY-005 | Key info display | \`TestA_Key_Info\` | test/acceptance/pki_test.go |
| TC-A-KEY-006 | Key list | \`TestA_Key_List\` | test/acceptance/pki_test.go |
| TC-A-CA-001 | EC CA initialization | \`TestA_CA_Init_EC\` | test/acceptance/pki_test.go |
| TC-A-CA-002 | RSA CA initialization | \`TestA_CA_Init_RSA\` | test/acceptance/pki_test.go |
| TC-A-CA-003 | ML-DSA CA initialization | \`TestA_CA_Init_MLDSA\` | test/acceptance/pki_test.go |
| TC-A-CA-004 | SLH-DSA CA initialization | \`TestA_CA_Init_SLHDSA\` | test/acceptance/pki_test.go |
| TC-A-CA-005 | Catalyst hybrid CA initialization | \`TestA_CA_Init_Catalyst\` | test/acceptance/pki_test.go |
| TC-A-CA-006 | Composite hybrid CA initialization | \`TestA_CA_Init_Composite\` | test/acceptance/pki_test.go |
| TC-A-CA-007 | Subordinate CA initialization | \`TestA_CA_Init_Subordinate\` | test/acceptance/pki_test.go |
| TC-A-CA-008 | CA info display | \`TestA_CA_Info\` | test/acceptance/pki_test.go |
| TC-A-CSR-001 | EC CSR generation | \`TestA_CSR_Gen_EC\` | test/acceptance/pki_test.go |
| TC-A-CSR-002 | RSA CSR generation | \`TestA_CSR_Gen_RSA\` | test/acceptance/pki_test.go |
| TC-A-CSR-003 | ML-KEM CSR with attestation | \`TestA_CSR_Gen_MLKEM_WithAttestation\` | test/acceptance/pki_test.go |
| TC-A-CERT-001 | EC certificate from CSR | \`TestA_Cert_Issue_EC_FromCSR\` | test/acceptance/pki_test.go |
| TC-A-CERT-002 | RSA certificate from CSR | \`TestA_Cert_Issue_RSA_FromCSR\` | test/acceptance/pki_test.go |
| TC-A-CERT-003 | Certificate verification | \`TestA_Cert_Verify\` | test/acceptance/pki_test.go |
| TC-A-CERT-004 | Certificate list | \`TestA_Cert_List\` | test/acceptance/pki_test.go |
| TC-A-CERT-005 | Certificate inspect | \`TestA_Cert_Inspect\` | test/acceptance/pki_test.go |
| TC-A-CRED-001 | EC credential profiles enrollment | \`TestA_Credential_Enroll_EC_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRED-002 | RSA credential profiles enrollment | \`TestA_Credential_Enroll_RSA_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRED-003 | ML-DSA credential profiles enrollment | \`TestA_Credential_Enroll_MLDSA_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRED-004 | SLH-DSA credential profiles enrollment | \`TestA_Credential_Enroll_SLHDSA_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRED-005 | Catalyst credential profiles enrollment | \`TestA_Credential_Enroll_Catalyst_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRED-006 | Composite credential profiles enrollment | \`TestA_Credential_Enroll_Composite_Profiles\` | test/acceptance/pki_test.go |
| TC-A-CRL-001 | CRL generation | \`TestA_CRL_Generate\` | test/acceptance/pki_test.go |
| TC-A-CRL-002 | Revoke and generate CRL | \`TestA_CRL_Revoke_And_Generate\` | test/acceptance/pki_test.go |
| TC-A-CRL-003 | PQC algorithms CRL | \`TestA_CRL_PQC_Algorithms\` | test/acceptance/pki_test.go |
| TC-A-PROFILE-001 | Profile list | \`TestA_Profile_List\` | test/acceptance/pki_test.go |
| TC-A-PROFILE-002 | Profile show | \`TestA_Profile_Show\` | test/acceptance/pki_test.go |
| TC-A-INSPECT-001 | Inspect certificate | \`TestA_Inspect_Certificate\` | test/acceptance/pki_test.go |
| TC-A-INSPECT-002 | Inspect PQC certificate | \`TestA_Inspect_PQC_Certificate\` | test/acceptance/pki_test.go |
| TC-A-INSPECT-003 | Inspect CRL | \`TestA_Inspect_CRL\` | test/acceptance/pki_test.go |
| TC-A-INSPECT-004 | Inspect CSR | \`TestA_Inspect_CSR\` | test/acceptance/pki_test.go |
| TC-A-E2E-001 | EC workflow end-to-end | \`TestA_E2E_EC_Workflow\` | test/acceptance/pki_test.go |
| TC-A-E2E-002 | ML-DSA workflow end-to-end | \`TestA_E2E_MLDSA_Workflow\` | test/acceptance/pki_test.go |
| TC-A-E2E-003 | Catalyst workflow end-to-end | \`TestA_E2E_Catalyst_Workflow\` | test/acceptance/pki_test.go |
| TC-A-E2E-004 | Composite workflow end-to-end | \`TestA_E2E_Composite_Workflow\` | test/acceptance/pki_test.go |
| TC-A-E2E-005 | Subordinate CA chain | \`TestA_E2E_SubordinateCA_Chain\` | test/acceptance/pki_test.go |
| TC-A-CLI-001 | CLI help | \`TestA_CLI_Help\` | test/acceptance/pki_test.go |
| TC-A-CLI-002 | CLI version | \`TestA_CLI_Version\` | test/acceptance/pki_test.go |

### TC-A-AGILITY - Crypto Agility Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-AGILITY-001 | EC to Catalyst to PQ transition | \`TestA_Agility_EC_Catalyst_PQ\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-002 | EC to Composite to PQ transition | \`TestA_Agility_EC_Composite_PQ\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-003 | RSA to EC to PQ transition | \`TestA_Agility_RSA_EC_PQ\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-004 | EC to PQ direct transition | \`TestA_Agility_EC_PQ_Direct\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-005 | Catalyst to PQ transition | \`TestA_Agility_Catalyst_PQ\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-006 | Composite to PQ transition | \`TestA_Agility_Composite_PQ\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-007 | EC to SLH-DSA transition | \`TestA_Agility_EC_SLHDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-008 | Full PKI transition | \`TestA_Agility_Full_PKI_Transition\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-009 | Rotate EC to Catalyst to ML-DSA | \`TestA_Agility_Rotate_EC_Catalyst_MLDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-010 | Rotate EC to Composite to ML-DSA | \`TestA_Agility_Rotate_EC_Composite_MLDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-011 | Rotate RSA to EC to ML-DSA | \`TestA_Agility_Rotate_RSA_EC_MLDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-012 | Rotate EC to ML-DSA direct | \`TestA_Agility_Rotate_EC_MLDSA_Direct\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-013 | Rotate Catalyst to ML-DSA | \`TestA_Agility_Rotate_Catalyst_MLDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-014 | Rotate Composite to ML-DSA | \`TestA_Agility_Rotate_Composite_MLDSA\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-015 | Rotate CA versions | \`TestA_Agility_Rotate_CA_Versions\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-016 | Rotate credential versions | \`TestA_Agility_Rotate_Credential_Versions\` | test/acceptance/cryptoagility_test.go |
| TC-A-AGILITY-017 | Rotate CA info | \`TestA_Agility_Rotate_CA_Info\` | test/acceptance/cryptoagility_test.go |

### TC-A-CMS - CMS CLI Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-CMS-001 | CMS sign with EC | \`TestA_CMS_Sign_EC\` | test/acceptance/cms_test.go |
| TC-A-CMS-002 | CMS sign with RSA | \`TestA_CMS_Sign_RSA\` | test/acceptance/cms_test.go |
| TC-A-CMS-003 | CMS sign with ML-DSA | \`TestA_CMS_Sign_MLDSA\` | test/acceptance/cms_test.go |
| TC-A-CMS-004 | CMS sign with SLH-DSA | \`TestA_CMS_Sign_SLHDSA\` | test/acceptance/cms_test.go |
| TC-A-CMS-005 | CMS sign with Catalyst | \`TestA_CMS_Sign_Catalyst\` | test/acceptance/cms_test.go |
| TC-A-CMS-006 | CMS sign with Composite | \`TestA_CMS_Sign_Composite\` | test/acceptance/cms_test.go |
| TC-A-CMS-007 | CMS encrypt with RSA | \`TestA_CMS_Encrypt_RSA\` | test/acceptance/cms_test.go |
| TC-A-CMS-008 | CMS encrypt with EC | \`TestA_CMS_Encrypt_EC\` | test/acceptance/cms_test.go |
| TC-A-CMS-009 | CMS encrypt with ML-KEM | \`TestA_CMS_Encrypt_MLKEM\` | test/acceptance/cms_test.go |
| TC-A-CMS-010 | CMS encrypt hybrid | \`TestA_CMS_Encrypt_Hybrid\` | test/acceptance/cms_test.go |
| TC-A-CMS-011 | CMS verify invalid data | \`TestA_CMS_Verify_InvalidData\` | test/acceptance/cms_test.go |

### TC-A-HSM - HSM CLI Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-HSM-001 | HSM list tokens | \`TestA_HSM_List_Tokens\` | test/acceptance/hsm_test.go |
| TC-A-HSM-002 | HSM test connection | \`TestA_HSM_Test_Connection\` | test/acceptance/hsm_test.go |
| TC-A-HSM-003 | HSM info | \`TestA_HSM_Info\` | test/acceptance/hsm_test.go |
| TC-A-HSM-004 | HSM EC key generation | \`TestA_HSM_Key_Gen_EC\` | test/acceptance/hsm_test.go |
| TC-A-HSM-005 | HSM RSA key generation | \`TestA_HSM_Key_Gen_RSA\` | test/acceptance/hsm_test.go |
| TC-A-HSM-006 | HSM key list | \`TestA_HSM_Key_List\` | test/acceptance/hsm_test.go |
| TC-A-HSM-007 | HSM CA init with existing key | \`TestA_HSM_CA_Init_WithExistingKey\` | test/acceptance/hsm_test.go |
| TC-A-HSM-008 | HSM CA init generate key | \`TestA_HSM_CA_Init_GenerateKey\` | test/acceptance/hsm_test.go |
| TC-A-HSM-009 | HSM CA init RSA | \`TestA_HSM_CA_Init_RSA\` | test/acceptance/hsm_test.go |
| TC-A-HSM-010 | HSM CA info | \`TestA_HSM_CA_Info\` | test/acceptance/hsm_test.go |
| TC-A-HSM-011 | HSM credential enroll software key | \`TestA_HSM_Credential_Enroll_SoftwareKey\` | test/acceptance/hsm_test.go |
| TC-A-HSM-012 | HSM credential enroll HSM key | \`TestA_HSM_Credential_Enroll_HSMKey\` | test/acceptance/hsm_test.go |
| TC-A-HSM-013 | HSM credential list | \`TestA_HSM_Credential_List\` | test/acceptance/hsm_test.go |

### TC-A-TSA - TSA CLI Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-TSA-001 | TSA sign with EC | \`TestA_TSA_Sign_EC\` | test/acceptance/tsa_test.go |
| TC-A-TSA-002 | TSA sign with RSA | \`TestA_TSA_Sign_RSA\` | test/acceptance/tsa_test.go |
| TC-A-TSA-003 | TSA sign with ML-DSA | \`TestA_TSA_Sign_MLDSA\` | test/acceptance/tsa_test.go |
| TC-A-TSA-004 | TSA sign with SLH-DSA | \`TestA_TSA_Sign_SLHDSA\` | test/acceptance/tsa_test.go |
| TC-A-TSA-005 | TSA sign with Catalyst | \`TestA_TSA_Sign_Catalyst\` | test/acceptance/tsa_test.go |
| TC-A-TSA-006 | TSA sign with Composite | \`TestA_TSA_Sign_Composite\` | test/acceptance/tsa_test.go |
| TC-A-TSA-007 | TSA verify invalid data | \`TestA_TSA_Verify_InvalidData\` | test/acceptance/tsa_test.go |
| TC-A-TSA-008 | TSA info | \`TestA_TSA_Info\` | test/acceptance/tsa_test.go |

### TC-A-OCSP - OCSP CLI Acceptance Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-A-OCSP-001 | OCSP sign with EC | \`TestA_OCSP_Sign_EC\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-002 | OCSP sign with ML-DSA | \`TestA_OCSP_Sign_MLDSA\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-003 | OCSP sign with SLH-DSA | \`TestA_OCSP_Sign_SLHDSA\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-004 | OCSP sign with Catalyst | \`TestA_OCSP_Sign_Catalyst\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-005 | OCSP sign with Composite | \`TestA_OCSP_Sign_Composite\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-006 | OCSP status revoked | \`TestA_OCSP_Status_Revoked\` | test/acceptance/ocsp_test.go |
| TC-A-OCSP-007 | OCSP server | \`TestA_OCSP_Server\` | test/acceptance/ocsp_test.go |

---

## Cross-Validation Tests (TC-C-*)

Cross-validation tests verify interoperability with external implementations.

**Location**: `test/crossval/bouncycastle/`, `test/crossval/openssl/`

### TC-C-OSL - OpenSSL Cross-Validation

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-OSL-CERT-001 | OpenSSL verifies ECDSA certificate | OpenSSL | openssl verify returns OK |
| TC-C-OSL-CERT-002 | OpenSSL verifies ML-DSA certificate | OpenSSL | openssl verify returns OK for ML-DSA cert |
| TC-C-OSL-CMS-001 | OpenSSL verifies ML-DSA CMS signature | OpenSSL | openssl cms -verify returns OK |
| TC-C-OSL-CMSENC-001 | OpenSSL decrypts ML-KEM CMS | OpenSSL | ML-KEM encrypted content decrypted |
| TC-C-OSL-CRL-001 | OpenSSL verifies CRL | OpenSSL | openssl crl -verify returns OK |
| TC-C-OSL-OCSP-001 | OpenSSL verifies OCSP response | OpenSSL | OCSP response signature validates |
| TC-C-OSL-TSA-001 | OpenSSL verifies TSA timestamp | OpenSSL | Timestamp token signature validates |
| TC-C-OSL-CSR-001 | OpenSSL verifies CSR | OpenSSL | CSR signature validates |

### TC-C-BC - BouncyCastle Cross-Validation

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-BC-CERT-001 | BouncyCastle verifies ECDSA certificate | BouncyCastle | Certificate chain validates |
| TC-C-BC-CERT-002 | BouncyCastle verifies ML-DSA certificate | BouncyCastle | PQC certificate chain validates |
| TC-C-BC-CERT-003 | BouncyCastle verifies Catalyst certificate | BouncyCastle | Both classical and PQC signatures validate |
| TC-C-BC-CERT-004 | BouncyCastle verifies Composite certificate | BouncyCastle | Composite signature validates |
| TC-C-BC-CRL-001 | BouncyCastle verifies CRL | BouncyCastle | CRL signature validates |
| TC-C-BC-CRL-002 | BouncyCastle verifies Catalyst CRL | BouncyCastle | Catalyst hybrid CRL validates |
| TC-C-BC-CRL-003 | BouncyCastle verifies Composite CRL | BouncyCastle | Composite CRL validates |
| TC-C-BC-OCSP-001 | BouncyCastle verifies OCSP response | BouncyCastle | OCSP response signature validates |
| TC-C-BC-TSA-001 | BouncyCastle verifies TSA timestamp | BouncyCastle | Timestamp token validates |
| TC-C-BC-CMS-001 | BouncyCastle verifies CMS SignedData | BouncyCastle | CMS signature validates |
| TC-C-BC-CMSENC-001 | BouncyCastle decrypts CMS EnvelopedData | BouncyCastle | CMS EnvelopedData decrypted successfully |
| TC-C-BC-CSR-001 | BouncyCastle verifies CSR | BouncyCastle | CSR signature validates |
| TC-C-BC-CERT-005 | BouncyCastle verifies X.509 extensions | BouncyCastle | All standard and custom extensions parsed correctly |

---

## Fuzzing Tests (TC-Z-*)

Fuzzing tests ensure parsers handle malformed input without panicking.

### TC-Z-FUZZ - Fuzzing Tests

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-Z-CMS-001 | CMS SignedData parser fuzzing | \`FuzzParseSignedData\` | internal/cms/fuzz_test.go |
| TC-Z-OCSP-001 | OCSP request parser fuzzing | \`FuzzU_ParseRequest\` | internal/ocsp/fuzz_test.go |
| TC-Z-PROFILE-001 | Profile YAML parser fuzzing | \`FuzzLoadProfileFromBytes\` | internal/profile/fuzz_test.go |
| TC-Z-CSR-001 | PQC CSR parser fuzzing | \`FuzzParsePQCCSR\` | internal/x509util/fuzz_test.go |

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
- [Feature Coverage](FEATURE-COVERAGE.md) - Feature coverage
