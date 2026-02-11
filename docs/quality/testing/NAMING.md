---
title: "Test Naming Convention"
description: "Complete reference for QPKI test naming standards (ISO 29119)."
---

# Test Naming Convention

This document defines the complete naming standards for QPKI tests, following ISO/IEC 29119 Test Documentation principles.

## Quick Reference

```
Go Test:  TestU_CA_ParseCertificate_ValidPEM
TC-ID:    TC-U-CA-001
```

## Go Test Function Names

### Format

```
Test<TYPE>_<Domain>_<Function>_<Scenario>
```

### Prefixes

| Prefix | Type | Test Box | Description |
|--------|------|----------|-------------|
| `TestU_` | Unit | White box | Isolated function, mock dependencies |
| `TestF_` | Functional | Grey box | Internal workflow, real dependencies |
| `TestA_` | Acceptance | Black box | CLI end-to-end, user perspective |
| `TestC_` | Cross-validation | Black box | External validator (OpenSSL, BC) |
| `Fuzz` | Fuzzing | N/A | Parser robustness |

### Examples

```go
// Unit: TestU_<Package>_<Function>_<Scenario>
func TestU_CA_ParseCertificate_ValidPEM(t *testing.T)
func TestU_CA_ParseCertificate_InvalidPEM(t *testing.T)
func TestU_Key_Generate_ECDSA_P256(t *testing.T)

// Functional: TestF_<Domain>_<Workflow>_<Scenario>
func TestF_CA_Initialize_ECDSA(t *testing.T)
func TestF_CA_Initialize_MLDSA65(t *testing.T)
func TestF_CMS_Sign_WithTimestamp(t *testing.T)

// Acceptance: TestA_<Command>_<Subcommand>_<Scenario>
func TestA_CA_Init_WithProfile(t *testing.T)
func TestA_CA_Init_WithHSM(t *testing.T)
func TestA_Cert_Issue_FromCSR(t *testing.T)
func TestA_CMS_Sign_MLDSA(t *testing.T)

// Cross-validation: TestC_<Validator>_<Artifact>_<Algo>
func TestC_OpenSSL_VerifyCert_MLDSA65(t *testing.T)
func TestC_OpenSSL_DecryptCMS_MLKEM768(t *testing.T)
func TestC_BouncyCastle_VerifyCert_Catalyst(t *testing.T)

// Fuzzing: Fuzz<Parser>
func FuzzCMSParser(f *testing.F)
func FuzzOCSPRequest(f *testing.F)
func FuzzProfileYAML(f *testing.F)
```

## TC-ID Format (ISO 29119)

### Format

```
TC-<TYPE>-<DOMAIN>-<SEQ>           # Unit, Functional, Acceptance, Fuzz
TC-C-<TOOL>-<ARTIFACT>-<SEQ>       # Cross-validation
```

### Elements

| Element | Values | Description |
|---------|--------|-------------|
| TYPE | U, F, A, C, Z | Unit, Functional, Acceptance, Crossval, fuZz |
| DOMAIN | KEY, CA, CERT, CRL, OCSP, TSA, CMS, HSM, COSE, AUDIT | Functional domain |
| TOOL | OSL, BC | OpenSSL, BouncyCastle |
| ARTIFACT | CERT, CRL, CSR, CMS, CMSENC, OCSP, TSA | PKI artifact |
| SEQ | 001-999 | Sequential number |

### Examples

| TC-ID | Go Test | Description |
|-------|---------|-------------|
| TC-U-KEY-001 | `TestU_Key_Generate_ECDSA` | Unit: ECDSA key generation |
| TC-U-KEY-002 | `TestU_Key_Generate_MLDSA65` | Unit: ML-DSA-65 key generation |
| TC-F-CA-001 | `TestF_CA_Initialize_ECDSA` | Functional: CA init ECDSA |
| TC-F-CA-002 | `TestF_CA_Initialize_MLDSA65` | Functional: CA init ML-DSA |
| TC-A-CA-001 | `TestA_CA_Init_WithProfile` | Acceptance: CLI ca init |
| TC-A-CMS-001 | `TestA_CMS_Sign_MLDSA` | Acceptance: CLI cms sign |
| TC-C-OSL-CERT-001 | `TestC_OpenSSL_VerifyCert_ECDSA` | Crossval: OpenSSL cert |
| TC-C-BC-CERT-003 | `TestC_BouncyCastle_VerifyCert_Catalyst` | Crossval: BC Catalyst cert |
| TC-Z-CMS-001 | `FuzzCMSParser` | Fuzz: CMS parser |

## File Organization

```
post-quantum-pki/
├── internal/
│   ├── ca/
│   │   ├── ca.go
│   │   ├── ca_test.go          # TestU_* (unit)
│   │   └── ca_fuzz_test.go     # Fuzz* (fuzzing)
│   └── ...
│
├── cmd/qpki/
│   ├── ca.go
│   └── ca_test.go              # TestF_* (functional)
│
└── test/
    ├── acceptance/              # TestA_* (black box CLI, Go)
    │   └── *_test.go            # //go:build acceptance
    │
    ├── crossval/                # Cross-validation tests
    │   ├── bouncycastle/        # Java interop tests (Maven)
    │   └── openssl/             # Shell interop tests
    │
    ├── fixtures/                # All test data
    │   └── profiles/            # Test profile YAML files
    │
    └── scripts/                 # Test utility scripts
        ├── run_tests.sh
        └── generate_*.sh
```

## Build Tags

```go
//go:build acceptance

package acceptance

func TestA_CA_Init_ECDSA(t *testing.T) { ... }
```

```go
//go:build crossval

package crossval

func TestC_OpenSSL_VerifyCert_MLDSA(t *testing.T) { ... }
```

### Running by Tag

```bash
# Unit + Functional (default)
go test ./...

# Acceptance only
go test -tags=acceptance ./test/acceptance/...

# Cross-validation only
go test -tags=crossval ./test/crossval/...

# All tests
go test -tags=acceptance,crossval ./...
```

## Domain Reference

| Domain | Description | Example Tests |
|--------|-------------|---------------|
| KEY | Key generation/management | `TestU_Key_Generate_*` |
| CA | Certificate Authority | `TestF_CA_Initialize_*` |
| CERT | Certificate operations | `TestF_Cert_Issue_*` |
| CRL | Revocation lists | `TestF_CRL_Generate_*` |
| OCSP | OCSP protocol | `TestF_OCSP_Response_*` |
| TSA | Timestamping | `TestF_TSA_Timestamp_*` |
| CMS | Cryptographic messages | `TestF_CMS_Sign_*` |
| HSM | Hardware security | `TestF_HSM_Initialize_*` |
| COSE | CBOR signing | `TestU_COSE_Sign_*` |
| AUDIT | Audit logging | `TestU_Audit_Log_*` |

## Cross-Validation Validators

| Validator | Abbreviation | Tests |
|-----------|--------------|-------|
| OpenSSL 3.6+ | OSL | `TestC_OpenSSL_*` |
| BouncyCastle 1.83+ | BC | `TestC_BouncyCastle_*` |

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [CLI Coverage](COVERAGE-CLI.md) - CLI command coverage
- [Feature Coverage](COVERAGE-FEATURES.md) - Feature coverage
