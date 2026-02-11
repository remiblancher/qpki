---
title: "Interoperability Matrix"
description: "Cross-validation testing between QPKI and external implementations"
generated: true
---

# Interoperability Matrix

> **Note**: This file is auto-generated from `specs/compliance/interop-matrix.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document details the cross-validation testing between QPKI and external implementations.

## External Validators

| Tool | Version | Capabilities |
|------|---------|--------------|
| **OpenSSL** | 3.6+ | Classical (ECDSA, RSA, Ed25519), PQC (ML-DSA, SLH-DSA, ML-KEM) |
| **BouncyCastle** | 1.83+ | Classical (ECDSA, RSA, Ed25519), PQC (ML-DSA, SLH-DSA, ML-KEM), Catalyst hybrid, Composite (draft-07) |

## TC-ID Naming Convention

Cross-validation test case IDs follow the format: `TC-C-<TOOL>-<ARTIFACT>-<SEQ>`

| Segment | Values |
|---------|--------|
| **TOOL** | `OSL` (OpenSSL), `BC` (BouncyCastle) |
| **ARTIFACT** | `CERT`, `CRL`, `CSR`, `CMS`, `CMSENC`, `OCSP`, `TSA`, `CAT`, `COMP`, `EXT` |
| **SEQ** | `001-999` |

## Cross-Validation Matrix

### OpenSSL 3.6+

| Artifact | TC-IDs | Status | Notes |
|----------|--------|--------|-------|
| Certificate | `TC-C-OSL-CERT-001, TC-C-OSL-CERT-002` | pass | - |
| CRL | `TC-C-OSL-CRL-001` | pass | - |
| CSR | `TC-C-OSL-CSR-001` | pass | - |
| CMS SignedData | `TC-C-OSL-CMS-001` | pass | - |
| CMS EnvelopedData | `TC-C-OSL-CMSENC-001` | pass | - |
| OCSP | `TC-C-OSL-OCSP-001` | pass | - |
| TSA | `TC-C-OSL-TSA-001` | pass | - |
| Catalyst Hybrid | `` | partial | Classical signature only (PQC alternative ignored) |
| Composite | `` | not_supported | No composite support in OpenSSL |

### BouncyCastle 1.83+

| Artifact | TC-IDs | Status | Notes |
|----------|--------|--------|-------|
| Certificate | `TC-C-BC-CERT-001, TC-C-BC-CERT-002` | pass | - |
| CRL | `TC-C-BC-CRL-001` | pass | - |
| CSR | `TC-C-BC-CSR-001` | pass | - |
| CMS SignedData | `TC-C-BC-CMS-001` | pass | - |
| CMS EnvelopedData | `TC-C-BC-CMSENC-001` | pass | - |
| OCSP | `TC-C-BC-OCSP-001` | pass | - |
| TSA | `TC-C-BC-TSA-001` | pass | - |
| Catalyst Hybrid | `TC-C-BC-CERT-003, TC-C-BC-CRL-002` | pass | Both classical and PQC signatures validated |
| Composite | `TC-C-BC-CERT-004, TC-C-BC-CRL-003` | partial | OID mismatch: BC uses draft-07 (2.16.840.1.114027.80.8.1.x), QPKI uses draft-13 (1.3.6.1.5.5.7.6.x) |

## Known Limitations

| Feature | Status | Details |
|---------|--------|---------|
| **Composite signatures** | partial | BC 1.83 uses draft-07 OIDs (2.16.840.1.114027.80.8.1.x), QPKI uses draft-13 (1.3.6.1.5.5.7.6.x) |
| **Catalyst in OpenSSL** | partial | Only ECDSA signature verified, PQC alternative signature ignored |
| **CMS Encryption ML-KEM** | full | OpenSSL 3.6+ and BC 1.83+ full support |

## CI Job Reference

| CI Job | Test Pattern | Scripts | Duration |
|--------|--------------|---------|----------|
| `test` | TC-U-*, TC-F-* | *_test.go | ~15 min |
| `crosstest-openssl` | TC-C-OSL-* | test/openssl/verify_*.sh | ~30 min |
| `crosstest-bc` | TC-C-BC-* | test/bouncycastle/src/test/java/*Test.java | ~15 min |
| `fuzz` | TC-Z-* | *_fuzz_test.go | ~30 min |

## OpenSSL Cross-Test Scripts

| Script | TC-IDs | Description |
|--------|--------|-------------|
| `verify_certs.sh` | TC-C-OSL-CERT-001, TC-C-OSL-CERT-002 | Certificate verification (EC, ML, SLH) |
| `verify_crl.sh` | TC-C-OSL-CRL-001 | CRL verification |
| `verify_csr.sh` | TC-C-OSL-CSR-001 | CSR verification |
| `verify_cms.sh` | TC-C-OSL-CMS-001 | CMS SignedData |
| `verify_cms_encrypt.sh` | TC-C-OSL-CMSENC-001 | CMS EnvelopedData (ECDH, ML-KEM) |
| `verify_ocsp.sh` | TC-C-OSL-OCSP-001 | OCSP responses |
| `verify_tsa.sh` | TC-C-OSL-TSA-001 | TSA timestamps |

## BouncyCastle Cross-Test Classes

| Class | TC-IDs | Description |
|-------|--------|-------------|
| `ClassicalVerifyTest.java` | TC-C-BC-CERT-001 | ECDSA certificate verification |
| `PQCVerifyTest.java` | TC-C-BC-CERT-002 | ML-DSA, SLH-DSA verification |
| `CatalystVerifyTest.java` | TC-C-BC-CERT-003 | Catalyst hybrid certificate |
| `CompositeVerifyTest.java` | TC-C-BC-CERT-004 | Composite hybrid certificate |
| `CRLVerifyTest.java` | TC-C-BC-CRL-001, TC-C-BC-CRL-002, TC-C-BC-CRL-003 | CRL verification (standard, Catalyst, Composite) |
| `CSRVerifyTest.java` | TC-C-BC-CSR-001 | CSR signature verification |
| `CMSVerifyTest.java` | TC-C-BC-CMS-001 | CMS signed data verification |
| `CMSEnvelopedTest.java` | TC-C-BC-CMSENC-001 | CMS EnvelopedData/AuthEnvelopedData |
| `OCSPVerifyTest.java` | TC-C-BC-OCSP-001 | OCSP response verification |
| `TSAVerifyTest.java` | TC-C-BC-TSA-001 | Timestamp verification |
| `ExtensionsVerifyTest.java` | TC-C-BC-CERT-005 | X.509 extension parsing |

## Running Cross-Validation Tests

```bash
# Run all cross-validation tests
make crosstest

# Run OpenSSL tests only
make crosstest-openssl

# Run BouncyCastle tests only
make crosstest-bc
```

## See Also

- [Test Strategy](../testing/STRATEGY.md) - Testing philosophy
- [FIPS Compliance](FIPS.md) - PQC algorithm compliance
- [RFC Compliance](RFC.md) - Protocol compliance
- [specs/compliance/interop-matrix.yaml](../../../specs/compliance/interop-matrix.yaml) - Source data
