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

Cross-validation test case IDs follow the format: `TC-C-<TOOL>-<ARTIFACT>`

| Segment | Values |
|---------|--------|
| **TOOL** | `OSL` (OpenSSL), `BC` (BouncyCastle) |
| **ARTIFACT** | `CERT`, `CRL`, `CSR`, `CMS`, `CMSENC`, `OCSP`, `TSA`, `CAT`, `COMP` |

### Algorithm Keys

| Key | Algorithm |
|-----|-----------|
| `EC` | Classical ECDSA (P-256, P-384, P-521) |
| `RSA` | RSA (2048, 4096) |
| `ED` | Ed25519 |
| `ML` | ML-DSA (44, 65, 87) - FIPS 204 |
| `SLH` | SLH-DSA (128f, 192f, 256f) - FIPS 205 |
| `KEM` | ML-KEM (512, 768, 1024) - FIPS 203 |
| `CAT` | Catalyst hybrid (ECDSA + ML-DSA) |
| `COMP` | Composite hybrid (IETF draft-13) |

## Cross-Validation Matrix

### OpenSSL 3.6+

| Artifact | Status | Notes |
|----------|--------|-------|
| Certificate | pass | - |
| CRL | pass | - |
| CSR | pass | - |
| CMS SignedData | pass | - |
| CMS EnvelopedData | pass | - |
| OCSP | pass | - |
| TSA | pass | - |
| Catalyst Hybrid | partial | Classical signature only (PQC alternative ignored) |
| Composite | not_supported | No composite support in OpenSSL |

### BouncyCastle 1.83+

| Artifact | Status | Notes |
|----------|--------|-------|
| Certificate | pass | - |
| CRL | pass | - |
| CSR | pass | - |
| CMS SignedData | pass | - |
| CMS EnvelopedData | pass | - |
| OCSP | pass | - |
| TSA | pass | - |
| Catalyst Hybrid | pass | Both classical and PQC signatures validated |
| Composite | partial | OID mismatch: BC uses draft-07 (2.16.840.1.114027.80.8.1.x), QPKI uses draft-13 (1.3.6.1.5.5.7.6.x) |

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

| Script | TC Prefix | Description |
|--------|-----------|-------------|
| `verify_certs.sh` | TC-C-OSL-CERT | Certificate verification (EC, ML, SLH, CAT) |
| `verify_crl.sh` | TC-C-OSL-CRL | CRL verification (EC, ML, SLH, CAT) |
| `verify_csr.sh` | TC-C-OSL-CSR | CSR verification (EC, ML, SLH, CAT) |
| `verify_cms.sh` | TC-C-OSL-CMS | CMS SignedData (fixture-based) |
| `verify_cms_encrypt.sh` | TC-C-OSL-CMSENC | CMS EnvelopedData (ECDH, ML-KEM) |
| `verify_ocsp.sh` | TC-C-OSL-OCSP | OCSP responses (fixture-based) |
| `verify_tsa.sh` | TC-C-OSL-TSA | TSA timestamps (fixture-based) |

## BouncyCastle Cross-Test Classes

| Class | TC Prefix | Description |
|-------|-----------|-------------|
| `ClassicalVerifyTest.java` | TC-C-BC-CERT-EC | ECDSA certificate verification |
| `PQCVerifyTest.java` | TC-C-BC-CERT-ML, TC-C-BC-CERT-SLH | ML-DSA, SLH-DSA verification |
| `CatalystVerifyTest.java` | TC-C-BC-CAT | Catalyst hybrid (both signatures) |
| `CompositeVerifyTest.java` | TC-C-BC-COMP | Composite hybrid (parsing) |
| `CRLVerifyTest.java` | TC-C-BC-CRL | CRL verification |
| `CSRVerifyTest.java` | TC-C-BC-CSR | CSR signature verification |
| `CMSVerifyTest.java` | TC-C-BC-CMS | CMS signed data verification |
| `CMSEnvelopedTest.java` | TC-C-BC-CMSENC | CMS EnvelopedData/AuthEnvelopedData (ECDH, RSA, ML-KEM) |
| `OCSPVerifyTest.java` | TC-C-BC-OCSP | OCSP response verification |
| `TSAVerifyTest.java` | TC-C-BC-TSA | Timestamp verification |
| `ExtensionsVerifyTest.java` | - | X.509 extension parsing |

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
