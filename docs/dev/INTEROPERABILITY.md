# Interoperability Matrix

This document details the cross-validation testing between QPKI and external implementations.

## 1. External Validators

| Tool | Version | Capabilities |
|------|---------|--------------|
| **OpenSSL** | 3.6+ | Native PQC (ML-DSA, SLH-DSA, ML-KEM), classical algorithms |
| **BouncyCastle** | 1.83+ | Full PQC support, Catalyst extensions, Composite (draft-07) |

## 2. Test Case Naming Convention

### Cross-Validation TC-IDs

Format: `TC-<TOOL>-<ARTIFACT>-<ALGO>`

| Segment | Values |
|---------|--------|
| **TOOL** | `XOSL` (OpenSSL), `XBC` (BouncyCastle) |
| **ARTIFACT** | `CERT`, `CRL`, `CSR`, `CMS`, `OCSP`, `TSA` |
| **ALGO** | `EC`, `ML`, `SLH`, `CAT`, `COMP` |

### Algorithm Keys

| Key | Algorithm |
|-----|-----------|
| `EC` | Classical ECDSA (P-256, P-384, P-521) |
| `ML` | ML-DSA (44, 65, 87) - FIPS 204 |
| `SLH` | SLH-DSA (128f, 192f, 256f) - FIPS 205 |
| `CAT` | Catalyst hybrid (ECDSA + ML-DSA) |
| `COMP` | Composite hybrid (IETF draft-13) |

### Examples

| TC-ID | Description |
|-------|-------------|
| `TC-XOSL-CERT-EC` | OpenSSL verifies ECDSA certificate |
| `TC-XOSL-CMS-ML` | OpenSSL verifies ML-DSA CMS signature |
| `TC-XBC-OCSP-CAT` | BouncyCastle verifies Catalyst OCSP response |
| `TC-XBC-CERT-COMP` | BouncyCastle verifies Composite certificate |

### Internal TC-IDs

Format: `TC-<CATEGORY>-<ALGO>-<NUM>`

| Category | Description |
|----------|-------------|
| `TC-CERT` | X.509 certificate operations |
| `TC-CSR` | Certificate Signing Requests |
| `TC-CRL` | Certificate Revocation Lists |
| `TC-OCSP` | OCSP operations |
| `TC-TSA` | Timestamping operations |
| `TC-CMS` | CMS operations |
| `TC-FUZZ` | Fuzzing tests |

## 3. Algorithm x Operation Matrix

| Operation | EC | RSA | Ed25519 | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|-----------|:--:|:---:|:-------:|:------:|:-------:|:------:|:--------:|:---------:|
| Key Gen | TC-KEY-EC | TC-KEY-RSA | TC-KEY-ED | TC-KEY-ML | TC-KEY-SLH | TC-KEY-KEM | TC-KEY-CAT | TC-KEY-COMP |
| CA Init | TC-CA-EC | TC-CA-RSA | - | TC-CA-ML | TC-CA-SLH | - | TC-CA-CAT | TC-CA-COMP |
| Cert Issue | TC-CERT-EC | TC-CERT-RSA | - | TC-CERT-ML | TC-CERT-SLH | TC-CERT-KEM* | TC-CERT-CAT | TC-CERT-COMP |
| CSR Gen | TC-CSR-EC | TC-CSR-RSA | TC-CSR-ED | TC-CSR-ML | TC-CSR-SLH | TC-CSR-KEM | TC-CSR-CAT | TC-CSR-COMP |
| CRL Gen | TC-CRL-EC | TC-CRL-RSA | - | TC-CRL-ML | TC-CRL-SLH | - | TC-CRL-CAT | TC-CRL-COMP |
| OCSP | TC-OCSP-EC | TC-OCSP-RSA | - | TC-OCSP-ML | TC-OCSP-SLH | - | TC-OCSP-CAT | TC-OCSP-COMP |
| TSA | TC-TSA-EC | TC-TSA-RSA | - | TC-TSA-ML | TC-TSA-SLH | - | TC-TSA-CAT | TC-TSA-COMP |
| CMS Sign | TC-CMS-EC | TC-CMS-RSA | - | TC-CMS-ML | TC-CMS-SLH | - | TC-CMS-CAT | TC-CMS-COMP |
| CMS Encrypt | - | TC-CMS-RSA-ENC | - | - | - | TC-CMS-KEM-ENC | - | - |

*ML-KEM certificates require RFC 9883 attestation

## 4. Cross-Validation Matrix

### Full Matrix (CI Summary View)

#### OpenSSL 3.6

| Artefact | Classical | ML-DSA | SLH-DSA | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:--------:|:---------:|
| Cert | TC-XOSL-CERT-EC | TC-XOSL-CERT-ML | TC-XOSL-CERT-SLH | TC-XOSL-CERT-CAT* | N/A |
| CRL | TC-XOSL-CRL-EC | TC-XOSL-CRL-ML | TC-XOSL-CRL-SLH | TC-XOSL-CRL-CAT* | N/A |
| CSR | TC-XOSL-CSR-EC | TC-XOSL-CSR-ML | TC-XOSL-CSR-SLH | TC-XOSL-CSR-CAT* | N/A |
| CMS | TC-XOSL-CMS-EC | TC-XOSL-CMS-ML | TC-XOSL-CMS-SLH | TC-XOSL-CMS-CAT* | N/A |
| OCSP | TC-XOSL-OCSP-EC | TC-XOSL-OCSP-ML | TC-XOSL-OCSP-SLH | TC-XOSL-OCSP-CAT* | N/A |
| TSA | TC-XOSL-TSA-EC | TC-XOSL-TSA-ML | TC-XOSL-TSA-SLH | TC-XOSL-TSA-CAT* | N/A |

#### BouncyCastle 1.83

| Artefact | Classical | ML-DSA | SLH-DSA | Catalyst | Composite |
|----------|:---------:|:------:|:-------:|:--------:|:---------:|
| Cert | TC-XBC-CERT-EC | TC-XBC-CERT-ML | TC-XBC-CERT-SLH | TC-XBC-CERT-CAT | TC-XBC-CERT-COMP** |
| CRL | TC-XBC-CRL-EC | TC-XBC-CRL-ML | TC-XBC-CRL-SLH | TC-XBC-CRL-CAT | TC-XBC-CRL-COMP** |
| CSR | TC-XBC-CSR-EC | TC-XBC-CSR-ML | TC-XBC-CSR-SLH | TC-XBC-CSR-CAT**** | TC-XBC-CSR-COMP***** |
| CMS | TC-XBC-CMS-EC | TC-XBC-CMS-ML | TC-XBC-CMS-SLH | TC-XBC-CMS-CAT | TC-XBC-CMS-COMP*** |
| OCSP | TC-XBC-OCSP-EC | TC-XBC-OCSP-ML | TC-XBC-OCSP-SLH | TC-XBC-OCSP-CAT | TC-XBC-OCSP-COMP*** |
| TSA | TC-XBC-TSA-EC | TC-XBC-TSA-ML | TC-XBC-TSA-SLH | TC-XBC-TSA-CAT | TC-XBC-TSA-COMP*** |

**Legend:**
- `*` OpenSSL verifies classical signature only; PQC alternative signature ignored
- `**` BC Composite Cert/CRL: draft-07 OIDs (parse OK, verify needs OID alignment)
- `***` BC Composite CMS/OCSP/TSA: parsing only (OID mismatch)
- `****` BC CSR Catalyst: parsing only (alt key attributes issue)
- `*****` BC CSR Composite: parsing only (draft-13 OID mismatch)
- `N/A` Not supported by external validator

## 5. Known Limitations

| Feature | Status | Details |
|---------|--------|---------|
| **Composite signatures** | Partial | BC 1.83 uses draft-07 OIDs (`2.16.840.1.114027.80.8.1.x`), QPKI uses draft-13 (`1.3.6.1.5.5.7.6.x`) |
| **Catalyst in OpenSSL** | Partial | Only ECDSA signature verified, PQC alternative signature ignored |
| **CMS Encryption OpenSSL** | Not supported | OpenSSL 3.6 does not support ML-KEM in CMS |

## 6. CI Job Reference

| CI Job | Test Cases | Scripts/Classes | Duration |
|--------|------------|-----------------|----------|
| `test` | TC-UNIT-*, TC-INT-* | `*_test.go` | ~15 min |
| `pki-test` | TC-CA-*, TC-CERT-*, TC-KEY-*, TC-CSR-*, TC-CRL-*, TC-CRED-* | CI workflow steps | ~15 min |
| `ocsp-test` | TC-OCSP-* | CI workflow steps | ~15 min |
| `tsa-test` | TC-TSA-* | CI workflow steps | ~15 min |
| `cms-test` | TC-CMS-* | CI workflow steps | ~15 min |
| `crosstest-openssl` | TC-XOSL-* | `test/openssl/verify_*.sh` | ~30 min |
| `crosstest-bc` | TC-XBC-* | `test/bouncycastle/src/test/java/*Test.java` | ~15 min |
| `hsm-test` | TC-HSM-* | CI workflow steps (SoftHSM2) | ~15 min |
| `cryptoagility-test` | TC-AGIL-* | CI workflow steps | ~30 min |
| `fuzz` | TC-FUZZ-* | `*_fuzz_test.go` | ~30 min |
| `security` | TC-SEC-* | Trivy scanner | ~10 min |

## 7. OpenSSL Cross-Test Scripts

### Structure

```
test/openssl/
├── run_all.sh                    ← Orchestrator + generates summary
├── lib/
│   ├── verify_certs.sh           ← TC-XOSL-CERT-* (all algos)
│   ├── verify_crl.sh             ← TC-XOSL-CRL-* (all algos)
│   ├── verify_csr.sh             ← TC-XOSL-CSR-* (all algos)
│   ├── verify_cms.sh             ← TC-XOSL-CMS-* (fixture-based)
│   ├── verify_ocsp.sh            ← TC-XOSL-OCSP-* (fixture-based)
│   └── verify_tsa.sh             ← TC-XOSL-TSA-* (fixture-based)
├── verify_extension_variants.sh  ← X.509 extension edge cases
└── verify_cms_encrypt.sh         ← CMS encryption (ML-KEM)
```

### Module Details

| Script | TC-IDs | Description |
|--------|--------|-------------|
| `run_all.sh` | All | Orchestrator, sources lib/, generates summary matrix |
| `lib/verify_certs.sh` | TC-XOSL-CERT-* | Certificate verification (EC, ML, SLH, CAT) |
| `lib/verify_crl.sh` | TC-XOSL-CRL-* | CRL verification (EC, ML, SLH, CAT) |
| `lib/verify_csr.sh` | TC-XOSL-CSR-* | CSR verification (EC, ML, SLH, CAT) |
| `lib/verify_cms.sh` | TC-XOSL-CMS-* | CMS SignedData (fixture-based) |
| `lib/verify_ocsp.sh` | TC-XOSL-OCSP-* | OCSP responses (fixture-based) |
| `lib/verify_tsa.sh` | TC-XOSL-TSA-* | TSA timestamps (fixture-based) |
| `verify_extension_variants.sh` | - | X.509 extension edge cases |
| `verify_cms_encrypt.sh` | - | CMS EnvelopedData (ML-KEM) |

## 8. BouncyCastle Cross-Test Classes

### Structure

```
test/bouncycastle/
├── pom.xml
├── generate_summary.sh           ← Parses surefire + generates summary
└── src/test/java/pki/crosstest/
    ├── ClassicalVerifyTest.java  ← TC-XBC-CERT-EC
    ├── PQCVerifyTest.java        ← TC-XBC-CERT-ML, TC-XBC-CERT-SLH
    ├── CatalystVerifyTest.java   ← TC-XBC-CERT-CAT
    ├── CompositeVerifyTest.java  ← TC-XBC-CERT-COMP
    ├── CRLVerifyTest.java        ← TC-XBC-CRL-*
    ├── CSRVerifyTest.java        ← TC-XBC-CSR-*
    ├── CMSVerifyTest.java        ← TC-XBC-CMS-*
    ├── OCSPVerifyTest.java       ← TC-XBC-OCSP-*
    ├── TSAVerifyTest.java        ← TC-XBC-TSA-*
    └── ExtensionsVerifyTest.java ← Extension parsing tests
```

### Class Details

| Class | TC-IDs | Description |
|-------|--------|-------------|
| `ClassicalVerifyTest.java` | TC-XBC-CERT-EC | ECDSA certificate verification |
| `PQCVerifyTest.java` | TC-XBC-CERT-ML, TC-XBC-CERT-SLH | ML-DSA, SLH-DSA verification |
| `CatalystVerifyTest.java` | TC-XBC-CERT-CAT | Catalyst hybrid (both signatures) |
| `CompositeVerifyTest.java` | TC-XBC-CERT-COMP | Composite hybrid (parsing) |
| `CRLVerifyTest.java` | TC-XBC-CRL-* | CRL verification |
| `CSRVerifyTest.java` | TC-XBC-CSR-* | CSR signature verification |
| `CMSVerifyTest.java` | TC-XBC-CMS-* | CMS signed data verification |
| `OCSPVerifyTest.java` | TC-XBC-OCSP-* | OCSP response verification |
| `TSAVerifyTest.java` | TC-XBC-TSA-* | Timestamp verification |
| `ExtensionsVerifyTest.java` | - | X.509 extension parsing |

## 9. See Also

- [TESTING.md](TESTING.md) - Testing strategy and local execution
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow
