---
title: "RFC Compliance Matrix"
description: "IETF RFC compliance status for QPKI PKI operations."
---

# RFC Compliance Matrix

This document details QPKI's compliance with IETF RFCs for PKI operations.

## RFC 5280 - X.509 PKI Certificates and CRL

| Section | Requirement | Status | Tests | Notes |
|---------|-------------|--------|-------|-------|
| 4.1 | Certificate Structure | Implemented | TC-CERT-* | X.509 v3 |
| 4.2.1.1 | Authority Key Identifier | Implemented | Auto | Auto-generated |
| 4.2.1.2 | Subject Key Identifier | Implemented | Auto | SHA-1 hash |
| 4.2.1.3 | Key Usage | Implemented | TC-CERT-* | Critical by default |
| 4.2.1.4 | Certificate Policies | Implemented | TC-CERT-* | CPS + UserNotice |
| 4.2.1.6 | Subject Alternative Name | Implemented | TC-CERT-* | 54 variants tested |
| 4.2.1.9 | Basic Constraints | Implemented | TC-CA-* | Critical for CA |
| 4.2.1.10 | Name Constraints | Implemented | TC-CA-* | CA only, critical |
| 4.2.1.12 | Extended Key Usage | Implemented | TC-CERT-* | Optional critical |
| 4.2.2.1 | Authority Information Access | Implemented | TC-CERT-* | Non-critical required |
| 5 | CRL Structure | Implemented | TC-CRL-* | X.509 v2 CRL |
| 5.2.3 | CRL Entry Extensions | Implemented | TC-CRL-* | Reason codes |

### Extension Variants Tested

54 extension variants in `test/fixtures/extension-variants/`:
- AIA: CA Issuers, OCSP, combined
- Basic Constraints: CA true/false, pathLen
- Certificate Policies: CPS, UserNotice, critical
- CRL Distribution Points: single/multiple URLs
- Extended Key Usage: all predefined + critical variants
- Key Usage: CA settings, end-entity settings
- Name Constraints: permit/exclude DNS, email, IP
- Subject Alternative Name: DNS, email, IP, URI, combined

## RFC 2986 - PKCS#10 CSR

| Requirement | Status | Tests | Notes |
|-------------|--------|-------|-------|
| CSR Structure | Implemented | TC-CERT-* | 16 CSR variants |
| Signature Verification | Implemented | TC-FUZZ-CSR-* | Fuzzing coverage |
| Attributes | Implemented | TC-CERT-* | extensionRequest |

## RFC 6960 - OCSP

| Section | Requirement | Status | Tests |
|---------|-------------|--------|-------|
| 4.1 | Request Syntax | Implemented | TC-OCSP-* |
| 4.2 | Response Syntax | Implemented | TC-OCSP-* |
| 4.2.1 | BasicOCSPResponse | Implemented | TC-OCSP-* |
| 4.2.2.2.1 | OCSP No Check | Implemented | Profile config |

### Cross-Validation

| Validator | Status |
|-----------|--------|
| OpenSSL 3.6+ | Pass |
| BouncyCastle 1.83+ | Pass |

## RFC 3161 - Time-Stamp Protocol

| Section | Requirement | Status | Tests |
|---------|-------------|--------|-------|
| 2.4.1 | Request Format | Implemented | TC-TSA-* |
| 2.4.2 | Response Format | Implemented | TC-TSA-* |
| 2.4.2 | TimeStampToken | Implemented | TC-TSA-* |

### Cross-Validation

| Validator | Status |
|-----------|--------|
| OpenSSL 3.6+ | Pass |
| BouncyCastle 1.83+ | Pass |

## RFC 5652 - CMS

| Section | Requirement | Status | Tests |
|---------|-------------|--------|-------|
| 5 | SignedData | Implemented | TC-CMS-SIGN-* |
| 5.3 | SignerInfo | Implemented | TC-CMS-SIGN-* |
| 6 | EnvelopedData | Implemented | TC-CMS-ENC-* |
| 6.2 | RecipientInfo | Implemented | TC-CMS-ENC-* |

### Algorithm Support in CMS

| Algorithm | RFC | SignedData | EnvelopedData |
|-----------|-----|------------|---------------|
| ECDSA | RFC 5652 | Yes | N/A |
| EdDSA | RFC 8419 | Yes | N/A |
| ML-DSA | RFC 9882 | Yes | N/A |
| SLH-DSA | RFC 9814 | Yes | N/A |
| ECDH | RFC 5652 | N/A | Yes |
| ML-KEM | FIPS 203 | N/A | Yes |

### Cross-Validation

| Validator | SignedData | EnvelopedData |
|-----------|------------|---------------|
| OpenSSL 3.6+ | Pass | Pass |
| BouncyCastle 1.83+ | Pass | Pass |

## RFC 9883 - ML-KEM CSR Attestation

| Requirement | Status | Tests |
|-------------|--------|-------|
| KEM Proof of Possession | Implemented | TC-CERT-KEM-* |
| CSR Attestation Extension | Implemented | TC-CERT-KEM-* |

## Hybrid Standards

### ITU-T X.509 Section 9.8 (Catalyst)

| Requirement | Status | Tests | Notes |
|-------------|--------|-------|-------|
| AltSubjectPublicKeyInfo | Implemented | TC-CA-CAT-* | OID 2.5.29.72 |
| AltSignatureAlgorithm | Implemented | TC-CA-CAT-* | OID 2.5.29.73 |
| AltSignatureValue | Implemented | TC-CA-CAT-* | OID 2.5.29.74 |

**Cross-Validation:**
- BouncyCastle 1.83+: Full support (both signatures validated)
- OpenSSL 3.6+: Partial (classical signature only)

### IETF draft-ounsworth-pq-composite-sigs-13

| Requirement | Status | Tests | Notes |
|-------------|--------|-------|-------|
| Composite Public Key | Implemented | TC-CA-COMP-* | IANA OIDs |
| Composite Signature | Implemented | TC-CA-COMP-* | Both must validate |

**Cross-Validation:**
- BouncyCastle 1.83+: Partial (OID mismatch: BC uses draft-07)
- OpenSSL 3.6+: Not supported

## eIDAS / ETSI EN 319 412-5

| QCStatement | OID | Status |
|-------------|-----|--------|
| QcCompliance | 0.4.0.1862.1.1 | Implemented |
| QcRetentionPeriod | 0.4.0.1862.1.3 | Implemented |
| QcSSCD | 0.4.0.1862.1.4 | Implemented |
| QcPDS | 0.4.0.1862.1.5 | Implemented |
| QcType | 0.4.0.1862.1.6 | Implemented |

## See Also

- [FIPS Compliance](FIPS-COMPLIANCE.md) - PQC algorithm compliance
- [Interoperability Report](INTEROP-REPORT.md) - Cross-validation details
- [specs/compliance/standards-matrix.yaml](../../specs/compliance/standards-matrix.yaml) - Machine-readable matrix
