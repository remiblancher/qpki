---
title: "RFC Compliance Matrix"
description: "IETF RFC compliance status for QPKI PKI operations."
generated: true
---

# RFC Compliance Matrix

> **Note**: This file is auto-generated from `specs/compliance/standards-matrix.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document details QPKI's compliance with IETF RFCs for PKI operations.

## RFC 5280 - Internet X.509 Public Key Infrastructure

**Status**: implemented

| Section | Requirement | Status | Tests |
|---------|-------------|--------|-------|
| 4.1 | Certificate Structure | implemented | TC-CERT-* |
| 4.2.1.1 | Authority Key Identifier | implemented | - |
| 4.2.1.2 | Subject Key Identifier | implemented | - |
| 4.2.1.3 | Key Usage | implemented | TC-CERT-* |
| 4.2.1.4 | Certificate Policies | implemented | TC-CERT-* |
| 4.2.1.6 | Subject Alternative Name | implemented | TC-CERT-* |
| 4.2.1.9 | Basic Constraints | implemented | TC-CA-* |
| 4.2.1.10 | Name Constraints | implemented | TC-CA-* |
| 4.2.1.12 | Extended Key Usage | implemented | TC-CERT-* |
| 4.2.2.1 | Authority Information Access | implemented | TC-CERT-* |
| 5 | CRL Structure | implemented | TC-CRL-* |

## RFC 2986 - PKCS #10: Certificate Signing Request

**Status**: implemented

**Tests**: TC-CERT-*, TC-FUZZ-CSR-*

## RFC 6960 - Online Certificate Status Protocol (OCSP)

**Status**: implemented

**Tests**: TC-OCSP-*

### Cross-Validation

| Validator | Status |
|-----------|--------|
| OpenSSL 3.6+ | pass |
| BouncyCastle 1.83+ | pass |

## RFC 3161 - Time-Stamp Protocol (TSP)

**Status**: implemented

**Tests**: TC-TSA-*

### Cross-Validation

| Validator | Status |
|-----------|--------|
| OpenSSL 3.6+ | pass |
| BouncyCastle 1.83+ | pass |

## RFC 5652 - Cryptographic Message Syntax (CMS)

**Status**: implemented

| Section | Requirement | Status | Tests |
|---------|-------------|--------|-------|
| 5 | SignedData | implemented | TC-CMS-SIGN-* |
| 6 | EnvelopedData | implemented | TC-CMS-ENC-* |

### Cross-Validation

| Validator | Status |
|-----------|--------|
| OpenSSL 3.6+ | pass |
| BouncyCastle 1.83+ | pass |

## RFC 8419 - EdDSA in CMS

**Status**: implemented

**Tests**: TC-CMS-SIGN-*

## RFC 9814 - SLH-DSA in CMS

**Status**: implemented

**Tests**: TC-CMS-SIGN-*

## RFC 9882 - ML-DSA in CMS

**Status**: implemented

**Tests**: TC-CMS-SIGN-ML-*

## RFC 9883 - ML-KEM CSR Attestation

**Status**: implemented

**Tests**: TC-CERT-KEM-*

## Hybrid Standards

### Catalyst Hybrid Certificates

**Source**: ITU-T X.509 Section 9.8 | **Status**: implemented

| Validator | Status | Notes |
|-----------|--------|-------|
| BouncyCastle 1.83+ | pass | Both classical and PQC signatures validated |
| OpenSSL 3.6+ | partial | Classical signature only (PQC alternative ignored) |

### Composite Signatures

**Source**: draft-ounsworth-pq-composite-sigs-13 | **Status**: implemented

| Validator | Status | Notes |
|-----------|--------|-------|
| BouncyCastle 1.83+ | partial | OID mismatch: BC uses draft-07, QPKI uses draft-13 |
| OpenSSL 3.6+ | not_supported | No composite support in OpenSSL |

## See Also

- [FIPS Compliance](FIPS.md) - PQC algorithm compliance
- [specs/compliance/standards-matrix.yaml](../../../specs/compliance/standards-matrix.yaml) - Source data
