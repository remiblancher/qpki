---
title: "CLI Test Coverage"
description: "Acceptance test coverage for QPKI CLI commands."
generated: true
---

# CLI Test Coverage

> **Note**: This file is auto-generated from `specs/tests/cli-coverage.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This document tracks acceptance test (TestA_*) coverage for each CLI command.

## Summary

| Metric | Value |
|--------|-------|
| Total Commands | 24 |
| Covered | 0 |
| Partial | 2 |
| **Gap** | **22** |
| Last Updated | 2026-02-11 |

## Coverage Legend

| Status | Description |
|--------|-------------|
| covered | All major paths tested |
| partial | Some paths tested, gaps identified |
| gap | No acceptance tests exist |

## Commands

| Command | Status | Tests | Gaps |
|---------|--------|-------|------|
| qpki ca init | gap | 0 | 2 |
| qpki ca rotate | gap | 0 | 1 |
| qpki ca export | partial | 2 | 1 |
| qpki cert issue | gap | 0 | 1 |
| qpki cert revoke | gap | 0 | 1 |
| qpki cert list | gap | 0 | 1 |
| qpki csr create | gap | 0 | 1 |
| qpki credential enroll | gap | 0 | 1 |
| qpki credential export | partial | 1 | 1 |
| qpki crl generate | gap | 0 | 1 |
| qpki ocsp serve | gap | 0 | 2 |
| qpki ocsp request | gap | 0 | 1 |
| qpki tsa sign | gap | 0 | 1 |
| qpki tsa verify | gap | 0 | 1 |
| qpki cms sign | gap | 0 | 1 |
| qpki cms verify | gap | 0 | 1 |
| qpki cms encrypt | gap | 0 | 1 |
| qpki cms decrypt | gap | 0 | 1 |
| qpki key gen | gap | 0 | 1 |
| qpki hsm info | gap | 0 | 1 |
| qpki inspect | gap | 0 | 1 |
| qpki cose sign | gap | 0 | 1 |
| qpki profile list | gap | 0 | 1 |
| qpki profile show | gap | 0 | 1 |


## Identified Gaps

Commands without acceptance tests (TestA_*):

### qpki ca init

- No TestA_CA_Init_* acceptance tests
- HSM initialization not tested via CLI

### qpki ca rotate

- No TestA_CA_Rotate_* acceptance tests

### qpki cert issue

- No TestA_Cert_Issue_* acceptance tests

### qpki cert revoke

- No TestA_Cert_Revoke_* acceptance tests

### qpki cert list

- No CLI acceptance tests (TestF_Cert_List_* are functional, not CLI)

### qpki csr create

- No TestA_CSR_Create_* acceptance tests

### qpki credential enroll

- No TestA_Credential_Enroll_* acceptance tests

### qpki crl generate

- No TestA_CRL_Generate_* acceptance tests

### qpki ocsp serve

- No TestA_OCSP_Serve_* acceptance tests
- Server lifecycle not tested

### qpki ocsp request

- No TestA_OCSP_Request_* acceptance tests

### qpki tsa sign

- No TestA_TSA_Sign_* acceptance tests

### qpki tsa verify

- No TestA_TSA_Verify_* acceptance tests

### qpki cms sign

- No TestA_CMS_Sign_* acceptance tests

### qpki cms verify

- No TestA_CMS_Verify_* acceptance tests

### qpki cms encrypt

- No TestA_CMS_Encrypt_* acceptance tests

### qpki cms decrypt

- No TestA_CMS_Decrypt_* acceptance tests

### qpki key gen

- No TestA_Key_Gen_* acceptance tests

### qpki hsm info

- No TestA_HSM_Info_* acceptance tests

### qpki inspect

- No TestA_Inspect_* acceptance tests

### qpki cose sign

- No TestA_COSE_Sign_* acceptance tests

### qpki profile list

- No TestA_Profile_List_* acceptance tests

### qpki profile show

- No TestA_Profile_Show_* acceptance tests


## Partial Coverage

Commands with some tests but identified gaps:

### qpki ca export

Tests: TestA_CA_Export_Chain_WithCrossSign, TestA_CA_Export_Chain_NoCrossSign

Gaps:
- Missing HSM export tests

### qpki credential export

Tests: TestA_Credential_Export_Chain_HybridCA

Gaps:
- Only hybrid CA tested


## How to Add Acceptance Tests

1. Create test file in `test/acceptance/` directory
2. Use `//go:build acceptance` build tag
3. Name tests `TestA_<Command>_<Scenario>`
4. Update `specs/tests/cli-coverage.yaml` with new tests
5. Run `make quality-docs` to regenerate this file

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [Test Naming](NAMING.md) - Naming conventions
- [specs/tests/cli-coverage.yaml](../../../specs/tests/cli-coverage.yaml) - Source data
