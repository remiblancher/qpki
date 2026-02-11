---
title: "Testing Strategy"
description: "Testing philosophy, categories, and execution for QPKI development."
---

# Testing Strategy

This document covers the testing philosophy, categories, and execution for QPKI development.

## 1. Philosophy

### Integration Testing, Not Primitive Testing

We do NOT duplicate tests that underlying cryptographic libraries already perform. For PQC (ML-DSA, SLH-DSA, ML-KEM), we use [cloudflare/circl](https://github.com/cloudflare/circl) which includes NIST KAT tests and comprehensive fuzzing.

**What we test:**
- Key generation produces valid keys (integration)
- Sign/Verify round-trip works (integration)
- Key serialization to PEM/DER (PKI-specific)
- Certificate integration (PKI-specific)
- Cross-validation with OpenSSL/BouncyCastle

**What we don't test:**
- KAT vectors (circl does this)
- Edge cases in primitive operations (circl does this)

### External Validation

Every certificate type is verified by **at least 2 independent implementations**:
- QPKI itself
- OpenSSL 3.6+ (with native PQC support)
- BouncyCastle 1.83+ (Java)

## 2. Test Categories

| Category | Location | CI Job | Purpose |
|----------|----------|--------|---------|
| Unit | `*_test.go` | `test` | Individual function correctness |
| Integration | `internal/ca/*_test.go` | `test` | Full CA workflows |
| CLI | `cmd/qpki/*_test.go` | `test` | Command-line interface |
| Fuzzing | `*_fuzz_test.go` | `fuzz` | ASN.1 parser robustness |
| Cross-OpenSSL | `test/openssl/` | `crosstest-openssl` | OpenSSL interoperability |
| Cross-BC | `test/bouncycastle/` | `crosstest-bc` | BouncyCastle interoperability |
| Protocol | CI workflow steps | `ocsp-test`, `tsa-test`, `cms-test` | RFC protocol compliance |
| HSM | CI workflow steps | `hsm-test` | PKCS#11 integration |
| E2E | External lab repo | `lab-tests` | Real-world scenarios |

## 3. Coverage

| Metric | Threshold | Enforcement |
|--------|-----------|-------------|
| Minimum coverage | 60% | CI blocks merge |
| Target for new code | 70% | Code review |
| Patch coverage | 70% | Codecov check |

## 4. Running Tests Locally

```bash
# Standard unit tests
make test

make test-race

make coverage

make fuzz

make fuzz-quick

make fuzz-all

make crosstest

make crosstest-openssl

make crosstest-bc
```

## 5. CI Pipeline Overview

```
                                        ┌─ Workflow
                                        │    └─ pki-test
                                        │
                                        ├─ Protocols
                                        │    ├─ ocsp-test
                                        │    ├─ tsa-test
                                        │    └─ cms-test
                                        │
test ───┬──> build (+ smoke) ───────────┼─ Interoperability
        │                               │    ├─ crosstest-openssl
lint ───┘                               │    └─ crosstest-bc
                                        │
                                        ├─ Integration
                                        │    └─ hsm-test
                                        │
                                        └─ E2E Scenarios
                                             ├─ cryptoagility-test
                                             └─ lab-tests
```

All jobs after `build` run **in parallel**.

| Job | Description |
|-----|-------------|
| `pki-test` | PKI operations (key, CSR, CA, cert, CRL, credential) |
| `ocsp-test` | OCSP sign/verify |
| `tsa-test` | TSA sign/verify |
| `cms-test` | CMS sign/encrypt |
| `crosstest-openssl` | Interoperability with OpenSSL 3.6 |
| `crosstest-bc` | Interoperability with BouncyCastle 1.83 |
| `hsm-test` | HSM operations with SoftHSM2 |
| `cryptoagility-test` | Algorithm transitions (EC → Catalyst → ML-DSA) |
| `lab-tests` | End-to-end demos from pki-lab repo |

See [INTEROPERABILITY.md](INTEROPERABILITY.md) for the detailed test matrix and cross-validation coverage.

## 6. Writing Tests

### Naming Conventions

```go
// Unit test
func TestU_FunctionName_Scenario(t *testing.T) {}

// Functional/Integration test
func TestF_Workflow_Scenario(t *testing.T) {}

// Fuzz test
func FuzzParserName(f *testing.F) {}
```

### Test File Organization

- Place tests in the same package as the code being tested
- Use `_test.go` suffix
- Group related tests in the same file
- Use table-driven tests for multiple scenarios

## 7. Fuzzing Targets

Fuzzing tests ensure parsers don't panic on malformed input:

| Package | Focus |
|---------|-------|
| `cms` | ASN.1 parsing (SignedData, EnvelopedData) |
| `tsa` | ASN.1 parsing (Request, Response) |
| `ocsp` | ASN.1 parsing (Request, Response) |
| `ca` | Composite signatures, public key parsing |
| `crypto` | Algorithm parsing, key/signature handling |
| `profile` | Profile YAML parsing |
| `credential` | Credential JSON parsing |
| `x509util` | CSR parsing, hybrid extensions |

## 8. See Also

- [INTEROPERABILITY.md](INTEROPERABILITY.md) - Cross-validation matrix
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow
