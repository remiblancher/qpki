# Testing Strategy

This document describes the testing strategy for the PKI tool, including internal tests and cross-validation with external tools.

## Overview

The PKI tool uses a multi-layered testing approach:

1. **Unit Tests** - Go tests for individual functions and packages
2. **Smoke Tests** - End-to-end tests using the CLI
3. **Cross-Tests** - External validation with OpenSSL and BouncyCastle

## Test Types

### Unit Tests (`go test`)

Standard Go unit tests covering:
- ASN.1 encoding/decoding
- Key generation and parsing
- Signature creation and verification
- Certificate issuance logic
- Profile parsing

Run unit tests:
```bash
make test           # Standard tests
make test-race      # Tests with race detector
make coverage       # Tests with coverage report
```

### Smoke Tests (CI)

End-to-end tests in the CI pipeline (`build` job):

| Test | Certificate Type | Verification |
|------|-----------------|--------------|
| ECDSA | `ec/root-ca` + `ec/tls-server` | `pki verify` + `openssl verify` |
| RSA | `rsa/root-ca` + `rsa/tls-server` | `pki verify` + `openssl verify` |
| ML-DSA-87 | `ml-dsa-kem/root-ca` + `ml-dsa-kem/tls-server` | `pki verify` |
| SLH-DSA-256f | `slh-dsa/root-ca-256f` + `slh-dsa/tls-server-256f` | `pki verify` |
| Catalyst | `hybrid/catalyst/root-ca` + `hybrid/catalyst/tls-server` | `pki verify` + `openssl verify` |
| Composite | `hybrid/composite/root-ca` + `hybrid/composite/tls-server` | `pki verify` |

### Cross-Tests (External Validation)

External validation using independent implementations ensures our certificates are standard-compliant and interoperable.

## Cross-Validation Strategy

### Why Cross-Tests?

- **Smoke tests** verify our code works internally
- **Cross-tests** verify our output is correct according to external implementations
- If BouncyCastle validates our certificates, they are standard-compliant

### External Tools

#### OpenSSL

| Version | Capabilities |
|---------|-------------|
| 3.0 (Ubuntu 24.04) | Classical certificates only |
| 3.5+ (April 2025) | Native PQC (ML-DSA, SLH-DSA, ML-KEM) |

OpenSSL tests:
- `verify_classical.sh` - Verify ECDSA/RSA certificates
- `verify_catalyst.sh` - Verify classical signature of Catalyst certificates
- `verify_pqc.sh` - Display PQC certificates (requires OpenSSL 3.5+)

#### BouncyCastle Java (1.79+)

| Feature | Support |
|---------|---------|
| Classical (ECDSA/RSA) | ✅ |
| PQC (ML-DSA, SLH-DSA) | ✅ |
| Catalyst extensions | ✅ (classical + extension parsing) |
| Composite (IETF) | ✅ (native in 1.79+) |

BouncyCastle tests:
- `ClassicalVerifyTest.java` - Verify ECDSA certificates
- `PQCVerifyTest.java` - Verify ML-DSA and SLH-DSA certificates
- `CatalystVerifyTest.java` - Verify Catalyst certificates
- `CompositeVerifyTest.java` - Verify IETF Composite certificates

## Test Coverage Matrix

| Certificate Type | `pki verify` | OpenSSL | BouncyCastle |
|-----------------|--------------|---------|--------------|
| ECDSA P-256/384 | ✅ | ✅ verify | ✅ verify |
| RSA 2048/4096 | ✅ | ✅ verify | ✅ verify |
| ML-DSA-44/65/87 | ✅ | ⚠️ display (3.5+) | ✅ verify |
| SLH-DSA-* | ✅ | ⚠️ display (3.5+) | ✅ verify |
| Catalyst (ECDSA+ML-DSA) | ✅ both | ✅ classical | ✅ classical + extensions |
| Composite (IETF) | ✅ both | ❌ | ✅ verify |

**Goal:** Every certificate type verified by **at least 2 independent implementations**.

## Running Cross-Tests

### Prerequisites

- Go 1.22+
- Java 17+ (for BouncyCastle)
- Maven 3.6+ (for BouncyCastle)

### Run All Cross-Tests

```bash
make crosstest
```

This will:
1. Build the PKI binary
2. Generate test fixtures (all certificate types)
3. Run OpenSSL tests
4. Run BouncyCastle tests

### Run Individual Tests

```bash
# Generate fixtures only
make crosstest-fixtures

# OpenSSL tests only
make crosstest-openssl

# BouncyCastle tests only (requires Java 17+)
make crosstest-bc
```

### Run Tests Manually

```bash
# Generate fixtures
./test/generate_fixtures.sh

# OpenSSL tests
cd test/openssl
./run_all.sh

# BouncyCastle tests
cd test/bouncycastle
mvn test
```

## CI Pipeline

```
┌─────────┐    ┌──────┐    ┌───────────┐    ┌──────────────┐
│  test   │───▶│ lint │───▶│   build   │───▶│  cross-test  │
│ (unit)  │    │      │    │ (smoke)   │    │  (BC+OpenSSL)│
└─────────┘    └──────┘    └───────────┘    └──────────────┘
```

The `cross-test` job runs after `build` and validates all certificate types with external tools.

## Test Directory Structure

```
test/
├── fixtures/                    # Generated test certificates
│   ├── classical/              # ECDSA certificates
│   ├── pqc/
│   │   ├── mldsa/             # ML-DSA certificates
│   │   └── slhdsa/            # SLH-DSA certificates
│   ├── catalyst/               # Catalyst hybrid certificates
│   └── composite/              # IETF Composite certificates
├── openssl/
│   ├── verify_classical.sh    # Classical certificate tests
│   ├── verify_catalyst.sh     # Catalyst tests (classical part)
│   ├── verify_pqc.sh          # PQC display tests
│   └── run_all.sh             # Run all OpenSSL tests
├── bouncycastle/
│   ├── pom.xml                # Maven project
│   └── src/test/java/pki/crosstest/
│       ├── ClassicalVerifyTest.java
│       ├── PQCVerifyTest.java
│       ├── CatalystVerifyTest.java
│       └── CompositeVerifyTest.java
└── generate_fixtures.sh        # Generate all test certificates
```

## Adding New Tests

### OpenSSL Test

1. Create `test/openssl/verify_<type>.sh`
2. Add to `test/openssl/run_all.sh`
3. Update CI workflow if needed

### BouncyCastle Test

1. Create `test/bouncycastle/src/test/java/pki/crosstest/<Type>VerifyTest.java`
2. Tests are automatically discovered by Maven

### New Certificate Type

1. Add fixture generation to `test/generate_fixtures.sh`
2. Add OpenSSL test if applicable
3. Add BouncyCastle test
4. Update coverage matrix in this document

## References

- [OpenSSL 3.5 ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
- [BouncyCastle 1.79 Release](https://www.bouncycastle.org/)
- [BouncyCastle PQC Almanac](https://downloads.bouncycastle.org/java/docs/PQC-Almanac.pdf)
