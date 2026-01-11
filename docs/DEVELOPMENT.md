# Development Guide

This document covers contributing guidelines, testing strategy, and CI/CD for QPKI development.

## 1. Getting Started

### 1.1 Prerequisites

- Go 1.25 or later
- Git
- Make (optional, for convenience commands)
- Java 17+ (for BouncyCastle cross-tests)
- Maven 3.6+ (for BouncyCastle cross-tests)

### 1.2 Clone and Build

```bash
git clone https://github.com/remiblancher/post-quantum-pki.git
cd pki

# Build
go build -o qpki ./cmd/qpki

# Run tests
go test -v ./...

# Run tests with race detection
go test -v -race ./...
```

## 2. Development Workflow

### 2.1 Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/<description>` | `feature/add-ocsp-support` |
| Bug fix | `fix/<description>` | `fix/crl-parsing-error` |
| Documentation | `docs/<description>` | `docs/update-readme` |
| Refactoring | `refactor/<description>` | `refactor/crypto-package` |

### 2.2 Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding tests
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

**Examples:**
```
feat(ca): add OCSP responder support

fix(crypto): handle nil public key in SubjectKeyID

docs(readme): update installation instructions
```

### 2.3 Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `go test -v -race ./...`
5. Run linter: `golangci-lint run`
6. Push to your fork
7. Create a Pull Request

## 3. Code Style

### 3.1 Go Style

Follow standard Go conventions:
- Use `gofmt` for formatting
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Follow [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)

### 3.2 Linting

We use `golangci-lint`:

```bash
golangci-lint run
```

Enabled linters:
- errcheck, gosimple, govet, ineffassign, staticcheck, unused, gofmt, goimports

### 3.3 Documentation

- All exported functions must have doc comments
- Doc comments should start with the function name
- Include examples for complex functions

```go
// GenerateKey creates a new cryptographic key pair.
//
// Supported algorithms: ecdsa-p256, ecdsa-p384, ed25519, rsa-2048,
// ml-dsa-44, ml-dsa-65, ml-dsa-87.
func GenerateKey(alg AlgorithmID) (Signer, error) {
    // ...
}
```

## 4. Testing Strategy

### 4.1 Testing Philosophy

- **Unit tests** for individual functions and methods
- **Integration tests** for complete CA workflows
- **External validation** with OpenSSL for X.509 compliance
- **Fuzzing tests** for ASN.1 parsers to ensure robustness
- **All tests run without external dependencies**

#### Integration Testing, Not Primitive Testing

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

### 4.2 Coverage Goals

**CI Enforcement:** Minimum threshold **60%**. New code should target **70%**.

### 4.3 Test Categories

| Category | Purpose | Tools | Location |
|----------|---------|-------|----------|
| Unit | Individual functions | go test | `*_test.go` |
| Integration | Full CA workflows | go test | `internal/ca/*_test.go` |
| CLI | Command-line interface | go test | `cmd/qpki/*_test.go` |
| Fuzzing | ASN.1 parser robustness | go test -fuzz | `*_fuzz_test.go` |
| Validation | X.509 compliance | OpenSSL | `test/openssl/` |

### 4.4 Running Tests

```bash
# Standard tests
make test

# Tests with race detector
make test-race

# Coverage report
make coverage

# Fuzz tests (60 seconds)
go test -fuzz=FuzzParseSignedData -fuzztime=60s ./internal/cms/
```

## 5. Cross-Validation

External validation ensures certificates are standard-compliant and interoperable.

### 5.1 External Tools

#### OpenSSL

| Version | Capabilities |
|---------|-------------|
| 3.0 (Ubuntu 24.04) | Classical certificates only |
| 3.5+ (April 2025) | Native PQC (ML-DSA, SLH-DSA, ML-KEM) |

#### BouncyCastle Java (1.83+)

| Feature | Support |
|---------|---------|
| Classical (ECDSA/RSA) | Supported |
| PQC (ML-DSA, SLH-DSA) | Supported |
| Catalyst extensions | Supported |
| Composite (IETF) | Supported |

### 5.2 Coverage Matrix

| Certificate Type | `pki verify` | OpenSSL | BouncyCastle |
|-----------------|--------------|---------|--------------|
| ECDSA P-256/384 | Verify | Verify | Verify |
| RSA 2048/4096 | Verify | Verify | Verify |
| ML-DSA-44/65/87 | Verify | Display (3.5+) | Verify |
| SLH-DSA-* | Verify | Display (3.5+) | Verify |
| Catalyst (ECDSA+ML-DSA) | Both | Classical | Classical + extensions |
| Composite (IETF) | Both | Not supported | Verify |

**Goal:** Every certificate type verified by **at least 2 independent implementations**.

### 5.3 Running Cross-Tests

```bash
# All cross-tests
make crosstest

# Generate fixtures only
make crosstest-fixtures

# OpenSSL tests only
make crosstest-openssl

# BouncyCastle tests only (requires Java 17+)
make crosstest-bc
```

## 6. Test Matrix

### 6.1 Algorithm Coverage

All algorithms are tested for: KeyGen, Sign/Encap, Verify/Decap, Serialize, Parse.

**Signature:** ecdsa-p256/384/521, ed25519, rsa-2048/4096, ml-dsa-44/65/87, slh-dsa-*
**Key Encapsulation:** ml-kem-512/768/1024

### 6.2 Operations Coverage

All operations have unit and integration tests: CA init, certificate issuance (simple/Catalyst/Composite), revocation, CRL generation, OCSP, TSA, CMS SignedData/EnvelopedData.

### 6.3 Fuzzing Coverage

Fuzzing tests ensure parsers don't panic on malformed input:

| Package | Focus |
|---------|-------|
| cms | ASN.1 parsing (SignedData, EnvelopedData) |
| tsa | ASN.1 parsing (Request, Response) |
| ocsp | ASN.1 parsing (Request, Response) |
| ca | Composite signatures, public key parsing |
| crypto | Algorithm parsing, key/signature handling |
| profile | Profile parsing |
| credential | Credential parsing |
| x509util | X.509 utilities |

## 7. CI Pipeline

```
┌─────────┐    ┌──────┐    ┌───────────┐    ┌──────────────┐
│  test   │───>│ lint │───>│   build   │───>│  cross-test  │
│ (unit)  │    │      │    │ (smoke)   │    │  (BC+OpenSSL)│
└─────────┘    └──────┘    └───────────┘    └──────────────┘
```

## 8. Project Extension

### 8.1 Adding New Algorithms

1. Add algorithm constant to `internal/crypto/algorithms.go`
2. Add OID to `internal/x509util/oids.go`
3. Implement key generation in `internal/crypto/keygen.go`
4. Add signing support in `internal/crypto/software.go`
5. Add tests for all operations
6. Update documentation

### 8.2 Adding New Certificate Profiles

1. Create new file in `internal/profile/`
2. Implement `Profile` interface
3. Register in profile registry
4. Add CLI support in `cmd/qpki/issue.go`
5. Add tests
6. Update GUIDE.md

### 8.3 Adding CLI Commands

1. Create new file in `cmd/qpki/`
2. Define cobra command with flags
3. Register in `init()` function
4. Add tests
5. Update GUIDE.md

## 9. Security

### 9.1 Security Considerations

- Never log sensitive data (private keys, passphrases)
- Use constant-time comparisons for secrets
- Validate all inputs
- Handle errors properly (don't ignore them)

### 9.2 Reporting Vulnerabilities

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email the maintainers directly
3. Include detailed reproduction steps
4. Allow time for a fix before disclosure

## 10. Release Process

### 10.1 Versioning

We use [Semantic Versioning](https://semver.org/):

- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### 10.2 Release Checklist

1. Update version in code
2. Update CHANGELOG.md
3. Run full test suite
4. Create annotated tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. GitHub Actions builds and releases

## 11. Code of Conduct

### Expected Behavior

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what is best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or personal attacks
- Publishing others' private information
- Other unprofessional conduct

## 12. Contributing

Contributions are welcome.

By contributing to this project, you agree to the
Contributor License Agreement (CLA).
See [CLA.md](../CLA.md).

## 13. License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## 14. References

- [OpenSSL 3.5 ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
- [BouncyCastle PQC Almanac](https://downloads.bouncycastle.org/java/docs/PQC-Almanac.pdf)
- [Effective Go](https://go.dev/doc/effective_go)

## 15. See Also

- [GUIDE](GUIDE.md) - CLI reference
- [ARCHITECTURE](ARCHITECTURE.md) - System design
