# Contributing Guide

This document covers contributing guidelines, development workflow, and code style for QPKI.

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

## 4. Project Extension

### 4.1 Adding New Algorithms

1. Add algorithm constant to `internal/crypto/algorithms.go`
2. Add OID to `internal/x509util/oids.go`
3. Implement key generation in `internal/crypto/keygen.go`
4. Add signing support in `internal/crypto/software.go`
5. Add tests for all operations
6. Update documentation

### 4.2 Adding New Certificate Profiles

1. Create new file in `internal/profile/`
2. Implement `Profile` interface
3. Register in profile registry
4. Add CLI support in `cmd/qpki/issue.go`
5. Add tests
6. Update relevant documentation (CA.md, CREDENTIALS.md, CLI-REFERENCE.md)

### 4.3 Adding CLI Commands

1. Create new file in `cmd/qpki/`
2. Define cobra command with flags
3. Register in `init()` function
4. Add tests
5. Update relevant documentation (CLI-REFERENCE.md)

## 5. Security

### 5.1 Security Considerations

- Never log sensitive data (private keys, passphrases)
- Use constant-time comparisons for secrets
- Validate all inputs
- Handle errors properly (don't ignore them)

### 5.2 Reporting Vulnerabilities

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email the maintainers directly
3. Include detailed reproduction steps
4. Allow time for a fix before disclosure

## 6. Release Process

### 6.1 Versioning

We use [Semantic Versioning](https://semver.org/):

- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### 6.2 Release Checklist

1. Update version in code
2. Update CHANGELOG.md
3. Run full test suite
4. Create annotated tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. GitHub Actions builds and releases

## 7. Dependency Management

### 7.1 Dependabot

[Dependabot](https://docs.github.com/en/code-security/dependabot) keeps dependencies up to date automatically.

- **Go modules**: Weekly scan of `go.mod`
- **GitHub Actions**: Weekly scan of workflows
- PRs labeled `dependencies` + `go` or `ci`

### 7.2 Manual Updates

```bash
go get -u ./...
go mod tidy
```

## 8. Code of Conduct

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

## 9. Contributing

Contributions are welcome.

By contributing to this project, you agree to the
Contributor License Agreement (CLA).
See [CLA.md](../../CLA.md).

## 10. License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## 11. References

- [OpenSSL 3.5 ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
- [BouncyCastle PQC Almanac](https://downloads.bouncycastle.org/java/docs/PQC-Almanac.pdf)
- [Effective Go](https://go.dev/doc/effective_go)

## 12. AI-Assisted Development

This project uses AI-assisted development. See [AI_USAGE.md](../../AI_USAGE.md) for details on how AI tools are used in this project.

## 13. See Also

- [TESTING.md](TESTING.md) - Testing strategy
- [INTEROPERABILITY.md](INTEROPERABILITY.md) - Cross-validation matrix
- [../CA.md](../CA.md) - CA operations
- [../CREDENTIALS.md](../CREDENTIALS.md) - Credential management
- [../CLI-REFERENCE.md](../CLI-REFERENCE.md) - Command reference
- [../ARCHITECTURE.md](../ARCHITECTURE.md) - System design
