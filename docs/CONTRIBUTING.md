# Contributing

Thank you for your interest in contributing to the Post-Quantum PKI (QPKI) project!

## 1. Getting Started

### 1.1 Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for convenience commands)

### 1.2 Clone the Repository

```bash
git clone https://github.com/remiblancher/post-quantum-pki.git
cd pki
```

### 1.3 Build and Test

```bash
# Build
go build -o pki ./cmd/pki

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

test(profiles): add TLS client profile tests
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

We use `golangci-lint` with the following linters:

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gofmt
    - goimports
```

Run locally:
```bash
golangci-lint run
```

### 3.3 Documentation

- All exported functions must have doc comments
- Doc comments should start with the function name
- Include examples for complex functions

```go
// GenerateKey creates a new cryptographic key pair.
//
// Supported algorithms: ecdsa-p256, ecdsa-p384, ed25519, rsa-2048, rsa-4096,
// ml-dsa-44, ml-dsa-65, ml-dsa-87.
//
// Example:
//
//	signer, err := crypto.GenerateKey(crypto.AlgECDSAP256)
//	if err != nil {
//	    log.Fatal(err)
//	}
func GenerateKey(alg AlgorithmID) (Signer, error) {
    // ...
}
```

## 4. Testing

### 4.1 Test Requirements

- All new code must have tests
- Minimum 80% coverage for new code
- Tests must pass with race detection

### 4.2 Test Structure

```go
func TestFunctionName_Scenario(t *testing.T) {
    // Arrange
    input := ...

    // Act
    result, err := FunctionName(input)

    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

### 4.3 Table-Driven Tests

Preferred for multiple test cases:

```go
func TestParseAlgorithm(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    AlgorithmID
        wantErr bool
    }{
        {"ecdsa p256", "ecdsa-p256", AlgECDSAP256, false},
        {"invalid", "invalid", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseAlgorithm(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("got %v, want %v", got, tt.want)
            }
        })
    }
}
```

### 4.4 Test Isolation

- Use `t.TempDir()` for file-based tests
- Don't rely on global state
- Clean up resources in tests

## 5. Project Structure

### 5.1 Adding New Algorithms

1. Add algorithm constant to `internal/crypto/algorithms.go`
2. Add OID to `internal/x509util/oids.go`
3. Implement key generation in `internal/crypto/keygen.go`
4. Add signing support in `internal/crypto/software.go`
5. Add tests for all operations
6. Update documentation

### 5.2 Adding New Certificate Profiles

1. Create new file in `internal/profiles/`
2. Implement `Profile` interface
3. Register in profile registry
4. Add CLI support in `cmd/pki/issue.go`
5. Add tests
6. Update USER_GUIDE.md

### 5.3 Adding CLI Commands

1. Create new file in `cmd/pki/`
2. Define cobra command with flags
3. Register in `init()` function
4. Add tests
5. Update USER_GUIDE.md

## 6. Security

### 6.1 Security Considerations

- Never log sensitive data (private keys, passphrases)
- Use constant-time comparisons for secrets
- Validate all inputs
- Handle errors properly (don't ignore them)

### 6.2 Reporting Vulnerabilities

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email the maintainers directly
3. Include detailed reproduction steps
4. Allow time for a fix before disclosure

## 7. Release Process

### 7.1 Versioning

We use [Semantic Versioning](https://semver.org/):

- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### 7.2 Release Checklist

1. Update version in code
2. Update CHANGELOG.md
3. Run full test suite
4. Create annotated tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. GitHub Actions builds and releases

## 8. Getting Help

- Open an issue for questions
- Tag issues appropriately (`question`, `bug`, `enhancement`)
- Check existing issues before opening new ones

## 9. Code of Conduct

### 9.1 Expected Behavior

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what is best for the community
- Show empathy towards others

### 9.2 Unacceptable Behavior

- Harassment or discrimination
- Trolling or personal attacks
- Publishing others' private information
- Other unprofessional conduct

## 10. License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
