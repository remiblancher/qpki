# Test Strategy

This document describes the testing approach, test categories, and coverage matrix for the Quantum-Safe PKI.

## 1. Approach

### 1.1 Testing Philosophy

- **Unit tests** for individual functions and methods
- **Integration tests** for complete CA workflows
- **External validation** with OpenSSL for X.509 compliance
- **All tests run without external dependencies** (no network, no HSM required)

### 1.2 Coverage Goals

| Package | Target Coverage |
|---------|-----------------|
| internal/crypto | 80% |
| internal/ca | 80% |
| internal/profiles | 90% |
| internal/x509util | 85% |

## 2. Test Categories

| Category | Purpose | Tools | Location |
|----------|---------|-------|----------|
| Unit | Individual functions | go test | `*_test.go` |
| Integration | Full CA workflows | go test | `internal/ca/*_test.go` |
| CLI | Command-line interface | go test | `cmd/pki/*_test.go` |
| Validation | X.509 compliance | OpenSSL | `test/openssl/` |

## 3. Test Matrix

### 3.1 Algorithm Coverage

| Algorithm | KeyGen | Sign | Verify | Serialize | Parse |
|-----------|--------|------|--------|-----------|-------|
| ecdsa-p256 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ecdsa-p384 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ecdsa-p521 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ed25519 | ✓ | ✓ | ✓ | ✓ | ✓ |
| rsa-2048 | ✓ | ✓ | ✓ | ✓ | ✓ |
| rsa-4096 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ml-dsa-44 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ml-dsa-65 | ✓ | ✓ | ✓ | ✓ | ✓ |
| ml-dsa-87 | ✓ | ✓ | ✓ | ✓ | ✓ |

### 3.2 Profile Coverage

| Profile | Key Usage | Ext Key Usage | SAN | Basic Constraints | OpenSSL Verify |
|---------|-----------|---------------|-----|-------------------|----------------|
| root-ca | ✓ | - | - | CA:TRUE | ✓ |
| issuing-ca | ✓ | - | - | CA:TRUE | ✓ |
| tls-server | ✓ | ✓ | ✓ | CA:FALSE | ✓ |
| tls-client | ✓ | ✓ | - | CA:FALSE | ✓ |

### 3.3 CA Operations Coverage

| Operation | Unit Test | Integration Test |
|-----------|-----------|------------------|
| Initialize CA | ✓ | ✓ |
| Load CA | ✓ | ✓ |
| Issue certificate | ✓ | ✓ |
| Issue Catalyst certificate | ✓ | ✓ |
| Revoke certificate | ✓ | ✓ |
| Generate CRL | ✓ | ✓ |
| List certificates | ✓ | ✓ |
| Parse index file | ✓ | ✓ |
| Enroll with profile | ✓ | ✓ |
| Bundle management | ✓ | ✓ |

### 3.4 Profile/Bundle Coverage

| Feature | Unit Test | Integration Test |
|---------|-----------|------------------|
| Profile validation | ✓ | - |
| Profile loading (YAML) | ✓ | - |
| Default profiles | ✓ | ✓ |
| ProfileStore | ✓ | - |
| Bundle creation | ✓ | - |
| Bundle persistence | ✓ | - |
| Bundle lifecycle | ✓ | - |

### 3.5 Catalyst/Hybrid Coverage

| Feature | Unit Test | Integration Test |
|---------|-----------|------------------|
| HybridSigner creation | ✓ | - |
| HybridSigner SignHybrid | ✓ | - |
| HybridSigner persistence | ✓ | - |
| Catalyst extensions encode | ✓ | - |
| Catalyst extensions decode | ✓ | - |
| RelatedCertificate | ✓ | - |
| Hybrid CSR creation | ✓ | - |

## 4. Test List

### 4.1 Unit Tests (internal/crypto)

```
TestGenerateKey_ECDSA_P256
TestGenerateKey_ECDSA_P384
TestGenerateKey_ECDSA_P521
TestGenerateKey_Ed25519
TestGenerateKey_RSA2048
TestGenerateKey_RSA4096
TestGenerateKey_MLDSA44
TestGenerateKey_MLDSA65
TestGenerateKey_MLDSA87
TestSign_ECDSA
TestSign_Ed25519
TestSign_RSA
TestSign_MLDSA
TestVerify_ECDSA
TestVerify_Ed25519
TestVerify_RSA
TestVerify_MLDSA
TestSerializePrivateKey
TestParsePrivateKey
TestSerializePrivateKey_Encrypted
TestParsePrivateKey_Encrypted
TestAlgorithmFromString
TestAlgorithm_String
TestAlgorithm_IsPQC
TestAlgorithm_IsClassical
```

### 4.2 Unit Tests (internal/profiles)

```
TestRootCAProfile_Apply
TestRootCAProfile_Validate
TestIssuingCAProfile_Apply
TestIssuingCAProfile_Validate
TestTLSServerProfile_Apply
TestTLSServerProfile_Validate
TestTLSClientProfile_Apply
TestTLSClientProfile_Validate
TestProfileFromString
```

### 4.3 Unit Tests (internal/x509util)

```
TestBuilder_Build
TestBuilder_SetProfile
TestBuilder_AddDNS
TestBuilder_AddIP
TestBuilder_AddEmail
TestSubjectKeyID
TestAuthorityKeyID
TestHybridExtension_Encode
TestHybridExtension_Decode
TestOID_MLDSA
TestOID_MLKEM
```

### 4.4 Integration Tests (internal/ca)

```
TestCA_Initialize
TestCA_Initialize_WithPassphrase
TestCA_Initialize_AllAlgorithms
TestCA_Load
TestCA_Load_WithPassphrase
TestCA_IssueTLSServer
TestCA_IssueTLSServer_WithDNS
TestCA_IssueTLSServer_WithIP
TestCA_IssueTLSClient
TestCA_IssueIssuingCA
TestCA_Revoke
TestCA_Revoke_Reasons
TestCA_GenerateCRL
TestCA_GenerateCRL_Empty
TestCA_GenerateCRL_Multiple
TestStore_NextSerial
TestStore_SaveCertificate
TestStore_LoadCertificate
TestStore_ReadIndex
TestStore_WriteIndex
TestStore_MarkRevoked
TestStore_ListRevoked
TestStore_IsRevoked
TestParseRevocationReason
TestRevocationReason_String
```

### 4.5 Hybrid/PQC Tests (internal/crypto)

```
TestNewHybridSigner
TestNewHybridSigner_NilClassical
TestNewHybridSigner_NilPQC
TestNewHybridSigner_WrongClassicalType
TestNewHybridSigner_WrongPQCType
TestGenerateHybridSigner
TestHybridSigner_SignHybrid
TestHybridSigner_VerifyHybrid
TestHybridSigner_ClassicalSigner
TestHybridSigner_PQCSigner
TestHybridSigner_ClassicalPublicKey
TestHybridSigner_PQCPublicKey
TestSaveHybridKeys
TestLoadHybridSigner
TestSaveHybridKeyBundle
TestLoadHybridSignerBundle
TestHybridKeyPair_ToHybridSigner
TestHybridSigner_SignHybrid_EmptyMessage
TestHybridSigner_SignHybrid_LargeMessage
```

### 4.6 Extensions Tests (internal/x509util)

```
TestEncodeHybridExtension_Valid
TestEncodeHybridExtension_NonPQCAlgorithm
TestDecodeHybridExtension
TestFindHybridExtension_NotFound
TestHasHybridExtension
TestParseHybridExtension
TestEncodeAltSubjectPublicKeyInfo
TestDecodeAltSubjectPublicKeyInfo
TestEncodeAltSignatureAlgorithm
TestDecodeAltSignatureAlgorithm
TestEncodeAltSignatureValue
TestDecodeAltSignatureValue
TestFindCatalystExtensions
TestFindCatalystExtensions_NotFound
TestFindCatalystExtensions_Partial
TestHasCatalystExtensions
TestIsCatalystComplete
TestParseCatalystExtensions
TestEncodeRelatedCertificate
TestDecodeRelatedCertificate
TestFindRelatedCertificateExtension
TestHasRelatedCertificate
TestVerifyRelatedCertificate
TestParseRelatedCertificate
TestOIDToString
TestOidToAlgorithm
TestCatalystExtensions_RoundTrip
TestRelatedCertificate_RoundTrip
```

### 4.7 CSR Tests (internal/x509util)

```
TestCreateSimpleCSR
TestCreateSimpleCSR_NoSigner
TestCreateSimpleCSR_WithEmailAddresses
TestCreateHybridCSR
TestCreateHybridCSR_NilClassicalSigner
TestCreateHybridCSR_NilPQCSigner
TestHybridCSR_IsHybrid
TestHybridCSR_IsHybrid_NonHybrid
TestHybridCSR_DER
TestHybridCSR_Verify
TestHybridCSR_Verify_MissingAltKey
TestHybridCSR_Verify_MissingAltSignature
TestHybridCSR_Verify_InvalidPQCSignature
TestParseHybridCSR
TestParseHybridCSR_NonHybrid
TestParseHybridCSR_InvalidDER
TestCreateHybridCSRFromSigner
TestCSRAttributeOIDs
TestCreateHybridCSR_EmptySubject
TestCreateHybridCSR_WithMLDSA44
TestCreateHybridCSR_WithMLDSA87
```

### 4.8 Policy/Profile Tests (internal/policy)

```
TestProfile_Validate
TestProfile_Validate_Invalid
TestProfile_Validate_Modes
TestProfile_Validate_Algorithms
TestProfile_CertificateCount
TestProfile_IsHybridSignature
TestProfile_IsSeparateSignature
TestProfile_IsCatalystSignature
TestProfile_IsHybridEncryption
TestProfile_HasEncryption
TestLoadProfileFromBytes
TestLoadProfileFromBytes_Invalid
TestLoadProfilesFromDirectory
TestParseDuration
TestProfileStore_SaveLoadList
TestProfileStore_All
TestDefaultProfiles
TestInstallDefaultProfiles
```

### 4.9 Bundle Tests (internal/bundle)

```
TestNewBundle
TestBundle_AddCertificate
TestBundle_SetValidity
TestBundle_Activate
TestBundle_Revoke
TestBundle_IsValid
TestBundle_IsExpired
TestBundle_ContainsCertificate
TestBundle_GetCertificateByRole
TestBundle_GetCertificateBySerial
TestBundle_SignatureCertificates
TestBundle_EncryptionCertificates
TestSubject_ToPkixName
TestSubjectFromPkixName
TestBundle_MarshalJSON
TestBundle_UnmarshalJSON
TestEncodeCertificatesPEM
TestDecodeCertificatesPEM
TestEncodeKeysPEM
TestFileStore_SaveLoad
TestFileStore_LoadCertificates
TestFileStore_LoadKeys
TestFileStore_List
TestFileStore_UpdateStatus
TestFileStore_Delete
```

## 5. Running Tests

### 5.1 All Tests

```bash
go test -v ./...
```

### 5.2 With Coverage

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### 5.3 Race Detection

```bash
go test -v -race ./...
```

### 5.4 Specific Package

```bash
go test -v ./internal/crypto/...
go test -v ./internal/ca/...
```

### 5.5 Specific Test

```bash
go test -v -run TestCA_Initialize ./internal/ca/
```

## 6. OpenSSL Validation

### 6.1 Verify Certificate Chain

```bash
#!/bin/bash
# test/openssl/verify_chain.sh

set -e

# Generate test PKI
./pki init-ca --name "Test Root" --dir /tmp/root-ca
./pki issue --ca-dir /tmp/root-ca --profile ecdsa/issuing-ca \
  --cn "Test Issuing" --out /tmp/issuing.crt --key-out /tmp/issuing.key
./pki issue --ca-dir /tmp/root-ca --profile ecdsa/tls-server \
  --cn test.local --out /tmp/leaf.crt --key-out /tmp/leaf.key

# Verify with OpenSSL
openssl verify -CAfile /tmp/root-ca/ca.crt /tmp/issuing.crt
openssl verify -CAfile /tmp/root-ca/ca.crt -untrusted /tmp/issuing.crt /tmp/leaf.crt

echo "Chain verification: PASSED"
```

### 6.2 Verify CRL

```bash
#!/bin/bash
# test/openssl/verify_crl.sh

set -e

# Generate CRL
./pki gen-crl --ca-dir /tmp/root-ca

# Verify CRL format
openssl crl -in /tmp/root-ca/crl/ca.crl -text -noout

# Verify CRL signature
openssl crl -in /tmp/root-ca/crl/ca.crl -CAfile /tmp/root-ca/ca.crt -verify

echo "CRL verification: PASSED"
```

### 6.3 Verify Key Usage

```bash
#!/bin/bash
# test/openssl/verify_extensions.sh

set -e

# Check CA certificate
KU=$(openssl x509 -in /tmp/root-ca/ca.crt -text -noout | grep "Key Usage")
if [[ ! "$KU" =~ "Certificate Sign" ]]; then
  echo "ERROR: CA missing Certificate Sign key usage"
  exit 1
fi

# Check server certificate
EKU=$(openssl x509 -in /tmp/leaf.crt -text -noout | grep -A1 "Extended Key Usage")
if [[ ! "$EKU" =~ "TLS Web Server Authentication" ]]; then
  echo "ERROR: Server cert missing TLS Server EKU"
  exit 1
fi

echo "Extensions verification: PASSED"
```

## 7. CI Integration

Tests run automatically on:
- Push to `main` branch
- Pull requests to `main` branch

### 7.1 GitHub Actions Workflow

See `.github/workflows/ci.yml` for the complete CI configuration.

### 7.2 Required Checks

| Check | Required | Description |
|-------|----------|-------------|
| Unit tests | Yes | All unit tests must pass |
| Race detection | Yes | No race conditions |
| Lint | Yes | golangci-lint must pass |
| Build | Yes | Binary must compile |

## 8. Test Data

### 8.1 Test Fixtures

Test fixtures are generated dynamically using `t.TempDir()` to ensure isolation between tests.

### 8.2 Golden Files

No golden files are used. All expected values are computed or defined inline.

## 9. Mocking

### 9.1 Approach

- No external mocking libraries
- Interface-based dependency injection
- Test doubles implemented as needed

### 9.2 Example

```go
// mockSigner implements crypto.Signer for testing
type mockSigner struct {
    publicKey crypto.PublicKey
    signFunc  func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (m *mockSigner) Public() crypto.PublicKey {
    return m.publicKey
}

func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    return m.signFunc(rand, digest, opts)
}
```

## 10. Performance Testing

### 10.1 Benchmarks

```bash
go test -bench=. ./internal/crypto/
```

### 10.2 Key Benchmarks

```
BenchmarkGenerateKey_ECDSA_P256
BenchmarkGenerateKey_MLDSA65
BenchmarkSign_ECDSA_P256
BenchmarkSign_MLDSA65
BenchmarkVerify_ECDSA_P256
BenchmarkVerify_MLDSA65
```
