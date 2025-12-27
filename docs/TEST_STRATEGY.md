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
| internal/tsa | 80% |
| internal/cms | 80% |
| internal/ocsp | 80% |

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

### 3.4 TSA Operations Coverage (RFC 3161)

| Operation | Unit Test | Integration Test | OpenSSL Interop |
|-----------|-----------|------------------|-----------------|
| Parse TimeStampReq | ✓ | - | ✓ |
| Generate TSTInfo | ✓ | - | - |
| Create TimeStampResp | ✓ | ✓ | ✓ |
| Sign with CMS | ✓ | ✓ | ✓ |
| Verify token | ✓ | ✓ | - |
| HTTP server | - | ✓ | ✓ |
| CLI sign | - | ✓ | - |
| CLI verify | - | ✓ | - |

### 3.5 CMS Operations Coverage (RFC 5652)

| Operation | Unit Test | Integration Test | OpenSSL Interop |
|-----------|-----------|------------------|-----------------|
| Sign (attached) | ✓ | ✓ | ✓ |
| Sign (detached) | ✓ | ✓ | ✓ |
| Verify (attached) | ✓ | ✓ | ✓ |
| Verify (detached) | ✓ | ✓ | ✓ |
| Include certificates | ✓ | ✓ | ✓ |
| DER SET OF sorting | ✓ | - | ✓ |
| Parse SignedData | ✓ | - | - |
| `pki info` display | - | ✓ | - |

### 3.6 OCSP Operations Coverage (RFC 6960)

| Operation | Unit Test | Integration Test | OpenSSL Interop |
|-----------|-----------|------------------|-----------------|
| Parse OCSPRequest | ✓ | - | ✓ |
| Create OCSPRequest | ✓ | ✓ | ✓ |
| Parse OCSPResponse | ✓ | - | ✓ |
| Create OCSPResponse | ✓ | ✓ | ✓ |
| CertID calculation | ✓ | ✓ | - |
| Status: good | ✓ | ✓ | ✓ |
| Status: revoked | ✓ | ✓ | ✓ |
| Status: unknown | ✓ | ✓ | ✓ |
| Nonce extension | ✓ | ✓ | ✓ |
| Verify signature | ✓ | ✓ | - |
| HTTP GET transport | ✓ | ✓ | ✓ |
| HTTP POST transport | ✓ | ✓ | ✓ |
| Responder integration | - | ✓ | ✓ |
| CLI sign | - | ✓ | - |
| CLI verify | - | ✓ | - |
| CLI request | - | ✓ | - |
| CLI info | - | ✓ | - |
| CLI serve | - | ✓ | ✓ |

### 3.8 Profile/Bundle Coverage

| Feature | Unit Test | Integration Test |
|---------|-----------|------------------|
| Profile validation | ✓ | - |
| Profile loading (YAML) | ✓ | - |
| Default profiles | ✓ | ✓ |
| ProfileStore | ✓ | - |
| Bundle creation | ✓ | - |
| Bundle persistence | ✓ | - |
| Bundle lifecycle | ✓ | - |

### 3.9 Catalyst/Hybrid Coverage

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

### 4.10 TSA Tests (internal/tsa)

```
TestParseRequest
TestParseRequest_InvalidVersion
TestParseRequest_UnsupportedHash
TestCreateToken
TestResponse
TestResponseMarshal
TestNewMessageImprint
TestRandomSerialGenerator
TestAccuracyIsZero
TestGetHashLength
TestValidateHashAlgorithm
```

### 4.11 CMS Tests (internal/cms)

```
TestSign_Attached
TestSign_Detached
TestSign_IncludeCerts
TestSign_WithoutCerts
TestVerify_Attached
TestVerify_Detached
TestVerify_NoCACert
TestMarshalSignedAttrs_DERSorting
TestSortAttributes
TestParseSignedData
TestExtractSignerCert
TestComputeDigest_SHA256
TestComputeDigest_SHA384
TestComputeDigest_SHA512
TestOIDToHash
TestExtractSigningTime
```

**Note:** CMS tests are pending implementation. The package is validated through TSA and OpenSSL interoperability tests (section 6.5).

### 4.12 OCSP Tests (internal/ocsp)

```
TestParseRequest
TestParseRequest_InvalidVersion
TestParseRequest_NoRequests
TestParseRequestFromHTTP_GET
TestParseRequestFromHTTP_POST
TestCreateRequest
TestCreateRequestWithNonce
TestOCSPRequest_Marshal
TestCertID_NewCertID
TestCertID_NewCertIDFromSerial
TestCertID_MatchesCertID
TestCertID_MatchesIssuer
TestResponseBuilder_AddGood
TestResponseBuilder_AddRevoked
TestResponseBuilder_AddUnknown
TestResponseBuilder_AddNonce
TestResponseBuilder_Build
TestNewErrorResponse
TestNewMalformedResponse
TestNewInternalErrorResponse
TestParseResponse
TestVerify
TestVerify_SkipSignature
TestVerify_ExpiredResponse
TestVerify_FutureResponse
TestVerify_CertIDMismatch
TestIsGood
TestIsRevoked
TestGetResponseNonce
TestGetResponseInfo
TestValidateNonce
TestResponder_Respond
TestResponder_CheckStatus
TestResponder_CheckStatusBySerial
TestResponder_CheckStatusBySerialHex
TestResponder_CreateResponseForSerial
TestVerifyResponderCert
TestExtractCertificates
```

**Note:** OCSP tests are pending implementation. The package is validated through CLI integration tests and OpenSSL interoperability tests (section 6.6).

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
./pki ca init --name "Test Root" --dir /tmp/root-ca
./pki cert issue --ca-dir /tmp/root-ca --profile ec/issuing-ca \
  --cn "Test Issuing" --out /tmp/issuing.crt --key-out /tmp/issuing.key
./pki cert issue --ca-dir /tmp/root-ca --profile ec/tls-server \
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
./pki cert gen-crl --ca-dir /tmp/root-ca

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

### 6.4 TSA Interoperability Tests (RFC 3161)

Tests with OpenSSL 3.x (ubuntu-latest) / LibreSSL 3.3.6 (macOS).

```bash
#!/bin/bash
# test/openssl/verify_tsa.sh

set -e

# Setup
./pki ca init --name "TSA Root" --dir /tmp/tsa-ca
./pki cert issue --ca-dir /tmp/tsa-ca --profile ec/timestamping \
  --cn "Test TSA" --out /tmp/tsa.crt --key-out /tmp/tsa.key

# Test 1: PKI sign -> OpenSSL verify structure
echo "Test 1: TSA token structure"
echo "test data" > /tmp/test.txt
./pki tsa sign --data /tmp/test.txt --cert /tmp/tsa.crt --key /tmp/tsa.key -o /tmp/token.tsr
openssl ts -reply -in /tmp/token.tsr -text

# Test 2: OpenSSL request -> PKI server -> OpenSSL verify
echo "Test 2: RFC 3161 protocol"
./pki tsa serve --port 8318 --cert /tmp/tsa.crt --key /tmp/tsa.key &
TSA_PID=$!
sleep 1

openssl ts -query -data /tmp/test.txt -sha256 -out /tmp/request.tsq
curl -s -H "Content-Type: application/timestamp-query" \
  --data-binary @/tmp/request.tsq \
  http://localhost:8318/ -o /tmp/response.tsr

openssl ts -reply -in /tmp/response.tsr -text
kill $TSA_PID

echo "TSA verification: PASSED"
```

**Note:** OpenSSL cannot verify ML-DSA signatures. PQC tokens are verified internally only.

### 6.5 CMS Interoperability Tests (RFC 5652)

Tests with OpenSSL 3.x (ubuntu-latest) / LibreSSL 3.3.6 (macOS).

```bash
#!/bin/bash
# test/openssl/verify_cms.sh

set -e

# Setup
./pki ca init --name "CMS Test CA" --dir /tmp/cms-ca
./pki cert issue --ca-dir /tmp/cms-ca --profile ec/smime \
  --cn "Test Signer" --out /tmp/signer.crt --key-out /tmp/signer.key

echo "Test content for CMS signing" > /tmp/message.txt

# Test 1: PKI attached -> OpenSSL verify
echo "Test 1: PKI attached signature -> OpenSSL verify"
./pki cms sign --data /tmp/message.txt --cert /tmp/signer.crt --key /tmp/signer.key \
  --include-certs --detached=false -o /tmp/attached.p7s
openssl cms -verify -in /tmp/attached.p7s -inform DER -CAfile /tmp/cms-ca/ca.crt
echo "PASSED"

# Test 2: PKI detached -> OpenSSL verify
echo "Test 2: PKI detached signature -> OpenSSL verify"
./pki cms sign --data /tmp/message.txt --cert /tmp/signer.crt --key /tmp/signer.key \
  --include-certs -o /tmp/detached.p7s
openssl cms -verify -in /tmp/detached.p7s -inform DER \
  -content /tmp/message.txt -binary -CAfile /tmp/cms-ca/ca.crt
echo "PASSED"

# Test 3: OpenSSL attached -> PKI verify
echo "Test 3: OpenSSL attached signature -> PKI verify"
openssl cms -sign -in /tmp/message.txt -signer /tmp/signer.crt -inkey /tmp/signer.key \
  -outform DER -out /tmp/openssl-attached.p7s -nodetach -md sha256
./pki cms verify --signature /tmp/openssl-attached.p7s
echo "PASSED"

# Test 4: OpenSSL detached -> PKI verify
echo "Test 4: OpenSSL detached signature -> PKI verify"
openssl cms -sign -in /tmp/message.txt -signer /tmp/signer.crt -inkey /tmp/signer.key \
  -outform DER -out /tmp/openssl-detached.p7s -binary -md sha256
./pki cms verify --signature /tmp/openssl-detached.p7s --data /tmp/message.txt
echo "PASSED"

echo "CMS verification: ALL TESTS PASSED"
```

**Important Notes:**
- For detached signatures, OpenSSL requires `-binary` flag to prevent CRLF canonicalization
- OpenSSL cannot verify PQC (ML-DSA) signatures - those are verified internally only
- LibreSSL 3.3.6 (macOS) behaves identically to OpenSSL 3.x for these tests

### 6.6 OCSP Interoperability Tests (RFC 6960)

Tests with OpenSSL 3.x (ubuntu-latest) / LibreSSL 3.3.6 (macOS).

```bash
#!/bin/bash
# test/openssl/verify_ocsp.sh

set -e

# Setup CA and certificates
./pki ca init --name "OCSP Test CA" --dir /tmp/ocsp-ca
./pki cert issue --ca-dir /tmp/ocsp-ca --profile ec/tls-server \
  --cn "test.local" --dns test.local \
  --out /tmp/server.crt --key-out /tmp/server.key

# Test 1: PKI request -> OpenSSL verify structure
echo "Test 1: OCSP request creation"
./pki ocsp request --issuer /tmp/ocsp-ca/ca.crt --cert /tmp/server.crt \
  --nonce -o /tmp/request.ocsp
openssl ocsp -reqin /tmp/request.ocsp -text -noverify
echo "PASSED"

# Test 2: PKI response -> OpenSSL verify structure
echo "Test 2: OCSP response creation (good status)"
SERIAL=$(openssl x509 -in /tmp/server.crt -serial -noout | cut -d= -f2)
./pki ocsp sign --serial $SERIAL --status good \
  --ca /tmp/ocsp-ca/ca.crt --key /tmp/ocsp-ca/private/ca.key \
  -o /tmp/response.ocsp
openssl ocsp -respin /tmp/response.ocsp -text -noverify
echo "PASSED"

# Test 3: PKI response (revoked) -> OpenSSL verify structure
echo "Test 3: OCSP response creation (revoked status)"
./pki ocsp sign --serial $SERIAL --status revoked \
  --revocation-time "2025-01-15T10:00:00Z" --revocation-reason keyCompromise \
  --ca /tmp/ocsp-ca/ca.crt --key /tmp/ocsp-ca/private/ca.key \
  -o /tmp/revoked.ocsp
openssl ocsp -respin /tmp/revoked.ocsp -text -noverify
echo "PASSED"

# Test 4: OpenSSL request -> PKI server -> OpenSSL verify
echo "Test 4: OCSP HTTP protocol (GET + POST)"
./pki ocsp serve --port 8320 --ca-dir /tmp/ocsp-ca &
OCSP_PID=$!
sleep 1

# Test via OpenSSL client
openssl ocsp -issuer /tmp/ocsp-ca/ca.crt -cert /tmp/server.crt \
  -url http://localhost:8320/ -resp_text
kill $OCSP_PID
echo "PASSED"

# Test 5: PKI request creation with nonce
echo "Test 5: Nonce extension support"
./pki ocsp request --issuer /tmp/ocsp-ca/ca.crt --cert /tmp/server.crt \
  --nonce -o /tmp/nonce-req.ocsp
# Verify nonce is present
openssl ocsp -reqin /tmp/nonce-req.ocsp -text -noverify | grep -i nonce
echo "PASSED"

echo "OCSP verification: ALL TESTS PASSED"
```

**Important Notes:**
- OpenSSL `-noverify` is used for structure tests (signature verified internally)
- OpenSSL cannot verify PQC (ML-DSA) OCSP signatures - those are verified internally only
- OCSP stapling tests require TLS server integration (out of scope)
- LibreSSL 3.3.6 (macOS) behaves identically to OpenSSL 3.x for these tests

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
