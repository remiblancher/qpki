//go:build acceptance

package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// COSE Sign and Verify Tests (TestA_COSE_*)
//
// Tests for COSE (CBOR Object Signing and Encryption) and CWT (CBOR Web Token).
// Covers classical algorithms (EC, RSA), post-quantum (ML-DSA, SLH-DSA),
// and hybrid modes (Catalyst, Composite).
// =============================================================================

// =============================================================================
// 2.1 Classical Algorithms (EC, RSA)
// =============================================================================

func TestA_COSE_Sign1_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE EC CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)
	assertFileExists(t, signedPath)

	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")

	info := runQPKI(t, "cose", "info", signedPath)
	assertOutputContains(t, info, "Sign1")
}

func TestA_COSE_Sign1_RSA(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "COSE RSA CA")

	signCred := enrollCredentialWithInfo(t, caDir, "rsa/signing", "cn=RSA COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_CWT_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE EC CWT CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://issuer.example.com",
		"--sub", "user-123",
		"--exp", "1h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)
	assertFileExists(t, tokenPath)

	output := runQPKI(t, "cose", "verify", tokenPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")

	info := runQPKI(t, "cose", "info", tokenPath)
	assertOutputContains(t, info, "CWT")
	assertOutputContains(t, info, "user-123")
}

// =============================================================================
// 2.2 ML-DSA Algorithms
// =============================================================================

func TestA_COSE_Sign1_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ml/root-ca", "COSE ML-DSA-65 CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ml/signing", "cn=ML-DSA-65 COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_CWT_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ml/root-ca", "COSE ML-DSA CWT CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ml/signing", "cn=ML-DSA CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://pqc-issuer.example.com",
		"--sub", "quantum-user",
		"--exp", "24h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", tokenPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

// =============================================================================
// 2.2b SLH-DSA Algorithms
// =============================================================================

func TestA_COSE_Sign1_SLHDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "slh-dsa-sha2-128f")
	caDir := setupCA(t, "slh/root-ca", "COSE SLH-DSA-SHA2-128f CA")

	signCred := enrollCredentialWithInfo(t, caDir, "slh/signing", "cn=SLH-DSA COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_CWT_SLHDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "slh-dsa-sha2-128f")
	caDir := setupCA(t, "slh/root-ca", "COSE SLH-DSA CWT CA")

	signCred := enrollCredentialWithInfo(t, caDir, "slh/signing", "cn=SLH-DSA CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://slhdsa-issuer.example.com",
		"--sub", "sphincs-user",
		"--exp", "1h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", tokenPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

// =============================================================================
// 2.3 Hybrid Modes (Catalyst and Composite)
// =============================================================================

func TestA_COSE_Sign_Catalyst(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "COSE Catalyst CA")

	signCred := enrollCredentialWithInfo(t, caDir, "hybrid/catalyst/signing", "cn=Catalyst COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for hybrid COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")

	info := runQPKI(t, "cose", "info", signedPath)
	assertOutputContains(t, info, "Sign")
}

func TestA_COSE_Sign_Composite(t *testing.T) {
	// COSE does not support composite algorithms directly.
	// Composite certificates use a single combined algorithm (EC+ML-DSA in one signature),
	// but COSE only supports single classical/PQC algorithms or multiple signatures (Catalyst mode).
	// For hybrid COSE, use Catalyst mode (TestA_COSE_Sign_Catalyst) instead.
	t.Skip("COSE does not support composite algorithms - use Catalyst hybrid mode instead")
}

func TestA_COSE_CWT_Catalyst(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "COSE Catalyst CWT CA")

	signCred := enrollCredentialWithInfo(t, caDir, "hybrid/catalyst/signing", "cn=Catalyst CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://hybrid-issuer.example.com",
		"--sub", "hybrid-user",
		"--exp", "1h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	output := runQPKI(t, "cose", "verify", tokenPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_CWT_Composite(t *testing.T) {
	// COSE does not support composite algorithms directly.
	// Composite certificates use a single combined algorithm (EC+ML-DSA in one signature),
	// but COSE only supports single classical/PQC algorithms or multiple signatures (Catalyst mode).
	// For hybrid CWT, use Catalyst mode (TestA_COSE_CWT_Catalyst) instead.
	t.Skip("COSE does not support composite algorithms - use Catalyst hybrid mode instead")
}

// =============================================================================
// 2.4 HSM-Specific Tests
// =============================================================================

func TestA_COSE_HSM_Sign1_EC(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "cose-ec-" + randomSuffix()

	// Generate EC key in HSM
	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Create self-signed certificate for the key
	caDir := t.TempDir()
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--use-existing-key",
		"--profile", "ec/root-ca",
		"--var", "cn=HSM COSE EC CA",
		"--ca-dir", caDir,
	)
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	// Sign data using HSM key
	testData := writeTestFile(t, "hsm-cose-data.txt", "Test data for HSM COSE signing")
	outputPath := filepath.Join(t.TempDir(), "hsm-signed.cbor")

	runQPKI(t, "cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", filepath.Join(caDir, "ca.crt"),
		"--include-certs",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--out", outputPath,
	)

	// Verify
	output := runQPKI(t, "cose", "verify", outputPath,
		"--ca", filepath.Join(caDir, "ca.crt"),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_HSM_Sign1_MLDSA(t *testing.T) {
	skipIfNoPQCHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "cose-mldsa-" + randomSuffix()

	// Generate ML-DSA key in HSM
	runQPKI(t, "key", "gen",
		"--algorithm", "ml-dsa-65",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Create self-signed certificate
	caDir := t.TempDir()
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--use-existing-key",
		"--profile", "ml/root-ca",
		"--var", "cn=HSM COSE ML-DSA CA",
		"--ca-dir", caDir,
	)
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	// Sign CWT
	outputPath := filepath.Join(t.TempDir(), "hsm-mldsa.cbor")

	runQPKI(t, "cose", "sign",
		"--type", "cwt",
		"--iss", "https://hsm-pqc.example.com",
		"--sub", "hsm-user",
		"--exp", "1h",
		"--cert", filepath.Join(caDir, "ca.crt"),
		"--include-certs",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--out", outputPath,
	)

	// Verify
	output := runQPKI(t, "cose", "verify", outputPath,
		"--ca", filepath.Join(caDir, "ca.crt"),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_HSM_Hybrid(t *testing.T) {
	skipIfNoPQCHSM(t)
	configPath := getHSMConfigPath(t)

	// Use same label for both keys (hybrid mode)
	keyLabel := "cose-hybrid-" + randomSuffix()

	// Generate EC key
	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Generate ML-DSA key with same label
	runQPKI(t, "key", "gen",
		"--algorithm", "ml-dsa-65",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Create hybrid certificate
	caDir := t.TempDir()
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--use-existing-key",
		"--profile", "hybrid/catalyst/root-ca",
		"--var", "cn=HSM Hybrid COSE CA",
		"--ca-dir", caDir,
	)
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	// Sign with hybrid keys
	testData := writeTestFile(t, "hybrid-data.txt", "Hybrid COSE test data")
	outputPath := filepath.Join(t.TempDir(), "hsm-hybrid.cbor")

	runQPKI(t, "cose", "sign",
		"--type", "sign",
		"--data", testData,
		"--cert", filepath.Join(caDir, "ca.crt"),
		"--include-certs",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--out", outputPath,
	)

	// Verify
	output := runQPKI(t, "cose", "verify", outputPath,
		"--ca", filepath.Join(caDir, "ca.crt"),
	)
	assertOutputContains(t, output, "VALID")
}

// =============================================================================
// 2.5 Validation and Error Tests
// =============================================================================

func TestA_COSE_Verify_OK(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Verify OK CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for verification")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify with correct CA
	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_Verify_EmbeddedPayload(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Verify Embedded CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for embedded verification")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	// Sign with embedded payload
	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify the signed message (payload is embedded in COSE Sign1)
	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_Verify_CertChain(t *testing.T) {
	// Create root CA
	rootCADir := setupCA(t, "ec/root-ca", "COSE Root CA")

	// Create subordinate CA
	subCADir := setupSubordinateCA(t, "ec/issuing-ca", "COSE Sub CA", rootCADir)

	// Issue credential from subordinate CA
	signCred := enrollCredentialWithInfo(t, subCADir, "ec/signing", "cn=Chain COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for chain verification")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify with sub CA directly
	output := runQPKI(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, subCADir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_COSE_Verify_InvalidSignature(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Invalid Sig CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data for COSE signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Read and tamper with the message
	data, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("failed to read signed message: %v", err)
	}

	// Tamper with last byte (part of signature)
	data[len(data)-1] ^= 0xFF

	tamperedPath := filepath.Join(dir, "tampered.cbor")
	if err := os.WriteFile(tamperedPath, data, 0644); err != nil {
		t.Fatalf("failed to write tampered message: %v", err)
	}

	// Verification should fail
	runQPKIExpectError(t, "cose", "verify", tamperedPath,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_COSE_CWT_Expiration(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Expiration CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	// Create CWT with expiration
	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://issuer.example.com",
		"--sub", "test-user",
		"--exp", "1h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify with expiration check (should pass since not expired)
	output := runQPKI(t, "cose", "verify", tokenPath,
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")

	// Verify that info shows expiration
	info := runQPKI(t, "cose", "info", tokenPath)
	assertOutputContains(t, info, "Exp")
}

func TestA_COSE_Verify_WrongCA(t *testing.T) {
	// Create two separate CAs
	caDir1 := setupCA(t, "ec/root-ca", "COSE CA 1")
	caDir2 := setupCA(t, "ec/root-ca", "COSE CA 2")

	signCred := enrollCredentialWithInfo(t, caDir1, "ec/signing", "cn=Signer CA1")

	testData := writeTestFile(t, "cose-data.txt", "Test data")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify with wrong CA should fail chain validation
	runQPKIExpectError(t, "cose", "verify", signedPath,
		"--ca", getCACert(t, caDir2),
	)
}

func TestA_COSE_Sign_MissingKey(t *testing.T) {
	dir := t.TempDir()
	testData := writeTestFile(t, "data.txt", "Test data")

	// Sign without key should fail
	runQPKIExpectError(t, "cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--out", filepath.Join(dir, "output.cbor"),
	)
}

// =============================================================================
// 2.6 Info Command Tests
// =============================================================================

func TestA_COSE_Info_Sign1(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Info Sign1 CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign1",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	info := runQPKI(t, "cose", "info", signedPath)
	assertOutputContains(t, info, "Sign1")
	assertOutputContains(t, info, "Algorithm")
}

func TestA_COSE_Info_CWT(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "COSE Info CWT CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC CWT Issuer")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.cbor")

	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--iss", "https://info-test.example.com",
		"--sub", "info-user",
		"--exp", "1h",
		"--out", tokenPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	info := runQPKI(t, "cose", "info", tokenPath)
	assertOutputContains(t, info, "CWT")
	assertOutputContains(t, info, "https://info-test.example.com")
	assertOutputContains(t, info, "info-user")
}

func TestA_COSE_Info_Hybrid(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)

	caDir := setupCA(t, "hybrid/catalyst/root-ca", "COSE Info Hybrid CA")

	signCred := enrollCredentialWithInfo(t, caDir, "hybrid/catalyst/signing", "cn=Hybrid COSE Signer")

	testData := writeTestFile(t, "cose-data.txt", "Test data")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.cbor")

	args := []string{
		"cose", "sign",
		"--type", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--include-certs",
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	info := runQPKI(t, "cose", "info", signedPath)
	assertOutputContains(t, info, "Sign")
}

// =============================================================================
// 2.7 Crypto-Agility Tests
// =============================================================================

// TestA_COSE_Agility_EC_To_MLDSA tests signing with EC then ML-DSA (parallel PKIs).
func TestA_COSE_Agility_EC_To_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")

	// Phase 1: EC PKI
	ecCADir := setupCA(t, "ec/root-ca", "COSE EC Phase")
	ecCred := enrollCredentialWithInfo(t, ecCADir, "ec/signing", "cn=EC COSE Signer")

	ecTokenPath := filepath.Join(t.TempDir(), "ec-token.cbor")
	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, ecCred.Dir),
		"--include-certs",
		"--iss", "https://ec-issuer.example.com",
		"--sub", "phase1-user",
		"--exp", "24h",
		"--out", ecTokenPath,
	}
	args = append(args, ecCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ecCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cose", "verify", ecTokenPath, "--ca", getCACert(t, ecCADir))

	// Phase 2: ML-DSA PKI
	mlCADir := setupCA(t, "ml/root-ca", "COSE ML-DSA Phase")
	mlCred := enrollCredentialWithInfo(t, mlCADir, "ml/signing", "cn=ML-DSA COSE Signer")

	mlTokenPath := filepath.Join(t.TempDir(), "mldsa-token.cbor")
	args = []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, mlCred.Dir),
		"--include-certs",
		"--iss", "https://mldsa-issuer.example.com",
		"--sub", "phase2-user",
		"--exp", "24h",
		"--out", mlTokenPath,
	}
	args = append(args, mlCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, mlCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cose", "verify", mlTokenPath, "--ca", getCACert(t, mlCADir))

	// Both tokens should still be verifiable with their respective CAs
	runQPKI(t, "cose", "verify", ecTokenPath, "--ca", getCACert(t, ecCADir))
	runQPKI(t, "cose", "verify", mlTokenPath, "--ca", getCACert(t, mlCADir))
}

// TestA_COSE_Agility_EC_Catalyst_PQ tests EC -> Catalyst -> ML-DSA parallel PKIs.
func TestA_COSE_Agility_EC_Catalyst_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)

	// Phase 1: EC
	ecCADir := setupCA(t, "ec/root-ca", "Agility EC CA")
	ecCred := enrollCredentialWithInfo(t, ecCADir, "ec/signing", "cn=EC Signer")
	ecTokenPath := filepath.Join(t.TempDir(), "ec.cbor")
	args := []string{"cose", "sign", "--type", "cwt", "--cert", getCredentialCert(t, ecCred.Dir),
		"--include-certs", "--iss", "https://ec.example.com", "--sub", "ec-user", "--exp", "1h", "--out", ecTokenPath}
	args = append(args, ecCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ecCred.Dir))...)
	runQPKI(t, args...)
	runQPKI(t, "cose", "verify", ecTokenPath, "--ca", getCACert(t, ecCADir))

	// Phase 2: Catalyst (Hybrid)
	catCADir := setupCA(t, "hybrid/catalyst/root-ca", "Agility Catalyst CA")
	catCred := enrollCredentialWithInfo(t, catCADir, "hybrid/catalyst/signing", "cn=Catalyst Signer")
	catTokenPath := filepath.Join(t.TempDir(), "catalyst.cbor")
	args = []string{"cose", "sign", "--type", "cwt", "--cert", getCredentialCert(t, catCred.Dir),
		"--include-certs", "--iss", "https://catalyst.example.com", "--sub", "catalyst-user", "--exp", "1h", "--out", catTokenPath}
	args = append(args, catCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, catCred.Dir))...)
	runQPKI(t, args...)
	runQPKI(t, "cose", "verify", catTokenPath, "--ca", getCACert(t, catCADir))

	// Phase 3: ML-DSA only
	mlCADir := setupCA(t, "ml/root-ca", "Agility ML-DSA CA")
	mlCred := enrollCredentialWithInfo(t, mlCADir, "ml/signing", "cn=ML-DSA Signer")
	mlTokenPath := filepath.Join(t.TempDir(), "mldsa.cbor")
	args = []string{"cose", "sign", "--type", "cwt", "--cert", getCredentialCert(t, mlCred.Dir),
		"--include-certs", "--iss", "https://mldsa.example.com", "--sub", "mldsa-user", "--exp", "1h", "--out", mlTokenPath}
	args = append(args, mlCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, mlCred.Dir))...)
	runQPKI(t, args...)
	runQPKI(t, "cose", "verify", mlTokenPath, "--ca", getCACert(t, mlCADir))

	// All tokens verifiable
	runQPKI(t, "cose", "verify", ecTokenPath, "--ca", getCACert(t, ecCADir))
	runQPKI(t, "cose", "verify", catTokenPath, "--ca", getCACert(t, catCADir))
	runQPKI(t, "cose", "verify", mlTokenPath, "--ca", getCACert(t, mlCADir))
}

// TestA_COSE_Agility_VerifyOldTokenAfterRotation tests that old CWTs remain valid after CA rotation.
func TestA_COSE_Agility_VerifyOldTokenAfterRotation(t *testing.T) {
	// Create CA and issue token
	caDir := setupCA(t, "ec/root-ca", "Rotation Test CA")
	cred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=Rotation Signer")

	tokenPath := filepath.Join(t.TempDir(), "old-token.cbor")
	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, cred.Dir),
		"--include-certs",
		"--iss", "https://rotation.example.com",
		"--sub", "old-user",
		"--exp", "24h",
		"--out", tokenPath,
	}
	args = append(args, cred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, cred.Dir))...)
	runQPKI(t, args...)

	// Verify original token
	runQPKI(t, "cose", "verify", tokenPath, "--ca", getCACert(t, caDir))

	// Issue a new credential (simulating rotation)
	newCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=New Rotation Signer")
	newTokenPath := filepath.Join(t.TempDir(), "new-token.cbor")
	args = []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, newCred.Dir),
		"--include-certs",
		"--iss", "https://rotation.example.com",
		"--sub", "new-user",
		"--exp", "24h",
		"--out", newTokenPath,
	}
	args = append(args, newCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, newCred.Dir))...)
	runQPKI(t, args...)

	// Both old and new tokens should be verifiable
	runQPKI(t, "cose", "verify", tokenPath, "--ca", getCACert(t, caDir))
	runQPKI(t, "cose", "verify", newTokenPath, "--ca", getCACert(t, caDir))
}

// TestA_COSE_Agility_HybridTransition tests transition from EC through hybrid to ML-DSA only.
func TestA_COSE_Agility_HybridTransition(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)

	// Start with EC
	ecCADir := setupCA(t, "ec/root-ca", "Transition EC CA")
	ecCred := enrollCredentialWithInfo(t, ecCADir, "ec/signing", "cn=EC Signer")

	// Transition to hybrid (both EC and ML-DSA)
	hybridCADir := setupCA(t, "hybrid/catalyst/root-ca", "Transition Hybrid CA")
	hybridCred := enrollCredentialWithInfo(t, hybridCADir, "hybrid/catalyst/signing", "cn=Hybrid Signer")

	// End with ML-DSA only
	mlCADir := setupCA(t, "ml/root-ca", "Transition ML-DSA CA")
	mlCred := enrollCredentialWithInfo(t, mlCADir, "ml/signing", "cn=ML-DSA Signer")

	// Sign with each credential - all use CWT type (hybrid CWT automatically creates multi-signature)
	tokens := make(map[string]string)
	for name, info := range map[string]struct {
		cred  CredentialInfo
		caDir string
	}{
		"ec":     {ecCred, ecCADir},
		"hybrid": {hybridCred, hybridCADir},
		"mldsa":  {mlCred, mlCADir},
	} {
		tokenPath := filepath.Join(t.TempDir(), name+".cbor")
		tokens[name] = tokenPath

		args := []string{
			"cose", "sign",
			"--type", "cwt", // CWT type - hybrid mode auto-creates multi-signature
			"--cert", getCredentialCert(t, info.cred.Dir),
			"--include-certs",
			"--iss", "https://" + name + ".example.com",
			"--sub", name + "-user",
			"--exp", "1h",
			"--out", tokenPath,
		}
		args = append(args, info.cred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, info.cred.Dir))...)
		runQPKI(t, args...)

		runQPKI(t, "cose", "verify", tokenPath, "--ca", getCACert(t, info.caDir))
	}
}

// TestA_COSE_Agility_MultipleIssuers tests verification with multiple issuer CAs.
func TestA_COSE_Agility_MultipleIssuers(t *testing.T) {
	// Create multiple CAs
	ca1Dir := setupCA(t, "ec/root-ca", "Multi-Issuer CA 1")
	ca2Dir := setupCA(t, "ec/root-ca", "Multi-Issuer CA 2")

	cred1 := enrollCredentialWithInfo(t, ca1Dir, "ec/signing", "cn=Issuer 1")
	cred2 := enrollCredentialWithInfo(t, ca2Dir, "ec/signing", "cn=Issuer 2")

	// Sign tokens from each issuer
	token1Path := filepath.Join(t.TempDir(), "issuer1.cbor")
	args := []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, cred1.Dir),
		"--include-certs",
		"--iss", "https://issuer1.example.com",
		"--sub", "user1",
		"--exp", "1h",
		"--out", token1Path,
	}
	args = append(args, cred1.KeyConfig.buildSignKeyArgs(getCredentialKey(t, cred1.Dir))...)
	runQPKI(t, args...)

	token2Path := filepath.Join(t.TempDir(), "issuer2.cbor")
	args = []string{
		"cose", "sign",
		"--type", "cwt",
		"--cert", getCredentialCert(t, cred2.Dir),
		"--include-certs",
		"--iss", "https://issuer2.example.com",
		"--sub", "user2",
		"--exp", "1h",
		"--out", token2Path,
	}
	args = append(args, cred2.KeyConfig.buildSignKeyArgs(getCredentialKey(t, cred2.Dir))...)
	runQPKI(t, args...)

	// Each token verifies with its own CA
	runQPKI(t, "cose", "verify", token1Path, "--ca", getCACert(t, ca1Dir))
	runQPKI(t, "cose", "verify", token2Path, "--ca", getCACert(t, ca2Dir))

	// Cross-verification should fail
	runQPKIExpectError(t, "cose", "verify", token1Path, "--ca", getCACert(t, ca2Dir))
	runQPKIExpectError(t, "cose", "verify", token2Path, "--ca", getCACert(t, ca1Dir))
}
