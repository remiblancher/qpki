//go:build acceptance

package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// CMS Sign and Verify Tests (TestA_CMS_*)
// =============================================================================

func TestA_CMS_Sign_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "CMS EC CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)
	assertFileExists(t, signedPath)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)

	output := runQPKI(t, "cms", "info", signedPath)
	assertOutputContains(t, output, "Signer")
}

func TestA_CMS_Sign_RSA(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "CMS RSA CA")

	signCred := enrollCredentialWithInfo(t, caDir, "rsa/signing", "cn=RSA CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_CMS_Sign_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ml/root-ca", "CMS ML-DSA CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ml/signing", "cn=ML-DSA CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_CMS_Sign_SLHDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "slh-dsa-sha2-128f")
	caDir := setupCA(t, "slh/root-ca", "CMS SLH-DSA CA")

	signCred := enrollCredentialWithInfo(t, caDir, "slh/signing", "cn=SLH-DSA CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_CMS_Sign_Catalyst(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "CMS Catalyst CA")

	signCred := enrollCredentialWithInfo(t, caDir, "hybrid/catalyst/signing", "cn=Catalyst CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_CMS_Sign_Composite(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/composite/root-ca", "CMS Composite CA")

	signCred := enrollCredentialWithInfo(t, caDir, "hybrid/composite/signing", "cn=Composite CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS signing")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "cms", "verify", signedPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

// =============================================================================
// CMS Encrypt and Decrypt Tests (TestA_CMS_Encrypt_*)
// RSA: Supported in HSM mode via crypto.Decrypter interface
// EC (ECDH): Not supported in HSM mode (requires CKM_ECDH1_DERIVE)
// ML-KEM: Supported in PQC HSM mode (Utimaco) via CKM_UTI_MLKEM_DECAP
// =============================================================================

func TestA_CMS_Encrypt_RSA(t *testing.T) {
	// RSA CMS decryption is supported in HSM mode via crypto.Decrypter
	caDir := setupCA(t, "rsa/root-ca", "CMS RSA CA")

	encCred := enrollCredentialWithInfo(t, caDir, "rsa/encryption", "cn=RSA CMS Recipient")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS encryption")

	dir := t.TempDir()
	encryptedPath := filepath.Join(dir, "encrypted.p7m")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	runQPKI(t, "cms", "encrypt",
		"--recipient", getCredentialCert(t, encCred.Dir),
		"--in", testData,
		"--out", encryptedPath,
	)
	assertFileExists(t, encryptedPath)

	// Build decrypt args based on key mode (software vs HSM)
	decryptArgs := []string{"cms", "decrypt",
		"--in", encryptedPath,
		"--out", decryptedPath,
	}
	decryptArgs = append(decryptArgs, encCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, encCred.Dir))...)
	runQPKI(t, decryptArgs...)

	// Verify decrypted content matches original
	original, _ := os.ReadFile(testData)
	decrypted, _ := os.ReadFile(decryptedPath)
	if string(original) != string(decrypted) {
		t.Errorf("decrypted content doesn't match original")
	}
}

func TestA_CMS_Encrypt_EC(t *testing.T) {
	// ECDH key agreement requires CKM_ECDH1_DERIVE - not implemented for HSM
	if isHSMMode() {
		t.Skip("ECDH key agreement not supported in HSM mode (requires CKM_ECDH1_DERIVE)")
	}

	caDir := setupCA(t, "ec/root-ca", "CMS EC CA")

	encCredDir := enrollCredential(t, caDir, "ec/encryption", "cn=EC CMS Recipient")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS encryption")

	dir := t.TempDir()
	encryptedPath := filepath.Join(dir, "encrypted.p7m")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	runQPKI(t, "cms", "encrypt",
		"--recipient", getCredentialCert(t, encCredDir),
		"--in", testData,
		"--out", encryptedPath,
	)

	runQPKI(t, "cms", "decrypt",
		"--key", getCredentialKey(t, encCredDir),
		"--in", encryptedPath,
		"--out", decryptedPath,
	)

	original, _ := os.ReadFile(testData)
	decrypted, _ := os.ReadFile(decryptedPath)
	if string(original) != string(decrypted) {
		t.Errorf("decrypted content doesn't match original")
	}
}

func TestA_CMS_Encrypt_MLKEM(t *testing.T) {
	// ML-KEM CMS decryption is not supported in HSM mode due to Utimaco limitations:
	// The HSM enforces that ML-KEM derived shared secrets cannot be extracted,
	// but CMS decryption requires the raw shared secret for HKDF processing.
	// ML-KEM signing/key generation works fine in HSM mode.
	if isHSMMode() {
		t.Skip("ML-KEM CMS decryption not supported in HSM mode (shared secret extraction not allowed)")
	}

	caDir := setupCA(t, "ml/root-ca", "CMS ML-KEM CA")

	encCred := enrollCredentialWithInfo(t, caDir, "ml/encryption", "cn=ML-KEM CMS Recipient")

	testData := writeTestFile(t, "cms-data.txt", "Test data for CMS encryption")

	dir := t.TempDir()
	encryptedPath := filepath.Join(dir, "encrypted.p7m")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	runQPKI(t, "cms", "encrypt",
		"--recipient", getCredentialCert(t, encCred.Dir),
		"--in", testData,
		"--out", encryptedPath,
	)

	// Build decrypt args based on key mode (software vs HSM)
	decryptArgs := []string{"cms", "decrypt",
		"--in", encryptedPath,
		"--out", decryptedPath,
	}
	decryptArgs = append(decryptArgs, encCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, encCred.Dir))...)
	runQPKI(t, decryptArgs...)

	original, _ := os.ReadFile(testData)
	decrypted, _ := os.ReadFile(decryptedPath)
	if string(original) != string(decrypted) {
		t.Errorf("decrypted content doesn't match original")
	}
}

func TestA_CMS_Encrypt_Hybrid(t *testing.T) {
	// Hybrid test uses EC which requires ECDH - not supported in HSM mode
	if isHSMMode() {
		t.Skip("Hybrid CMS uses ECDH which is not supported in HSM mode")
	}

	// Create two CAs: one EC, one ML-KEM
	ecCaDir := setupCA(t, "ec/root-ca", "CMS EC CA")
	mlCaDir := setupCA(t, "ml/root-ca", "CMS ML CA")

	ecEncCredDir := enrollCredential(t, ecCaDir, "ec/encryption", "cn=EC CMS Recipient")
	mlEncCredDir := enrollCredential(t, mlCaDir, "ml/encryption", "cn=ML-KEM CMS Recipient")

	testData := writeTestFile(t, "cms-data.txt", "Test data for hybrid CMS encryption")

	dir := t.TempDir()
	encryptedPath := filepath.Join(dir, "encrypted.p7m")
	ecDecryptedPath := filepath.Join(dir, "ec-decrypted.txt")
	mlDecryptedPath := filepath.Join(dir, "ml-decrypted.txt")

	// Encrypt with both recipients
	runQPKI(t, "cms", "encrypt",
		"--recipient", getCredentialCert(t, ecEncCredDir),
		"--recipient", getCredentialCert(t, mlEncCredDir),
		"--in", testData,
		"--out", encryptedPath,
	)

	// Decrypt with EC key
	runQPKI(t, "cms", "decrypt",
		"--key", getCredentialKey(t, ecEncCredDir),
		"--in", encryptedPath,
		"--out", ecDecryptedPath,
	)

	// Decrypt with ML-KEM key
	runQPKI(t, "cms", "decrypt",
		"--key", getCredentialKey(t, mlEncCredDir),
		"--in", encryptedPath,
		"--out", mlDecryptedPath,
	)

	// Verify both decryptions match original
	original, _ := os.ReadFile(testData)
	ecDecrypted, _ := os.ReadFile(ecDecryptedPath)
	mlDecrypted, _ := os.ReadFile(mlDecryptedPath)

	if string(original) != string(ecDecrypted) {
		t.Errorf("EC decrypted content doesn't match original")
	}
	if string(original) != string(mlDecrypted) {
		t.Errorf("ML-KEM decrypted content doesn't match original")
	}
}

func TestA_CMS_Verify_InvalidData(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "CMS EC CA")

	signCred := enrollCredentialWithInfo(t, caDir, "ec/signing", "cn=EC CMS Signer")

	testData := writeTestFile(t, "cms-data.txt", "Original data")
	wrongData := writeTestFile(t, "wrong-data.txt", "Different data")

	dir := t.TempDir()
	signedPath := filepath.Join(dir, "signed.p7s")

	args := []string{
		"cms", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, signCred.Dir),
		"--out", signedPath,
	}
	args = append(args, signCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, signCred.Dir))...)
	runQPKI(t, args...)

	// Verify with wrong data should fail
	runQPKIExpectError(t, "cms", "verify", signedPath,
		"--data", wrongData,
		"--ca", getCACert(t, caDir),
	)
}
