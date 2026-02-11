//go:build acceptance

package acceptance

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// TSA Sign and Verify Tests (TestA_TSA_*)
// =============================================================================

func TestA_TSA_Sign_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "TSA EC CA")

	// Issue TSA credential
	tsaCredDir := enrollCredential(t, caDir, "ec/timestamping", "cn=EC Timestamp Authority")

	// Create test data
	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	// Sign timestamp
	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)
	assertFileExists(t, tsrPath)

	// Verify timestamp
	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)

	// Get TSA info
	output := runQPKI(t, "tsa", "info", tsrPath)
	assertOutputContains(t, output, "Time")
}

func TestA_TSA_Sign_RSA(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "TSA RSA CA")

	tsaCredDir := enrollCredential(t, caDir, "rsa/timestamping", "cn=RSA Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Sign_MLDSA(t *testing.T) {
	caDir := setupCA(t, "ml/root-ca", "TSA ML-DSA CA")

	tsaCredDir := enrollCredential(t, caDir, "ml/timestamping", "cn=ML-DSA Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Sign_SLHDSA(t *testing.T) {
	caDir := setupCA(t, "slh/root-ca", "TSA SLH-DSA CA")

	tsaCredDir := enrollCredential(t, caDir, "slh/timestamping", "cn=SLH-DSA Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Sign_Catalyst(t *testing.T) {
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "TSA Catalyst CA")

	tsaCredDir := enrollCredential(t, caDir, "hybrid/catalyst/timestamping", "cn=Catalyst Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Sign_Composite(t *testing.T) {
	caDir := setupCA(t, "hybrid/composite/root-ca", "TSA Composite CA")

	tsaCredDir := enrollCredential(t, caDir, "hybrid/composite/timestamping", "cn=Composite Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	runQPKI(t, "tsa", "verify", tsrPath,
		"--data", testData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Verify_InvalidData(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "TSA EC CA")

	tsaCredDir := enrollCredential(t, caDir, "ec/timestamping", "cn=EC Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Original data")
	wrongData := writeTestFile(t, "wrong-data.txt", "Different data")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	// Verify with wrong data should fail
	runQPKIExpectError(t, "tsa", "verify", tsrPath,
		"--data", wrongData,
		"--ca", getCACert(t, caDir),
	)
}

func TestA_TSA_Info(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "TSA EC CA")

	tsaCredDir := enrollCredential(t, caDir, "ec/timestamping", "cn=EC Timestamp Authority")

	testData := writeTestFile(t, "test-data.txt", "Test data for timestamping")

	dir := t.TempDir()
	tsrPath := filepath.Join(dir, "timestamp.tsr")

	runQPKI(t, "tsa", "sign",
		"--data", testData,
		"--cert", getCredentialCert(t, tsaCredDir),
		"--key", getCredentialKey(t, tsaCredDir),
		"--out", tsrPath,
	)

	output := runQPKI(t, "tsa", "info", tsrPath)
	assertOutputContains(t, output, "Time")
	assertOutputContains(t, output, "Hash")
}
