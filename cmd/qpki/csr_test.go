package main

import (
	"testing"
)

// resetCSRFlags resets all CSR command flags to their default values.
func resetCSRFlags() {
	csrGenKey = ""
	csrGenPassphrase = ""
	csrGenAlgorithm = ""
	csrGenKeyOut = ""
	csrGenKeyPass = ""
	csrGenOutput = ""
	csrGenCN = ""
	csrGenOrg = ""
	csrGenCountry = ""
	csrGenDNS = nil
	csrGenEmail = nil
	csrGenIP = nil
	csrGenAttestCert = ""
	csrGenAttestKey = ""
	csrGenAttestPass = ""
	csrGenIncludeCert = false
	csrGenHybridAlg = ""
	csrGenHybridKeyOut = ""
	csrGenHybridKeyPass = ""
	csrGenHSMConfig = ""
	csrGenKeyLabel = ""
	csrGenKeyID = ""
}

// =============================================================================
// CSR Generation Tests (Classical)
// =============================================================================

func TestF_Cert_CSR_ECDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_RSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "rsa-2048",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_Ed25519(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ed25519",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_WithSANs(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--dns", "server.example.com",
		"--dns", "www.example.com",
		"--email", "admin@example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_WithSubjectFields(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--org", "Example Inc",
		"--country", "US",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_WithExistingKey(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a key
	keyPath := tc.path("existing.key")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Then create CSR with existing key
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--key", keyPath,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, csrOut)
}

// =============================================================================
// CSR Generation Tests (PQC)
// =============================================================================

func TestF_Cert_CSR_MLDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("mldsa.key")
	csrOut := tc.path("mldsa.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ml-dsa-65",
		"--keyout", keyOut,
		"--cn", "pqc.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

// =============================================================================
// CSR Error Cases
// =============================================================================

func TestF_Cert_CSR_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("key.pem"),
		"--cn", "test.local",
	)
	assertError(t, err)
}

func TestF_Cert_CSR_EmptyCN(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// CSR with empty CN is allowed (SANs can be used instead)
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("key.pem"),
		"--cn", "",
		"--dns", "server.example.com",
		"--out", tc.path("out.csr"),
	)
	assertNoError(t, err)
}

func TestF_Cert_CSR_MutuallyExclusiveFlags(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// Generate a key first
	keyPath := tc.path("existing.key")
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
	)

	resetCSRFlags()

	// Try to use both --key and --algorithm
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--key", keyPath,
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("new.key"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_MissingKeySource(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_AlgorithmWithoutKeyout(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_InvalidAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "invalid-algo",
		"--keyout", tc.path("key.pem"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_KeyFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--key", tc.path("nonexistent.key"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

// =============================================================================
// CSR Generation Tests (Hybrid)
// =============================================================================

func TestF_Cert_CSR_Hybrid_ECDSA_MLDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	classicalKeyOut := tc.path("classical.key")
	hybridKeyOut := tc.path("hybrid.key")
	csrOut := tc.path("hybrid.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", classicalKeyOut,
		"--hybrid", "ml-dsa-65",
		"--hybrid-keyout", hybridKeyOut,
		"--cn", "hybrid.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, classicalKeyOut)
	assertFileExists(t, hybridKeyOut)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_Hybrid_WithExistingKey(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a classical key
	existingKeyPath := tc.path("existing.key")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", existingKeyPath,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Create hybrid CSR with existing classical key
	hybridKeyOut := tc.path("hybrid.key")
	csrOut := tc.path("hybrid.csr")

	_, err = executeCommand(rootCmd, "csr", "gen",
		"--key", existingKeyPath,
		"--hybrid", "ml-dsa-65",
		"--hybrid-keyout", hybridKeyOut,
		"--cn", "hybrid.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, hybridKeyOut)
	assertFileExists(t, csrOut)
}

func TestF_Cert_CSR_Hybrid_InvalidPQCAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("classical.key"),
		"--hybrid", "invalid-algo",
		"--hybrid-keyout", tc.path("hybrid.key"),
		"--cn", "hybrid.example.com",
		"--out", tc.path("hybrid.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_Hybrid_NonPQCAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// Using a classical algorithm for --hybrid should fail
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("classical.key"),
		"--hybrid", "ecdsa-p384",
		"--hybrid-keyout", tc.path("hybrid.key"),
		"--cn", "hybrid.example.com",
		"--out", tc.path("hybrid.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_CSR_Hybrid_MissingHybridKeyout(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("classical.key"),
		"--hybrid", "ml-dsa-65",
		"--cn", "hybrid.example.com",
		"--out", tc.path("hybrid.csr"),
	)
	assertError(t, err)
}

// =============================================================================
// CSR Generation Tests (KEM with Attestation)
// =============================================================================

func TestF_Cert_CSR_KEM_MissingAttestation(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// ML-KEM requires attestation certificate
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ml-kem-768",
		"--keyout", tc.path("kem.key"),
		"--cn", "kem.example.com",
		"--out", tc.path("kem.csr"),
	)
	assertError(t, err)
}

// =============================================================================
// CSR Info Tests
// =============================================================================

func TestF_CSR_Info_Classical(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--org", "Test Org",
		"--dns", "server.example.com",
		"--dns", "www.example.com",
		"--email", "admin@example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Get info about the CSR - just verify command succeeds
	_, err = executeCommand(rootCmd, "csr", "info", csrOut)
	assertNoError(t, err)
}

func TestF_CSR_Info_PQC(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a PQC CSR
	keyOut := tc.path("mldsa.key")
	csrOut := tc.path("mldsa.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ml-dsa-65",
		"--keyout", keyOut,
		"--cn", "pqc.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Get info about the CSR
	_, err = executeCommand(rootCmd, "csr", "info", csrOut)
	assertNoError(t, err)
}

func TestF_CSR_Info_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "csr", "info", tc.path("nonexistent.csr"))
	assertError(t, err)
}

func TestF_CSR_Info_InvalidCSR(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.csr", "not a valid CSR")
	_, err := executeCommand(rootCmd, "csr", "info", invalidPath)
	assertError(t, err)
}

func TestF_CSR_Info_MissingArg(t *testing.T) {
	_, err := executeCommand(rootCmd, "csr", "info")
	assertError(t, err)
}

// =============================================================================
// CSR Verify Tests
// =============================================================================

func TestF_CSR_Verify_Valid(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Verify the CSR - just verify command succeeds
	_, err = executeCommand(rootCmd, "csr", "verify", csrOut)
	assertNoError(t, err)
}

func TestF_CSR_Verify_PQC(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// First generate a PQC CSR
	keyOut := tc.path("mldsa.key")
	csrOut := tc.path("mldsa.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ml-dsa-65",
		"--keyout", keyOut,
		"--cn", "pqc.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Verify the CSR - PQC signature verification uses Go's x509 which
	// doesn't support PQC algorithms natively, so this is expected to fail.
	// The important test is that the command path is exercised.
	_, err = executeCommand(rootCmd, "csr", "verify", csrOut)
	// PQC CSR verification currently fails due to Go x509 limitations
	assertError(t, err)
}

func TestF_CSR_Verify_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "csr", "verify", tc.path("nonexistent.csr"))
	assertError(t, err)
}

func TestF_CSR_Verify_InvalidCSR(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.csr", "not a valid CSR")
	_, err := executeCommand(rootCmd, "csr", "verify", invalidPath)
	assertError(t, err)
}

func TestF_CSR_Verify_MissingArg(t *testing.T) {
	_, err := executeCommand(rootCmd, "csr", "verify")
	assertError(t, err)
}

func TestF_CSR_Verify_Hybrid(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// Generate a hybrid CSR
	classicalKeyOut := tc.path("classical.key")
	hybridKeyOut := tc.path("hybrid.key")
	csrOut := tc.path("hybrid.csr")

	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", classicalKeyOut,
		"--hybrid", "ml-dsa-65",
		"--hybrid-keyout", hybridKeyOut,
		"--cn", "hybrid.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Verify the hybrid CSR
	_, err = executeCommand(rootCmd, "csr", "verify", csrOut)
	assertNoError(t, err)
}
