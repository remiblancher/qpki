package main

import (
	"testing"
)

// resetCSRFlags resets all CSR command flags to their default values.
func resetCSRFlags() {
	csrKey = ""
	csrPassphrase = ""
	csrAlgorithm = ""
	csrKeyOut = ""
	csrKeyPass = ""
	csrOutput = ""
	csrCN = ""
	csrOrg = ""
	csrCountry = ""
	csrDNS = nil
	csrEmail = nil
	csrIP = nil
	csrAttestCert = ""
	csrAttestKey = ""
	csrAttestPass = ""
	csrIncludeCert = false
	csrHybridAlg = ""
	csrHybridKeyOut = ""
	csrHybridKeyPass = ""
}

// =============================================================================
// CSR Generation Tests (Classical)
// =============================================================================

func TestCSR_ECDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestCSR_RSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "rsa-2048",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestCSR_Ed25519(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ed25519",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)
	assertFileExists(t, keyOut)
	assertFileExists(t, csrOut)
}

func TestCSR_WithSANs(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
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

func TestCSR_WithSubjectFields(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
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

func TestCSR_WithExistingKey(t *testing.T) {
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
	_, err = executeCommand(rootCmd, "cert", "csr",
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

func TestCSR_MLDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("mldsa.key")
	csrOut := tc.path("mldsa.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
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

func TestCSR_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("key.pem"),
		"--cn", "test.local",
	)
	assertError(t, err)
}

func TestCSR_EmptyCN(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// CSR with empty CN is allowed (SANs can be used instead)
	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("key.pem"),
		"--cn", "",
		"--dns", "server.example.com",
		"--out", tc.path("out.csr"),
	)
	assertNoError(t, err)
}

func TestCSR_MutuallyExclusiveFlags(t *testing.T) {
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
	_, err := executeCommand(rootCmd, "cert", "csr",
		"--key", keyPath,
		"--algorithm", "ecdsa-p256",
		"--keyout", tc.path("new.key"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestCSR_MissingKeySource(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestCSR_AlgorithmWithoutKeyout(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestCSR_InvalidAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "invalid-algo",
		"--keyout", tc.path("key.pem"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}

func TestCSR_KeyFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--key", tc.path("nonexistent.key"),
		"--cn", "test.local",
		"--out", tc.path("out.csr"),
	)
	assertError(t, err)
}
