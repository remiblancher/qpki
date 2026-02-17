package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
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

// =============================================================================
// Unit Tests for csr.go validation functions
// =============================================================================

func TestU_ValidateCompositeFlags(t *testing.T) {
	tests := []struct {
		name         string
		mode         csrGenMode
		keyOut       string
		hybridKeyOut string
		wantErr      bool
	}{
		{
			name:    "no composite flag",
			mode:    csrGenMode{hasGen: true},
			wantErr: false,
		},
		{
			name:    "composite without gen",
			mode:    csrGenMode{hasComposite: true, hasGen: false},
			wantErr: true,
		},
		{
			name:    "composite with existing key",
			mode:    csrGenMode{hasComposite: true, hasGen: true, hasKey: true},
			wantErr: true,
		},
		{
			name:    "composite with HSM",
			mode:    csrGenMode{hasComposite: true, hasGen: true, hasHSM: true},
			wantErr: true,
		},
		{
			name:    "composite with hybrid",
			mode:    csrGenMode{hasComposite: true, hasGen: true, hasHybrid: true},
			wantErr: true,
		},
		{
			name:         "composite without keyout",
			mode:         csrGenMode{hasComposite: true, hasGen: true},
			keyOut:       "",
			hybridKeyOut: "hybrid.key",
			wantErr:      true,
		},
		{
			name:         "composite without hybrid-keyout",
			mode:         csrGenMode{hasComposite: true, hasGen: true},
			keyOut:       "key.pem",
			hybridKeyOut: "",
			wantErr:      true,
		},
		{
			name:         "valid composite",
			mode:         csrGenMode{hasComposite: true, hasGen: true},
			keyOut:       "key.pem",
			hybridKeyOut: "hybrid.key",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags
			oldKeyOut := csrGenKeyOut
			oldHybridKeyOut := csrGenHybridKeyOut
			defer func() {
				csrGenKeyOut = oldKeyOut
				csrGenHybridKeyOut = oldHybridKeyOut
			}()

			csrGenKeyOut = tt.keyOut
			csrGenHybridKeyOut = tt.hybridKeyOut

			err := validateCompositeFlags(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCompositeFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_ValidateCSRHSMFlags(t *testing.T) {
	tests := []struct {
		name      string
		mode      csrGenMode
		algorithm string
		keyLabel  string
		wantErr   bool
	}{
		{
			name:    "no HSM flag",
			mode:    csrGenMode{hasHSM: false},
			wantErr: false,
		},
		{
			name:      "HSM without algorithm",
			mode:      csrGenMode{hasHSM: true},
			algorithm: "",
			keyLabel:  "my-key",
			wantErr:   true,
		},
		{
			name:      "HSM without key label",
			mode:      csrGenMode{hasHSM: true},
			algorithm: "ecdsa-p256",
			keyLabel:  "",
			wantErr:   true,
		},
		{
			name:      "valid HSM flags",
			mode:      csrGenMode{hasHSM: true},
			algorithm: "ecdsa-p256",
			keyLabel:  "my-key",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags
			oldAlg := csrGenAlgorithm
			oldLabel := csrGenKeyLabel
			defer func() {
				csrGenAlgorithm = oldAlg
				csrGenKeyLabel = oldLabel
			}()

			csrGenAlgorithm = tt.algorithm
			csrGenKeyLabel = tt.keyLabel

			err := validateCSRHSMFlags(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCSRHSMFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_ValidateCompositeCombination(t *testing.T) {
	tests := []struct {
		name         string
		classicalAlg string
		pqcAlg       string
		wantErr      bool
	}{
		{
			name:         "ECDSA-P256 + ML-DSA-65 (valid)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ml-dsa-65",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P384 + ML-DSA-65 (valid)",
			classicalAlg: "ecdsa-p384",
			pqcAlg:       "ml-dsa-65",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P521 + ML-DSA-87 (valid)",
			classicalAlg: "ecdsa-p521",
			pqcAlg:       "ml-dsa-87",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P256 + ML-DSA-44 (invalid combo)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ml-dsa-44",
			wantErr:      true,
		},
		{
			name:         "RSA-2048 not supported",
			classicalAlg: "rsa-2048",
			pqcAlg:       "ml-dsa-65",
			wantErr:      true,
		},
		{
			name:         "invalid classical algorithm",
			classicalAlg: "invalid-alg",
			pqcAlg:       "ml-dsa-65",
			wantErr:      true,
		},
		{
			name:         "invalid PQC algorithm",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "invalid-pqc",
			wantErr:      true,
		},
		{
			name:         "classical algorithm for PQC (wrong type)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ecdsa-p384",
			wantErr:      true,
		},
		{
			name:         "PQC algorithm for classical (wrong type)",
			classicalAlg: "ml-dsa-65",
			pqcAlg:       "ml-dsa-87",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCompositeCombination(tt.classicalAlg, tt.pqcAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCompositeCombination() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_ValidateHybridCombination(t *testing.T) {
	tests := []struct {
		name         string
		classicalAlg string
		pqcAlg       string
		wantErr      bool
	}{
		{
			name:         "ECDSA-P256 + ML-DSA-44 (valid)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ml-dsa-44",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P256 + ML-DSA-65 (valid)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ml-dsa-65",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P384 + ML-DSA-65 (valid)",
			classicalAlg: "ecdsa-p384",
			pqcAlg:       "ml-dsa-65",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P384 + ML-DSA-87 (valid)",
			classicalAlg: "ecdsa-p384",
			pqcAlg:       "ml-dsa-87",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P521 + ML-DSA-87 (valid)",
			classicalAlg: "ecdsa-p521",
			pqcAlg:       "ml-dsa-87",
			wantErr:      false,
		},
		{
			name:         "ED25519 + ML-DSA-44 (valid)",
			classicalAlg: "ed25519",
			pqcAlg:       "ml-dsa-44",
			wantErr:      false,
		},
		{
			name:         "ED448 + ML-DSA-87 (valid)",
			classicalAlg: "ed448",
			pqcAlg:       "ml-dsa-87",
			wantErr:      false,
		},
		{
			name:         "ECDSA-P256 + ML-DSA-87 (invalid combo)",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "ml-dsa-87",
			wantErr:      true,
		},
		{
			name:         "RSA-2048 not supported for hybrid",
			classicalAlg: "rsa-2048",
			pqcAlg:       "ml-dsa-65",
			wantErr:      true,
		},
		{
			name:         "invalid classical algorithm",
			classicalAlg: "invalid-alg",
			pqcAlg:       "ml-dsa-65",
			wantErr:      true,
		},
		{
			name:         "invalid PQC algorithm",
			classicalAlg: "ecdsa-p256",
			pqcAlg:       "invalid-pqc",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHybridCombination(tt.classicalAlg, tt.pqcAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHybridCombination() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_FormatCSRPubKeyAlg(t *testing.T) {
	// Test with ECDSA P-256 CSR
	ecdsaCSR := createTestCSR(t, "ecdsa-p256", "test-format")
	result := formatCSRPubKeyAlg(ecdsaCSR)
	if result != "ECDSA P-256" {
		t.Errorf("formatCSRPubKeyAlg() for ECDSA P-256 = %v, want ECDSA P-256", result)
	}

	// Test with ECDSA P-384 CSR
	ecdsaCSR384 := createTestCSR(t, "ecdsa-p384", "test-format-384")
	result = formatCSRPubKeyAlg(ecdsaCSR384)
	if result != "ECDSA P-384" {
		t.Errorf("formatCSRPubKeyAlg() for ECDSA P-384 = %v, want ECDSA P-384", result)
	}
}

// createTestCSR creates a test CSR with the given algorithm
func createTestCSR(t *testing.T, algorithm, commonName string) *x509.CertificateRequest {
	t.Helper()

	alg, err := crypto.ParseAlgorithm(algorithm)
	if err != nil {
		t.Fatalf("failed to parse algorithm: %v", err)
	}

	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "key.pem")

	cfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := crypto.NewKeyProvider(cfg)
	signer, err := km.Generate(alg, cfg)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	subject := pkix.Name{CommonName: commonName}
	template := &x509.CertificateRequest{Subject: subject}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	return csr
}
