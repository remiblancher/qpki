//go:build acceptance

package acceptance

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// Key Generation Tests (TestA_Key_*)
// =============================================================================

func TestA_Key_Gen_EC_Algorithms(t *testing.T) {
	algorithms := []string{"ecdsa-p256", "ecdsa-p384", "ecdsa-p521"}
	dir := t.TempDir()

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyPath := filepath.Join(dir, algo+".key")
			runQPKI(t, "key", "gen", "--algorithm", algo, "--out", keyPath)
			assertFileExists(t, keyPath)
		})
	}
}

func TestA_Key_Gen_RSA_Algorithms(t *testing.T) {
	algorithms := []string{"rsa-2048", "rsa-4096"}
	dir := t.TempDir()

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyPath := filepath.Join(dir, algo+".key")
			runQPKI(t, "key", "gen", "--algorithm", algo, "--out", keyPath)
			assertFileExists(t, keyPath)
		})
	}
}

func TestA_Key_Gen_MLDSA_Algorithms(t *testing.T) {
	algorithms := []string{"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}
	dir := t.TempDir()

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyPath := filepath.Join(dir, algo+".key")
			runQPKI(t, "key", "gen", "--algorithm", algo, "--out", keyPath)
			assertFileExists(t, keyPath)
		})
	}
}

func TestA_Key_Gen_SLHDSA_Algorithms(t *testing.T) {
	algorithms := []string{"slh-dsa-sha2-128f", "slh-dsa-sha2-192f"}
	dir := t.TempDir()

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyPath := filepath.Join(dir, algo+".key")
			runQPKI(t, "key", "gen", "--algorithm", algo, "--out", keyPath)
			assertFileExists(t, keyPath)
		})
	}
}

func TestA_Key_Info(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name      string
		algorithm string
	}{
		{"ec", "ecdsa-p384"},
		{"rsa", "rsa-4096"},
		{"mldsa", "ml-dsa-65"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(dir, tt.name+".key")
			runQPKI(t, "key", "gen", "--algorithm", tt.algorithm, "--out", keyPath)
			output := runQPKI(t, "key", "info", keyPath)
			assertOutputContains(t, output, "Algorithm")
		})
	}
}

func TestA_Key_List(t *testing.T) {
	dir := t.TempDir()

	// Generate a few keys
	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p256", "--out", filepath.Join(dir, "ec.key"))
	runQPKI(t, "key", "gen", "--algorithm", "ml-dsa-65", "--out", filepath.Join(dir, "ml.key"))

	output := runQPKI(t, "key", "list", "--dir", dir)
	assertOutputContains(t, output, "ec.key")
	assertOutputContains(t, output, "ml.key")
}

// =============================================================================
// CA Tests (TestA_CA_*)
// =============================================================================

func TestA_CA_Init_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
	assertFileExists(t, filepath.Join(caDir, "ca.meta.json"))
}

func TestA_CA_Init_RSA(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "RSA Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
}

func TestA_CA_Init_MLDSA(t *testing.T) {
	caDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
}

func TestA_CA_Init_SLHDSA(t *testing.T) {
	caDir := setupCA(t, "slh/root-ca", "SLH-DSA Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
}

func TestA_CA_Init_Catalyst(t *testing.T) {
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
}

func TestA_CA_Init_Composite(t *testing.T) {
	caDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
}

func TestA_CA_Init_Subordinate(t *testing.T) {
	parentDir := setupCA(t, "ec/root-ca", "EC Root CA")
	subDir := setupSubordinateCA(t, "ec/issuing-ca", "EC Issuing CA", parentDir)
	assertFileExists(t, filepath.Join(subDir, "ca.crt"))
}

func TestA_CA_Info(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
	}{
		{"ec", "ec/root-ca"},
		{"rsa", "rsa/root-ca"},
		{"mldsa", "ml/root-ca"},
		{"slhdsa", "slh/root-ca"},
		{"catalyst", "hybrid/catalyst/root-ca"},
		{"composite", "hybrid/composite/root-ca"},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			caDir := setupCA(t, p.profile, p.name+" Root CA")
			output := runQPKI(t, "ca", "info", "--ca-dir", caDir)
			assertOutputContains(t, output, p.name)
		})
	}
}

// =============================================================================
// CSR Tests (TestA_CSR_*)
// =============================================================================

func TestA_CSR_Gen_EC(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.key")
	csrPath := filepath.Join(dir, "ec.csr")

	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p384", "--out", keyPath)
	runQPKI(t, "csr", "gen",
		"--key", keyPath,
		"--cn", "ec-csr-test.local",
		"--out", csrPath,
	)
	assertFileExists(t, csrPath)
}

func TestA_CSR_Gen_RSA(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "rsa.key")
	csrPath := filepath.Join(dir, "rsa.csr")

	runQPKI(t, "key", "gen", "--algorithm", "rsa-4096", "--out", keyPath)
	runQPKI(t, "csr", "gen",
		"--key", keyPath,
		"--cn", "rsa-csr-test.local",
		"--out", csrPath,
	)
	assertFileExists(t, csrPath)
}

func TestA_CSR_Gen_MLKEM_WithAttestation(t *testing.T) {
	// Create ML-DSA CA for attestation
	caDir := setupCA(t, "ml/root-ca", "Attestation CA")

	// Issue ML-DSA signing credential for attestation
	credDir := enrollCredential(t, caDir, "ml/signing", "cn=Attestation Signer")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mlkem.key")
	csrPath := filepath.Join(dir, "mlkem.csr")

	// Create ML-KEM CSR with ML-DSA attestation (RFC 9883)
	runQPKI(t, "csr", "gen",
		"--algorithm", "ml-kem-768",
		"--keyout", keyPath,
		"--attest-cert", getCredentialCert(t, credDir),
		"--attest-key", getCredentialKey(t, credDir),
		"--cn", "mlkem-test.local",
		"--out", csrPath,
	)
	assertFileExists(t, csrPath)
	assertFileExists(t, keyPath)
}

// =============================================================================
// Certificate Tests (TestA_Cert_*)
// =============================================================================

func TestA_Cert_Issue_EC_FromCSR(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	csrPath := filepath.Join(dir, "server.csr")
	certPath := filepath.Join(dir, "server.crt")

	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p384", "--out", keyPath)
	runQPKI(t, "csr", "gen", "--key", keyPath, "--cn", "ec.test.local", "--out", csrPath)
	runQPKI(t, "cert", "issue",
		"--ca-dir", caDir,
		"--csr", csrPath,
		"--profile", "ec/tls-server",
		"--out", certPath,
	)
	assertFileExists(t, certPath)
}

func TestA_Cert_Issue_RSA_FromCSR(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "RSA Root CA")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	csrPath := filepath.Join(dir, "server.csr")
	certPath := filepath.Join(dir, "server.crt")

	runQPKI(t, "key", "gen", "--algorithm", "rsa-4096", "--out", keyPath)
	runQPKI(t, "csr", "gen", "--key", keyPath, "--cn", "rsa.test.local", "--out", csrPath)
	runQPKI(t, "cert", "issue",
		"--ca-dir", caDir,
		"--csr", csrPath,
		"--profile", "rsa/tls-server",
		"--out", certPath,
	)
	assertFileExists(t, certPath)
}

func TestA_Cert_Verify(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")
	credDir := enrollCredential(t, caDir, "ec/tls-server",
		"cn=verify.test.local",
		"dns_names=verify.test.local",
	)

	output := runQPKI(t, "cert", "verify",
		getCredentialCert(t, credDir),
		"--ca", getCACert(t, caDir),
	)
	assertOutputContains(t, output, "VALID")
}

func TestA_Cert_List(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")

	// Issue a few certificates
	enrollCredential(t, caDir, "ec/tls-server", "cn=server1.test.local", "dns_names=server1.test.local")
	enrollCredential(t, caDir, "ec/tls-server", "cn=server2.test.local", "dns_names=server2.test.local")

	output := runQPKI(t, "cert", "list", "--ca-dir", caDir)
	assertOutputContains(t, output, "server1.test.local")
	assertOutputContains(t, output, "server2.test.local")
}

func TestA_Cert_Inspect(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")
	credDir := enrollCredential(t, caDir, "ec/tls-server",
		"cn=inspect.test.local",
		"dns_names=inspect.test.local",
	)

	output := runQPKI(t, "inspect", getCredentialCert(t, credDir))
	assertOutputContains(t, output, "inspect.test.local")
	assertOutputContains(t, output, "Subject")
}

// =============================================================================
// Credential Enroll Tests (TestA_Credential_*)
// =============================================================================

func TestA_Credential_Enroll_EC_Profiles(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"ec/tls-server", []string{"cn=ec.test.local", "dns_names=ec.test.local"}},
		{"ec/ocsp-responder", []string{"cn=EC OCSP Responder"}},
		{"ec/timestamping", []string{"cn=EC TSA"}},
		{"ec/code-signing", []string{"cn=EC Code Signer"}},
		{"ec/email", []string{"cn=ec-user@test.local", "email=ec-user@test.local"}},
		{"ec/signing", []string{"cn=EC Signer"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
			assertFileExists(t, getCredentialKey(t, credDir))
		})
	}
}

func TestA_Credential_Enroll_RSA_Profiles(t *testing.T) {
	caDir := setupCA(t, "rsa/root-ca", "RSA Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"rsa/tls-server", []string{"cn=rsa.test.local", "dns_names=rsa.test.local"}},
		{"rsa/timestamping", []string{"cn=RSA TSA"}},
		{"rsa/code-signing", []string{"cn=RSA Code Signer"}},
		{"rsa/email", []string{"cn=rsa-user@test.local", "email=rsa-user@test.local"}},
		{"rsa/encryption", []string{"cn=RSA Encryption"}},
		{"rsa/signing", []string{"cn=RSA Signer"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
		})
	}
}

func TestA_Credential_Enroll_MLDSA_Profiles(t *testing.T) {
	caDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"ml/tls-server-sign", []string{"cn=mldsa.test.local", "dns_names=mldsa.test.local"}},
		{"ml/ocsp-responder", []string{"cn=ML-DSA OCSP Responder"}},
		{"ml/timestamping", []string{"cn=ML-DSA TSA"}},
		{"ml/code-signing", []string{"cn=ML-DSA Code Signer"}},
		{"ml/email-sign", []string{"cn=mldsa-user@test.local", "email=mldsa-user@test.local"}},
		{"ml/signing", []string{"cn=ML-DSA Signer"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
		})
	}
}

func TestA_Credential_Enroll_SLHDSA_Profiles(t *testing.T) {
	caDir := setupCA(t, "slh/root-ca", "SLH-DSA Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"slh/tls-server", []string{"cn=slhdsa.test.local", "dns_names=slhdsa.test.local"}},
		{"slh/timestamping", []string{"cn=SLH-DSA TSA"}},
		{"slh/tls-client", []string{"cn=slhdsa-client.test.local"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
		})
	}
}

func TestA_Credential_Enroll_Catalyst_Profiles(t *testing.T) {
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"hybrid/catalyst/tls-server", []string{"cn=catalyst.test.local", "dns_names=catalyst.test.local"}},
		{"hybrid/catalyst/ocsp-responder", []string{"cn=Catalyst OCSP Responder"}},
		{"hybrid/catalyst/timestamping", []string{"cn=Catalyst TSA"}},
		{"hybrid/catalyst/signing", []string{"cn=Catalyst Signer"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
		})
	}
}

func TestA_Credential_Enroll_Composite_Profiles(t *testing.T) {
	caDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")

	profiles := []struct {
		profile string
		vars    []string
	}{
		{"hybrid/composite/tls-server", []string{"cn=composite.test.local", "dns_names=composite.test.local"}},
	}

	for _, p := range profiles {
		t.Run(p.profile, func(t *testing.T) {
			credDir := enrollCredential(t, caDir, p.profile, p.vars...)
			assertFileExists(t, getCredentialCert(t, credDir))
		})
	}
}

// =============================================================================
// CRL Tests (TestA_CRL_*)
// =============================================================================

func TestA_CRL_Generate(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")

	runQPKI(t, "crl", "gen", "--ca-dir", caDir)

	// CRL is generated in ca-dir/crl/
	crlPath := filepath.Join(caDir, "crl", "ca.crl")
	assertFileExists(t, crlPath)
}

func TestA_CRL_Revoke_And_Generate(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")

	// Issue a certificate
	enrollCredential(t, caDir, "ec/tls-server",
		"cn=revoke.test.local",
		"dns_names=revoke.test.local",
	)

	// Get the serial number of the last issued certificate
	serial := getLastSerial(t, caDir)

	// Revoke it and generate CRL in one step
	runQPKI(t, "cert", "revoke", serial,
		"--ca-dir", caDir,
		"--reason", "keyCompromise",
		"--gen-crl",
	)

	// Verify CRL was generated
	crlPath := filepath.Join(caDir, "crl", "ca.crl")
	assertFileExists(t, crlPath)

	// Inspect CRL
	output := runQPKI(t, "inspect", crlPath)
	assertOutputContains(t, output, "CRL")
}

func TestA_CRL_PQC_Algorithms(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
	}{
		{"mldsa", "ml/root-ca"},
		{"slhdsa", "slh/root-ca"},
		{"catalyst", "hybrid/catalyst/root-ca"},
		{"composite", "hybrid/composite/root-ca"},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			caDir := setupCA(t, p.profile, p.name+" Root CA")
			runQPKI(t, "crl", "gen", "--ca-dir", caDir)
			crlPath := filepath.Join(caDir, "crl", "ca.crl")
			assertFileExists(t, crlPath)
		})
	}
}

// =============================================================================
// Profile Tests (TestA_Profile_*)
// =============================================================================

func TestA_Profile_List(t *testing.T) {
	output := runQPKI(t, "profile", "list")
	assertOutputContains(t, output, "ec/root-ca")
	assertOutputContains(t, output, "ml/root-ca")
}

func TestA_Profile_Show(t *testing.T) {
	output := runQPKI(t, "profile", "show", "ec/root-ca")
	assertOutputContains(t, output, "algorithm")
}

// =============================================================================
// Inspect Tests (TestA_Inspect_*)
// =============================================================================

func TestA_Inspect_Certificate(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")
	output := runQPKI(t, "inspect", getCACert(t, caDir))
	assertOutputContains(t, output, "Subject")
	assertOutputContains(t, output, "EC Root CA")
}

func TestA_Inspect_PQC_Certificate(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
	}{
		{"mldsa", "ml/root-ca"},
		{"slhdsa", "slh/root-ca"},
		{"catalyst", "hybrid/catalyst/root-ca"},
		{"composite", "hybrid/composite/root-ca"},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			caDir := setupCA(t, p.profile, p.name+" Root CA")
			output := runQPKI(t, "inspect", getCACert(t, caDir))
			assertOutputContains(t, output, "Subject")
		})
	}
}

func TestA_Inspect_CRL(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "EC Root CA")
	runQPKI(t, "crl", "gen", "--ca-dir", caDir)
	crlPath := filepath.Join(caDir, "crl", "ca.crl")

	output := runQPKI(t, "inspect", crlPath)
	assertOutputContains(t, output, "CRL")
}

func TestA_Inspect_CSR(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")
	csrPath := filepath.Join(dir, "test.csr")

	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p256", "--out", keyPath)
	runQPKI(t, "csr", "gen", "--key", keyPath, "--cn", "csr.test.local", "--out", csrPath)

	output := runQPKI(t, "inspect", csrPath)
	assertOutputContains(t, output, "csr.test.local")
}

// =============================================================================
// End-to-End Workflow Tests (TestA_E2E_*)
// =============================================================================

func TestA_E2E_EC_Workflow(t *testing.T) {
	// Full EC workflow: CA init -> key gen -> CSR -> issue -> verify
	caDir := setupCA(t, "ec/root-ca", "EC E2E CA")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	csrPath := filepath.Join(dir, "server.csr")
	certPath := filepath.Join(dir, "server.crt")

	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p256", "--out", keyPath)
	runQPKI(t, "csr", "gen", "--key", keyPath, "--cn", "e2e.test.local", "--dns", "e2e.test.local", "--out", csrPath)
	runQPKI(t, "cert", "issue", "--ca-dir", caDir, "--csr", csrPath, "--profile", "ec/tls-server", "--out", certPath)
	runQPKI(t, "cert", "verify", certPath, "--ca", getCACert(t, caDir))
	runQPKI(t, "cert", "list", "--ca-dir", caDir)
}

func TestA_E2E_MLDSA_Workflow(t *testing.T) {
	// Full ML-DSA workflow using credential enroll
	caDir := setupCA(t, "ml/root-ca", "ML-DSA E2E CA")

	credDir := enrollCredential(t, caDir, "ml/tls-server-sign",
		"cn=mldsa-e2e.test.local",
		"dns_names=mldsa-e2e.test.local",
	)

	runQPKI(t, "cert", "verify", getCredentialCert(t, credDir), "--ca", getCACert(t, caDir))
	runQPKI(t, "inspect", getCredentialCert(t, credDir))
}

func TestA_E2E_Catalyst_Workflow(t *testing.T) {
	// Full Catalyst hybrid workflow
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst E2E CA")

	credDir := enrollCredential(t, caDir, "hybrid/catalyst/tls-server",
		"cn=catalyst-e2e.test.local",
		"dns_names=catalyst-e2e.test.local",
	)

	runQPKI(t, "cert", "verify", getCredentialCert(t, credDir), "--ca", getCACert(t, caDir))
	runQPKI(t, "inspect", getCredentialCert(t, credDir))
}

func TestA_E2E_Composite_Workflow(t *testing.T) {
	// Full Composite hybrid workflow
	caDir := setupCA(t, "hybrid/composite/root-ca", "Composite E2E CA")

	credDir := enrollCredential(t, caDir, "hybrid/composite/tls-server",
		"cn=composite-e2e.test.local",
		"dns_names=composite-e2e.test.local",
	)

	runQPKI(t, "cert", "verify", getCredentialCert(t, credDir), "--ca", getCACert(t, caDir))
	runQPKI(t, "inspect", getCredentialCert(t, credDir))
	runQPKI(t, "inspect", getCACert(t, caDir))
}

func TestA_E2E_SubordinateCA_Chain(t *testing.T) {
	// Root CA -> Issuing CA -> End-entity
	rootDir := setupCA(t, "ec/root-ca", "Root CA")
	issuingDir := setupSubordinateCA(t, "ec/issuing-ca", "Issuing CA", rootDir)

	credDir := enrollCredential(t, issuingDir, "ec/tls-server",
		"cn=sub.test.local",
		"dns_names=sub.test.local",
	)

	// Verify chain: cert -> issuing CA
	runQPKI(t, "cert", "verify", getCredentialCert(t, credDir), "--ca", getCACert(t, issuingDir))

	// Verify issuing CA -> root CA
	runQPKI(t, "cert", "verify", getCACert(t, issuingDir), "--ca", getCACert(t, rootDir))
}

// =============================================================================
// Version and Help Tests (TestA_CLI_*)
// =============================================================================

func TestA_CLI_Help(t *testing.T) {
	output := runQPKI(t, "--help")
	assertOutputContains(t, output, "qpki")
}

func TestA_CLI_Version(t *testing.T) {
	output := runQPKI(t, "--version")
	assertOutputContains(t, output, "qpki")
}
