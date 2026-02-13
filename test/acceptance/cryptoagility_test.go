//go:build acceptance

package acceptance

import (
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Crypto-Agility Tests (TestA_Agility_*)
//
// These tests verify the ability to transition between cryptographic algorithms
// while maintaining certificate chain validity and operational continuity.
//
// Two approaches are tested:
// 1. Parallel PKI (TestA_Agility_*): Create separate PKIs for each algorithm
// 2. Rotation (TestA_Agility_Rotate_*): Rotate existing CA/credentials in-place
// =============================================================================

// =============================================================================
// Helper Functions for Rotation
// =============================================================================

// rotateCA rotates a CA to a new profile and activates it.
func rotateCA(t *testing.T, caDir, newProfile string) string {
	t.Helper()
	output := runQPKI(t, "ca", "rotate", "--ca-dir", caDir, "--profile", newProfile)
	version := extractVersion(t, output, "New version:")
	if version == "" {
		t.Fatalf("failed to extract CA version from rotate output: %s", output)
	}
	runQPKI(t, "ca", "activate", "--ca-dir", caDir, "--version", version)
	return version
}

// rotateCredential rotates a credential to a new profile and activates it.
func rotateCredential(t *testing.T, credID, caDir, credDir, newProfile string) string {
	t.Helper()
	output := runQPKI(t, "credential", "rotate", credID,
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", newProfile)
	version := extractVersion(t, output, "Version:")
	if version == "" {
		t.Fatalf("failed to extract credential version from rotate output: %s", output)
	}
	runQPKI(t, "credential", "activate", credID, "--cred-dir", credDir, "--version", version)
	return version
}

// extractVersion extracts a version string (v1, v2, etc.) from output.
func extractVersion(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, prefix) {
			for _, word := range strings.Fields(line) {
				if len(word) >= 2 && word[0] == 'v' && word[1] >= '0' && word[1] <= '9' {
					return word
				}
			}
		}
	}
	return ""
}

// getFirstCredentialID returns the first credential ID in the credentials directory.
func getFirstCredentialID(t *testing.T, credDir string) string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(credDir, "*"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no credentials found in %s", credDir)
	}
	return filepath.Base(entries[0])
}

// verifyCAVersionCount checks that the CA has the expected number of versions.
func verifyCAVersionCount(t *testing.T, caDir string, expectedCount int) {
	t.Helper()
	output := runQPKI(t, "ca", "versions", "--ca-dir", caDir)
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Check if line starts with vN where N is a digit (e.g., v1, v2)
		if len(line) >= 2 && line[0] == 'v' && line[1] >= '0' && line[1] <= '9' {
			count++
		}
	}
	if count < expectedCount {
		t.Errorf("expected at least %d CA versions, got %d", expectedCount, count)
	}
}

// =============================================================================
// Parallel PKI Tests (create separate PKIs for each algorithm)
// =============================================================================

// TestA_Agility_EC_Catalyst_PQ tests creating parallel PKIs:
// EC (classical) -> Catalyst (hybrid) -> ML-DSA (post-quantum)
func TestA_Agility_EC_Catalyst_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	// Phase 1: EC PKI
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=phase1.test.local", "dns_names=phase1.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 2: Catalyst PKI
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	catalystCredDir := enrollCredential(t, catalystRootDir, "hybrid/catalyst/tls-server",
		"cn=phase2.test.local", "dns_names=phase2.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, catalystCredDir), "--ca", getCACert(t, catalystRootDir))

	// Phase 3: ML-DSA PKI
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=phase3.test.local", "dns_names=phase3.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))

	// All three PKIs operational
	runQPKI(t, "inspect", getCACert(t, ecRootDir))
	runQPKI(t, "inspect", getCACert(t, catalystRootDir))
	runQPKI(t, "inspect", getCACert(t, mlRootDir))
}

// TestA_Agility_EC_Composite_PQ tests EC -> Composite -> ML-DSA parallel PKIs.
func TestA_Agility_EC_Composite_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-composite.test.local", "dns_names=ec-composite.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	compositeRootDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")
	compositeCredDir := enrollCredential(t, compositeRootDir, "hybrid/composite/tls-server",
		"cn=composite.test.local", "dns_names=composite.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, compositeCredDir), "--ca", getCACert(t, compositeRootDir))

	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-final.test.local", "dns_names=ml-final.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_RSA_EC_PQ tests RSA -> EC -> ML-DSA parallel PKIs.
func TestA_Agility_RSA_EC_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	rsaRootDir := setupCA(t, "rsa/root-ca", "RSA Root CA")
	rsaCredDir := enrollCredential(t, rsaRootDir, "rsa/tls-server",
		"cn=rsa.test.local", "dns_names=rsa.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, rsaCredDir), "--ca", getCACert(t, rsaRootDir))

	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec.test.local", "dns_names=ec.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml.test.local", "dns_names=ml.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_EC_PQ_Direct tests EC -> ML-DSA direct (no hybrid).
func TestA_Agility_EC_PQ_Direct(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-direct.test.local", "dns_names=ec-direct.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-direct.test.local", "dns_names=ml-direct.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))

	runQPKI(t, "cert", "list", "--ca-dir", ecRootDir)
	runQPKI(t, "cert", "list", "--ca-dir", mlRootDir)
}

// TestA_Agility_Catalyst_PQ tests Catalyst -> ML-DSA parallel PKIs.
func TestA_Agility_Catalyst_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	catalystCredDir := enrollCredential(t, catalystRootDir, "hybrid/catalyst/tls-server",
		"cn=catalyst-start.test.local", "dns_names=catalyst-start.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, catalystCredDir), "--ca", getCACert(t, catalystRootDir))

	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-from-catalyst.test.local", "dns_names=ml-from-catalyst.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_Composite_PQ tests Composite -> ML-DSA parallel PKIs.
func TestA_Agility_Composite_PQ(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	compositeRootDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")
	compositeCredDir := enrollCredential(t, compositeRootDir, "hybrid/composite/tls-server",
		"cn=composite-start.test.local", "dns_names=composite-start.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, compositeCredDir), "--ca", getCACert(t, compositeRootDir))

	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-from-composite.test.local", "dns_names=ml-from-composite.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_EC_SLHDSA tests EC -> SLH-DSA parallel PKIs.
func TestA_Agility_EC_SLHDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "slh-dsa-sha2-128f")
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-to-slh.test.local", "dns_names=ec-to-slh.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	slhRootDir := setupCA(t, "slh/root-ca", "SLH-DSA Root CA")
	slhCredDir := enrollCredential(t, slhRootDir, "slh/tls-server",
		"cn=slh.test.local", "dns_names=slh.test.local")
	runQPKI(t, "cert", "verify", getCredentialCert(t, slhCredDir), "--ca", getCACert(t, slhRootDir))
}

// TestA_Agility_Full_PKI_Transition tests complete PKI with subordinate CAs.
func TestA_Agility_Full_PKI_Transition(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t) // Phase 2 uses Catalyst hybrid profiles
	// Phase 1: EC PKI with hierarchy
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecIssuingDir := setupSubordinateCA(t, "ec/issuing-ca", "EC Issuing CA", ecRootDir)
	enrollCredential(t, ecIssuingDir, "ec/tls-server", "cn=server.test.local", "dns_names=server.test.local")
	enrollCredential(t, ecIssuingDir, "ec/tls-client", "cn=client.test.local")
	enrollCredential(t, ecIssuingDir, "ec/code-signing", "cn=Code Signer")
	runQPKI(t, "crl", "gen", "--ca-dir", ecIssuingDir)
	assertFileExists(t, filepath.Join(ecIssuingDir, "crl", "ca.crl"))

	// Phase 2: Catalyst PKI with hierarchy
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	catalystIssuingDir := setupSubordinateCA(t, "hybrid/catalyst/issuing-ca", "Catalyst Issuing CA", catalystRootDir)
	enrollCredential(t, catalystIssuingDir, "hybrid/catalyst/tls-server", "cn=server-hybrid.test.local", "dns_names=server-hybrid.test.local")
	enrollCredential(t, catalystIssuingDir, "hybrid/catalyst/signing", "cn=Hybrid Signer")
	runQPKI(t, "crl", "gen", "--ca-dir", catalystIssuingDir)

	// Phase 3: ML-DSA PKI with hierarchy
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlIssuingDir := setupSubordinateCA(t, "ml/issuing-ca", "ML-DSA Issuing CA", mlRootDir)
	enrollCredential(t, mlIssuingDir, "ml/tls-server-sign", "cn=server-pq.test.local", "dns_names=server-pq.test.local")
	enrollCredential(t, mlIssuingDir, "ml/code-signing", "cn=PQ Code Signer")
	runQPKI(t, "crl", "gen", "--ca-dir", mlIssuingDir)

	// All operational
	runQPKI(t, "cert", "list", "--ca-dir", ecIssuingDir)
	runQPKI(t, "cert", "list", "--ca-dir", catalystIssuingDir)
	runQPKI(t, "cert", "list", "--ca-dir", mlIssuingDir)
}

// =============================================================================
// In-Place Rotation Tests (rotate existing CA/credentials)
// =============================================================================

// TestA_Agility_Rotate_EC_Catalyst_MLDSA tests full 3-step in-place rotation:
// EC -> Catalyst -> ML-DSA within the same CA
func TestA_Agility_Rotate_EC_Catalyst_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "ec/root-ca", "EC Rotation CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "ec/tls-server",
		"--var", "cn=rotation.test.local", "--var", "dns_names=rotation.test.local")
	credID := getFirstCredentialID(t, credDir)

	// Rotate to Catalyst
	rotateCA(t, caDir, "hybrid/catalyst/root-ca")
	rotateCredential(t, credID, caDir, credDir, "hybrid/catalyst/signing")

	// Rotate to ML-DSA
	rotateCA(t, caDir, "ml/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	// Verify 3 versions
	verifyCAVersionCount(t, caDir, 3)
	output := runQPKI(t, "credential", "versions", credID, "--cred-dir", credDir)
	assertOutputContains(t, output, "v1")
	assertOutputContains(t, output, "v2")
	assertOutputContains(t, output, "v3")
}

// TestA_Agility_Rotate_EC_Composite_MLDSA tests EC -> Composite -> ML-DSA rotation.
func TestA_Agility_Rotate_EC_Composite_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "ec/root-ca", "EC Composite Rotation CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "ec/tls-server",
		"--var", "cn=composite-rotation.test.local", "--var", "dns_names=composite-rotation.test.local")
	credID := getFirstCredentialID(t, credDir)

	rotateCA(t, caDir, "hybrid/composite/root-ca")
	rotateCredential(t, credID, caDir, credDir, "hybrid/composite/signing")

	rotateCA(t, caDir, "ml/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	verifyCAVersionCount(t, caDir, 3)
}

// TestA_Agility_Rotate_RSA_EC_MLDSA tests RSA -> EC -> ML-DSA rotation.
func TestA_Agility_Rotate_RSA_EC_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "rsa/root-ca", "RSA Migration CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "rsa/tls-server",
		"--var", "cn=rsa-migration.test.local", "--var", "dns_names=rsa-migration.test.local")
	credID := getFirstCredentialID(t, credDir)

	rotateCA(t, caDir, "ec/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ec/signing")

	rotateCA(t, caDir, "ml/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	verifyCAVersionCount(t, caDir, 3)
}

// TestA_Agility_Rotate_EC_MLDSA_Direct tests direct EC -> ML-DSA rotation with cross-sign.
func TestA_Agility_Rotate_EC_MLDSA_Direct(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ec/root-ca", "EC Direct Migration CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "ec/tls-server",
		"--var", "cn=direct-migration.test.local", "--var", "dns_names=direct-migration.test.local")
	credID := getFirstCredentialID(t, credDir)

	// Direct rotation with cross-sign
	output := runQPKI(t, "ca", "rotate", "--ca-dir", caDir, "--profile", "ml/root-ca", "--cross-sign")
	version := extractVersion(t, output, "New version:")
	runQPKI(t, "ca", "activate", "--ca-dir", caDir, "--version", version)

	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	verifyCAVersionCount(t, caDir, 2)
}

// TestA_Agility_Rotate_Catalyst_MLDSA tests Catalyst -> ML-DSA rotation.
func TestA_Agility_Rotate_Catalyst_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Migration CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "hybrid/catalyst/tls-server",
		"--var", "cn=catalyst-migration.test.local", "--var", "dns_names=catalyst-migration.test.local")
	credID := getFirstCredentialID(t, credDir)

	rotateCA(t, caDir, "ml/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	verifyCAVersionCount(t, caDir, 2)
}

// TestA_Agility_Rotate_Composite_MLDSA tests Composite -> ML-DSA rotation.
func TestA_Agility_Rotate_Composite_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/composite/root-ca", "Composite Migration CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "hybrid/composite/tls-server",
		"--var", "cn=composite-migration.test.local", "--var", "dns_names=composite-migration.test.local")
	credID := getFirstCredentialID(t, credDir)

	rotateCA(t, caDir, "ml/root-ca")
	rotateCredential(t, credID, caDir, credDir, "ml/signing")

	verifyCAVersionCount(t, caDir, 2)
}

// TestA_Agility_Rotate_CA_Versions tests CA version management.
func TestA_Agility_Rotate_CA_Versions(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "ec/root-ca", "Version Test CA")

	output := runQPKI(t, "ca", "versions", "--ca-dir", caDir)
	assertOutputContains(t, output, "v1")
	assertOutputContains(t, output, "active")

	rotateCA(t, caDir, "hybrid/catalyst/root-ca")

	output = runQPKI(t, "ca", "versions", "--ca-dir", caDir)
	assertOutputContains(t, output, "v1")
	assertOutputContains(t, output, "v2")
}

// TestA_Agility_Rotate_Credential_Versions tests credential version management.
func TestA_Agility_Rotate_Credential_Versions(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "ec/root-ca", "Cred Version Test CA")
	credDir := filepath.Join(caDir, "credentials")

	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir, "--cred-dir", credDir, "--profile", "ec/tls-server",
		"--var", "cn=version-test.local", "--var", "dns_names=version-test.local")
	credID := getFirstCredentialID(t, credDir)

	output := runQPKI(t, "credential", "versions", credID, "--cred-dir", credDir)
	assertOutputContains(t, output, "v1")

	rotateCA(t, caDir, "hybrid/catalyst/root-ca")
	rotateCredential(t, credID, caDir, credDir, "hybrid/catalyst/signing")

	output = runQPKI(t, "credential", "versions", credID, "--cred-dir", credDir)
	assertOutputContains(t, output, "v1")
	assertOutputContains(t, output, "v2")
}

// TestA_Agility_Rotate_CA_Info tests CA info after rotation.
func TestA_Agility_Rotate_CA_Info(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ec/root-ca", "Info Test CA")

	output := runQPKI(t, "ca", "info", "--ca-dir", caDir)
	if !strings.Contains(strings.ToLower(output), "ec") && !strings.Contains(strings.ToLower(output), "ecdsa") {
		t.Errorf("expected EC/ECDSA in CA info, got: %s", output)
	}

	rotateCA(t, caDir, "ml/root-ca")

	output = runQPKI(t, "ca", "info", "--ca-dir", caDir)
	if !strings.Contains(strings.ToLower(output), "ml-dsa") && !strings.Contains(strings.ToLower(output), "mldsa") {
		t.Errorf("expected ML-DSA in CA info after rotation, got: %s", output)
	}
}
