//go:build acceptance

package acceptance

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// Crypto-Agility Tests (TestA_Agility_*)
//
// These tests verify the ability to transition between cryptographic algorithms
// while maintaining certificate chain validity and operational continuity.
// =============================================================================

// TestA_Agility_EC_Catalyst_PQ tests the transition path:
// EC (classical) -> Catalyst (hybrid) -> ML-DSA (post-quantum)
func TestA_Agility_EC_Catalyst_PQ(t *testing.T) {
	// Phase 1: Start with EC root CA
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")

	// Issue EC end-entity certificate
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=phase1.test.local",
		"dns_names=phase1.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 2: Transition to Catalyst hybrid
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")

	// Cross-certify: Catalyst CA signs EC CA (for backward compatibility)
	// Issue Catalyst end-entity certificate
	catalystCredDir := enrollCredential(t, catalystRootDir, "hybrid/catalyst/tls-server",
		"cn=phase2.test.local",
		"dns_names=phase2.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, catalystCredDir), "--ca", getCACert(t, catalystRootDir))

	// Phase 3: Complete transition to ML-DSA
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")

	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=phase3.test.local",
		"dns_names=phase3.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))

	// Verify all three chains are independently valid
	runQPKI(t, "inspect", getCACert(t, ecRootDir))
	runQPKI(t, "inspect", getCACert(t, catalystRootDir))
	runQPKI(t, "inspect", getCACert(t, mlRootDir))
}

// TestA_Agility_EC_Composite_PQ tests the transition path:
// EC (classical) -> Composite (hybrid) -> ML-DSA (post-quantum)
func TestA_Agility_EC_Composite_PQ(t *testing.T) {
	// Phase 1: EC
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-composite.test.local",
		"dns_names=ec-composite.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 2: Composite hybrid
	compositeRootDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")
	compositeCredDir := enrollCredential(t, compositeRootDir, "hybrid/composite/tls-server",
		"cn=composite.test.local",
		"dns_names=composite.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, compositeCredDir), "--ca", getCACert(t, compositeRootDir))

	// Phase 3: ML-DSA
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-final.test.local",
		"dns_names=ml-final.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_RSA_EC_PQ tests the transition path:
// RSA (legacy) -> EC (classical) -> ML-DSA (post-quantum)
func TestA_Agility_RSA_EC_PQ(t *testing.T) {
	// Phase 1: RSA (legacy systems)
	rsaRootDir := setupCA(t, "rsa/root-ca", "RSA Root CA")
	rsaCredDir := enrollCredential(t, rsaRootDir, "rsa/tls-server",
		"cn=rsa.test.local",
		"dns_names=rsa.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, rsaCredDir), "--ca", getCACert(t, rsaRootDir))

	// Phase 2: EC (modern classical)
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec.test.local",
		"dns_names=ec.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 3: ML-DSA (post-quantum)
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml.test.local",
		"dns_names=ml.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_EC_PQ_Direct tests direct transition:
// EC (classical) -> ML-DSA (post-quantum) without hybrid phase
func TestA_Agility_EC_PQ_Direct(t *testing.T) {
	// Phase 1: EC
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-direct.test.local",
		"dns_names=ec-direct.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 2: Direct to ML-DSA (skip hybrid)
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-direct.test.local",
		"dns_names=ml-direct.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))

	// Both PKIs should be independently operational
	runQPKI(t, "cert", "list", "--ca-dir", ecRootDir)
	runQPKI(t, "cert", "list", "--ca-dir", mlRootDir)
}

// TestA_Agility_Catalyst_PQ tests hybrid to pure PQ transition:
// Catalyst (hybrid) -> ML-DSA (post-quantum)
func TestA_Agility_Catalyst_PQ(t *testing.T) {
	// Phase 1: Catalyst hybrid
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	catalystCredDir := enrollCredential(t, catalystRootDir, "hybrid/catalyst/tls-server",
		"cn=catalyst-start.test.local",
		"dns_names=catalyst-start.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, catalystCredDir), "--ca", getCACert(t, catalystRootDir))

	// Phase 2: Pure ML-DSA
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-from-catalyst.test.local",
		"dns_names=ml-from-catalyst.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_Composite_PQ tests composite hybrid to pure PQ transition:
// Composite (hybrid) -> ML-DSA (post-quantum)
func TestA_Agility_Composite_PQ(t *testing.T) {
	// Phase 1: Composite hybrid
	compositeRootDir := setupCA(t, "hybrid/composite/root-ca", "Composite Root CA")
	compositeCredDir := enrollCredential(t, compositeRootDir, "hybrid/composite/tls-server",
		"cn=composite-start.test.local",
		"dns_names=composite-start.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, compositeCredDir), "--ca", getCACert(t, compositeRootDir))

	// Phase 2: Pure ML-DSA
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlCredDir := enrollCredential(t, mlRootDir, "ml/tls-server-sign",
		"cn=ml-from-composite.test.local",
		"dns_names=ml-from-composite.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, mlCredDir), "--ca", getCACert(t, mlRootDir))
}

// TestA_Agility_SLH_DSA tests SLH-DSA integration in agility scenarios
func TestA_Agility_EC_SLHDSA(t *testing.T) {
	// Phase 1: EC
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecCredDir := enrollCredential(t, ecRootDir, "ec/tls-server",
		"cn=ec-to-slh.test.local",
		"dns_names=ec-to-slh.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, ecCredDir), "--ca", getCACert(t, ecRootDir))

	// Phase 2: SLH-DSA (alternative PQ algorithm)
	slhRootDir := setupCA(t, "slh/root-ca", "SLH-DSA Root CA")
	slhCredDir := enrollCredential(t, slhRootDir, "slh/tls-server",
		"cn=slh.test.local",
		"dns_names=slh.test.local",
	)
	runQPKI(t, "cert", "verify", getCredentialCert(t, slhCredDir), "--ca", getCACert(t, slhRootDir))
}

// TestA_Agility_Full_PKI_Transition tests a complete PKI transition scenario
// including subordinate CAs and multiple end-entity types
func TestA_Agility_Full_PKI_Transition(t *testing.T) {
	// === Phase 1: Classical EC PKI ===
	ecRootDir := setupCA(t, "ec/root-ca", "EC Root CA")
	ecIssuingDir := setupSubordinateCA(t, "ec/issuing-ca", "EC Issuing CA", ecRootDir)

	// Issue various credential types
	enrollCredential(t, ecIssuingDir, "ec/tls-server", "cn=server.test.local", "dns_names=server.test.local")
	enrollCredential(t, ecIssuingDir, "ec/tls-client", "cn=client.test.local")
	enrollCredential(t, ecIssuingDir, "ec/code-signing", "cn=Code Signer")

	// Generate CRL
	ecCrlPath := filepath.Join(t.TempDir(), "ec.crl")
	runQPKI(t, "crl", "generate", "--ca-dir", ecIssuingDir, "--out", ecCrlPath)
	assertFileExists(t, ecCrlPath)

	// === Phase 2: Catalyst Hybrid PKI (parallel operation) ===
	catalystRootDir := setupCA(t, "hybrid/catalyst/root-ca", "Catalyst Root CA")
	catalystIssuingDir := setupSubordinateCA(t, "hybrid/catalyst/issuing-ca", "Catalyst Issuing CA", catalystRootDir)

	enrollCredential(t, catalystIssuingDir, "hybrid/catalyst/tls-server", "cn=server-hybrid.test.local", "dns_names=server-hybrid.test.local")
	enrollCredential(t, catalystIssuingDir, "hybrid/catalyst/signing", "cn=Hybrid Signer")

	catalystCrlPath := filepath.Join(t.TempDir(), "catalyst.crl")
	runQPKI(t, "crl", "generate", "--ca-dir", catalystIssuingDir, "--out", catalystCrlPath)

	// === Phase 3: Pure ML-DSA PKI ===
	mlRootDir := setupCA(t, "ml/root-ca", "ML-DSA Root CA")
	mlIssuingDir := setupSubordinateCA(t, "ml/issuing-ca", "ML-DSA Issuing CA", mlRootDir)

	enrollCredential(t, mlIssuingDir, "ml/tls-server-sign", "cn=server-pq.test.local", "dns_names=server-pq.test.local")
	enrollCredential(t, mlIssuingDir, "ml/code-signing", "cn=PQ Code Signer")

	mlCrlPath := filepath.Join(t.TempDir(), "ml.crl")
	runQPKI(t, "crl", "generate", "--ca-dir", mlIssuingDir, "--out", mlCrlPath)

	// Verify all PKIs are operational
	runQPKI(t, "cert", "list", "--ca-dir", ecIssuingDir)
	runQPKI(t, "cert", "list", "--ca-dir", catalystIssuingDir)
	runQPKI(t, "cert", "list", "--ca-dir", mlIssuingDir)
}
