package x509util_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// =============================================================================
// Integration tests for PQC CSR processing (issue command support)
// =============================================================================

// TestF_IssueFromMLDSACSR tests the full flow of creating an ML-DSA CSR
// and extracting the information needed for certificate issuance.
func TestF_IssueFromMLDSACSR(t *testing.T) {
	// Generate ML-DSA key pair
	kp, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}

	signer, err := crypto.NewSoftwareSigner(kp)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create PQC CSR
	csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
		Subject: pkix.Name{
			CommonName:   "alice@example.com",
			Organization: []string{"ACME Corp"},
			Country:      []string{"FR"},
		},
		DNSNames:       []string{"alice.example.com"},
		EmailAddresses: []string{"alice@example.com"},
		Signer:         signer,
	})
	if err != nil {
		t.Fatalf("CreatePQCSignatureCSR failed: %v", err)
	}

	// Parse the CSR (simulating what issue.go does)
	pqcInfo, err := x509util.ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("ParsePQCCSR failed: %v", err)
	}

	// Verify signature (no attestation needed for ML-DSA)
	if err := x509util.VerifyPQCCSRSignature(pqcInfo, nil); err != nil {
		t.Fatalf("VerifyPQCCSRSignature failed: %v", err)
	}

	// Verify extracted information
	if pqcInfo.Subject.CommonName != "alice@example.com" {
		t.Errorf("CommonName mismatch: got %s, want alice@example.com", pqcInfo.Subject.CommonName)
	}

	// Verify algorithm detection
	pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
	if pubKeyAlg != crypto.AlgMLDSA65 {
		t.Errorf("Algorithm mismatch: got %s, want ml-dsa-65", pubKeyAlg)
	}

	// Verify public key can be parsed
	parsedPubKey, err := crypto.ParsePublicKey(pubKeyAlg, pqcInfo.PublicKeyBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if parsedPubKey == nil {
		t.Error("Parsed public key is nil")
	}

	t.Logf("Successfully processed ML-DSA-65 CSR for %s", pqcInfo.Subject.CommonName)
}

// TestF_IssueFromSLHDSACSR tests SLH-DSA CSR processing.
func TestF_IssueFromSLHDSACSR(t *testing.T) {
	// Generate SLH-DSA key pair
	kp, err := crypto.GenerateKeyPair(crypto.AlgSLHDSA128f)
	if err != nil {
		t.Fatalf("Failed to generate SLH-DSA-128f key pair: %v", err)
	}

	signer, err := crypto.NewSoftwareSigner(kp)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create PQC CSR
	csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
		Subject: pkix.Name{
			CommonName: "server.example.com",
		},
		DNSNames: []string{"server.example.com", "www.example.com"},
		Signer:   signer,
	})
	if err != nil {
		t.Fatalf("CreatePQCSignatureCSR failed: %v", err)
	}

	// Parse and verify
	pqcInfo, err := x509util.ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("ParsePQCCSR failed: %v", err)
	}

	if err := x509util.VerifyPQCCSRSignature(pqcInfo, nil); err != nil {
		t.Fatalf("VerifyPQCCSRSignature failed: %v", err)
	}

	// Verify algorithm
	pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
	if pubKeyAlg != crypto.AlgSLHDSA128f {
		t.Errorf("Algorithm mismatch: got %s, want slh-dsa-128f", pubKeyAlg)
	}

	t.Logf("Successfully processed SLH-DSA-128f CSR for %s", pqcInfo.Subject.CommonName)
}

// TestF_IssueFromMLKEMCSR tests ML-KEM CSR with RFC 9883 attestation.
func TestF_IssueFromMLKEMCSR(t *testing.T) {
	// Step 1: Create attestation certificate (signature key)
	attestKP, err := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate attestation key pair: %v", err)
	}
	attestSigner, err := crypto.NewSoftwareSigner(attestKP)
	if err != nil {
		t.Fatalf("Failed to create attestation signer: %v", err)
	}

	// Mock attestation certificate with actual public key
	attestCert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "alice@example.com",
		},
		RawIssuer: mustMarshalSubject(t, pkix.Name{CommonName: "Test CA"}),
		PublicKey: attestKP.PublicKey, // Include actual public key
	}

	// Step 2: Generate ML-KEM key pair
	kemKP, err := crypto.GenerateKEMKeyPair(crypto.AlgMLKEM768)
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM-768 key pair: %v", err)
	}

	// Step 3: Create ML-KEM CSR with RFC 9883 attestation
	csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
		Subject: pkix.Name{
			CommonName: "alice@example.com",
		},
		KEMPublicKey: kemKP.PublicKey,
		KEMAlgorithm: crypto.AlgMLKEM768,
		AttestCert:   attestCert,
		AttestSigner: attestSigner,
		IncludeCert:  false,
	})
	if err != nil {
		t.Fatalf("CreateKEMCSRWithAttestation failed: %v", err)
	}

	// Step 4: Parse the CSR
	pqcInfo, err := x509util.ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("ParsePQCCSR failed: %v", err)
	}

	// Step 5: Verify it has a possession statement
	if !pqcInfo.HasPossessionStatement() {
		t.Fatal("ML-KEM CSR should have RFC 9883 possession statement")
	}

	// Step 6: Validate RFC 9883 statement
	if err := x509util.ValidateRFC9883Statement(pqcInfo, attestCert); err != nil {
		t.Fatalf("ValidateRFC9883Statement failed: %v", err)
	}

	// Step 7: Verify signature using attestation public key
	if err := x509util.VerifyPQCCSRSignature(pqcInfo, attestCert.PublicKey); err != nil {
		t.Fatalf("VerifyPQCCSRSignature failed: %v", err)
	}

	// Step 8: Verify algorithm detection
	pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
	if pubKeyAlg != crypto.AlgMLKEM768 {
		t.Errorf("Algorithm mismatch: got %s, want ml-kem-768", pubKeyAlg)
	}

	// Step 9: For KEM, the public key bytes are used directly (no ParsePublicKey)
	// This is because the certificate will embed the raw KEM public key
	if len(pqcInfo.PublicKeyBytes) == 0 {
		t.Error("KEM public key bytes are empty")
	}

	t.Logf("Successfully processed ML-KEM-768 CSR with RFC 9883 attestation (pubkey: %d bytes)", len(pqcInfo.PublicKeyBytes))
}

// TestF_IssueFromMLKEMCSR_AttestCertMissing tests that ML-KEM CSR fails
// without attestation certificate.
func TestF_IssueFromMLKEMCSR_AttestCertMissing(t *testing.T) {
	// Create a valid ML-KEM CSR with attestation
	attestKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	attestSigner, _ := crypto.NewSoftwareSigner(attestKP)
	attestCert := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		RawIssuer:    mustMarshalSubject(t, pkix.Name{CommonName: "Test CA"}),
		PublicKey:    attestKP.PublicKey,
	}
	kemKP, _ := crypto.GenerateKEMKeyPair(crypto.AlgMLKEM768)

	csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
		Subject:      pkix.Name{CommonName: "test"},
		KEMPublicKey: kemKP.PublicKey,
		KEMAlgorithm: crypto.AlgMLKEM768,
		AttestCert:   attestCert,
		AttestSigner: attestSigner,
	})
	if err != nil {
		t.Fatalf("CreateKEMCSRWithAttestation failed: %v", err)
	}

	// Parse CSR
	pqcInfo, err := x509util.ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("ParsePQCCSR failed: %v", err)
	}

	// Try to verify without attestation public key - should fail
	err = x509util.VerifyPQCCSRSignature(pqcInfo, nil)
	if err == nil {
		t.Error("Expected error when verifying ML-KEM CSR without attestation key")
	}
}

// TestF_IssueFromCSR_SignatureInvalid tests signature verification failure.
func TestF_IssueFromCSR_SignatureInvalid(t *testing.T) {
	// Generate ML-DSA key pair
	kp, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA44)
	signer, _ := crypto.NewSoftwareSigner(kp)

	csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
		Subject: pkix.Name{CommonName: "test"},
		Signer:  signer,
	})
	if err != nil {
		t.Fatalf("CreatePQCSignatureCSR failed: %v", err)
	}

	// Parse CSR
	pqcInfo, err := x509util.ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("ParsePQCCSR failed: %v", err)
	}

	// Corrupt the signature
	if len(pqcInfo.SignatureBytes) > 0 {
		pqcInfo.SignatureBytes[0] ^= 0xFF
	}

	// Verify should fail
	err = x509util.VerifyPQCCSRSignature(pqcInfo, nil)
	if err == nil {
		t.Error("Expected error when verifying CSR with corrupted signature")
	}
}

// TestF_IssueFromCSR_AllMLDSAVariants tests all ML-DSA security levels.
func TestF_IssueFromCSR_AllMLDSAVariants(t *testing.T) {
	variants := []crypto.AlgorithmID{
		crypto.AlgMLDSA44,
		crypto.AlgMLDSA65,
		crypto.AlgMLDSA87,
	}

	for _, alg := range variants {
		t.Run(string(alg), func(t *testing.T) {
			kp, err := crypto.GenerateKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", alg, err)
			}

			signer, _ := crypto.NewSoftwareSigner(kp)

			csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
				Subject: pkix.Name{CommonName: "test-" + string(alg)},
				Signer:  signer,
			})
			if err != nil {
				t.Fatalf("CreatePQCSignatureCSR failed: %v", err)
			}

			pqcInfo, err := x509util.ParsePQCCSR(csrDER)
			if err != nil {
				t.Fatalf("ParsePQCCSR failed: %v", err)
			}

			if err := x509util.VerifyPQCCSRSignature(pqcInfo, nil); err != nil {
				t.Fatalf("VerifyPQCCSRSignature failed: %v", err)
			}

			detectedAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
			if detectedAlg != alg {
				t.Errorf("Algorithm mismatch: got %s, want %s", detectedAlg, alg)
			}
		})
	}
}

// TestF_IssueFromCSR_AllMLKEMVariants tests all ML-KEM security levels.
func TestF_IssueFromCSR_AllMLKEMVariants(t *testing.T) {
	variants := []crypto.AlgorithmID{
		crypto.AlgMLKEM512,
		crypto.AlgMLKEM768,
		crypto.AlgMLKEM1024,
	}

	// Create attestation signer once
	attestKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	attestSigner, _ := crypto.NewSoftwareSigner(attestKP)

	for _, alg := range variants {
		t.Run(string(alg), func(t *testing.T) {
			kemKP, err := crypto.GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", alg, err)
			}

			attestCert := &x509.Certificate{
				SerialNumber: big.NewInt(int64(len(alg))),
				RawIssuer:    mustMarshalSubject(t, pkix.Name{CommonName: "Test CA"}),
				PublicKey:    attestKP.PublicKey,
			}

			csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
				Subject:      pkix.Name{CommonName: "test-" + string(alg)},
				KEMPublicKey: kemKP.PublicKey,
				KEMAlgorithm: alg,
				AttestCert:   attestCert,
				AttestSigner: attestSigner,
			})
			if err != nil {
				t.Fatalf("CreateKEMCSRWithAttestation failed: %v", err)
			}

			pqcInfo, err := x509util.ParsePQCCSR(csrDER)
			if err != nil {
				t.Fatalf("ParsePQCCSR failed: %v", err)
			}

			if !pqcInfo.HasPossessionStatement() {
				t.Fatal("Expected possession statement")
			}

			if err := x509util.VerifyPQCCSRSignature(pqcInfo, attestCert.PublicKey); err != nil {
				t.Fatalf("VerifyPQCCSRSignature failed: %v", err)
			}

			detectedAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
			if detectedAlg != alg {
				t.Errorf("Algorithm mismatch: got %s, want %s", detectedAlg, alg)
			}
		})
	}
}

// mustMarshalSubject marshals a pkix.Name for testing.
func mustMarshalSubject(t *testing.T, name pkix.Name) []byte {
	t.Helper()
	// Use a simple encoding for test purposes
	return []byte{0x30, 0x00} // Empty SEQUENCE
}
