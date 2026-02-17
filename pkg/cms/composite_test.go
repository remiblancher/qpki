package cms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// =============================================================================
// Composite Test Helpers
// =============================================================================

// compositeTestSetup holds the test environment for Composite CMS tests.
type compositeTestSetup struct {
	CA           *ca.CA
	CACert       *x509.Certificate
	HybridSigner pkicrypto.HybridSigner
	Classical    pkicrypto.AlgorithmID
	PQC          pkicrypto.AlgorithmID
}

// setupCompositeCA creates a Composite CA for testing.
func setupCompositeCA(t *testing.T, classical, pqc pkicrypto.AlgorithmID) *compositeTestSetup {
	t.Helper()

	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.CompositeCAConfig{
		CommonName:         "Test Composite CA",
		Organization:       "Test Org",
		ClassicalAlgorithm: classical,
		PQCAlgorithm:       pqc,
		ValidityYears:      1,
		PathLen:            0,
	}

	caInst, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize Composite CA: %v", err)
	}

	hybridSigner, ok := caInst.Signer().(pkicrypto.HybridSigner)
	if !ok {
		t.Fatalf("CA signer is not a HybridSigner")
	}

	return &compositeTestSetup{
		CA:           caInst,
		CACert:       caInst.Certificate(),
		HybridSigner: hybridSigner,
		Classical:    classical,
		PQC:          pqc,
	}
}

// generateCompositeCertificate creates an end-entity Composite certificate.
func generateCompositeCertificate(t *testing.T, setup *compositeTestSetup) (*x509.Certificate, pkicrypto.HybridSigner) {
	t.Helper()

	// Generate subject keys matching the CA's algorithm
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(setup.Classical)
	if err != nil {
		t.Fatalf("Failed to generate classical signer: %v", err)
	}

	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(setup.PQC)
	if err != nil {
		t.Fatalf("Failed to generate PQC signer: %v", err)
	}

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	req := ca.CompositeRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test End Entity",
				Organization: []string{"Test Org"},
			},
		},
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       setup.Classical,
		PQCAlg:             setup.PQC,
		Validity:           24 * time.Hour,
	}

	cert, err := setup.CA.IssueComposite(req)
	if err != nil {
		t.Fatalf("Failed to issue Composite certificate: %v", err)
	}

	return cert, hybridSigner
}

// =============================================================================
// Tests for signComposite function
// =============================================================================

func TestU_signComposite_MLDSA65_P256(t *testing.T) {
	// Generate signers
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate classical signer: %v", err)
	}

	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate PQC signer: %v", err)
	}

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	// Sign test data
	testData := []byte("Test data for composite signature")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("signComposite() returned empty signature")
	}

	// Verify the signature structure (should be CompositeSignatureValue)
	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}

	// ML-DSA-65 signature should be 3309 bytes
	if len(compSig.MLDSASig.Bytes) != 3309 {
		t.Errorf("ML-DSA signature size = %d, want 3309", len(compSig.MLDSASig.Bytes))
	}

	// ECDSA signature should be non-empty (variable size due to ASN.1 encoding)
	if len(compSig.ClassicalSig.Bytes) == 0 {
		t.Error("Classical signature should not be empty")
	}
}

func TestU_signComposite_MLDSA65_P384(t *testing.T) {
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP384)
	if err != nil {
		t.Fatalf("Failed to generate classical signer: %v", err)
	}

	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate PQC signer: %v", err)
	}

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	testData := []byte("Test data for P384+MLDSA65 composite")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}

	if len(compSig.MLDSASig.Bytes) != 3309 {
		t.Errorf("ML-DSA-65 signature size = %d, want 3309", len(compSig.MLDSASig.Bytes))
	}
}

func TestU_signComposite_MLDSA87_P521(t *testing.T) {
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP521)
	if err != nil {
		t.Fatalf("Failed to generate classical signer: %v", err)
	}

	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("Failed to generate PQC signer: %v", err)
	}

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	testData := []byte("Test data for P521+MLDSA87 composite")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}

	// ML-DSA-87 signature should be 4627 bytes
	if len(compSig.MLDSASig.Bytes) != 4627 {
		t.Errorf("ML-DSA-87 signature size = %d, want 4627", len(compSig.MLDSASig.Bytes))
	}
}

func TestU_signComposite_InvalidCombination(t *testing.T) {
	// P256 + ML-DSA-87 is not a valid combination
	classicalSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	pqcSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	testData := []byte("Test data")
	_, err = signComposite(testData, hybridSigner)
	if err == nil {
		t.Error("signComposite() should fail for invalid algorithm combination")
	}
}

// =============================================================================
// Tests for CMS Sign/Verify with Composite certificates
// =============================================================================

func TestF_CMS_Composite_SignAndVerify_MLDSA65_P256(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	// Sign data
	testData := []byte("Test message for CMS Composite signing")
	signedData, err := Sign(context.Background(), testData, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify (skip cert chain verification for unit test)
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if string(result.Content) != string(testData) {
		t.Errorf("Content mismatch: got %q, want %q", result.Content, testData)
	}
}

func TestF_CMS_Composite_SignAndVerify_MLDSA65_P384(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	testData := []byte("Test message for P384+MLDSA65")
	signedData, err := Sign(context.Background(), testData, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if string(result.Content) != string(testData) {
		t.Errorf("Content mismatch")
	}
}

func TestF_CMS_Composite_SignAndVerify_MLDSA87_P521(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP521, pkicrypto.AlgMLDSA87)
	cert, signer := generateCompositeCertificate(t, setup)

	testData := []byte("Test message for P521+MLDSA87")
	signedData, err := Sign(context.Background(), testData, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if string(result.Content) != string(testData) {
		t.Errorf("Content mismatch")
	}
}

func TestF_CMS_Composite_AllVariants(t *testing.T) {
	variants := []struct {
		name      string
		classical pkicrypto.AlgorithmID
		pqc       pkicrypto.AlgorithmID
	}{
		{"MLDSA65-ECDSA-P256", pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
		{"MLDSA65-ECDSA-P384", pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA65},
		{"MLDSA87-ECDSA-P521", pkicrypto.AlgECDSAP521, pkicrypto.AlgMLDSA87},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			setup := setupCompositeCA(t, v.classical, v.pqc)
			cert, signer := generateCompositeCertificate(t, setup)

			testData := []byte("Test message for " + v.name)
			signedData, err := Sign(context.Background(), testData, &SignerConfig{
				Certificate:  cert,
				Signer:       signer,
				DigestAlg:    crypto.SHA512,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			result, err := Verify(context.Background(), signedData, &VerifyConfig{
				SkipCertVerify: true,
			})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if string(result.Content) != string(testData) {
				t.Errorf("Content mismatch for %s", v.name)
			}
		})
	}
}

// =============================================================================
// Tests for signDataWithCert with Composite certificates
// =============================================================================

func TestU_signDataWithCert_Composite(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	// Verify the certificate is detected as Composite
	certType := x509util.GetCertificateType(cert)
	if certType != x509util.CertTypeComposite {
		t.Fatalf("Certificate type = %v, want Composite", certType)
	}

	testData := []byte("Test data for signDataWithCert")
	signature, err := signDataWithCert(testData, signer, crypto.SHA512, cert)
	if err != nil {
		t.Fatalf("signDataWithCert() error = %v", err)
	}

	// Verify it's a composite signature structure
	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Signature is not a CompositeSignatureValue: %v", err)
	}

	if len(compSig.MLDSASig.Bytes) == 0 {
		t.Error("ML-DSA signature should not be empty")
	}

	if len(compSig.ClassicalSig.Bytes) == 0 {
		t.Error("Classical signature should not be empty")
	}
}

func TestU_signDataWithCert_Composite_RequiresHybridSigner(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, _ := generateCompositeCertificate(t, setup)

	// Use a non-hybrid signer (should fail)
	nonHybridSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)

	testData := []byte("Test data")
	_, err := signDataWithCert(testData, nonHybridSigner, crypto.SHA512, cert)
	if err == nil {
		t.Error("signDataWithCert() should fail when Composite cert is used without HybridSigner")
	}
}

// =============================================================================
// Tests for getSignatureAlgorithmIdentifierWithCert with Composite
// =============================================================================

func TestU_getSignatureAlgorithmIdentifierWithCert_Composite(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	algID, err := getSignatureAlgorithmIdentifierWithCert(signer, crypto.SHA512, cert)
	if err != nil {
		t.Fatalf("getSignatureAlgorithmIdentifierWithCert() error = %v", err)
	}

	// Should return the composite algorithm OID
	expectedOID := x509util.OIDMLDSA65ECDSAP256SHA512
	if !algID.Algorithm.Equal(expectedOID) {
		t.Errorf("Algorithm OID = %v, want %v", algID.Algorithm, expectedOID)
	}
}

func TestU_getSignatureAlgorithmIdentifierWithCert_Composite_AllVariants(t *testing.T) {
	tests := []struct {
		name        string
		classical   pkicrypto.AlgorithmID
		pqc         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "P256+MLDSA65",
			classical:   pkicrypto.AlgECDSAP256,
			pqc:         pkicrypto.AlgMLDSA65,
			expectedOID: x509util.OIDMLDSA65ECDSAP256SHA512,
		},
		{
			name:        "P384+MLDSA65",
			classical:   pkicrypto.AlgECDSAP384,
			pqc:         pkicrypto.AlgMLDSA65,
			expectedOID: x509util.OIDMLDSA65ECDSAP384SHA512,
		},
		{
			name:        "P521+MLDSA87",
			classical:   pkicrypto.AlgECDSAP521,
			pqc:         pkicrypto.AlgMLDSA87,
			expectedOID: x509util.OIDMLDSA87ECDSAP521SHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupCompositeCA(t, tt.classical, tt.pqc)
			cert, signer := generateCompositeCertificate(t, setup)

			algID, err := getSignatureAlgorithmIdentifierWithCert(signer, crypto.SHA512, cert)
			if err != nil {
				t.Fatalf("getSignatureAlgorithmIdentifierWithCert() error = %v", err)
			}

			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Algorithm OID = %v, want %v", algID.Algorithm, tt.expectedOID)
			}
		})
	}
}

func TestU_getSignatureAlgorithmIdentifierWithCert_Composite_RequiresHybridSigner(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, _ := generateCompositeCertificate(t, setup)

	// Use a non-hybrid signer
	nonHybridSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)

	_, err := getSignatureAlgorithmIdentifierWithCert(nonHybridSigner, crypto.SHA512, cert)
	if err == nil {
		t.Error("getSignatureAlgorithmIdentifierWithCert() should fail for Composite cert without HybridSigner")
	}
}

// =============================================================================
// Tests for Composite signature verification (error cases)
// =============================================================================

func TestF_CMS_Composite_TamperedSignature(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	testData := []byte("Test message")
	signedData, err := Sign(context.Background(), testData, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Tamper with the signature
	tamperedData := modifySignature(t, signedData)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{
		SkipCertVerify: true,
	})
	if err == nil {
		t.Error("Verify() should fail for tampered signature")
	}
}

func TestF_CMS_Composite_TamperedContent(t *testing.T) {
	setup := setupCompositeCA(t, pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	cert, signer := generateCompositeCertificate(t, setup)

	testData := []byte("Test message")
	signedData, err := Sign(context.Background(), testData, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Tamper with the message digest
	tamperedData := modifyMessageDigest(t, signedData)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{
		SkipCertVerify: true,
	})
	if err == nil {
		t.Error("Verify() should fail for tampered content")
	}
}

// =============================================================================
// Tests for Composite signature components (ML-DSA and ECDSA)
// =============================================================================

func TestU_signComposite_VerifyComponents(t *testing.T) {
	// Generate signers
	classicalSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	pqcSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	testData := []byte("Test data for component verification")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	// Parse the composite signature
	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}

	// Get the composite algorithm
	compAlg, err := ca.GetCompositeAlgorithm(pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Build domain separator
	domainSep, err := ca.BuildDomainSeparator(compAlg.OID)
	if err != nil {
		t.Fatalf("BuildDomainSeparator() error = %v", err)
	}

	// Reconstruct the message that was signed
	messageToVerify := append(domainSep, testData...)

	// Verify ML-DSA component
	pqcPub := pqcSigner.Public()
	pqcKey, ok := pqcPub.(*mldsa65.PublicKey)
	if !ok {
		t.Fatalf("PQC public key is not *mldsa65.PublicKey")
	}

	mldsaValid := mldsa65.Verify(pqcKey, messageToVerify, nil, compSig.MLDSASig.Bytes)
	if !mldsaValid {
		t.Error("ML-DSA signature verification failed")
	}

	// Verify ECDSA component
	classicalPub := classicalSigner.Public()
	ecdsaPub, ok := classicalPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Classical public key is not *ecdsa.PublicKey")
	}

	// ECDSA was signed with SHA-512 digest
	h := crypto.SHA512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	ecdsaValid := ecdsa.VerifyASN1(ecdsaPub, digest, compSig.ClassicalSig.Bytes)
	if !ecdsaValid {
		t.Error("ECDSA signature verification failed")
	}
}

func TestU_signComposite_MLDSA87_VerifyComponents(t *testing.T) {
	classicalSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP521)
	pqcSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	testData := []byte("Test data for ML-DSA-87 component verification")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	var compSig ca.CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}

	compAlg, _ := ca.GetCompositeAlgorithm(pkicrypto.AlgECDSAP521, pkicrypto.AlgMLDSA87)
	domainSep, _ := ca.BuildDomainSeparator(compAlg.OID)
	messageToVerify := append(domainSep, testData...)

	// Verify ML-DSA-87 component
	pqcKey, ok := pqcSigner.Public().(*mldsa87.PublicKey)
	if !ok {
		t.Fatalf("PQC public key is not *mldsa87.PublicKey")
	}

	mldsaValid := mldsa87.Verify(pqcKey, messageToVerify, nil, compSig.MLDSASig.Bytes)
	if !mldsaValid {
		t.Error("ML-DSA-87 signature verification failed")
	}

	// Verify ECDSA P-521 component
	ecdsaPub := classicalSigner.Public().(*ecdsa.PublicKey)
	if ecdsaPub.Curve != elliptic.P521() {
		t.Errorf("Expected P-521 curve, got %v", ecdsaPub.Curve.Params().Name)
	}

	h := crypto.SHA512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	ecdsaValid := ecdsa.VerifyASN1(ecdsaPub, digest, compSig.ClassicalSig.Bytes)
	if !ecdsaValid {
		t.Error("ECDSA P-521 signature verification failed")
	}
}

// =============================================================================
// Tests for extracting signature algorithm OID from CMS
// =============================================================================

func TestF_CMS_Composite_SignatureAlgorithmOID(t *testing.T) {
	tests := []struct {
		name        string
		classical   pkicrypto.AlgorithmID
		pqc         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"P256+MLDSA65", pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65, x509util.OIDMLDSA65ECDSAP256SHA512},
		{"P384+MLDSA65", pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA65, x509util.OIDMLDSA65ECDSAP384SHA512},
		{"P521+MLDSA87", pkicrypto.AlgECDSAP521, pkicrypto.AlgMLDSA87, x509util.OIDMLDSA87ECDSAP521SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupCompositeCA(t, tt.classical, tt.pqc)
			cert, signer := generateCompositeCertificate(t, setup)

			testData := []byte("Test message")
			signedData, err := Sign(context.Background(), testData, &SignerConfig{
				Certificate:  cert,
				Signer:       signer,
				DigestAlg:    crypto.SHA512,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// Extract the signature algorithm OID from the CMS structure
			sigAlgOID := extractSignerInfoOID(t, signedData)
			if !sigAlgOID.Equal(tt.expectedOID) {
				t.Errorf("Signature algorithm OID = %v, want %v", sigAlgOID, tt.expectedOID)
			}
		})
	}
}
