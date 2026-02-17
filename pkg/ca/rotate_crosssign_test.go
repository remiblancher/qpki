package ca

import (
	"os"
	"path/filepath"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// crossSign Tests
// =============================================================================

func TestU_CA_CrossSign_ECDSAtoECDSA(t *testing.T) {
	// Create old CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old ECDSA CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new CA with different curve
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New ECDSA CA",
		Algorithm:     pkicrypto.AlgECDSAP384,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign() error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign() returned nil certificate")
	}

	// Verify cross-signed cert has new CA's subject
	if crossSignedCert.Subject.CommonName != "New ECDSA CA" {
		t.Errorf("Subject CN = %s, want New ECDSA CA", crossSignedCert.Subject.CommonName)
	}

	// Verify cross-signed cert is signed by old CA
	if crossSignedCert.Issuer.CommonName != "Old ECDSA CA" {
		t.Errorf("Issuer CN = %s, want Old ECDSA CA", crossSignedCert.Issuer.CommonName)
	}

	// Verify basic constraints are preserved
	if !crossSignedCert.IsCA {
		t.Error("Cross-signed cert should be CA")
	}
}

func TestU_CA_CrossSign_RSAtoRSA(t *testing.T) {
	// Create old CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old RSA CA",
		Algorithm:     pkicrypto.AlgRSA2048,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA RSA) error = %v", err)
	}

	// Create new CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New RSA CA",
		Algorithm:     pkicrypto.AlgRSA2048,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA RSA) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign(RSA) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign(RSA) returned nil certificate")
	}

	// Verify cross-signed cert has new CA's subject
	if crossSignedCert.Subject.CommonName != "New RSA CA" {
		t.Errorf("Subject CN = %s, want New RSA CA", crossSignedCert.Subject.CommonName)
	}

	// Verify cross-signed cert is signed by old CA
	if crossSignedCert.Issuer.CommonName != "Old RSA CA" {
		t.Errorf("Issuer CN = %s, want Old RSA CA", crossSignedCert.Issuer.CommonName)
	}
}

func TestU_CA_CrossSign_Ed25519toEd25519(t *testing.T) {
	// Create old CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old Ed25519 CA",
		Algorithm:     pkicrypto.AlgEd25519,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA Ed25519) error = %v", err)
	}

	// Create new CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New Ed25519 CA",
		Algorithm:     pkicrypto.AlgEd25519,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA Ed25519) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign(Ed25519) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign(Ed25519) returned nil certificate")
	}

	// Verify cross-signed cert has new CA's subject
	if crossSignedCert.Subject.CommonName != "New Ed25519 CA" {
		t.Errorf("Subject CN = %s, want New Ed25519 CA", crossSignedCert.Subject.CommonName)
	}
}

func TestU_CA_CrossSign_MixedAlgorithms(t *testing.T) {
	// Create old ECDSA CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old ECDSA CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new RSA CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New RSA CA",
		Algorithm:     pkicrypto.AlgRSA2048,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA RSA) error = %v", err)
	}

	// Cross-sign ECDSA -> RSA
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign(ECDSA->RSA) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign(ECDSA->RSA) returned nil certificate")
	}

	// Verify correct subjects
	if crossSignedCert.Subject.CommonName != "New RSA CA" {
		t.Errorf("Subject CN = %s, want New RSA CA", crossSignedCert.Subject.CommonName)
	}

	if crossSignedCert.Issuer.CommonName != "Old ECDSA CA" {
		t.Errorf("Issuer CN = %s, want Old ECDSA CA", crossSignedCert.Issuer.CommonName)
	}
}

// =============================================================================
// crossSignPQC Tests
// =============================================================================

func TestU_CA_CrossSignPQC_ECDSAtoPQC(t *testing.T) {
	// Create old classical CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old ECDSA CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new PQC CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := PQCCAConfig{
		CommonName:    "New MLDSA CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := InitializePQCCA(newStore, newCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(newCA) error = %v", err)
	}

	// Cross-sign using crossSignPQC (since Go's x509 doesn't support PQC public keys)
	crossSignedCert, err := crossSignPQC(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSignPQC() error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSignPQC() returned nil certificate")
	}

	// Verify cross-signed cert has new CA's subject
	if crossSignedCert.Subject.CommonName != "New MLDSA CA" {
		t.Errorf("Subject CN = %s, want New MLDSA CA", crossSignedCert.Subject.CommonName)
	}

	// Verify cross-signed cert is signed by old CA
	if crossSignedCert.Issuer.CommonName != "Old ECDSA CA" {
		t.Errorf("Issuer CN = %s, want Old ECDSA CA", crossSignedCert.Issuer.CommonName)
	}
}

func TestU_CA_CrossSignPQC_RSAtoPQC(t *testing.T) {
	// Create old RSA CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old RSA CA",
		Algorithm:     pkicrypto.AlgRSA2048,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA RSA) error = %v", err)
	}

	// Create new PQC CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := PQCCAConfig{
		CommonName:    "New MLDSA CA",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := InitializePQCCA(newStore, newCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(newCA) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSignPQC(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSignPQC(RSA->PQC) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSignPQC(RSA->PQC) returned nil certificate")
	}

	// Verify correct subjects
	if crossSignedCert.Subject.CommonName != "New MLDSA CA" {
		t.Errorf("Subject CN = %s, want New MLDSA CA", crossSignedCert.Subject.CommonName)
	}
}

func TestU_CA_CrossSignPQC_SLHDSA(t *testing.T) {
	// Create old ECDSA CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old ECDSA CA",
		Algorithm:     pkicrypto.AlgECDSAP384,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new SLH-DSA CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := PQCCAConfig{
		CommonName:    "New SLHDSA CA",
		Algorithm:     pkicrypto.AlgSLHDSA128f,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := InitializePQCCA(newStore, newCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(SLH-DSA) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSignPQC(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSignPQC(SLHDSA) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSignPQC(SLHDSA) returned nil certificate")
	}
}

// =============================================================================
// saveCrossSignedCert Tests
// =============================================================================

func TestU_CA_SaveCrossSignedCert(t *testing.T) {
	// Create a simple CA to get a certificate
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Save the certificate using saveCrossSignedCert
	crossSignedPath := filepath.Join(tmpDir, "cross-signed", "by-previous.crt")
	err = saveCrossSignedCert(crossSignedPath, ca.Certificate())
	if err != nil {
		t.Fatalf("saveCrossSignedCert() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(crossSignedPath); os.IsNotExist(err) {
		t.Error("saveCrossSignedCert() should create the file")
	}
}

func TestU_CA_SaveCrossSignedCert_CreatesDirectory(t *testing.T) {
	// Create a simple CA to get a certificate
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Save to a deeply nested path that doesn't exist
	nestedPath := filepath.Join(tmpDir, "deep", "nested", "path", "cert.pem")
	err = saveCrossSignedCert(nestedPath, ca.Certificate())
	if err != nil {
		t.Fatalf("saveCrossSignedCert() with nested path error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Error("saveCrossSignedCert() should create nested directories")
	}
}

// =============================================================================
// crossSign with Extensions Tests
// =============================================================================

func TestU_CA_CrossSign_PreservesExtensions(t *testing.T) {
	// Create old CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       2,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new CA with path length constraint
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New CA",
		Algorithm:     pkicrypto.AlgECDSAP384,
		ValidityYears: 10,
		PathLen:       1, // Different path length
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA) error = %v", err)
	}

	// Cross-sign
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign() error = %v", err)
	}

	// Verify path length is preserved
	if crossSignedCert.MaxPathLen != newCA.Certificate().MaxPathLen {
		t.Errorf("MaxPathLen = %d, want %d", crossSignedCert.MaxPathLen, newCA.Certificate().MaxPathLen)
	}

	// Verify KeyUsage is preserved
	if crossSignedCert.KeyUsage != newCA.Certificate().KeyUsage {
		t.Errorf("KeyUsage mismatch")
	}
}

// =============================================================================
// crossSign Hybrid Tests
// =============================================================================

func TestU_CA_CrossSign_HybridCAToClassical(t *testing.T) {
	// Create old Hybrid CA (Catalyst)
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := HybridCAConfig{
		CommonName:         "Old Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	oldCA, err := InitializeHybridCA(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA(oldCA) error = %v", err)
	}

	// Create new classical CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New Classical CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA) error = %v", err)
	}

	// Cross-sign using hybrid CA
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign(Hybrid->Classical) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign(Hybrid->Classical) returned nil certificate")
	}

	// Verify correct subjects
	if crossSignedCert.Subject.CommonName != "New Classical CA" {
		t.Errorf("Subject CN = %s, want New Classical CA", crossSignedCert.Subject.CommonName)
	}

	if crossSignedCert.Issuer.CommonName != "Old Hybrid CA" {
		t.Errorf("Issuer CN = %s, want Old Hybrid CA", crossSignedCert.Issuer.CommonName)
	}
}

func TestU_CA_CrossSign_ClassicalToHybrid(t *testing.T) {
	// Create old classical CA
	oldDir := t.TempDir()
	oldStore := NewFileStore(oldDir)

	oldCfg := Config{
		CommonName:    "Old Classical CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(oldStore, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new Hybrid CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := HybridCAConfig{
		CommonName:         "New Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	newCA, err := InitializeHybridCA(newStore, newCfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA(newCA) error = %v", err)
	}

	// Cross-sign classical -> hybrid
	// This should work via crossSignPQC because hybrid cert has PQC public key
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign(Classical->Hybrid) error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign(Classical->Hybrid) returned nil certificate")
	}

	// Verify correct subjects
	if crossSignedCert.Subject.CommonName != "New Hybrid CA" {
		t.Errorf("Subject CN = %s, want New Hybrid CA", crossSignedCert.Subject.CommonName)
	}
}
