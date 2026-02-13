package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// HybridCAConfig holds configuration for initializing a hybrid CA.
type HybridCAConfig struct {
	// CommonName is the CA's common name.
	CommonName string

	// Organization is the CA's organization.
	Organization string

	// Country is the CA's country code.
	Country string

	// ClassicalAlgorithm is the classical signature algorithm.
	ClassicalAlgorithm pkicrypto.AlgorithmID

	// PQCAlgorithm is the PQC signature algorithm.
	PQCAlgorithm pkicrypto.AlgorithmID

	// ValidityYears is the CA certificate validity in years.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	PathLen int

	// Passphrase for encrypting the private keys.
	Passphrase string
}

// InitializeHybridCA creates a new Catalyst-capable CA with both classical and PQC keys.
//
// This creates a CA that can issue Catalyst certificates with dual signatures.
// The CA certificate itself is a Catalyst certificate with both keys and signatures.
func InitializeHybridCA(store Store, cfg HybridCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Get full algorithm IDs (e.g., "ecdsa-p384", "ml-dsa-87")
	classicalAlgoID := string(cfg.ClassicalAlgorithm)
	pqcAlgoID := string(cfg.PQCAlgorithm)

	// Create CAInfo
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())

	// Create v1 as the initial active version with both algos
	info.CreateInitialVersion(
		[]string{"catalyst"},
		[]string{classicalAlgoID, pqcAlgoID},
	)

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Use initializeHybridInStore to create the CA in the version directory
	versionStore := NewFileStore(info.VersionDir("v1"))
	ca, err := initializeHybridInStore(versionStore, store, cfg)
	if err != nil {
		return nil, err
	}

	// Add key references for both classical and PQC keys (path relative to CA base directory)
	info.AddKey(KeyRef{
		ID:        "classical",
		Algorithm: cfg.ClassicalAlgorithm,
		Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/v1/keys/ca.%s.key", classicalAlgoID)),
	})
	info.AddKey(KeyRef{
		ID:        "pqc",
		Algorithm: cfg.PQCAlgorithm,
		Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/v1/keys/ca.%s.key", pqcAlgoID)),
	})

	// Save CAInfo
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	// Audit: Hybrid CA created
	if err := audit.LogCACreated(
		store.BasePath(),
		ca.cert.Subject.String(),
		fmt.Sprintf("Catalyst: %s + %s", cfg.ClassicalAlgorithm, cfg.PQCAlgorithm),
		true,
	); err != nil {
		return nil, err
	}

	// Update CA with global store and info
	ca.store = store
	ca.info = info

	return ca, nil
}

// createHybridKeysAndDirs creates directories and generates/saves hybrid keys.
func createHybridKeysAndDirs(store *FileStore, cfg HybridCAConfig) (pkicrypto.HybridSigner, error) {
	keysDir := store.BasePath() + "/keys"
	certsDir := store.BasePath() + "/certs"
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	hybridSigner, err := pkicrypto.GenerateHybridSigner(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hybrid CA key: %w", err)
	}

	classicalKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.ClassicalAlgorithm)
	pqcKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.PQCAlgorithm)
	if err := hybridSigner.SaveHybridKeys(classicalKeyPath, pqcKeyPath, []byte(cfg.Passphrase)); err != nil {
		return nil, fmt.Errorf("failed to save CA keys: %w", err)
	}

	return hybridSigner, nil
}

// buildCatalystTemplate builds the certificate template for a Catalyst CA.
func buildCatalystTemplate(cfg HybridCAConfig) (*x509.Certificate, error) {
	builder := x509util.NewCertificateBuilder().
		CommonName(cfg.CommonName).
		Organization(cfg.Organization).
		Country(cfg.Country).
		CA(cfg.PathLen).
		ValidForYears(cfg.ValidityYears)

	return builder.Build()
}

// setCatalystTemplateIdentifiers sets serial number and subject key ID on the template.
func setCatalystTemplateIdentifiers(template *x509.Certificate, serialStore Store, classicalPub interface{}) error {
	serialBytes, err := serialStore.NextSerial(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	skid, err := x509util.SubjectKeyID(classicalPub)
	if err != nil {
		return fmt.Errorf("failed to compute subject key ID: %w", err)
	}
	template.SubjectKeyId = skid
	return nil
}

// addAltKeyExtensions adds AltSubjectPublicKeyInfo and AltSignatureAlgorithm extensions.
func addAltKeyExtensions(template *x509.Certificate, pqcAlg pkicrypto.AlgorithmID, pqcPubBytes []byte) error {
	altPubKeyExt, err := x509util.EncodeAltSubjectPublicKeyInfo(pqcAlg, pqcPubBytes)
	if err != nil {
		return fmt.Errorf("failed to encode AltSubjectPublicKeyInfo: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altPubKeyExt)

	altSigAlgExt, err := x509util.EncodeAltSignatureAlgorithm(pqcAlg)
	if err != nil {
		return fmt.Errorf("failed to encode AltSignatureAlgorithm: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigAlgExt)
	return nil
}

// createCatalystSelfSignedCert creates a self-signed Catalyst certificate with dual signatures.
func createCatalystSelfSignedCert(template *x509.Certificate, signer pkicrypto.HybridSigner) (*x509.Certificate, error) {
	classicalSigner := signer.ClassicalSigner()
	classicalPub := classicalSigner.Public()

	// Step 1: Create pre-TBS certificate (without AltSignatureValue)
	preTBSDER, err := x509.CreateCertificate(rand.Reader, template, template, classicalPub, classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-TBS CA certificate: %w", err)
	}
	preTBSCert, err := x509.ParseCertificate(preTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pre-TBS CA certificate: %w", err)
	}

	// Step 2: Build PreTBSCertificate and sign with PQC
	preTBS, err := x509util.BuildPreTBSCertificate(preTBSCert.RawTBSCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to build PreTBSCertificate: %w", err)
	}
	pqcSig, err := signer.PQCSigner().Sign(rand.Reader, preTBS, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CA certificate with PQC: %w", err)
	}

	// Step 3: Add AltSignatureValue extension
	altSigValueExt, err := x509util.EncodeAltSignatureValue(pqcSig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureValue: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigValueExt)

	// Step 4: Create final self-signed Catalyst CA certificate
	finalDER, err := x509.CreateCertificate(rand.Reader, template, template, classicalPub, classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create Catalyst CA certificate: %w", err)
	}
	return x509.ParseCertificate(finalDER)
}

// createLocalCAInfo creates and saves CAInfo for a hybrid CA directory.
func createLocalCAInfo(store *FileStore, cfg HybridCAConfig) (*CAInfo, error) {
	classicalAlgoID := string(cfg.ClassicalAlgorithm)
	pqcAlgoID := string(cfg.PQCAlgorithm)

	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())
	info.AddKey(KeyRef{
		ID:        "classical",
		Algorithm: cfg.ClassicalAlgorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.ClassicalAlgorithm)),
	})
	info.AddKey(KeyRef{
		ID:        "pqc",
		Algorithm: cfg.PQCAlgorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.PQCAlgorithm)),
	})
	info.CreateInitialVersion([]string{"catalyst"}, []string{classicalAlgoID, pqcAlgoID})

	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}
	return info, nil
}

// initializeHybridInStore creates a Catalyst hybrid CA in the given store directory.
// It generates both classical and PQC keys, creates a Catalyst certificate with dual signatures,
// and saves everything. Does not check if the store already exists.
// The serialStore is used for serial number generation (can be same as store).
func initializeHybridInStore(store *FileStore, serialStore Store, cfg HybridCAConfig) (*CA, error) {
	hybridSigner, err := createHybridKeysAndDirs(store, cfg)
	if err != nil {
		return nil, err
	}

	template, err := buildCatalystTemplate(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template: %w", err)
	}

	if err := setCatalystTemplateIdentifiers(template, serialStore, hybridSigner.ClassicalSigner().Public()); err != nil {
		return nil, err
	}

	pqcPubBytes, err := pkicrypto.PublicKeyBytes(hybridSigner.PQCSigner().Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	if err := addAltKeyExtensions(template, cfg.PQCAlgorithm, pqcPubBytes); err != nil {
		return nil, err
	}

	cert, err := createCatalystSelfSignedCert(template, hybridSigner)
	if err != nil {
		return nil, err
	}

	certPath := HybridCertPath(store.BasePath(), HybridCertCatalyst, cfg.ClassicalAlgorithm, cfg.PQCAlgorithm, false)
	if err := saveCertToPath(certPath, cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	info, err := createLocalCAInfo(store, cfg)
	if err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   cert,
		signer: hybridSigner,
		info:   info,
	}, nil
}

// =============================================================================
// InitializeHybridWithSigner - Create Catalyst CA from existing HybridSigner
// =============================================================================

// HybridWithSignerConfig holds configuration for creating a Catalyst CA with an existing signer.
type HybridWithSignerConfig struct {
	// CommonName is the CA's common name.
	CommonName string

	// Organization is the CA's organization.
	Organization string

	// Country is the CA's country code.
	Country string

	// ValidityYears is the CA certificate validity in years.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	PathLen int

	// HSMConfig is the path to the HSM config file (for metadata).
	HSMConfig string

	// KeyLabel is the key label in the HSM (shared by classical and PQC keys).
	KeyLabel string
}

// InitializeHybridWithSigner creates a Catalyst CA using an existing HybridSigner.
// This is used for HSM-based Catalyst CAs where the keys already exist in the HSM.
// Unlike InitializeHybridCA, this does not generate keys but uses the provided signer.
func InitializeHybridWithSigner(store Store, cfg HybridWithSignerConfig, signer pkicrypto.HybridSigner) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Get algorithm IDs from the signer
	classicalAlg := signer.ClassicalSigner().Algorithm()
	pqcAlg := signer.PQCSigner().Algorithm()
	classicalAlgoID := string(classicalAlg)
	pqcAlgoID := string(pqcAlg)

	// Create CAInfo
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())

	// Create v1 as the initial active version with both algos
	info.CreateInitialVersion(
		[]string{"catalyst"},
		[]string{classicalAlgoID, pqcAlgoID},
	)

	// Create version directory structure
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Create certs directory
	versionDir := info.VersionDir("v1")
	certsDir := filepath.Join(versionDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Build certificate template
	hybridCfg := HybridCAConfig{
		CommonName:         cfg.CommonName,
		Organization:       cfg.Organization,
		Country:            cfg.Country,
		ClassicalAlgorithm: classicalAlg,
		PQCAlgorithm:       pqcAlg,
		ValidityYears:      cfg.ValidityYears,
		PathLen:            cfg.PathLen,
	}

	template, err := buildCatalystTemplate(hybridCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template: %w", err)
	}

	if err := setCatalystTemplateIdentifiers(template, store, signer.ClassicalSigner().Public()); err != nil {
		return nil, err
	}

	// Get PQC public key bytes for AltSubjectPublicKeyInfo
	pqcPubBytes, err := pkicrypto.PublicKeyBytes(signer.PQCSigner().Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	if err := addAltKeyExtensions(template, pqcAlg, pqcPubBytes); err != nil {
		return nil, err
	}

	// Create Catalyst certificate with dual signatures
	cert, err := createCatalystSelfSignedCert(template, signer)
	if err != nil {
		return nil, err
	}

	// Save certificate
	certPath := HybridCertPath(versionDir, HybridCertCatalyst, classicalAlg, pqcAlg, false)
	if err := saveCertToPath(certPath, cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Add HSM key references (both keys share the same label but different CKA_KEY_TYPE)
	info.AddKey(KeyRef{
		ID:        "classical",
		Algorithm: classicalAlg,
		Storage:   CreatePKCS11KeyRef(cfg.HSMConfig, cfg.KeyLabel, ""),
	})
	info.AddKey(KeyRef{
		ID:        "pqc",
		Algorithm: pqcAlg,
		Storage:   CreatePKCS11KeyRef(cfg.HSMConfig, cfg.KeyLabel, ""),
	})

	// Save CAInfo
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	// Audit: Hybrid CA created with HSM
	if err := audit.LogCACreated(
		store.BasePath(),
		cert.Subject.String(),
		fmt.Sprintf("Catalyst HSM: %s + %s", classicalAlg, pqcAlg),
		true,
	); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   cert,
		signer: signer,
		info:   info,
	}, nil
}
