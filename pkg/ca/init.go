package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// Config holds CA configuration options.
type Config struct {
	// CommonName is the CA's common name.
	CommonName string

	// Organization is the CA's organization.
	Organization string

	// Country is the CA's country code.
	Country string

	// Algorithm is the signature algorithm for the CA key.
	Algorithm pkicrypto.AlgorithmID

	// ValidityYears is the CA certificate validity in years.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	// Use -1 for unlimited, 0 for end-entity only.
	PathLen int

	// Passphrase for encrypting the private key.
	Passphrase string

	// HybridConfig enables hybrid PQC extension.
	HybridConfig *HybridConfig

	// Profile is the profile used to create this CA (stored in metadata).
	Profile string

	// KeyProvider is the key provider for key operations.
	// If nil, SoftwareKeyProvider is used by default.
	KeyProvider pkicrypto.KeyProvider

	// KeyStorageConfig is the configuration for key storage.
	// For software: set KeyPath and Passphrase.
	// For HSM: set PKCS11* fields.
	KeyStorageConfig pkicrypto.KeyStorageConfig

	// Extensions is the X.509 extensions configuration from the profile.
	// Applied to the CA certificate (e.g., key usage, policies).
	Extensions *profile.ExtensionsConfig
}

// HybridConfig configures hybrid PQC for the CA.
type HybridConfig struct {
	// Algorithm is the PQC algorithm.
	Algorithm pkicrypto.AlgorithmID

	// Policy is the hybrid verification policy.
	Policy x509util.HybridPolicy
}

// Validate checks that the Config has all required fields.
func (c *Config) Validate() error {
	if c.CommonName == "" {
		return fmt.Errorf("common_name is required")
	}
	if c.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if c.ValidityYears <= 0 {
		return fmt.Errorf("validity_years must be positive")
	}
	return nil
}

// Initialize creates a new CA with self-signed certificate.
// The CA is created with the new versioned structure (ca.json + versions/v1/).
func Initialize(store Store, cfg Config) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Get full algorithm ID (e.g., "ecdsa-p256", "ml-dsa-65")
	algoID := string(cfg.Algorithm)

	// Create CAInfo with subject
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())

	// Create v1 as the initial active version - store full algorithm IDs
	info.CreateInitialVersion(
		[]string{cfg.Profile},
		[]string{algoID},
	)

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Create a store for the version directory
	versionStore := NewFileStore(filepath.Join(store.BasePath(), "versions", "v1"))

	// Use initializeInStore to create the CA in the version directory
	ca, kp, keyCfg, err := initializeInStore(versionStore, store, cfg)
	if err != nil {
		return nil, err
	}

	// Add key reference to CAInfo (path relative to CA base directory)
	info.AddKey(KeyRef{
		ID:        "default",
		Algorithm: cfg.Algorithm,
		Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/v1/keys/ca.%s.key", algoID)),
	})

	// Save CAInfo to ca.json
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	// Audit: CA created successfully
	if err := audit.LogCACreated(store.BasePath(), ca.cert.Subject.String(), string(cfg.Algorithm), true); err != nil {
		return nil, err
	}

	// Update CA with global info
	ca.store = store
	ca.keyProvider = kp
	ca.keyConfig = keyCfg
	ca.info = info

	return ca, nil
}

// initializeInStore creates a CA in the given store directory.
// It generates keys, creates a self-signed certificate, and saves everything.
// Does not check if the store already exists or handle versioning.
// The serialStore is used for serial number generation (can be same as store).
// Returns the CA, key provider, and key config for the caller to use.
func initializeInStore(store *FileStore, serialStore Store, cfg Config) (*CA, pkicrypto.KeyProvider, pkicrypto.KeyStorageConfig, error) {
	// Create keys/ and certs/ directories
	keysDir := filepath.Join(store.BasePath(), "keys")
	certsDir := filepath.Join(store.BasePath(), "certs")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Determine key provider and storage config
	kp := cfg.KeyProvider
	if kp == nil {
		kp = pkicrypto.NewSoftwareKeyProvider()
	}

	// Build key storage config
	keyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.Algorithm)
	keyCfg := cfg.KeyStorageConfig
	if keyCfg.Type == "" {
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    keyPath,
			Passphrase: cfg.Passphrase,
		}
	}

	// Generate CA key pair using the key provider
	signer, err := kp.Generate(cfg.Algorithm, keyCfg)
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Build CA certificate
	builder := x509util.NewCertificateBuilder().
		CommonName(cfg.CommonName).
		Organization(cfg.Organization).
		Country(cfg.Country).
		CA(cfg.PathLen).
		ValidForYears(cfg.ValidityYears)

	template, err := builder.Build()
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to build certificate template: %w", err)
	}

	// Generate serial number (from the serial store, not the version store)
	serialBytes, err := serialStore.NextSerial(context.Background())
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set subject key ID
	skid, err := x509util.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to compute subject key ID: %w", err)
	}
	template.SubjectKeyId = skid

	// Apply extensions from profile if configured
	if cfg.Extensions != nil {
		if err := cfg.Extensions.Apply(template); err != nil {
			return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save CA certificate
	certPath := CACertPathForAlgorithm(store.BasePath(), cfg.Algorithm)
	if err := saveCertToPath(certPath, cert); err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create local CAInfo for this directory
	algoID := string(cfg.Algorithm)
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())
	info.AddKey(KeyRef{
		ID:        "default",
		Algorithm: cfg.Algorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.Algorithm)),
	})
	info.CreateInitialVersion([]string{cfg.Profile}, []string{algoID})
	if err := info.Save(); err != nil {
		return nil, nil, pkicrypto.KeyStorageConfig{}, fmt.Errorf("failed to save CA info: %w", err)
	}

	return &CA{
		store:  store,
		cert:   cert,
		signer: signer,
		info:   info,
	}, kp, keyCfg, nil
}

// InitializeWithSigner creates a new CA using an external signer (e.g., HSM).
// Unlike Initialize, this does not generate or save a private key.
// Creates versioned directory structure with CAInfo metadata.
func InitializeWithSigner(store Store, cfg Config, signer pkicrypto.Signer) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Create versioned directory structure
	algoID := string(cfg.Algorithm)
	versionDir := filepath.Join(store.BasePath(), "versions", "v1")
	certsDir := filepath.Join(versionDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create version certs directory: %w", err)
	}

	// Build CA certificate
	builder := x509util.NewCertificateBuilder().
		CommonName(cfg.CommonName).
		Organization(cfg.Organization).
		Country(cfg.Country).
		CA(cfg.PathLen).
		ValidForYears(cfg.ValidityYears)

	template, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template: %w", err)
	}

	// Generate serial number
	serialBytes, err := store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set subject key ID
	skid, err := x509util.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
	}
	template.SubjectKeyId = skid

	// Apply extensions from profile if configured
	if cfg.Extensions != nil {
		if err := cfg.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Self-sign the certificate
	var cert *x509.Certificate
	if cfg.Algorithm.IsPQC() {
		// Use custom PQC certificate creation (Go's x509 doesn't support PQC)
		cert, err = createPQCCACertificate(store, signer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create PQC CA certificate: %w", err)
		}
	} else {
		// Use standard x509 for classical algorithms
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA certificate: %w", err)
		}

		cert, err = x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
	}

	// Save CA certificate to versioned path
	certPath := filepath.Join(certsDir, fmt.Sprintf("ca.%s.pem", algoID))
	if err := store.SaveCertAt(context.Background(), certPath, cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create and save CAInfo metadata
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())
	info.CreateInitialVersion([]string{cfg.Profile}, []string{algoID})
	// Note: KeyRef will be added by the caller for HSM keys

	// Audit: CA created successfully (with HSM)
	if err := audit.LogCACreated(store.BasePath(), cert.Subject.String(), string(cfg.Algorithm)+" (HSM)", true); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   cert,
		signer: signer,
		info:   info,
	}, nil
}

// getAlgorithmFamily returns the algorithm family from an algorithm ID.
func getAlgorithmFamily(alg pkicrypto.AlgorithmID) string {
	switch alg {
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		return "ec"
	case "rsa-2048", "rsa-3072", "rsa-4096":
		return "rsa"
	case "ed25519", "ed448":
		return "ed"
	case "ml-dsa-44", "ml-dsa-65", "ml-dsa-87":
		return "ml-dsa"
	case "slh-dsa-sha2-128s", "slh-dsa-sha2-128f", "slh-dsa-sha2-192s", "slh-dsa-sha2-192f", "slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
		"slh-dsa-shake-128s", "slh-dsa-shake-128f", "slh-dsa-shake-192s", "slh-dsa-shake-192f", "slh-dsa-shake-256s", "slh-dsa-shake-256f":
		return "slh-dsa"
	default:
		return string(alg)
	}
}

// saveCertToPath saves a certificate to a PEM file.
func saveCertToPath(path string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}
