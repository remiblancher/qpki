package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// MultiProfileInitConfig holds configuration for initializing a multi-profile CA.
// A multi-profile CA has one certificate per algorithm family (e.g., EC + ML-DSA).
type MultiProfileInitConfig struct {
	// Profiles is a list of profile configurations to initialize.
	// Each profile produces one CA certificate.
	Profiles []ProfileInitConfig

	// Variables is a map of variable values for template resolution.
	// These are used to resolve {{ variable }} templates in profiles.
	Variables map[string]string

	// Passphrase for encrypting the private keys.
	Passphrase string

	// KeyProvider is the key provider for key operations.
	// If nil, SoftwareKeyProvider is used by default.
	KeyProvider pkicrypto.KeyProvider

	// KeyStorageConfig is the base configuration for key storage.
	KeyStorageConfig pkicrypto.KeyStorageConfig
}

// ProfileInitConfig holds configuration for a single profile in multi-profile init.
type ProfileInitConfig struct {
	// Profile is the loaded profile configuration.
	Profile *profile.Profile

	// ValidityYears overrides the profile's validity if set.
	// If zero, uses the profile's configured validity.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	// Use -1 for unlimited, 0 for end-entity only.
	PathLen int
}

// MultiProfileInitResult holds the result of multi-profile CA initialization.
type MultiProfileInitResult struct {
	// Info is the CA info.
	Info *CAInfo

	// Certificates maps algorithm family to the created certificate.
	Certificates map[string]*x509.Certificate
}

// InitializeMultiProfile creates a new CA with multiple certificates (one per profile).
// Each profile's certificate is stored in its algorithm family subdirectory.
//
// Directory structure:
//
//	ca/
//	├── ca.json
//	├── versions/
//	│   └── v1/
//	│       ├── ec/
//	│       │   ├── cert.pem
//	│       │   └── key.pem
//	│       └── ml-dsa/
//	│           ├── cert.pem
//	│           └── key.pem
//	├── certs/
//	├── crl/
//	├── index.txt
//	└── serial
func InitializeMultiProfile(basePath string, cfg MultiProfileInitConfig) (*MultiProfileInitResult, error) {
	if err := validateMultiProfileInitConfig(basePath, cfg); err != nil {
		return nil, err
	}

	store := NewFileStore(basePath)
	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	info := createMultiProfileCAInfo(basePath, cfg)

	kp := cfg.KeyProvider
	if kp == nil {
		kp = pkicrypto.NewSoftwareKeyProvider()
	}

	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	result := &MultiProfileInitResult{
		Info:         info,
		Certificates: make(map[string]*x509.Certificate),
	}

	subjectInfo := resolveSubjectFromConfig(cfg)

	for _, profCfg := range cfg.Profiles {
		cert, err := createProfileCertificate(profCfg, subjectInfo, info, store, kp, cfg)
		if err != nil {
			return nil, err
		}
		result.Certificates[profCfg.Profile.GetAlgorithmFamily()] = cert
	}

	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	return result, nil
}

// validateMultiProfileInitConfig validates the multi-profile configuration.
func validateMultiProfileInitConfig(basePath string, cfg MultiProfileInitConfig) error {
	if len(cfg.Profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}
	if CAInfoExists(basePath) {
		return fmt.Errorf("CA already exists at %s", basePath)
	}
	if _, err := os.Stat(filepath.Join(basePath, "ca.crt")); err == nil {
		return fmt.Errorf("CA already exists at %s (legacy format)", basePath)
	}
	return nil
}

// subjectInfo holds resolved subject information.
type subjectInfo struct {
	cn, org, country string
}

// resolveSubjectFromConfig extracts subject info from config variables.
func resolveSubjectFromConfig(cfg MultiProfileInitConfig) subjectInfo {
	cn := cfg.Variables["cn"]
	if cn == "" {
		cn = "Multi-Profile CA"
	}
	return subjectInfo{
		cn:      cn,
		org:     cfg.Variables["o"],
		country: cfg.Variables["c"],
	}
}

// createMultiProfileCAInfo creates and initializes the CAInfo structure.
func createMultiProfileCAInfo(basePath string, cfg MultiProfileInitConfig) *CAInfo {
	subj := resolveSubjectFromConfig(cfg)
	info := NewCAInfo(Subject{
		CommonName:   subj.cn,
		Organization: []string{subj.org},
		Country:      []string{subj.country},
	})
	info.SetBasePath(basePath)

	profileNames := make([]string, 0, len(cfg.Profiles))
	algoIDs := make([]string, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		profileNames = append(profileNames, p.Profile.Name)
		algoIDs = append(algoIDs, string(p.Profile.GetAlgorithm()))
	}
	info.CreateInitialVersion(profileNames, algoIDs)

	return info
}

// createProfileCertificate creates a CA certificate for a single profile.
func createProfileCertificate(profCfg ProfileInitConfig, subj subjectInfo, info *CAInfo, store *FileStore, kp pkicrypto.KeyProvider, cfg MultiProfileInitConfig) (*x509.Certificate, error) {
	prof := profCfg.Profile
	algoFamily := prof.GetAlgorithmFamily()
	algorithm := prof.GetAlgorithm()

	keyCfg := buildKeyStorageConfig(cfg, info, algorithm)
	signer, err := kp.Generate(algorithm, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key for %s: %w", algoFamily, err)
	}

	validityYears := determineValidityYears(profCfg)

	template, err := buildCertTemplate(subj, profCfg, validityYears, store, signer, prof)
	if err != nil {
		return nil, err
	}

	cert, err := signCertificate(template, signer, algorithm, subj, store, profCfg, algoFamily)
	if err != nil {
		return nil, err
	}

	certPath := info.CertPath("v1", string(algorithm))
	if err := saveCertToPath(certPath, cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate for %s: %w", algorithm, err)
	}

	if err := audit.LogCACreated(info.basePath, cert.Subject.String(), string(algorithm), true); err != nil {
		return nil, err
	}

	return cert, nil
}

// buildKeyStorageConfig builds the key storage configuration.
func buildKeyStorageConfig(cfg MultiProfileInitConfig, info *CAInfo, algorithm pkicrypto.AlgorithmID) pkicrypto.KeyStorageConfig {
	if cfg.KeyStorageConfig.Type != "" {
		return cfg.KeyStorageConfig
	}
	return pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    info.KeyPath("v1", string(algorithm)),
		Passphrase: cfg.Passphrase,
	}
}

// determineValidityYears determines the validity period in years.
func determineValidityYears(profCfg ProfileInitConfig) int {
	if profCfg.ValidityYears > 0 {
		return profCfg.ValidityYears
	}
	years := int(profCfg.Profile.Validity.Hours() / 24 / 365)
	if years == 0 {
		return 10
	}
	return years
}

// buildCertTemplate builds the certificate template.
func buildCertTemplate(subj subjectInfo, profCfg ProfileInitConfig, validityYears int, store *FileStore, signer pkicrypto.Signer, prof *profile.Profile) (*x509.Certificate, error) {
	algoFamily := prof.GetAlgorithmFamily()

	template, err := x509util.NewCertificateBuilder().
		CommonName(subj.cn).
		Organization(subj.org).
		Country(subj.country).
		CA(profCfg.PathLen).
		ValidForYears(validityYears).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template for %s: %w", algoFamily, err)
	}

	serialBytes, err := store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number for %s: %w", algoFamily, err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	skid, err := x509util.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to compute subject key ID for %s: %w", algoFamily, err)
	}
	template.SubjectKeyId = skid

	if prof.Extensions != nil {
		if err := prof.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions for %s: %w", algoFamily, err)
		}
	}

	return template, nil
}

// signCertificate signs the certificate using the appropriate method.
func signCertificate(template *x509.Certificate, signer pkicrypto.Signer, algorithm pkicrypto.AlgorithmID, subj subjectInfo, store *FileStore, profCfg ProfileInitConfig, algoFamily string) (*x509.Certificate, error) {
	if algorithm.IsPQC() {
		pqcCfg := Config{
			CommonName:    subj.cn,
			Organization:  subj.org,
			Country:       subj.country,
			Algorithm:     algorithm,
			ValidityYears: determineValidityYears(profCfg),
			PathLen:       profCfg.PathLen,
		}
		cert, err := createPQCCACertificate(store, signer, pqcCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create PQC CA certificate for %s: %w", algoFamily, err)
		}
		return cert, nil
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate for %s: %w", algoFamily, err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate for %s: %w", algoFamily, err)
	}
	return cert, nil
}
