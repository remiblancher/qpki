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
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// MultiProfileConfig holds configuration for initializing a multi-profile CA.
// A multi-profile CA has one certificate per algorithm family (e.g., EC + ML-DSA).
type MultiProfileConfig struct {
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
func InitializeMultiProfile(basePath string, cfg MultiProfileConfig) (*MultiProfileInitResult, error) {
	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Check if CA already exists
	if CAInfoExists(basePath) {
		return nil, fmt.Errorf("CA already exists at %s", basePath)
	}
	if _, err := os.Stat(filepath.Join(basePath, "ca.crt")); err == nil {
		return nil, fmt.Errorf("CA already exists at %s (legacy format)", basePath)
	}

	// Create base directories
	store := NewFileStore(basePath)
	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Resolve subject from variables
	cn := cfg.Variables["cn"]
	if cn == "" {
		cn = "Multi-Profile CA"
	}
	org := cfg.Variables["o"]
	country := cfg.Variables["c"]

	// Create CAInfo
	info := NewCAInfo(Subject{
		CommonName:   cn,
		Organization: []string{org},
		Country:      []string{country},
	})
	info.SetBasePath(basePath)

	// Extract profile names and algorithm IDs
	profileNames := make([]string, 0, len(cfg.Profiles))
	algoIDs := make([]string, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		profileNames = append(profileNames, p.Profile.Name)
		algoIDs = append(algoIDs, string(p.Profile.GetAlgorithm()))
	}

	// Create v1 as the initial active version with full algorithm IDs
	info.CreateInitialVersion(profileNames, algoIDs)

	// Determine key provider
	kp := cfg.KeyProvider
	if kp == nil {
		kp = pkicrypto.NewSoftwareKeyProvider()
	}

	result := &MultiProfileInitResult{
		Info:         info,
		Certificates: make(map[string]*x509.Certificate),
	}

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Create a certificate for each profile
	for _, profCfg := range cfg.Profiles {
		prof := profCfg.Profile
		algoFamily := prof.GetAlgorithmFamily()
		algorithm := prof.GetAlgorithm()

		// Build key storage config - use new path structure
		keyCfg := cfg.KeyStorageConfig
		if keyCfg.Type == "" {
			keyCfg = pkicrypto.KeyStorageConfig{
				Type:       pkicrypto.KeyProviderTypeSoftware,
				KeyPath:    info.KeyPath("v1", string(algorithm)),
				Passphrase: cfg.Passphrase,
			}
		}

		// Generate CA key pair
		signer, err := kp.Generate(algorithm, keyCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key for %s: %w", algoFamily, err)
		}

		// Determine validity
		validityYears := profCfg.ValidityYears
		if validityYears == 0 {
			validityYears = int(prof.Validity.Hours() / 24 / 365)
			if validityYears == 0 {
				validityYears = 10 // Default
			}
		}

		// Build CA certificate
		builder := x509util.NewCertificateBuilder().
			CommonName(cn).
			Organization(org).
			Country(country).
			CA(profCfg.PathLen).
			ValidForYears(validityYears)

		template, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build certificate template for %s: %w", algoFamily, err)
		}

		// Generate serial number
		serialBytes, err := store.NextSerial(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get serial number for %s: %w", algoFamily, err)
		}
		template.SerialNumber = new(big.Int).SetBytes(serialBytes)

		// Set subject key ID
		skid, err := x509util.SubjectKeyID(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID for %s: %w", algoFamily, err)
		}
		template.SubjectKeyId = skid

		// Apply extensions from profile if configured
		if prof.Extensions != nil {
			if err := prof.Extensions.Apply(template); err != nil {
				return nil, fmt.Errorf("failed to apply extensions for %s: %w", algoFamily, err)
			}
		}

		// Self-sign the certificate
		var cert *x509.Certificate
		if algorithm.IsPQC() {
			// For PQC algorithms, use manual ASN.1 construction (Go's x509 doesn't support PQC)
			pqcCfg := Config{
				CommonName:    cn,
				Organization:  org,
				Country:       country,
				Algorithm:     algorithm,
				ValidityYears: validityYears,
				PathLen:       profCfg.PathLen,
			}
			cert, err = createPQCCACertificate(store, signer, pqcCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create PQC CA certificate for %s: %w", algoFamily, err)
			}
		} else {
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
			if err != nil {
				return nil, fmt.Errorf("failed to create CA certificate for %s: %w", algoFamily, err)
			}
			cert, err = x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate for %s: %w", algoFamily, err)
			}
		}

		// Save CA certificate to versions/v1/certs/ca.{algorithm}.pem
		algoID := string(algorithm)
		certPath := info.CertPath("v1", algoID)
		if err := saveCertToPath(certPath, cert); err != nil {
			return nil, fmt.Errorf("failed to save CA certificate for %s: %w", algoID, err)
		}

		result.Certificates[algoFamily] = cert

		// Audit: CA created for this algorithm
		if err := audit.LogCACreated(basePath, cert.Subject.String(), string(algorithm), true); err != nil {
			return nil, err
		}
	}

	// Save CAInfo to ca.json
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	return result, nil
}
