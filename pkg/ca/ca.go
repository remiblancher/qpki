package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/remiblancher/qpki/pkg/audit"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// CA represents a Certificate Authority.
type CA struct {
	store       Store
	cert        *x509.Certificate
	signer      pkicrypto.Signer
	keyProvider pkicrypto.KeyProvider      // Key manager for enrollment operations
	keyConfig   pkicrypto.KeyStorageConfig // Key storage configuration for enrollment
	info        *CAInfo                    // CA info (unified metadata + versioning)
	keyRefs     []KeyRef                   // Key references (used during rotation for HSM keys)
}

// New loads an existing CA from the store.
func New(store Store) (*CA, error) {
	// Load CAInfo - required for all CAs
	info, err := LoadCAInfo(store.BasePath())
	if err != nil {
		return nil, fmt.Errorf("failed to load CA info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("CA metadata (ca.meta.json) not found - legacy CA format not supported")
	}

	// Load cert from versions/{active}/certs/
	activeVer := info.ActiveVersion()
	if activeVer == nil || len(activeVer.Algos) == 0 {
		return nil, fmt.Errorf("no active version or algorithms in CA metadata")
	}

	// Determine certificate path based on CA type (hybrid vs single-algorithm)
	certPath := getCertPathFromInfo(info, activeVer)
	cert, err := loadCertFromPath(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate from %s: %w", certPath, err)
	}

	// Audit: CA loaded successfully
	if err := audit.LogCALoaded(store.BasePath(), cert.Subject.String(), true); err != nil {
		return nil, err
	}

	return &CA{
		store: store,
		cert:  cert,
		info:  info,
	}, nil
}

// getCertPathFromInfo determines the certificate path based on CA type.
// For hybrid CAs (Composite/Catalyst), uses the hybrid naming convention.
// For single-algorithm CAs, uses the standard algorithm-based naming.
func getCertPathFromInfo(info *CAInfo, activeVer *CAVersion) string {
	// Check if this is a hybrid CA by looking at profiles
	isComposite := false
	isCatalyst := false
	for _, profile := range activeVer.Profiles {
		if strings.Contains(profile, "composite") {
			isComposite = true
			break
		}
		// Check for catalyst mode - profile name may be "catalyst-*" or "hybrid-*"
		if strings.Contains(profile, "catalyst") || strings.Contains(profile, "hybrid") {
			isCatalyst = true
			break
		}
	}

	// For hybrid CAs, get classical and PQC algorithm IDs from keys
	if isComposite || isCatalyst {
		classicalKey := info.GetClassicalKey()
		pqcKey := info.GetPQCKey()
		if classicalKey != nil && pqcKey != nil {
			if isComposite {
				return info.HybridCertPathForVersion(info.Active, HybridCertComposite, classicalKey.Algorithm, pqcKey.Algorithm, false)
			}
			return info.HybridCertPathForVersion(info.Active, HybridCertCatalyst, classicalKey.Algorithm, pqcKey.Algorithm, false)
		}
	}

	// Single-algorithm CA - use first algorithm
	return info.CertPath(info.Active, activeVer.Algos[0])
}

// NewWithSigner loads an existing CA with a signer.
func NewWithSigner(store Store, signer pkicrypto.Signer) (*CA, error) {
	ca, err := New(store)
	if err != nil {
		return nil, err
	}
	ca.signer = signer
	return ca, nil
}

// SetKeyProvider sets the key provider for enrollment operations.
// This allows enrolling credentials with keys stored in HSM instead of software.
func (ca *CA) SetKeyProvider(kp pkicrypto.KeyProvider, cfg pkicrypto.KeyStorageConfig) {
	ca.keyProvider = kp
	ca.keyConfig = cfg
}

// KeyProvider returns the current key provider, or a default SoftwareKeyProvider.
func (ca *CA) KeyProvider() pkicrypto.KeyProvider {
	if ca.keyProvider != nil {
		return ca.keyProvider
	}
	return pkicrypto.NewSoftwareKeyProvider()
}

// KeyStorageConfig returns the current key storage configuration.
func (ca *CA) KeyStorageConfig() pkicrypto.KeyStorageConfig {
	return ca.keyConfig
}

// Close releases resources held by the CA, including HSM sessions.
// This should be called when done using the CA to prevent resource leaks.
func (ca *CA) Close() error {
	if ca.signer == nil {
		return nil
	}

	// Check if signer implements io.Closer (e.g., PKCS11Signer)
	if closer, ok := ca.signer.(io.Closer); ok {
		return closer.Close()
	}

	// Check if signer is a HybridSigner with closable sub-signers
	if hybrid, ok := ca.signer.(pkicrypto.HybridSigner); ok {
		var errs []error
		if classical := hybrid.ClassicalSigner(); classical != nil {
			if closer, ok := classical.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if pqc := hybrid.PQCSigner(); pqc != nil {
			if closer, ok := pqc.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("errors closing hybrid signer: %v", errs)
		}
	}

	return nil
}

// Info returns the CA info.
func (ca *CA) Info() *CAInfo {
	return ca.info
}

// Metadata returns the CA metadata (alias for Info, for backward compatibility).
func (ca *CA) Metadata() *CAInfo {
	return ca.info
}

// loadCertFromPath loads a certificate from a PEM file.
func loadCertFromPath(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Certificate returns the CA certificate.
func (ca *CA) Certificate() *x509.Certificate {
	return ca.cert
}

// Signer returns the CA signer (private key).
// Returns nil if the signer hasn't been loaded yet.
func (ca *CA) Signer() pkicrypto.Signer {
	return ca.signer
}

// Store returns the CA store.
func (ca *CA) Store() Store {
	return ca.store
}

// KeyPaths returns the paths to the CA private keys.
// Returns a map of algo to path (e.g., {"ecdsa-p384": "/path/to/versions/v1/keys/ca.ecdsa-p384.key"}).
func (ca *CA) KeyPaths() map[string]string {
	paths := make(map[string]string)

	if ca.info != nil {
		activeVer := ca.info.ActiveVersion()
		if activeVer != nil {
			for _, algo := range activeVer.Algos {
				paths[algo] = ca.info.KeyPath(ca.info.Active, algo)
			}
		}
	}

	return paths
}

// DefaultKeyPath returns the path to the default CA private key.
// For display purposes in CLI output.
func (ca *CA) DefaultKeyPath() string {
	paths := ca.KeyPaths()
	for _, path := range paths {
		return path
	}
	return ""
}

// IsHybridCA returns true if the CA has a hybrid signer loaded.
func (ca *CA) IsHybridCA() bool {
	_, ok := ca.signer.(pkicrypto.HybridSigner)
	return ok
}
