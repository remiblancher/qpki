package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// CA represents a Certificate Authority.
type CA struct {
	store      *Store
	cert       *x509.Certificate
	signer     pkicrypto.Signer
	keyProvider pkicrypto.KeyProvider       // Key manager for enrollment operations
	keyConfig  pkicrypto.KeyStorageConfig // Key storage configuration for enrollment
	metadata   *CAMetadata                // CA metadata (may be nil for legacy CAs)
}

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

// New loads an existing CA from the store.
func New(store *Store) (*CA, error) {
	cert, err := store.LoadCACert()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load metadata if it exists
	metadata, err := LoadCAMetadata(store.BasePath())
	if err != nil {
		return nil, fmt.Errorf("failed to load CA metadata: %w", err)
	}

	// Audit: CA loaded successfully
	if err := audit.LogCALoaded(store.BasePath(), cert.Subject.String(), true); err != nil {
		return nil, err
	}

	return &CA{
		store:    store,
		cert:     cert,
		metadata: metadata,
	}, nil
}

// NewWithSigner loads an existing CA with a signer.
func NewWithSigner(store *Store, signer pkicrypto.Signer) (*CA, error) {
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

// GenerateCredentialKey generates a key for credential enrollment.
// It uses the configured KeyProvider (software or HSM) and returns both
// the signer and a StorageRef describing where the key is stored.
//
// For software keys: generates in memory, FileStore.Save() will persist it.
// For HSM keys: generates directly in HSM, returns a storage ref with PKCS#11 info.
//
// The credentialID and keyIndex are used to construct unique key labels for HSM.
func (ca *CA) GenerateCredentialKey(alg pkicrypto.AlgorithmID, credentialID string, keyIndex int) (pkicrypto.Signer, pkicrypto.StorageRef, error) {
	cfg := ca.keyConfig

	switch cfg.Type {
	case pkicrypto.KeyProviderTypePKCS11:
		// HSM: generate with unique label based on credential ID or provided prefix
		hsmCfg := cfg
		labelPrefix := cfg.PKCS11KeyLabel
		if labelPrefix == "" {
			labelPrefix = credentialID
		}
		hsmCfg.PKCS11KeyLabel = fmt.Sprintf("%s-%d", labelPrefix, keyIndex)
		km := ca.KeyProvider()
		signer, err := km.Generate(alg, hsmCfg)
		if err != nil {
			return nil, pkicrypto.StorageRef{}, err
		}
		return signer, pkicrypto.StorageRef{
			Type:   "pkcs11",
			Config: cfg.PKCS11ConfigPath,
			Label:  hsmCfg.PKCS11KeyLabel,
			KeyID:  cfg.PKCS11KeyID,
		}, nil

	default:
		// Software: generate in memory, FileStore will save it
		signer, err := pkicrypto.GenerateSoftwareSigner(alg)
		if err != nil {
			return nil, pkicrypto.StorageRef{}, err
		}
		// Return empty storage ref - FileStore.Save() will fill in the path
		return signer, pkicrypto.StorageRef{
			Type: "software",
		}, nil
	}
}

// Metadata returns the CA metadata.
func (ca *CA) Metadata() *CAMetadata {
	return ca.metadata
}

// Initialize creates a new CA with self-signed certificate.
func Initialize(store *Store, cfg Config) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Determine key provider and storage config
	kp := cfg.KeyProvider
	if kp == nil {
		kp = pkicrypto.NewSoftwareKeyProvider()
	}

	// Build key storage config if not provided
	keyCfg := cfg.KeyStorageConfig
	if keyCfg.Type == "" {
		// Default to software key storage with new naming convention
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    CAKeyPathForAlgorithm(store.BasePath(), cfg.Algorithm),
			Passphrase: cfg.Passphrase,
		}
	}

	// Generate CA key pair using the key provider
	signer, err := kp.Generate(cfg.Algorithm, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Build CA certificate
	builder := x509util.NewCertificateBuilder().
		CommonName(cfg.CommonName).
		Organization(cfg.Organization).
		Country(cfg.Country).
		CA(cfg.PathLen).
		ValidForYears(cfg.ValidityYears)

	// Add hybrid PQC extension if configured
	if cfg.HybridConfig != nil {
		pqcKP, err := pkicrypto.GenerateKeyPair(cfg.HybridConfig.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PQC key: %w", err)
		}

		pqcPubBytes, err := pqcKP.PublicKeyBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
		}

		builder = builder.HybridPQC(
			string(cfg.HybridConfig.Algorithm),
			pqcPubBytes,
			cfg.HybridConfig.Policy,
		)

		// TODO: Save PQC private key for hybrid signing
	}

	template, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template: %w", err)
	}

	// Generate serial number
	serialBytes, err := store.NextSerial()
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save CA certificate
	if err := store.SaveCACert(cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create and save metadata
	metadata := NewCAMetadata(cfg.Profile)

	// Build storage reference for the key
	var storageRef pkicrypto.StorageRef
	switch keyCfg.Type {
	case pkicrypto.KeyProviderTypePKCS11:
		storageRef = CreatePKCS11KeyRef(keyCfg.PKCS11Lib, keyCfg.PKCS11KeyLabel, keyCfg.PKCS11KeyID)
	default:
		// Use relative path in metadata
		storageRef = CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.Algorithm))
	}

	metadata.AddKey(KeyRef{
		ID:        "default",
		Algorithm: cfg.Algorithm,
		Storage:   storageRef,
	})

	if err := metadata.Save(store); err != nil {
		return nil, fmt.Errorf("failed to save CA metadata: %w", err)
	}

	// Audit: CA created successfully
	if err := audit.LogCACreated(store.BasePath(), cert.Subject.String(), string(cfg.Algorithm), true); err != nil {
		return nil, err
	}

	return &CA{
		store:       store,
		cert:        cert,
		signer:      signer,
		keyProvider: kp,
		keyConfig:   keyCfg,
		metadata:    metadata,
	}, nil
}

// InitializeWithSigner creates a new CA using an external signer (e.g., HSM).
// Unlike Initialize, this does not generate or save a private key.
func InitializeWithSigner(store *Store, cfg Config, signer pkicrypto.Signer) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
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
	serialBytes, err := store.NextSerial()
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

	// Self-sign the certificate using the external signer
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save CA certificate
	if err := store.SaveCACert(cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Audit: CA created successfully (with HSM)
	if err := audit.LogCACreated(store.BasePath(), cert.Subject.String(), string(cfg.Algorithm)+" (HSM)", true); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   cert,
		signer: signer,
	}, nil
}

// Certificate returns the CA certificate.
func (ca *CA) Certificate() *x509.Certificate {
	return ca.cert
}

// Store returns the CA store.
func (ca *CA) Store() *Store {
	return ca.store
}

// KeyPaths returns the paths to the CA private keys.
// For CAs with metadata, this returns the actual paths from metadata.
// For legacy CAs, this returns the default ca.key path.
// Returns a map of key ID to path (e.g., {"default": "/path/to/ca.ecdsa-p384.key"}).
func (ca *CA) KeyPaths() map[string]string {
	paths := make(map[string]string)

	if ca.metadata != nil && len(ca.metadata.Keys) > 0 {
		for _, key := range ca.metadata.Keys {
			if key.Storage.Type == "software" || key.Storage.Type == "" {
				// Resolve relative path to absolute
				keyPath := key.Storage.Path
				if !filepath.IsAbs(keyPath) {
					keyPath = filepath.Join(ca.store.BasePath(), keyPath)
				}
				paths[key.ID] = keyPath
			} else {
				// For HSM keys, indicate it's in HSM
				paths[key.ID] = fmt.Sprintf("HSM:%s", key.Storage.Label)
			}
		}
	} else {
		// Legacy CA
		paths["default"] = ca.store.CAKeyPath()
	}

	return paths
}

// DefaultKeyPath returns the path to the default CA private key.
// For display purposes in CLI output.
func (ca *CA) DefaultKeyPath() string {
	paths := ca.KeyPaths()
	if path, ok := paths["default"]; ok {
		return path
	}
	// Return first key path if no default
	for _, path := range paths {
		return path
	}
	return ca.store.CAKeyPath()
}

// LoadSigner loads the CA signer from the store.
// For hybrid CAs (with both classical and PQC keys), it automatically loads both
// keys and creates a HybridSigner.
func (ca *CA) LoadSigner(passphrase string) error {
	var signer pkicrypto.Signer
	var err error

	// Determine the base path for key resolution
	// For versioned CAs, keys are in active/ directory
	keyBasePath := ca.store.BasePath()
	versionIndex := filepath.Join(keyBasePath, "versions.json")
	if _, statErr := os.Stat(versionIndex); statErr == nil {
		// Versioned CA - use active/ as key base path
		keyBasePath = filepath.Join(keyBasePath, "active")
	}

	// Use metadata if available (new format)
	if ca.metadata != nil {
		// Check if this is a hybrid CA (has both classical and PQC keys)
		if ca.metadata.IsHybrid() {
			return ca.loadHybridSignerFromMetadata(passphrase, passphrase)
		}

		// Single key CA - use the default key
		keyRef := ca.metadata.GetDefaultKey()
		if keyRef != nil {
			keyCfg, cfgErr := keyRef.BuildKeyStorageConfig(keyBasePath, passphrase)
			if cfgErr != nil {
				_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to build key config")
				return fmt.Errorf("failed to build key config: %w", cfgErr)
			}

			km := pkicrypto.NewKeyProvider(keyCfg)
			signer, err = km.Load(keyCfg)
			if err != nil {
				_ = audit.LogAuthFailed(ca.store.BasePath(), "invalid passphrase or key load error")
				return fmt.Errorf("failed to load CA key: %w", err)
			}

			ca.keyProvider = km
			ca.keyConfig = keyCfg
		}
	}

	// Fallback to legacy path for CAs without metadata
	if signer == nil {
		// Try versioned path first, then legacy
		keyPath := filepath.Join(keyBasePath, "private", "ca.key")
		if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
			// Fallback to store's default path
			keyPath = ca.store.CAKeyPath()
		}
		signer, err = pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
		if err != nil {
			// Audit: key access failed (possible auth failure)
			_ = audit.LogAuthFailed(ca.store.BasePath(), "invalid passphrase or key load error")
			return fmt.Errorf("failed to load CA key: %w", err)
		}
	}

	// Audit: key accessed successfully
	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "CA signing key loaded"); err != nil {
		return err
	}

	ca.signer = signer
	return nil
}

// loadHybridSignerFromMetadata loads both classical and PQC keys from metadata
// and creates a HybridSigner.
func (ca *CA) loadHybridSignerFromMetadata(classicalPassphrase, pqcPassphrase string) error {
	classicalRef := ca.metadata.GetClassicalKey()
	pqcRef := ca.metadata.GetPQCKey()

	if classicalRef == nil || pqcRef == nil {
		return fmt.Errorf("hybrid CA metadata missing classical or PQC key reference")
	}

	// Determine the base path for key resolution
	// For versioned CAs, keys are in active/ directory
	keyBasePath := ca.store.BasePath()
	versionIndex := filepath.Join(keyBasePath, "versions.json")
	if _, statErr := os.Stat(versionIndex); statErr == nil {
		keyBasePath = filepath.Join(keyBasePath, "active")
	}

	// Load classical signer
	classicalCfg, err := classicalRef.BuildKeyStorageConfig(keyBasePath, classicalPassphrase)
	if err != nil {
		return fmt.Errorf("failed to build classical key config: %w", err)
	}
	classicalKM := pkicrypto.NewKeyProvider(classicalCfg)
	classicalSigner, err := classicalKM.Load(classicalCfg)
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key")
		return fmt.Errorf("failed to load classical CA key: %w", err)
	}

	// Load PQC signer
	pqcCfg, err := pqcRef.BuildKeyStorageConfig(keyBasePath, pqcPassphrase)
	if err != nil {
		return fmt.Errorf("failed to build PQC key config: %w", err)
	}
	pqcKM := pkicrypto.NewKeyProvider(pqcCfg)
	pqcSigner, err := pqcKM.Load(pqcCfg)
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key")
		return fmt.Errorf("failed to load PQC CA key: %w", err)
	}

	// Create hybrid signer
	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return fmt.Errorf("failed to create hybrid signer: %w", err)
	}

	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "Hybrid CA signing keys loaded"); err != nil {
		return err
	}

	ca.signer = hybridSigner
	return nil
}

// IssueRequest holds the parameters for issuing a certificate.
type IssueRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration

	// SignatureAlgorithm optionally specifies the signature algorithm.
	// If zero, it's inferred from the CA's key type.
	// Use this to specify RSA-PSS instead of PKCS#1 v1.5, or SHA-3 variants.
	SignatureAlgorithm x509.SignatureAlgorithm

	// HybridPQCKey is the optional PQC public key for hybrid certificates.
	HybridPQCKey []byte

	// HybridAlgorithm is the PQC algorithm for hybrid certificates.
	HybridAlgorithm pkicrypto.AlgorithmID

	// HybridPolicy is the hybrid verification policy.
	HybridPolicy x509util.HybridPolicy
}

// Issue issues a new certificate.
// For PQC CAs, this automatically delegates to IssuePQC() which uses manual DER construction.
func (ca *CA) Issue(req IssueRequest) (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// For PQC signers or PQC subject keys, use manual DER construction
	// since Go's x509 doesn't support PQC algorithms
	if ca.IsPQCSigner() || IsPQCPublicKey(req.PublicKey) {
		return ca.IssuePQC(req)
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply extensions from profile
	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Set issuer
	template.Issuer = ca.cert.Subject

	// Generate serial number
	serialBytes, err := ca.store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set authority key ID
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	// Set subject key ID
	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}

	// Set validity if not already set
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if req.Validity > 0 {
			template.NotAfter = template.NotBefore.Add(req.Validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}

	// Add hybrid PQC extension if provided
	if len(req.HybridPQCKey) > 0 {
		ext, err := x509util.EncodeHybridExtension(req.HybridAlgorithm, req.HybridPQCKey, req.HybridPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to encode hybrid extension: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	// Set signature algorithm if specified (e.g., for RSA-PSS or SHA-3)
	if req.SignatureAlgorithm != 0 {
		template.SignatureAlgorithm = req.SignatureAlgorithm
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit: certificate issued successfully
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"",
		cert.SignatureAlgorithm.String(),
		true,
	); err != nil {
		return nil, err
	}

	return cert, nil
}

// CatalystRequest holds the parameters for issuing a Catalyst certificate.
// Catalyst certificates contain dual signatures (classical + PQC) as per ITU-T X.509 Section 9.8.
type CatalystRequest struct {
	// Template is the base certificate template.
	Template *x509.Certificate

	// ClassicalPublicKey is the subject's classical public key (goes in SubjectPublicKeyInfo).
	ClassicalPublicKey crypto.PublicKey

	// PQCPublicKey is the subject's PQC public key (goes in AltSubjectPublicKeyInfo extension).
	PQCPublicKey crypto.PublicKey

	// PQCAlgorithm is the algorithm for the PQC key.
	PQCAlgorithm pkicrypto.AlgorithmID

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration
}

// IssueCatalyst issues a Catalyst certificate with dual keys and dual signatures.
//
// Catalyst certificates (ITU-T X.509 Section 9.8) contain:
//   - Classical public key in standard SubjectPublicKeyInfo
//   - PQC public key in AltSubjectPublicKeyInfo extension
//   - Classical signature in standard signatureValue
//   - PQC signature in AltSignatureValue extension
//
// The CA must be initialized with a HybridSigner to issue Catalyst certificates.
func (ca *CA) IssueCatalyst(req CatalystRequest) (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// CA must be a HybridSigner to issue Catalyst certificates
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		return nil, fmt.Errorf("CA must use a HybridSigner to issue Catalyst certificates")
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply extensions from profile
	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Set issuer
	template.Issuer = ca.cert.Subject

	// Generate serial number
	serialBytes, err := ca.store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set authority key ID
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	// Set subject key ID (from classical key)
	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(req.ClassicalPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}

	// Set validity if not already set
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if req.Validity > 0 {
			template.NotAfter = template.NotBefore.Add(req.Validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}

	// Get PQC public key bytes
	pqcKP := &pkicrypto.KeyPair{
		Algorithm: req.PQCAlgorithm,
		PublicKey: req.PQCPublicKey,
	}
	pqcPubBytes, err := pqcKP.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	// Add AltSubjectPublicKeyInfo extension (PQC public key)
	altPubKeyExt, err := x509util.EncodeAltSubjectPublicKeyInfo(req.PQCAlgorithm, pqcPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSubjectPublicKeyInfo: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altPubKeyExt)

	// Add AltSignatureAlgorithm extension
	pqcSignerAlg := hybridSigner.PQCSigner().Algorithm()
	altSigAlgExt, err := x509util.EncodeAltSignatureAlgorithm(pqcSignerAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureAlgorithm: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigAlgExt)

	// Step 1: Create pre-TBS certificate (without AltSignatureValue) using classical signature
	preTBSDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.ClassicalPublicKey, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-TBS certificate: %w", err)
	}

	preTBSCert, err := x509.ParseCertificate(preTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pre-TBS certificate: %w", err)
	}

	// Step 2: Build PreTBSCertificate for PQC signing
	// Per ITU-T X.509 Section 9.8, PreTBSCertificate excludes:
	//   - The signature algorithm field (specific to classical signature)
	//   - The AltSignatureValue extension (would be circular)
	preTBS, err := x509util.BuildPreTBSCertificate(preTBSCert.RawTBSCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to build PreTBSCertificate: %w", err)
	}

	// Sign PreTBS with PQC signer
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, preTBS, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with PQC: %w", err)
	}

	// Step 3: Add AltSignatureValue extension to the template
	altSigValueExt, err := x509util.EncodeAltSignatureValue(pqcSig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureValue: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigValueExt)

	// Step 4: Create final certificate with all extensions (re-sign with classical)
	finalDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.ClassicalPublicKey, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create final Catalyst certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Catalyst certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit: Catalyst certificate issued
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"Catalyst",
		fmt.Sprintf("%s + %s", cert.SignatureAlgorithm.String(), pqcSignerAlg),
		true,
	); err != nil {
		return nil, err
	}

	return cert, nil
}

// LoadHybridSigner loads a hybrid signer from the store for Catalyst certificate issuance.
// Deprecated: Use LoadSigner() instead, which automatically detects hybrid CAs from metadata.
func (ca *CA) LoadHybridSigner(classicalPassphrase, pqcPassphrase string) error {
	// Use metadata if available
	if ca.metadata != nil && ca.metadata.IsHybrid() {
		return ca.loadHybridSignerFromMetadata(classicalPassphrase, pqcPassphrase)
	}

	// Fallback to legacy path convention (ca.key + ca.key.pqc)
	classicalSigner, err := pkicrypto.LoadPrivateKey(ca.store.CAKeyPath(), []byte(classicalPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key")
		return fmt.Errorf("failed to load classical CA key: %w", err)
	}

	// Load PQC signer (assumed to be at ca.store.CAKeyPath() + ".pqc" or similar)
	pqcKeyPath := ca.store.CAKeyPath() + ".pqc"
	pqcSigner, err := pkicrypto.LoadPrivateKey(pqcKeyPath, []byte(pqcPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key")
		return fmt.Errorf("failed to load PQC CA key: %w", err)
	}

	// Create hybrid signer
	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return fmt.Errorf("failed to create hybrid signer: %w", err)
	}

	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "Hybrid CA signing keys loaded"); err != nil {
		return err
	}

	ca.signer = hybridSigner
	return nil
}

// IsHybridCA returns true if the CA has a hybrid signer loaded.
func (ca *CA) IsHybridCA() bool {
	_, ok := ca.signer.(pkicrypto.HybridSigner)
	return ok
}

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
func InitializeHybridCA(store *Store, cfg HybridCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate hybrid key pair for CA
	hybridSigner, err := pkicrypto.GenerateHybridSigner(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hybrid CA key: %w", err)
	}

	// Save both private keys using algorithm-based naming convention
	passphrase := []byte(cfg.Passphrase)
	classicalKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.ClassicalAlgorithm)
	pqcKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.PQCAlgorithm)
	if err := hybridSigner.SaveHybridKeys(classicalKeyPath, pqcKeyPath, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save CA keys: %w", err)
	}

	// Build CA certificate with Catalyst extensions
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
	serialBytes, err := store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set subject key ID (from classical key)
	skid, err := x509util.SubjectKeyID(hybridSigner.ClassicalSigner().Public())
	if err != nil {
		return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
	}
	template.SubjectKeyId = skid

	// Get PQC public key bytes
	pqcPubBytes, err := hybridSigner.PQCPublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	// Add AltSubjectPublicKeyInfo extension (PQC public key)
	altPubKeyExt, err := x509util.EncodeAltSubjectPublicKeyInfo(cfg.PQCAlgorithm, pqcPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSubjectPublicKeyInfo: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altPubKeyExt)

	// Add AltSignatureAlgorithm extension
	altSigAlgExt, err := x509util.EncodeAltSignatureAlgorithm(cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureAlgorithm: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigAlgExt)

	// Step 1: Create pre-TBS self-signed certificate (without AltSignatureValue)
	preTBSDER, err := x509.CreateCertificate(rand.Reader, template, template, hybridSigner.ClassicalSigner().Public(), hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-TBS CA certificate: %w", err)
	}

	preTBSCert, err := x509.ParseCertificate(preTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pre-TBS CA certificate: %w", err)
	}

	// Step 2: Build PreTBSCertificate and sign with PQC
	// Per ITU-T X.509 Section 9.8, PreTBSCertificate excludes:
	//   - The signature algorithm field (index 2)
	//   - The AltSignatureValue extension
	preTBS, err := x509util.BuildPreTBSCertificate(preTBSCert.RawTBSCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to build PreTBSCertificate: %w", err)
	}
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, preTBS, nil)
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
	finalDER, err := x509.CreateCertificate(rand.Reader, template, template, hybridSigner.ClassicalSigner().Public(), hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create Catalyst CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Catalyst CA certificate: %w", err)
	}

	// Save CA certificate
	if err := store.SaveCACert(cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create and save CA metadata
	metadata := NewCAMetadata("catalyst")
	metadata.AddKey(KeyRef{
		ID:        "classical",
		Algorithm: cfg.ClassicalAlgorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.ClassicalAlgorithm)),
	})
	metadata.AddKey(KeyRef{
		ID:        "pqc",
		Algorithm: cfg.PQCAlgorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.PQCAlgorithm)),
	})
	if err := metadata.Save(store); err != nil {
		return nil, fmt.Errorf("failed to save CA metadata: %w", err)
	}

	// Audit: Hybrid CA created
	if err := audit.LogCACreated(
		store.BasePath(),
		cert.Subject.String(),
		fmt.Sprintf("Catalyst: %s + %s", cfg.ClassicalAlgorithm, cfg.PQCAlgorithm),
		true,
	); err != nil {
		return nil, err
	}

	return &CA{
		store:    store,
		cert:     cert,
		signer:   hybridSigner,
		metadata: metadata,
	}, nil
}

// LinkedCertRequest holds the parameters for issuing a certificate linked to another.
// This is used for separate hybrid certificates where multiple certificates are
// bound together using the RelatedCertificate extension.
type LinkedCertRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration

	// RelatedCert is the certificate to link to.
	// The new certificate will contain a RelatedCertificate extension
	// pointing to this certificate.
	RelatedCert *x509.Certificate
}

// IssueLinked issues a certificate that is linked to another certificate.
//
// The issued certificate contains a RelatedCertificate extension that binds it
// to the provided related certificate. This is used for:
//   - Linking a PQC signature certificate to a classical signature certificate
//   - Linking an encryption certificate to a signature certificate
//   - Any other multi-certificate scenarios
//
// The related certificate must be valid and issued by the same CA (or a trusted CA).
func (ca *CA) IssueLinked(req LinkedCertRequest) (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	if req.RelatedCert == nil {
		return nil, fmt.Errorf("related certificate is required for linked issuance")
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply extensions from profile
	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Set issuer
	template.Issuer = ca.cert.Subject

	// Generate serial number
	serialBytes, err := ca.store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set authority key ID
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	// Set subject key ID
	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}

	// Set validity if not already set
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if req.Validity > 0 {
			template.NotAfter = template.NotBefore.Add(req.Validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}

	// Add RelatedCertificate extension
	relCertExt, err := x509util.EncodeRelatedCertificate(req.RelatedCert)
	if err != nil {
		return nil, fmt.Errorf("failed to encode RelatedCertificate extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, relCertExt)

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit: linked certificate issued
	relSerial := fmt.Sprintf("0x%X", req.RelatedCert.SerialNumber.Bytes())
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"linked to "+relSerial,
		cert.SignatureAlgorithm.String(),
		true,
	); err != nil {
		return nil, err
	}

	return cert, nil
}

// VerifyCatalystSignatures verifies both signatures on a Catalyst certificate.
// Returns true only if both classical and PQC signatures are valid.
func VerifyCatalystSignatures(cert *x509.Certificate, issuerCert *x509.Certificate) (bool, error) {
	// Parse Catalyst extensions
	catInfo, err := x509util.ParseCatalystExtensions(cert.Extensions)
	if err != nil {
		return false, fmt.Errorf("failed to parse Catalyst extensions: %w", err)
	}
	if catInfo == nil {
		return false, fmt.Errorf("certificate does not have Catalyst extensions")
	}

	// Verify classical signature (standard X.509)
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		return false, nil // Classical signature invalid
	}

	// For PQC signature verification, we need to reconstruct what was signed
	// The AltSignatureValue signs a TBS that includes AltSubjectPublicKeyInfo and AltSignatureAlgorithm
	// but not AltSignatureValue itself

	// Get issuer's PQC public key
	issuerCatInfo, err := x509util.ParseCatalystExtensions(issuerCert.Extensions)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer Catalyst extensions: %w", err)
	}
	if issuerCatInfo == nil {
		return false, fmt.Errorf("issuer certificate does not have Catalyst extensions")
	}

	// Parse issuer's PQC public key
	issuerPQCPub, err := pkicrypto.ParsePublicKey(issuerCatInfo.AltAlgorithm, issuerCatInfo.AltPublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer PQC public key: %w", err)
	}

	// Build PreTBSCertificate for PQC verification
	// Per ITU-T X.509 Section 9.8, PreTBSCertificate excludes:
	//   - The signature algorithm field (index 2)
	//   - The AltSignatureValue extension
	tbsWithoutAltSig, err := x509util.BuildPreTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return false, fmt.Errorf("failed to reconstruct TBS for PQC verification: %w", err)
	}

	// Verify PQC signature
	pqcValid := pkicrypto.Verify(catInfo.AltSigAlg, issuerPQCPub, tbsWithoutAltSig, catInfo.AltSignature)

	return pqcValid, nil
}

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
	// Version is the created version.
	Version *Version

	// Certificates maps algorithm family to the created certificate.
	Certificates map[string]*x509.Certificate

	// VersionStore is the version store for further operations.
	VersionStore *VersionStore
}

// InitializeMultiProfile creates a new CA with multiple certificates (one per profile).
// Each profile's certificate is stored in its algorithm family subdirectory.
//
// Directory structure:
//
//	ca/
//	├── versions.json
//	├── versions/
//	│   └── v1/
//	│       ├── ec/
//	│       │   ├── ca.crt
//	│       │   └── private/ca.key
//	│       └── ml-dsa/
//	│           ├── ca.crt
//	│           └── private/ca.key
//	└── current -> versions/v1
func InitializeMultiProfile(basePath string, cfg MultiProfileConfig) (*MultiProfileInitResult, error) {
	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Check if CA already exists
	if _, err := os.Stat(filepath.Join(basePath, "versions.json")); err == nil {
		return nil, fmt.Errorf("CA already exists at %s", basePath)
	}
	if _, err := os.Stat(filepath.Join(basePath, "ca.crt")); err == nil {
		return nil, fmt.Errorf("CA already exists at %s (legacy format)", basePath)
	}

	// Initialize version store
	versionStore := NewVersionStore(basePath)
	if err := versionStore.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize version store: %w", err)
	}

	// Extract profile names for version creation
	profileNames := make([]string, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		profileNames = append(profileNames, p.Profile.Name)
	}

	// Create initial version (v1) as active
	version, err := versionStore.CreateInitialVersion(profileNames)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial version: %w", err)
	}

	// Determine key provider
	kp := cfg.KeyProvider
	if kp == nil {
		kp = pkicrypto.NewSoftwareKeyProvider()
	}

	result := &MultiProfileInitResult{
		Version:      version,
		Certificates: make(map[string]*x509.Certificate),
		VersionStore: versionStore,
	}

	// Create a certificate for each profile
	for _, profCfg := range cfg.Profiles {
		prof := profCfg.Profile
		algoFamily := prof.GetAlgorithmFamily()
		algorithm := prof.GetAlgorithm()

		// Create profile directory within version
		profileDir := versionStore.ProfileDir(version.ID, algoFamily)
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create profile directory for %s: %w", algoFamily, err)
		}

		// Create store for this profile
		profileStore := NewStore(profileDir)
		if err := profileStore.Init(); err != nil {
			return nil, fmt.Errorf("failed to initialize store for %s: %w", algoFamily, err)
		}

		// Build key storage config
		keyCfg := cfg.KeyStorageConfig
		if keyCfg.Type == "" {
			keyCfg = pkicrypto.KeyStorageConfig{
				Type:       pkicrypto.KeyProviderTypeSoftware,
				KeyPath:    CAKeyPathForAlgorithm(profileDir, algorithm),
				Passphrase: cfg.Passphrase,
			}
		}

		// Generate CA key pair
		signer, err := kp.Generate(algorithm, keyCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key for %s: %w", algoFamily, err)
		}

		// Resolve subject from variables
		cn := cfg.Variables["cn"]
		if cn == "" {
			cn = fmt.Sprintf("CA %s", algoFamily)
		}
		org := cfg.Variables["o"]
		country := cfg.Variables["c"]

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
		serialBytes, err := profileStore.NextSerial()
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
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA certificate for %s: %w", algoFamily, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate for %s: %w", algoFamily, err)
		}

		// Save CA certificate
		if err := profileStore.SaveCACert(cert); err != nil {
			return nil, fmt.Errorf("failed to save CA certificate for %s: %w", algoFamily, err)
		}

		// Create and save metadata for this profile
		metadata := NewCAMetadata(prof.Name)
		var storageRef pkicrypto.StorageRef
		switch keyCfg.Type {
		case pkicrypto.KeyProviderTypePKCS11:
			storageRef = CreatePKCS11KeyRef(keyCfg.PKCS11Lib, keyCfg.PKCS11KeyLabel, keyCfg.PKCS11KeyID)
		default:
			storageRef = CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(algorithm))
		}
		metadata.AddKey(KeyRef{
			ID:        "default",
			Algorithm: algorithm,
			Storage:   storageRef,
		})
		if err := metadata.Save(profileStore); err != nil {
			return nil, fmt.Errorf("failed to save metadata for %s: %w", algoFamily, err)
		}

		// Add certificate reference to version
		certRef := CertRef{
			Profile:         prof.Name,
			Algorithm:       string(algorithm),
			AlgorithmFamily: algoFamily,
			Subject:         cert.Subject.String(),
			Serial:          fmt.Sprintf("%X", cert.SerialNumber.Bytes()),
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
		}
		if err := versionStore.AddCertificateRef(version.ID, certRef); err != nil {
			return nil, fmt.Errorf("failed to add certificate reference for %s: %w", algoFamily, err)
		}

		result.Certificates[algoFamily] = cert

		// Audit: CA created for this algorithm
		if err := audit.LogCACreated(profileDir, cert.Subject.String(), string(algorithm), true); err != nil {
			return nil, err
		}
	}

	// Create the active/ directory from v1 (already marked as active in CreateInitialVersion)
	if err := versionStore.ActivateInitialVersion(); err != nil {
		return nil, fmt.Errorf("failed to activate initial version: %w", err)
	}

	// Reload version to return the latest state
	result.Version, err = versionStore.GetVersion(version.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload version: %w", err)
	}

	return result, nil
}
