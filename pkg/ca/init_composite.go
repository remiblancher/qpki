package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// CompositeCAConfig holds configuration for initializing a composite CA.
type CompositeCAConfig struct {
	CommonName         string
	Organization       string
	Country            string
	ClassicalAlgorithm pkicrypto.AlgorithmID
	PQCAlgorithm       pkicrypto.AlgorithmID
	ValidityYears      int
	PathLen            int
	Passphrase         string
}

// InitializeCompositeCA creates a new composite CA with self-signed certificate.
// The CA certificate uses IETF composite signature format.
func InitializeCompositeCA(store Store, cfg CompositeCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported composite algorithm combination: %w", err)
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Get full algorithm IDs (e.g., "ecdsa-p384", "ml-dsa-65")
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
		[]string{"composite"},
		[]string{classicalAlgoID, pqcAlgoID},
	)

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Use initializeCompositeInStore to create the CA in the version directory
	versionStore := NewFileStore(info.VersionDir("v1"))
	ca, err := initializeCompositeInStore(versionStore, store, cfg, compAlg)
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

	// Audit
	if err := audit.LogCACreated(
		store.BasePath(),
		ca.cert.Subject.String(),
		fmt.Sprintf("Composite: %s", compAlg.Name),
		true,
	); err != nil {
		return nil, err
	}

	// Update CA with global store and info
	ca.store = store
	ca.info = info

	return ca, nil
}

// initializeCompositeInStore creates a composite CA in the given store directory.
// It generates both classical and PQC keys, creates a composite certificate,
// and saves everything. Does not check if the store already exists.
// The serialStore is used for serial number generation (can be same as store).
func initializeCompositeInStore(store *FileStore, serialStore Store, cfg CompositeCAConfig, compAlg *CompositeAlgorithm) (*CA, error) {
	// Create keys/ and certs/ directories
	keysDir := store.BasePath() + "/keys"
	certsDir := store.BasePath() + "/certs"
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Generate classical key pair using KeyProvider
	classicalKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.ClassicalAlgorithm)
	classicalKeyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    classicalKeyPath,
		Passphrase: cfg.Passphrase,
	}
	classicalKM := pkicrypto.NewKeyProvider(classicalKeyCfg)
	classicalSigner, err := classicalKM.Generate(cfg.ClassicalAlgorithm, classicalKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical CA key: %w", err)
	}

	// Generate PQC key pair using KeyProvider
	pqcKeyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.PQCAlgorithm)
	pqcKeyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    pqcKeyPath,
		Passphrase: cfg.Passphrase,
	}
	pqcKM := pkicrypto.NewKeyProvider(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(cfg.PQCAlgorithm, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC CA key: %w", err)
	}

	// Build composite public key
	compositePubKey, err := EncodeCompositePublicKey(
		cfg.PQCAlgorithm, pqcSigner.Public(),
		cfg.ClassicalAlgorithm, classicalSigner.Public(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode composite public key: %w", err)
	}

	// Build subject/issuer Name
	subject := buildName(cfg.CommonName, cfg.Organization, cfg.Country)
	subjectDER, err := asn1.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Generate serial number (from the serial store)
	serialBytes, err := serialStore.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Compute subject key ID (SHA-256 of composite public key)
	skidHash := sha256.Sum256(compositePubKey.PublicKey.Bytes)
	skid := skidHash[:20]

	// Build extensions
	extensions, err := buildCAExtensions(cfg.PathLen, skid)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build validity (use UTC for X.509 standard compliance)
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.AddDate(cfg.ValidityYears, 0, 0)

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		Issuer: asn1.RawValue{FullBytes: subjectDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  compositePubKey,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Create composite signature
	signature, err := CreateCompositeSignature(tbsDER, compAlg, pqcSigner, classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signature: %w", err)
	}

	// Build complete certificate using raw TBS bytes to preserve exact signature
	cert := compositeCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	// Parse back using Go's x509
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite certificate: %w", err)
	}

	// Save CA certificate with hybrid naming: ca.composite-{pqc}-{classical}.pem
	certPath := HybridCertPath(store.BasePath(), HybridCertComposite, cfg.ClassicalAlgorithm, cfg.PQCAlgorithm, false)
	if err := saveCertToPath(certPath, parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create composite signer for the CA
	compositeSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signer: %w", err)
	}

	// Create local CAInfo for this directory
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
	info.CreateInitialVersion([]string{"composite"}, []string{classicalAlgoID, pqcAlgoID})
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: compositeSigner,
		info:   info,
	}, nil
}

// =============================================================================
// InitializeCompositeWithSigner - Create Composite CA from existing HybridSigner
// =============================================================================

// CompositeWithSignerConfig holds configuration for creating a Composite CA with an existing signer.
type CompositeWithSignerConfig struct {
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

// InitializeCompositeWithSigner creates a Composite CA using an existing HybridSigner.
// This is used for HSM-based Composite CAs where the keys already exist in the HSM.
// Unlike InitializeCompositeCA, this does not generate keys but uses the provided signer.
func InitializeCompositeWithSigner(store Store, cfg CompositeWithSignerConfig, signer pkicrypto.HybridSigner) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	// Get algorithm IDs from the signer
	classicalAlg := signer.ClassicalSigner().Algorithm()
	pqcAlg := signer.PQCSigner().Algorithm()

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(classicalAlg, pqcAlg)
	if err != nil {
		return nil, fmt.Errorf("unsupported composite algorithm combination: %w", err)
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

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
		[]string{"composite"},
		[]string{classicalAlgoID, pqcAlgoID},
	)

	// Create version directory structure
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Create certs directory
	versionDir := info.VersionDir("v1")
	certsDir := versionDir + "/certs"
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Build composite public key
	compositePubKey, err := EncodeCompositePublicKey(
		pqcAlg, signer.PQCSigner().Public(),
		classicalAlg, signer.ClassicalSigner().Public(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode composite public key: %w", err)
	}

	// Build subject/issuer Name
	subject := buildName(cfg.CommonName, cfg.Organization, cfg.Country)
	subjectDER, err := asn1.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Generate serial number
	serialBytes, err := store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Compute subject key ID (SHA-256 of composite public key)
	skidHash := sha256.Sum256(compositePubKey.PublicKey.Bytes)
	skid := skidHash[:20]

	// Build extensions
	extensions, err := buildCAExtensions(cfg.PathLen, skid)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build validity
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.AddDate(cfg.ValidityYears, 0, 0)

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		Issuer: asn1.RawValue{FullBytes: subjectDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  compositePubKey,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Create composite signature using HybridSigner
	signature, err := CreateCompositeSignature(tbsDER, compAlg, signer.PQCSigner(), signer.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signature: %w", err)
	}

	// Build complete certificate
	cert := compositeCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	// Parse back using Go's x509
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite certificate: %w", err)
	}

	// Save CA certificate
	certPath := HybridCertPath(versionDir, HybridCertComposite, classicalAlg, pqcAlg, false)
	if err := saveCertToPath(certPath, parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Add HSM key references to v1 version (both keys share the same label but different CKA_KEY_TYPE)
	_ = info.AddVersionKey("v1", KeyRef{
		ID:        "classical",
		Algorithm: classicalAlg,
		Storage:   CreatePKCS11KeyRef(cfg.HSMConfig, cfg.KeyLabel, ""),
	})
	_ = info.AddVersionKey("v1", KeyRef{
		ID:        "pqc",
		Algorithm: pqcAlg,
		Storage:   CreatePKCS11KeyRef(cfg.HSMConfig, cfg.KeyLabel, ""),
	})

	// Save CAInfo
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	// Audit: Composite CA created with HSM
	if err := audit.LogCACreated(
		store.BasePath(),
		parsedCert.Subject.String(),
		fmt.Sprintf("Composite HSM: %s", compAlg.Name),
		true,
	); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: signer,
		info:   info,
	}, nil
}
