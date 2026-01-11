package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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

	// Generate classical key pair using KeyProvider
	classicalKeyPath := info.KeyPath("v1", string(cfg.ClassicalAlgorithm))
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
	pqcKeyPath := info.KeyPath("v1", string(cfg.PQCAlgorithm))
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
	certPath := info.HybridCertPathForVersion("v1", HybridCertComposite, cfg.ClassicalAlgorithm, cfg.PQCAlgorithm, false)
	if err := saveCertToPath(certPath, parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
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

	// Create composite signer for the CA
	compositeSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signer: %w", err)
	}

	// Audit
	if err := audit.LogCACreated(
		store.BasePath(),
		parsedCert.Subject.String(),
		fmt.Sprintf("Composite: %s", compAlg.Name),
		true,
	); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: compositeSigner,
		info:   info,
	}, nil
}
