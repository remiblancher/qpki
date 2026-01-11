package ca

import (
	"context"
	"crypto/rand"
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

// PQCCAConfig holds configuration for initializing a pure PQC CA.
type PQCCAConfig struct {
	// CommonName is the CA's common name.
	CommonName string

	// Organization is the CA's organization.
	Organization string

	// Country is the CA's country code.
	Country string

	// Algorithm is the PQC signature algorithm (ml-dsa-44, ml-dsa-65, ml-dsa-87).
	Algorithm pkicrypto.AlgorithmID

	// ValidityYears is the CA certificate validity in years.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	PathLen int

	// Passphrase for encrypting the private key.
	Passphrase string
}

// InitializePQCCA creates a new pure PQC CA with self-signed certificate.
//
// This function manually constructs the X.509 certificate using DER encoding
// since Go's crypto/x509 doesn't support PQC algorithms.
//
// Supported algorithms: ml-dsa-44, ml-dsa-65, ml-dsa-87
func InitializePQCCA(store Store, cfg PQCCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if !cfg.Algorithm.IsPQC() {
		return nil, fmt.Errorf("algorithm %s is not a PQC algorithm, use Initialize instead", cfg.Algorithm)
	}

	if !cfg.Algorithm.IsSignature() {
		return nil, fmt.Errorf("algorithm %s is not suitable for signing", cfg.Algorithm)
	}

	if err := store.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Get full algorithm ID (e.g., "ml-dsa-65")
	algoID := string(cfg.Algorithm)

	// Create CAInfo to set up versioned structure
	info := NewCAInfo(Subject{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
	})
	info.SetBasePath(store.BasePath())
	info.CreateInitialVersion([]string{"pqc"}, []string{algoID})

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Generate PQC key pair at versioned path
	keyPath := info.KeyPath("v1", algoID)
	keyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: cfg.Passphrase,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	signer, err := km.Generate(cfg.Algorithm, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC CA key: %w", err)
	}

	// Get signature algorithm OID
	sigAlgOID, err := algorithmToOID(cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm OID: %w", err)
	}

	// Get public key bytes
	kp := &pkicrypto.KeyPair{
		Algorithm: cfg.Algorithm,
		PublicKey: signer.Public(),
	}
	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
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

	// Compute subject key ID (SHA-256 of public key)
	skidHash := sha256.Sum256(pubBytes)
	skid := skidHash[:20] // Use first 20 bytes as per common practice

	// Build extensions
	extensions, err := buildCAExtensions(cfg.PathLen, skid)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build validity (use UTC for X.509 standard compliance)
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour) // Start 1 hour ago to handle clock skew
	notAfter := now.AddDate(cfg.ValidityYears, 0, 0)

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer: asn1.RawValue{FullBytes: subjectDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject: asn1.RawValue{FullBytes: subjectDER},
		PublicKey: publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: sigAlgOID, // ML-DSA uses same OID for key and signature
			},
			PublicKey: asn1.BitString{
				Bytes:     pubBytes,
				BitLength: len(pubBytes) * 8,
			},
		},
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign TBSCertificate with PQC signer
	// ML-DSA signs the full message (not a hash)
	signature, err := signer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Build complete certificate
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
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

	// Parse back using Go's x509 to get a proper Certificate object
	// Note: Go's x509.ParseCertificate will parse it but mark signature algorithm as unknown
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQC certificate: %w", err)
	}

	// Save CA certificate to versioned path
	certPath := info.CertPath("v1", algoID)
	if err := saveCertToPath(certPath, parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Add key reference and save CAInfo
	info.AddKey(KeyRef{
		ID:        "default",
		Algorithm: cfg.Algorithm,
		Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/v1/keys/ca.%s.key", algoID)),
	})
	if err := info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	// Audit: CA created successfully
	if err := audit.LogCACreated(store.BasePath(), parsedCert.Subject.String(), string(cfg.Algorithm), true); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: signer,
		info:   info,
	}, nil
}
