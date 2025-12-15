package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profiles"
	"github.com/remiblancher/pki/internal/x509util"
)

// CA represents a Certificate Authority.
type CA struct {
	store  *Store
	cert   *x509.Certificate
	signer pkicrypto.Signer
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

	return &CA{
		store: store,
		cert:  cert,
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

// Initialize creates a new CA with self-signed certificate.
func Initialize(store *Store, cfg Config) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate CA key pair
	signer, err := pkicrypto.GenerateSoftwareSigner(cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Save private key
	passphrase := []byte(cfg.Passphrase)
	if err := signer.SavePrivateKey(store.CAKeyPath(), passphrase); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %w", err)
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

// LoadSigner loads the CA signer from the store.
func (ca *CA) LoadSigner(passphrase string) error {
	signer, err := pkicrypto.LoadPrivateKey(ca.store.CAKeyPath(), []byte(passphrase))
	if err != nil {
		return fmt.Errorf("failed to load CA key: %w", err)
	}
	ca.signer = signer
	return nil
}

// IssueRequest holds the parameters for issuing a certificate.
type IssueRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Profile is the certificate profile to apply.
	Profile profiles.Profile

	// HybridPQCKey is the optional PQC public key for hybrid certificates.
	HybridPQCKey []byte

	// HybridAlgorithm is the PQC algorithm for hybrid certificates.
	HybridAlgorithm pkicrypto.AlgorithmID

	// HybridPolicy is the hybrid verification policy.
	HybridPolicy x509util.HybridPolicy
}

// Issue issues a new certificate.
func (ca *CA) Issue(req IssueRequest) (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply profile if provided
	if req.Profile != nil {
		if err := req.Profile.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply profile: %w", err)
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
		template.NotBefore = time.Now()
	}
	if template.NotAfter.IsZero() {
		if req.Profile != nil {
			template.NotAfter = template.NotBefore.Add(req.Profile.DefaultValidity())
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

	// Validate with profile
	if req.Profile != nil {
		if err := req.Profile.Validate(template); err != nil {
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
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

	return cert, nil
}

// IssueTLSServer issues a TLS server certificate.
func (ca *CA) IssueTLSServer(commonName string, dnsNames []string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		DNSNames: dnsNames,
	}
	template.Subject.CommonName = commonName

	profile := profiles.NewTLSServerProfile()

	return ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: publicKey,
		Profile:   profile,
	})
}

// IssueTLSClient issues a TLS client certificate.
func (ca *CA) IssueTLSClient(commonName string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{}
	template.Subject.CommonName = commonName

	profile := profiles.NewTLSClientProfile()

	return ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: publicKey,
		Profile:   profile,
	})
}

// IssueSubordinateCA issues a subordinate CA certificate.
func (ca *CA) IssueSubordinateCA(commonName string, organization string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{}
	template.Subject.CommonName = commonName
	if organization != "" {
		template.Subject.Organization = []string{organization}
	}

	profile := profiles.NewIssuingCAProfile()

	return ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: publicKey,
		Profile:   profile,
	})
}
