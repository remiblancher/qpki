package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/pki/internal/audit"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
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

	// Audit: CA loaded successfully
	if err := audit.LogCALoaded(store.BasePath(), cert.Subject.String(), true); err != nil {
		return nil, err
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

	// Audit: CA created successfully
	if err := audit.LogCACreated(store.BasePath(), cert.Subject.String(), string(cfg.Algorithm), true); err != nil {
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

// LoadSigner loads the CA signer from the store.
func (ca *CA) LoadSigner(passphrase string) error {
	signer, err := pkicrypto.LoadPrivateKey(ca.store.CAKeyPath(), []byte(passphrase))
	if err != nil {
		// Audit: key access failed (possible auth failure)
		_ = audit.LogAuthFailed(ca.store.BasePath(), "invalid passphrase or key load error")
		return fmt.Errorf("failed to load CA key: %w", err)
	}

	// Audit: key accessed successfully
	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "CA signing key loaded"); err != nil {
		return err
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

	// For PQC signers, use manual DER construction since Go's x509 doesn't support PQC
	if ca.IsPQCSigner() {
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
		template.NotBefore = time.Now()
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
		template.NotBefore = time.Now()
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

	// Step 2: Extract TBS (To Be Signed) data and sign with PQC
	// The TBS is the certificate without the signature, which we sign with PQC
	tbsBytes := preTBSCert.RawTBSCertificate

	// Sign TBS with PQC signer
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, tbsBytes, nil)
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
func (ca *CA) LoadHybridSigner(classicalPassphrase, pqcPassphrase string) error {
	// Load classical signer
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

	// Save both private keys
	passphrase := []byte(cfg.Passphrase)
	if err := hybridSigner.SaveHybridKeys(store.CAKeyPath(), store.CAKeyPath()+".pqc", passphrase); err != nil {
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

	// Step 2: Sign TBS with PQC
	tbsBytes := preTBSCert.RawTBSCertificate
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, tbsBytes, nil)
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
		store:  store,
		cert:   cert,
		signer: hybridSigner,
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
		template.NotBefore = time.Now()
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

	// Reconstruct TBS without AltSignatureValue for PQC verification
	// According to ITU-T X.509 Section 9.8, the PQC signature is computed over
	// the TBS without AltSignatureValue (to avoid circular dependency)
	tbsWithoutAltSig, err := x509util.ReconstructTBSWithoutAltSigValue(cert.RawTBSCertificate)
	if err != nil {
		return false, fmt.Errorf("failed to reconstruct TBS for PQC verification: %w", err)
	}

	// Verify PQC signature
	pqcValid := pkicrypto.Verify(catInfo.AltSigAlg, issuerPQCPub, tbsWithoutAltSig, catInfo.AltSignature)

	return pqcValid, nil
}
