package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/pki/internal/audit"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
	"github.com/remiblancher/pki/internal/x509util"
)

// CrossSignMode controls cross-signing behavior during rotation.
type CrossSignMode int

const (
	// CrossSignAuto enables cross-signing when the algorithm changes.
	CrossSignAuto CrossSignMode = iota

	// CrossSignOn always cross-signs the new CA with the old CA.
	CrossSignOn

	// CrossSignOff never cross-signs.
	CrossSignOff
)

// RotateCARequest holds parameters for rotating a CA.
type RotateCARequest struct {
	// CADir is the CA directory.
	CADir string

	// Profile is the profile to use for the new CA (optional, reuses existing if empty).
	Profile string

	// Passphrase for the CA private keys.
	Passphrase string

	// CrossSign controls cross-signing behavior.
	CrossSign CrossSignMode

	// DryRun if true, returns the plan without executing.
	DryRun bool
}

// RotateCAPlan describes what rotation will do (for dry-run).
type RotateCAPlan struct {
	// CurrentVersion is the currently active version (if versioned).
	CurrentVersion string

	// NewVersion is the version ID that will be created.
	NewVersion string

	// Profile is the profile that will be used.
	Profile string

	// Algorithm is the algorithm from the profile.
	Algorithm string

	// Subject is the CA subject.
	Subject string

	// WillCrossSign indicates if cross-signing will occur.
	WillCrossSign bool

	// CrossSignReason explains why cross-signing will/won't happen.
	CrossSignReason string

	// Steps describes the rotation steps.
	Steps []string
}

// RotateCAResult holds the result of a CA rotation.
type RotateCAResult struct {
	// Plan is the rotation plan (always populated).
	Plan *RotateCAPlan

	// NewCA is the newly created CA (nil if dry-run).
	NewCA *CA

	// Version is the new version (nil if dry-run).
	Version *Version

	// CrossSignedCert is the cross-signed certificate (if cross-signing was done).
	CrossSignedCert *x509.Certificate
}

// RotateCA rotates a CA, creating a new version with new keys.
func RotateCA(req RotateCARequest) (*RotateCAResult, error) {
	store := NewStore(req.CADir)
	if !store.Exists() {
		return nil, fmt.Errorf("CA not found at %s", req.CADir)
	}

	// Load current CA
	currentCA, err := New(store)
	if err != nil {
		return nil, fmt.Errorf("failed to load current CA: %w", err)
	}

	// Load profile store
	profileStore := profile.NewProfileStore(req.CADir)
	if err := profileStore.Load(); err != nil {
		return nil, fmt.Errorf("failed to load profiles: %w", err)
	}

	// Determine which profile to use
	profileName := req.Profile
	if profileName == "" {
		// Try to determine from existing CA metadata or use default
		profileName = determineCurrentProfile(store)
		if profileName == "" {
			return nil, fmt.Errorf("no profile specified and cannot determine current profile; use --profile")
		}
	}

	prof, ok := profileStore.Get(profileName)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", profileName)
	}

	// Determine if cross-signing is needed
	currentAlgo := currentCA.cert.SignatureAlgorithm.String()
	newAlgo := string(prof.GetAlgorithm())
	willCrossSign := shouldCrossSign(req.CrossSign, currentAlgo, newAlgo)

	crossSignReason := ""
	switch req.CrossSign {
	case CrossSignAuto:
		if willCrossSign {
			crossSignReason = fmt.Sprintf("algorithm changed from %s to %s", currentAlgo, newAlgo)
		} else {
			crossSignReason = "same algorithm family"
		}
	case CrossSignOn:
		crossSignReason = "explicitly enabled"
	case CrossSignOff:
		crossSignReason = "explicitly disabled"
	}

	// Build rotation plan
	versionStore := NewVersionStore(req.CADir)
	newVersionID := generateVersionID()

	plan := &RotateCAPlan{
		NewVersion:      newVersionID,
		Profile:         profileName,
		Algorithm:       newAlgo,
		Subject:         currentCA.cert.Subject.String(),
		WillCrossSign:   willCrossSign,
		CrossSignReason: crossSignReason,
		Steps:           buildRotationSteps(newVersionID, profileName, willCrossSign),
	}

	// Check if already versioned
	if versionStore.IsVersioned() {
		activeVersion, err := versionStore.GetActiveVersion()
		if err == nil {
			plan.CurrentVersion = activeVersion.ID
		}
	}

	result := &RotateCAResult{Plan: plan}

	// If dry-run, return the plan without executing
	if req.DryRun {
		return result, nil
	}

	// Execute rotation
	newVersion, newCA, crossSignedCert, err := executeRotation(req, currentCA, prof, versionStore, newVersionID)
	if err != nil {
		return nil, err
	}

	result.NewCA = newCA
	result.Version = newVersion
	result.CrossSignedCert = crossSignedCert

	return result, nil
}

// executeRotation performs the actual rotation.
func executeRotation(req RotateCARequest, currentCA *CA, prof *profile.Profile, versionStore *VersionStore, newVersionID string) (*Version, *CA, *x509.Certificate, error) {
	// Create new version
	notBefore := time.Now()
	notAfter := notBefore.Add(prof.Validity)

	version, err := versionStore.CreateVersion(
		prof.Name,
		string(prof.GetAlgorithm()),
		currentCA.cert.Subject.String(),
		notBefore,
		notAfter,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create version: %w", err)
	}

	// Initialize new CA in version directory
	versionDir := versionStore.VersionDir(version.ID)
	newStore := NewStore(versionDir)

	// Generate new CA keys based on profile
	var newCA *CA
	if prof.IsCatalyst() {
		// Hybrid CA
		cfg := HybridCAConfig{
			CommonName:         currentCA.cert.Subject.CommonName,
			Organization:       firstOrEmpty(currentCA.cert.Subject.Organization),
			Country:            firstOrEmpty(currentCA.cert.Subject.Country),
			ClassicalAlgorithm: prof.Algorithms[0],
			PQCAlgorithm:       prof.Algorithms[1],
			ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
			PathLen:            currentCA.cert.MaxPathLen,
			Passphrase:         req.Passphrase,
		}
		newCA, err = initializeHybridCAInDir(newStore, cfg)
	} else {
		// Regular CA
		cfg := Config{
			CommonName:    currentCA.cert.Subject.CommonName,
			Organization:  firstOrEmpty(currentCA.cert.Subject.Organization),
			Country:       firstOrEmpty(currentCA.cert.Subject.Country),
			Algorithm:     prof.GetAlgorithm(),
			ValidityYears: int(prof.Validity.Hours() / 24 / 365),
			PathLen:       currentCA.cert.MaxPathLen,
			Passphrase:    req.Passphrase,
		}
		newCA, err = initializeCAInDir(newStore, cfg)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize new CA: %w", err)
	}

	// Cross-sign if needed
	var crossSignedCert *x509.Certificate
	currentAlgo := currentCA.cert.SignatureAlgorithm.String()
	newAlgo := string(prof.GetAlgorithm())
	if shouldCrossSign(req.CrossSign, currentAlgo, newAlgo) {
		// Load current CA signer
		if err := currentCA.LoadSigner(req.Passphrase); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load current CA signer for cross-signing: %w", err)
		}

		crossSignedCert, err = crossSign(currentCA, newCA)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to cross-sign: %w", err)
		}

		// Save cross-signed certificate
		crossSignPath := versionStore.CrossSignedCertPath(version.ID, versionStore.basePath)
		if versionStore.IsVersioned() {
			activeVersion, err := versionStore.GetActiveVersion()
			if err == nil {
				crossSignPath = versionStore.CrossSignedCertPath(version.ID, activeVersion.ID)
			}
		}

		if err := saveCrossSignedCert(crossSignPath, crossSignedCert); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to save cross-signed certificate: %w", err)
		}

		// Update version metadata
		if err := versionStore.AddCrossSignedBy(version.ID, "previous"); err != nil {
			return nil, nil, nil, err
		}
	}

	// Audit: CA rotated
	if err := audit.LogCARotated(req.CADir, version.ID, prof.Name, crossSignedCert != nil); err != nil {
		return nil, nil, nil, err
	}

	return version, newCA, crossSignedCert, nil
}

// initializeCAInDir initializes a regular CA in the given store directory.
func initializeCAInDir(store *Store, cfg Config) (*CA, error) {
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

// initializeHybridCAInDir initializes a hybrid CA in the given store directory.
func initializeHybridCAInDir(store *Store, cfg HybridCAConfig) (*CA, error) {
	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate hybrid key pair
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

	// Set subject key ID
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

	// Add AltSubjectPublicKeyInfo extension
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

	// Create pre-TBS certificate
	preTBSDER, err := x509.CreateCertificate(rand.Reader, template, template, hybridSigner.ClassicalSigner().Public(), hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-TBS CA certificate: %w", err)
	}

	preTBSCert, err := x509.ParseCertificate(preTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pre-TBS CA certificate: %w", err)
	}

	// Sign TBS with PQC
	tbsBytes := preTBSCert.RawTBSCertificate
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, tbsBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CA certificate with PQC: %w", err)
	}

	// Add AltSignatureValue extension
	altSigValueExt, err := x509util.EncodeAltSignatureValue(pqcSig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureValue: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigValueExt)

	// Create final self-signed Catalyst CA certificate
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

	return &CA{
		store:  store,
		cert:   cert,
		signer: hybridSigner,
	}, nil
}

// crossSign creates a cross-signed certificate for newCA signed by oldCA.
func crossSign(oldCA, newCA *CA) (*x509.Certificate, error) {
	// Create a certificate with the new CA's public key, signed by the old CA
	template := &x509.Certificate{
		SerialNumber:          newCA.cert.SerialNumber,
		Subject:               newCA.cert.Subject,
		NotBefore:             newCA.cert.NotBefore,
		NotAfter:              newCA.cert.NotAfter,
		KeyUsage:              newCA.cert.KeyUsage,
		ExtKeyUsage:           newCA.cert.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            newCA.cert.MaxPathLen,
		MaxPathLenZero:        newCA.cert.MaxPathLenZero,
		SubjectKeyId:          newCA.cert.SubjectKeyId,
	}

	// Copy extensions (except signature-related)
	for _, ext := range newCA.cert.Extensions {
		// Skip extensions that will be overwritten
		if ext.Id.Equal(x509util.OIDAltSignatureValue) ||
			ext.Id.Equal(x509util.OIDExtAuthorityKeyId) {
			continue
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	// Sign with old CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, oldCA.cert, newCA.cert.PublicKey, oldCA.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create cross-signed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-signed certificate: %w", err)
	}

	return cert, nil
}

// saveCrossSignedCert saves a cross-signed certificate to file.
func saveCrossSignedCert(path string, cert *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	store := &Store{}
	return store.saveCert(path, cert)
}

// shouldCrossSign determines if cross-signing should happen.
func shouldCrossSign(mode CrossSignMode, currentAlgo, newAlgo string) bool {
	switch mode {
	case CrossSignOn:
		return true
	case CrossSignOff:
		return false
	case CrossSignAuto:
		// Cross-sign if algorithms are different
		return currentAlgo != newAlgo
	}
	return false
}

// determineCurrentProfile tries to determine the profile used for the current CA.
func determineCurrentProfile(store *Store) string {
	// Try to read from metadata file
	metaPath := filepath.Join(store.BasePath(), "ca.meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return ""
	}

	var meta struct {
		Profile string `json:"profile"`
	}
	if err := parseJSON(data, &meta); err != nil {
		return ""
	}

	return meta.Profile
}

// parseJSON unmarshals JSON data.
func parseJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// buildRotationSteps creates a list of steps for the rotation plan.
func buildRotationSteps(versionID, profile string, willCrossSign bool) []string {
	steps := []string{
		fmt.Sprintf("Create new version directory: versions/%s", versionID),
		fmt.Sprintf("Generate new CA key pair using profile: %s", profile),
		"Create self-signed CA certificate",
	}

	if willCrossSign {
		steps = append(steps, "Cross-sign new CA certificate with current CA")
		steps = append(steps, "Save cross-signed certificate")
	}

	steps = append(steps, "Update version index")
	steps = append(steps, fmt.Sprintf("New CA ready as pending version: %s", versionID))
	steps = append(steps, "Run 'pki ca activate' to activate the new version")

	return steps
}

// firstOrEmpty returns the first element of a slice or empty string.
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
