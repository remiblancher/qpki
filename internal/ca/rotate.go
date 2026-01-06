package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// RotateCARequest holds parameters for rotating a CA.
type RotateCARequest struct {
	// CADir is the CA directory.
	CADir string

	// Profile is the profile to use for the new CA (optional, reuses existing if empty).
	Profile string

	// Passphrase for the CA private keys.
	Passphrase string

	// CrossSign enables cross-signing the new CA with the previous CA.
	CrossSign bool

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

	// Support both profile names and file paths
	var prof *profile.Profile
	if strings.Contains(profileName, string(os.PathSeparator)) || strings.HasSuffix(profileName, ".yaml") || strings.HasSuffix(profileName, ".yml") {
		// Load as file path
		var err error
		prof, err = profile.LoadProfile(profileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile from path %s: %w", profileName, err)
		}
	} else {
		var ok bool
		prof, ok = profileStore.Get(profileName)
		if !ok {
			return nil, fmt.Errorf("profile not found: %s", profileName)
		}
	}

	// Get algorithm for display (show both for hybrid profiles)
	var newAlgo string
	if prof.IsCatalyst() || prof.IsComposite() {
		newAlgo = fmt.Sprintf("%s + %s", prof.Algorithms[0], prof.Algorithms[1])
	} else {
		newAlgo = string(prof.GetAlgorithm())
	}

	// Cross-sign decision
	willCrossSign := req.CrossSign
	crossSignReason := "disabled"
	if willCrossSign {
		crossSignReason = "enabled"
	}

	// Build rotation plan
	versionStore := NewVersionStore(req.CADir)
	newVersionID, err := versionStore.PeekNextVersionID()
	if err != nil {
		return nil, fmt.Errorf("failed to get next version ID: %w", err)
	}

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
	version, err := versionStore.CreateVersionWithID(newVersionID, []string{prof.Name})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create version: %w", err)
	}

	// Initialize new CA in version directory (using profile's algorithm family as subdirectory)
	algoFamily := prof.GetAlgorithmFamily()
	profileDir := versionStore.ProfileDir(version.ID, algoFamily)
	newStore := NewStore(profileDir)

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

	// Add certificate reference to version
	certRef := CertRef{
		Profile:         prof.Name,
		Algorithm:       string(prof.GetAlgorithm()),
		AlgorithmFamily: algoFamily,
		Subject:         newCA.cert.Subject.String(),
		Serial:          newCA.cert.SerialNumber.Text(16),
		NotBefore:       newCA.cert.NotBefore,
		NotAfter:        newCA.cert.NotAfter,
	}
	if err := versionStore.AddCertificateRef(version.ID, certRef); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add certificate reference: %w", err)
	}

	// Cross-sign if requested
	var crossSignedCert *x509.Certificate
	if req.CrossSign {
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
// Supports both classical algorithms (ECDSA, RSA, Ed25519) and PQC algorithms (ML-DSA, SLH-DSA).
func initializeCAInDir(store *Store, cfg Config) (*CA, error) {
	// For PQC algorithms, use PQC-specific initialization
	if cfg.Algorithm.IsPQC() {
		return initializePQCCAInDir(store, cfg)
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate CA key pair using KeyProvider
	keyPath := CAKeyPathForAlgorithm(store.BasePath(), cfg.Algorithm)
	keyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: cfg.Passphrase,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	signer, err := km.Generate(cfg.Algorithm, keyCfg)
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

	// Create and save CA metadata
	metadata := NewCAMetadata(cfg.Profile)
	metadata.AddKey(KeyRef{
		ID:        "default",
		Algorithm: cfg.Algorithm,
		Storage:   CreateSoftwareKeyRef(RelativeCAKeyPathForAlgorithm(cfg.Algorithm)),
	})
	if err := metadata.Save(store); err != nil {
		return nil, fmt.Errorf("failed to save CA metadata: %w", err)
	}

	return &CA{
		store:    store,
		cert:     cert,
		signer:   signer,
		metadata: metadata,
	}, nil
}

// initializePQCCAInDir initializes a PQC CA in the given store directory.
// Uses manual DER construction since Go's crypto/x509 doesn't support PQC algorithms.
func initializePQCCAInDir(store *Store, cfg Config) (*CA, error) {
	pqcCfg := PQCCAConfig{
		CommonName:    cfg.CommonName,
		Organization:  cfg.Organization,
		Country:       cfg.Country,
		Algorithm:     cfg.Algorithm,
		ValidityYears: cfg.ValidityYears,
		PathLen:       cfg.PathLen,
		Passphrase:    cfg.Passphrase,
	}
	return InitializePQCCA(store, pqcCfg)
}

// initializeHybridCAInDir initializes a hybrid CA in the given store directory.
func initializeHybridCAInDir(store *Store, cfg HybridCAConfig) (*CA, error) {
	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
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

	// Create hybrid signer from the two signers
	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid CA signer: %w", err)
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

	// Build PreTBSCertificate and sign with PQC
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

	// Create and save CA metadata
	metadata := NewCAMetadata("hybrid")
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

	return &CA{
		store:    store,
		cert:     cert,
		signer:   hybridSigner,
		metadata: metadata,
	}, nil
}

// crossSign creates a cross-signed certificate for newCA signed by oldCA.
func crossSign(oldCA, newCA *CA) (*x509.Certificate, error) {
	// Check if new CA has a PQC public key (Go returns nil for PQC public keys)
	if newCA.cert.PublicKey == nil {
		return crossSignPQC(oldCA, newCA)
	}

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

// crossSignPQC creates a cross-signed certificate for a PQC CA signed by oldCA.
// This is needed because Go's x509.CreateCertificate doesn't support PQC public keys.
func crossSignPQC(oldCA, newCA *CA) (*x509.Certificate, error) {
	// Get the signer algorithm from old CA
	signerAlg := oldCA.signer.Algorithm()

	// For hybrid signers, use the classical signer
	var signer pkicrypto.Signer
	if hs, ok := oldCA.signer.(pkicrypto.HybridSigner); ok {
		signer = hs.ClassicalSigner()
		signerAlg = hs.ClassicalSigner().Algorithm()
	} else {
		signer = oldCA.signer
	}

	// Get signature algorithm OID
	sigAlgOID := signerAlg.OID()
	if sigAlgOID == nil {
		return nil, fmt.Errorf("unsupported signer algorithm: %s has no OID", signerAlg)
	}

	// Parse the new CA's SPKI to get the public key info
	var newCAPubKey publicKeyInfo
	_, err := asn1.Unmarshal(newCA.cert.RawSubjectPublicKeyInfo, &newCAPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse new CA's public key info: %w", err)
	}

	// Build TBSCertificate manually using the new CA's public key
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: newCA.cert.SerialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer:   asn1.RawValue{FullBytes: oldCA.cert.RawSubject}, // Signed by old CA
		Validity: validity{NotBefore: newCA.cert.NotBefore, NotAfter: newCA.cert.NotAfter},
		Subject:  asn1.RawValue{FullBytes: newCA.cert.RawSubject}, // Same subject as new CA
		PublicKey: newCAPubKey,
	}

	// Copy extensions from new CA, filtering out those we'll replace
	for _, ext := range newCA.cert.Extensions {
		// Skip AltSignatureValue (it's specific to the self-signed cert)
		// Skip AuthorityKeyIdentifier (we'll add our own)
		if ext.Id.Equal(x509util.OIDAltSignatureValue) ||
			ext.Id.Equal(x509util.OIDExtAuthorityKeyId) {
			continue
		}
		tbs.Extensions = append(tbs.Extensions, ext)
	}

	// Add Authority Key Identifier from old CA
	if len(oldCA.cert.SubjectKeyId) > 0 {
		akid := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{
			KeyIdentifier: oldCA.cert.SubjectKeyId,
		}
		akidDER, err := asn1.Marshal(akid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authority key identifier: %w", err)
		}
		tbs.Extensions = append(tbs.Extensions, pkix.Extension{
			Id:       x509util.OIDExtAuthorityKeyId,
			Critical: false,
			Value:    akidDER,
		})
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign with old CA using appropriate options for the algorithm
	signerOpts := pkicrypto.DefaultSignerOpts(signerAlg)
	var digest []byte
	if signerOpts.Hash != 0 {
		// Classical algorithm - hash the TBS first
		h := signerOpts.Hash.New()
		h.Write(tbsDER)
		digest = h.Sum(nil)
	} else {
		// PQC or Ed25519 - sign the full message
		digest = tbsDER
	}

	signature, err := signer.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cross-signed certificate: %w", err)
	}

	// Assemble final certificate
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
		return nil, fmt.Errorf("failed to marshal cross-signed certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-signed certificate: %w", err)
	}

	return parsedCert, nil
}

// saveCrossSignedCert saves a cross-signed certificate to file.
func saveCrossSignedCert(path string, cert *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	store := &Store{}
	return store.saveCert(path, cert)
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

// MultiProfileRotateRequest holds parameters for rotating a CA with multiple profiles.
type MultiProfileRotateRequest struct {
	// CADir is the CA directory.
	CADir string

	// Profiles is a list of profiles to use for the new CA version.
	// Each profile produces one certificate.
	Profiles []*profile.Profile

	// Passphrase for the CA private keys.
	Passphrase string

	// CrossSign enables cross-signing the new CA with the previous CA.
	CrossSign bool

	// DryRun if true, returns the plan without executing.
	DryRun bool
}

// MultiProfileRotatePlan describes what multi-profile rotation will do.
type MultiProfileRotatePlan struct {
	// CurrentVersion is the currently active version (if versioned).
	CurrentVersion string

	// NewVersion is the version ID that will be created.
	NewVersion string

	// Profiles lists the profiles that will be used.
	Profiles []ProfileRotatePlan

	// Steps describes the rotation steps.
	Steps []string
}

// ProfileRotatePlan describes the plan for a single profile in multi-profile rotation.
type ProfileRotatePlan struct {
	// ProfileName is the profile name.
	ProfileName string

	// Algorithm is the algorithm from the profile.
	Algorithm string

	// AlgorithmFamily is the algorithm family (e.g., "ec", "ml-dsa").
	AlgorithmFamily string

	// WillCrossSign indicates if cross-signing will occur for this profile.
	WillCrossSign bool

	// CrossSignReason explains why cross-signing will/won't happen.
	CrossSignReason string
}

// MultiProfileRotateResult holds the result of a multi-profile CA rotation.
type MultiProfileRotateResult struct {
	// Plan is the rotation plan (always populated).
	Plan *MultiProfileRotatePlan

	// Version is the new version (nil if dry-run).
	Version *Version

	// Certificates maps algorithm family to the created certificate.
	Certificates map[string]*x509.Certificate

	// CrossSignedCerts maps algorithm family to its cross-signed certificate (if any).
	CrossSignedCerts map[string]*x509.Certificate
}

// RotateCAMultiProfile rotates a CA with multiple profiles, creating a new version with
// one certificate per profile (algorithm family).
func RotateCAMultiProfile(req MultiProfileRotateRequest) (*MultiProfileRotateResult, error) {
	if len(req.Profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Check if CA exists
	versionStore := NewVersionStore(req.CADir)
	if !versionStore.IsVersioned() {
		// Check for legacy CA
		store := NewStore(req.CADir)
		if !store.Exists() {
			return nil, fmt.Errorf("CA not found at %s", req.CADir)
		}
	}

	// Load current active version to get current certificates for cross-signing decisions
	var currentCerts map[string]*CertRef
	if versionStore.IsVersioned() {
		activeVersion, err := versionStore.GetActiveVersion()
		if err == nil {
			currentCerts = make(map[string]*CertRef)
			for i := range activeVersion.Certificates {
				cert := &activeVersion.Certificates[i]
				currentCerts[cert.AlgorithmFamily] = cert
			}
		}
	}

	// Build rotation plan
	newVersionID, err := versionStore.PeekNextVersionID()
	if err != nil {
		return nil, fmt.Errorf("failed to get next version ID: %w", err)
	}
	plan := &MultiProfileRotatePlan{
		NewVersion: newVersionID,
		Profiles:   make([]ProfileRotatePlan, 0, len(req.Profiles)),
	}

	// Check current version
	if versionStore.IsVersioned() {
		activeVersion, err := versionStore.GetActiveVersion()
		if err == nil {
			plan.CurrentVersion = activeVersion.ID
		}
	}

	// Plan each profile
	for _, prof := range req.Profiles {
		algoFamily := prof.GetAlgorithmFamily()
		newAlgo := string(prof.GetAlgorithm())

		// Determine cross-signing for this profile
		willCrossSign := false
		crossSignReason := "no previous certificate for this algorithm family"

		if _, ok := currentCerts[algoFamily]; ok {
			willCrossSign = req.CrossSign
			if willCrossSign {
				crossSignReason = "enabled"
			} else {
				crossSignReason = "disabled"
			}
		}

		plan.Profiles = append(plan.Profiles, ProfileRotatePlan{
			ProfileName:     prof.Name,
			Algorithm:       newAlgo,
			AlgorithmFamily: algoFamily,
			WillCrossSign:   willCrossSign,
			CrossSignReason: crossSignReason,
		})
	}

	plan.Steps = buildMultiProfileRotationSteps(newVersionID, plan.Profiles)

	result := &MultiProfileRotateResult{
		Plan:             plan,
		Certificates:     make(map[string]*x509.Certificate),
		CrossSignedCerts: make(map[string]*x509.Certificate),
	}

	// If dry-run, return the plan without executing
	if req.DryRun {
		return result, nil
	}

	// Execute rotation
	version, certs, crossSignedCerts, err := executeMultiProfileRotation(req, versionStore, currentCerts, newVersionID)
	if err != nil {
		return nil, err
	}

	result.Version = version
	result.Certificates = certs
	result.CrossSignedCerts = crossSignedCerts

	return result, nil
}

// executeMultiProfileRotation performs the actual multi-profile rotation.
func executeMultiProfileRotation(
	req MultiProfileRotateRequest,
	versionStore *VersionStore,
	currentCerts map[string]*CertRef,
	newVersionID string,
) (*Version, map[string]*x509.Certificate, map[string]*x509.Certificate, error) {
	// Extract profile names
	profileNames := make([]string, 0, len(req.Profiles))
	for _, prof := range req.Profiles {
		profileNames = append(profileNames, prof.Name)
	}

	// Create version with the specified ID
	version, err := versionStore.CreateVersionWithID(newVersionID, profileNames)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create version: %w", err)
	}

	certs := make(map[string]*x509.Certificate)
	crossSignedCerts := make(map[string]*x509.Certificate)

	// Load current CAs for cross-signing (if needed)
	var currentCAs map[string]*CA
	if len(currentCerts) > 0 && req.CrossSign {
		currentCAs = make(map[string]*CA)
		for algoFamily, certRef := range currentCerts {
			// Load CA from the profile directory
			profileDir := versionStore.ProfileDir(versionStore.getActiveVersionID(), algoFamily)
			store := NewStore(profileDir)
			ca, err := New(store)
			if err != nil {
				continue // Skip if can't load
			}
			if err := ca.LoadSigner(req.Passphrase); err != nil {
				continue // Skip if can't load signer
			}
			currentCAs[certRef.AlgorithmFamily] = ca
		}
	}

	// Create certificates for each profile
	for _, prof := range req.Profiles {
		algoFamily := prof.GetAlgorithmFamily()
		algorithm := prof.GetAlgorithm()

		// Create profile directory within version
		profileDir := versionStore.ProfileDir(version.ID, algoFamily)
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create profile directory for %s: %w", algoFamily, err)
		}

		profileStore := NewStore(profileDir)

		// Get subject from previous version or use defaults
		var cn, org, country string
		pathLen := 0

		if currentCert, ok := currentCerts[algoFamily]; ok {
			// Parse subject from current cert
			cn = currentCert.Subject
			// For now, use defaults - could parse subject DN if needed
		}

		if cn == "" {
			cn = "CA " + algoFamily
		}

		// Initialize CA based on profile type
		var newCA *CA
		if prof.IsCatalyst() {
			cfg := HybridCAConfig{
				CommonName:         cn,
				Organization:       org,
				Country:            country,
				ClassicalAlgorithm: prof.Algorithms[0],
				PQCAlgorithm:       prof.Algorithms[1],
				ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
				PathLen:            pathLen,
				Passphrase:         req.Passphrase,
			}
			newCA, err = initializeHybridCAInDir(profileStore, cfg)
		} else if algorithm.IsPQC() {
			cfg := Config{
				CommonName:    cn,
				Organization:  org,
				Country:       country,
				Algorithm:     algorithm,
				ValidityYears: int(prof.Validity.Hours() / 24 / 365),
				PathLen:       pathLen,
				Passphrase:    req.Passphrase,
				Profile:       prof.Name,
			}
			newCA, err = initializePQCCAInDir(profileStore, cfg)
		} else {
			cfg := Config{
				CommonName:    cn,
				Organization:  org,
				Country:       country,
				Algorithm:     algorithm,
				ValidityYears: int(prof.Validity.Hours() / 24 / 365),
				PathLen:       pathLen,
				Passphrase:    req.Passphrase,
				Profile:       prof.Name,
			}
			newCA, err = initializeCAInDir(profileStore, cfg)
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize CA for %s: %w", algoFamily, err)
		}

		certs[algoFamily] = newCA.Certificate()

		// Add certificate reference to version
		cert := newCA.Certificate()
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
			return nil, nil, nil, fmt.Errorf("failed to add certificate reference for %s: %w", algoFamily, err)
		}

		// Cross-sign if requested
		if currentCA, ok := currentCAs[algoFamily]; ok && req.CrossSign {
				crossSignedCert, err := crossSign(currentCA, newCA)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to cross-sign for %s: %w", algoFamily, err)
				}

				// Save cross-signed certificate
				crossSignPath := filepath.Join(profileDir, "cross-signed", "by-previous.crt")
				if err := saveCrossSignedCert(crossSignPath, crossSignedCert); err != nil {
					return nil, nil, nil, fmt.Errorf("failed to save cross-signed cert for %s: %w", algoFamily, err)
				}

			crossSignedCerts[algoFamily] = crossSignedCert
		}
	}

	// Update cross-signed metadata if any cross-signing occurred
	if len(crossSignedCerts) > 0 {
		if err := versionStore.AddCrossSignedBy(version.ID, "previous"); err != nil {
			return nil, nil, nil, err
		}
	}

	// Audit: CA rotated
	if err := audit.LogCARotated(req.CADir, version.ID, strings.Join(profileNames, ", "), len(crossSignedCerts) > 0); err != nil {
		return nil, nil, nil, err
	}

	// Reload version to get updated state
	version, err = versionStore.GetVersion(version.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to reload version: %w", err)
	}

	return version, certs, crossSignedCerts, nil
}

// getActiveVersionID returns the active version ID or empty string.
func (vs *VersionStore) getActiveVersionID() string {
	index, err := vs.LoadIndex()
	if err != nil {
		return ""
	}
	return index.ActiveVersion
}

// buildMultiProfileRotationSteps creates a list of steps for multi-profile rotation.
func buildMultiProfileRotationSteps(versionID string, profiles []ProfileRotatePlan) []string {
	steps := []string{
		fmt.Sprintf("Create new version directory: versions/%s", versionID),
	}

	for _, prof := range profiles {
		steps = append(steps, fmt.Sprintf("  - Generate %s key pair using profile: %s", prof.AlgorithmFamily, prof.ProfileName))
		if prof.WillCrossSign {
			steps = append(steps, fmt.Sprintf("  - Cross-sign %s certificate with current CA", prof.AlgorithmFamily))
		}
	}

	steps = append(steps, "Update version index")
	steps = append(steps, fmt.Sprintf("New CA ready as pending version: %s", versionID))
	steps = append(steps, "Run 'pki ca activate' to activate the new version")

	return steps
}
