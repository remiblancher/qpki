package ca

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
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

	// HSMConfig is the path to the HSM config file (for HSM-based rotation).
	HSMConfig string

	// KeyLabel is the key label for HSM keys (optional, auto-generated if empty).
	KeyLabel string
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
	store := NewFileStore(req.CADir)
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

	newCA, err := initializeNewCAForRotation(req, currentCA, prof, versionStore, version)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := addCertRefsToVersion(versionStore, version.ID, prof, newCA); err != nil {
		return nil, nil, nil, err
	}

	// Add key references to the version
	if err := addKeyRefsToVersion(req, currentCA, prof, versionStore, version.ID, newCA); err != nil {
		return nil, nil, nil, err
	}

	crossSignedCert, err := performCrossSignIfRequested(req, currentCA, newCA, versionStore, version)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := audit.LogCARotated(req.CADir, version.ID, prof.Name, crossSignedCert != nil); err != nil {
		return nil, nil, nil, err
	}

	return version, newCA, crossSignedCert, nil
}

// initializeNewCAForRotation creates a new CA based on the profile type.
func initializeNewCAForRotation(req RotateCARequest, currentCA *CA, prof *profile.Profile, versionStore *VersionStore, version *Version) (*CA, error) {
	versionDir := versionStore.VersionDir(version.ID)
	newStore := NewFileStore(versionDir)
	rootStore := NewFileStore(req.CADir)

	// Check if using HSM (either from request or from current CA)
	isHSM := req.HSMConfig != "" || (currentCA.info != nil && currentCA.info.IsHSMBased())

	switch {
	case prof.IsComposite():
		return initializeRotationComposite(newStore, rootStore, currentCA, prof, req.Passphrase)
	case prof.IsCatalyst() && isHSM:
		return initializeRotationCatalystHSM(req, newStore, rootStore, currentCA, prof, version.ID)
	case prof.IsCatalyst():
		return initializeRotationCatalyst(newStore, rootStore, currentCA, prof, req.Passphrase)
	case prof.GetAlgorithm().IsPQC():
		return initializeRotationPQC(newStore, rootStore, currentCA, prof, req.Passphrase)
	default:
		return initializeRotationClassical(newStore, rootStore, currentCA, prof, req.Passphrase)
	}
}

// initializeRotationComposite initializes a composite CA for rotation.
func initializeRotationComposite(newStore, rootStore *FileStore, currentCA *CA, prof *profile.Profile, passphrase string) (*CA, error) {
	cfg := CompositeCAConfig{
		CommonName:         currentCA.cert.Subject.CommonName,
		Organization:       firstOrEmpty(currentCA.cert.Subject.Organization),
		Country:            firstOrEmpty(currentCA.cert.Subject.Country),
		ClassicalAlgorithm: prof.Algorithms[0],
		PQCAlgorithm:       prof.Algorithms[1],
		ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
		PathLen:            currentCA.cert.MaxPathLen,
		Passphrase:         passphrase,
	}
	compAlg, err := GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported composite algorithm: %w", err)
	}
	newCA, err := initializeCompositeInStore(newStore, rootStore, cfg, compAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize composite CA: %w", err)
	}
	return newCA, nil
}

// initializeRotationCatalyst initializes a catalyst CA for rotation (software keys).
func initializeRotationCatalyst(newStore, rootStore *FileStore, currentCA *CA, prof *profile.Profile, passphrase string) (*CA, error) {
	cfg := HybridCAConfig{
		CommonName:         currentCA.cert.Subject.CommonName,
		Organization:       firstOrEmpty(currentCA.cert.Subject.Organization),
		Country:            firstOrEmpty(currentCA.cert.Subject.Country),
		ClassicalAlgorithm: prof.Algorithms[0],
		PQCAlgorithm:       prof.Algorithms[1],
		ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
		PathLen:            currentCA.cert.MaxPathLen,
		Passphrase:         passphrase,
	}
	newCA, err := initializeHybridInStore(newStore, rootStore, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize hybrid CA: %w", err)
	}
	return newCA, nil
}

// initializeRotationCatalystHSM initializes a catalyst CA for rotation with HSM keys.
func initializeRotationCatalystHSM(req RotateCARequest, newStore, rootStore *FileStore, currentCA *CA, prof *profile.Profile, versionID string) (*CA, error) {
	// Determine HSM config path
	hsmConfigPath := req.HSMConfig
	if hsmConfigPath == "" && currentCA.info != nil {
		// Try to get from current CA's active version - check any key (not just "classical")
		// For single-key CAs, the key ID is "default"; for hybrid CAs, it's "classical"/"pqc"
		if defaultKey := currentCA.info.GetDefaultKey(); defaultKey != nil && defaultKey.Storage.Type == "pkcs11" {
			hsmConfigPath = defaultKey.Storage.Config
			// Resolve relative path to absolute using CA base path
			if !filepath.IsAbs(hsmConfigPath) {
				hsmConfigPath = filepath.Join(currentCA.info.BasePath(), hsmConfigPath)
			}
		}
	}
	if hsmConfigPath == "" {
		return nil, fmt.Errorf("HSM config required for HSM-based rotation")
	}

	// Load HSM config
	hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load HSM config: %w", err)
	}

	// Determine key label (versioned)
	baseLabel := req.KeyLabel
	if baseLabel == "" && currentCA.info != nil {
		// Try to get base label from existing key's label (strip version suffix if present)
		if defaultKey := currentCA.info.GetDefaultKey(); defaultKey != nil && defaultKey.Storage.Label != "" {
			baseLabel = defaultKey.Storage.Label
			// Strip existing version suffix (e.g., "ca-key-abc123-v1" -> "ca-key-abc123")
			if idx := strings.LastIndex(baseLabel, "-v"); idx != -1 && idx < len(baseLabel)-2 {
				if _, err := fmt.Sscanf(baseLabel[idx+2:], "%d", new(int)); err == nil {
					baseLabel = baseLabel[:idx]
				}
			}
		}
	}
	if baseLabel == "" {
		// Fallback to CN-based label with timestamp for uniqueness
		baseLabel = fmt.Sprintf("%s-%d", currentCA.cert.Subject.CommonName, time.Now().Unix())
	}
	keyLabel := fmt.Sprintf("%s-%s", baseLabel, versionID)

	// Get algorithms from profile
	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate HSM keys
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	// Generate classical key
	classicalGenCfg := pkicrypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
		Algorithm:  classicalAlg,
	}
	classicalResult, err := pkicrypto.GenerateHSMKeyPair(classicalGenCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical HSM key: %w", err)
	}

	// Generate PQC key
	pqcGenCfg := pkicrypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
		Algorithm:  pqcAlg,
	}
	pqcResult, err := pkicrypto.GenerateHSMKeyPair(pqcGenCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC HSM key: %w", err)
	}

	// Create hybrid signer from HSM
	pkcs11Cfg := pkicrypto.PKCS11Config{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
	}
	hybridSigner, err := pkicrypto.NewPKCS11HybridSigner(pkcs11Cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HSM hybrid signer: %w", err)
	}

	// Create certs directory
	certsDir := filepath.Join(newStore.BasePath(), "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Build certificate template
	hybridCfg := HybridCAConfig{
		CommonName:         currentCA.cert.Subject.CommonName,
		Organization:       firstOrEmpty(currentCA.cert.Subject.Organization),
		Country:            firstOrEmpty(currentCA.cert.Subject.Country),
		ClassicalAlgorithm: classicalAlg,
		PQCAlgorithm:       pqcAlg,
		ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
		PathLen:            currentCA.cert.MaxPathLen,
	}

	template, err := buildCatalystTemplate(hybridCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate template: %w", err)
	}

	if err := setCatalystTemplateIdentifiers(template, rootStore, hybridSigner.ClassicalSigner().Public()); err != nil {
		return nil, err
	}

	// Get PQC public key bytes
	pqcPubBytes, err := pkicrypto.PublicKeyBytes(hybridSigner.PQCSigner().Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	if err := addAltKeyExtensions(template, pqcAlg, pqcPubBytes); err != nil {
		return nil, err
	}

	// Create Catalyst certificate
	cert, err := createCatalystSelfSignedCert(template, hybridSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create Catalyst certificate: %w", err)
	}

	// Save certificate
	certPath := HybridCertPath(newStore.BasePath(), HybridCertCatalyst, classicalAlg, pqcAlg, false)
	if err := saveCertToPath(certPath, cert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Store key references in the version (will be added by caller via CAInfo)
	keyRefs := []KeyRef{
		{
			ID:        "classical",
			Algorithm: classicalAlg,
			Storage:   CreatePKCS11KeyRef(hsmConfigPath, keyLabel, classicalResult.KeyID),
		},
		{
			ID:        "pqc",
			Algorithm: pqcAlg,
			Storage:   CreatePKCS11KeyRef(hsmConfigPath, keyLabel, pqcResult.KeyID),
		},
	}

	return &CA{
		store:   newStore,
		cert:    cert,
		signer:  hybridSigner,
		keyRefs: keyRefs, // Store for later use by caller
	}, nil
}

// initializeRotationPQC initializes a PQC CA for rotation.
func initializeRotationPQC(newStore, rootStore *FileStore, currentCA *CA, prof *profile.Profile, passphrase string) (*CA, error) {
	cfg := PQCCAConfig{
		CommonName:    currentCA.cert.Subject.CommonName,
		Organization:  firstOrEmpty(currentCA.cert.Subject.Organization),
		Country:       firstOrEmpty(currentCA.cert.Subject.Country),
		Algorithm:     prof.GetAlgorithm(),
		ValidityYears: int(prof.Validity.Hours() / 24 / 365),
		PathLen:       currentCA.cert.MaxPathLen,
		Passphrase:    passphrase,
	}
	newCA, err := initializePQCInStore(newStore, rootStore, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PQC CA: %w", err)
	}
	return newCA, nil
}

// initializeRotationClassical initializes a classical CA for rotation.
func initializeRotationClassical(newStore, rootStore *FileStore, currentCA *CA, prof *profile.Profile, passphrase string) (*CA, error) {
	cfg := Config{
		CommonName:    currentCA.cert.Subject.CommonName,
		Organization:  firstOrEmpty(currentCA.cert.Subject.Organization),
		Country:       firstOrEmpty(currentCA.cert.Subject.Country),
		Algorithm:     prof.GetAlgorithm(),
		ValidityYears: int(prof.Validity.Hours() / 24 / 365),
		PathLen:       currentCA.cert.MaxPathLen,
		Passphrase:    passphrase,
	}
	newCA, _, _, err := initializeInStore(newStore, rootStore, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}
	return newCA, nil
}

// addKeyRefsToVersion adds key references to the version metadata.
func addKeyRefsToVersion(req RotateCARequest, currentCA *CA, prof *profile.Profile, versionStore *VersionStore, versionID string, newCA *CA) error {
	// Load CAInfo to add keys to the version
	info, err := LoadCAInfo(req.CADir)
	if err != nil || info == nil {
		return fmt.Errorf("failed to load CA info: %w", err)
	}

	// If newCA has keyRefs (from HSM rotation), use those
	if len(newCA.keyRefs) > 0 {
		for _, keyRef := range newCA.keyRefs {
			if err := info.AddVersionKey(versionID, keyRef); err != nil {
				return fmt.Errorf("failed to add key reference: %w", err)
			}
		}
	} else if prof.IsCatalyst() || prof.IsComposite() {
		// Software keys for hybrid/composite - add key refs with file paths
		classicalAlgoID := string(prof.Algorithms[0])
		pqcAlgoID := string(prof.Algorithms[1])

		if err := info.AddVersionKey(versionID, KeyRef{
			ID:        "classical",
			Algorithm: prof.Algorithms[0],
			Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/%s/keys/ca.%s.key", versionID, classicalAlgoID)),
		}); err != nil {
			return fmt.Errorf("failed to add classical key reference: %w", err)
		}

		if err := info.AddVersionKey(versionID, KeyRef{
			ID:        "pqc",
			Algorithm: prof.Algorithms[1],
			Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/%s/keys/ca.%s.key", versionID, pqcAlgoID)),
		}); err != nil {
			return fmt.Errorf("failed to add PQC key reference: %w", err)
		}
	} else {
		// Single-algorithm CA - add single key ref
		algoID := string(prof.GetAlgorithm())
		if err := info.AddVersionKey(versionID, KeyRef{
			ID:        "default",
			Algorithm: prof.GetAlgorithm(),
			Storage:   CreateSoftwareKeyRef(fmt.Sprintf("versions/%s/keys/ca.%s.key", versionID, algoID)),
		}); err != nil {
			return fmt.Errorf("failed to add key reference: %w", err)
		}
	}

	return info.Save()
}

// addCertRefsToVersion adds certificate references to the version metadata.
func addCertRefsToVersion(versionStore *VersionStore, versionID string, prof *profile.Profile, newCA *CA) error {
	certRef := CertRef{
		Profile:         prof.Name,
		Algorithm:       string(prof.GetAlgorithm()),
		AlgorithmFamily: prof.GetAlgorithmFamily(),
		Subject:         newCA.cert.Subject.String(),
		Serial:          newCA.cert.SerialNumber.Text(16),
		NotBefore:       newCA.cert.NotBefore,
		NotAfter:        newCA.cert.NotAfter,
	}
	if err := versionStore.AddCertificateRef(versionID, certRef); err != nil {
		return fmt.Errorf("failed to add certificate reference: %w", err)
	}

	if prof.IsCatalyst() || prof.IsComposite() {
		pqcCertRef := CertRef{
			Profile:         prof.Name,
			Algorithm:       string(prof.Algorithms[1]),
			AlgorithmFamily: getAlgorithmFamily(prof.Algorithms[1]),
			Subject:         newCA.cert.Subject.String(),
			Serial:          newCA.cert.SerialNumber.Text(16),
			NotBefore:       newCA.cert.NotBefore,
			NotAfter:        newCA.cert.NotAfter,
		}
		if err := versionStore.AddCertificateRef(versionID, pqcCertRef); err != nil {
			return fmt.Errorf("failed to add PQC certificate reference: %w", err)
		}
	}
	return nil
}

// performCrossSignIfRequested handles cross-signing if requested.
func performCrossSignIfRequested(req RotateCARequest, currentCA *CA, newCA *CA, versionStore *VersionStore, version *Version) (*x509.Certificate, error) {
	if !req.CrossSign {
		return nil, nil
	}

	if err := currentCA.LoadSigner(req.Passphrase); err != nil {
		return nil, fmt.Errorf("failed to load current CA signer for cross-signing: %w", err)
	}

	crossSignedCert, err := crossSign(currentCA, newCA)
	if err != nil {
		return nil, fmt.Errorf("failed to cross-sign: %w", err)
	}

	crossSignPath := determineCrossSignPath(versionStore, version.ID)
	if err := saveCrossSignedCert(crossSignPath, crossSignedCert); err != nil {
		return nil, fmt.Errorf("failed to save cross-signed certificate: %w", err)
	}

	if err := versionStore.AddCrossSignedBy(version.ID, "previous"); err != nil {
		return nil, err
	}

	return crossSignedCert, nil
}

// determineCrossSignPath determines the path for the cross-signed certificate.
func determineCrossSignPath(versionStore *VersionStore, versionID string) string {
	crossSignPath := versionStore.CrossSignedCertPath(versionID, versionStore.basePath)
	if versionStore.IsVersioned() {
		if activeVersion, err := versionStore.GetActiveVersion(); err == nil {
			crossSignPath = versionStore.CrossSignedCertPath(versionID, activeVersion.ID)
		}
	}
	return crossSignPath
}

// determineCurrentProfile tries to determine the profile used for the current CA.
func determineCurrentProfile(store *FileStore) string {
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
