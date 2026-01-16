package ca

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
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

	switch {
	case prof.IsComposite():
		return initializeRotationComposite(newStore, rootStore, currentCA, prof, req.Passphrase)
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

// initializeRotationCatalyst initializes a catalyst CA for rotation.
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
