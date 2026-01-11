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

	// Initialize new CA in version directory
	algoFamily := prof.GetAlgorithmFamily()
	versionDir := versionStore.VersionDir(version.ID)
	newStore := NewFileStore(versionDir)
	rootStore := NewFileStore(req.CADir)

	// Generate new CA keys based on profile using refactored init functions
	var newCA *CA
	if prof.IsComposite() {
		// Composite CA (IETF format)
		cfg := CompositeCAConfig{
			CommonName:         currentCA.cert.Subject.CommonName,
			Organization:       firstOrEmpty(currentCA.cert.Subject.Organization),
			Country:            firstOrEmpty(currentCA.cert.Subject.Country),
			ClassicalAlgorithm: prof.Algorithms[0],
			PQCAlgorithm:       prof.Algorithms[1],
			ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
			PathLen:            currentCA.cert.MaxPathLen,
			Passphrase:         req.Passphrase,
		}
		compAlg, err := GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unsupported composite algorithm: %w", err)
		}
		newCA, err = initializeCompositeInStore(newStore, rootStore, cfg, compAlg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize composite CA: %w", err)
		}
	} else if prof.IsCatalyst() {
		// Catalyst Hybrid CA (ITU-T format)
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
		newCA, err = initializeHybridInStore(newStore, rootStore, cfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize hybrid CA: %w", err)
		}
	} else if prof.GetAlgorithm().IsPQC() {
		// PQC CA
		cfg := PQCCAConfig{
			CommonName:    currentCA.cert.Subject.CommonName,
			Organization:  firstOrEmpty(currentCA.cert.Subject.Organization),
			Country:       firstOrEmpty(currentCA.cert.Subject.Country),
			Algorithm:     prof.GetAlgorithm(),
			ValidityYears: int(prof.Validity.Hours() / 24 / 365),
			PathLen:       currentCA.cert.MaxPathLen,
			Passphrase:    req.Passphrase,
		}
		newCA, err = initializePQCInStore(newStore, rootStore, cfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize PQC CA: %w", err)
		}
	} else {
		// Regular CA (classical algorithms)
		cfg := Config{
			CommonName:    currentCA.cert.Subject.CommonName,
			Organization:  firstOrEmpty(currentCA.cert.Subject.Organization),
			Country:       firstOrEmpty(currentCA.cert.Subject.Country),
			Algorithm:     prof.GetAlgorithm(),
			ValidityYears: int(prof.Validity.Hours() / 24 / 365),
			PathLen:       currentCA.cert.MaxPathLen,
			Passphrase:    req.Passphrase,
		}
		newCA, _, _, err = initializeInStore(newStore, rootStore, cfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
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

	// For hybrid profiles, also add the PQC algorithm family
	if prof.IsCatalyst() || prof.IsComposite() {
		pqcAlgoFamily := getAlgorithmFamily(prof.Algorithms[1])
		pqcCertRef := CertRef{
			Profile:         prof.Name,
			Algorithm:       string(prof.Algorithms[1]),
			AlgorithmFamily: pqcAlgoFamily,
			Subject:         newCA.cert.Subject.String(),
			Serial:          newCA.cert.SerialNumber.Text(16),
			NotBefore:       newCA.cert.NotBefore,
			NotAfter:        newCA.cert.NotAfter,
		}
		if err := versionStore.AddCertificateRef(version.ID, pqcCertRef); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to add PQC certificate reference: %w", err)
		}
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
