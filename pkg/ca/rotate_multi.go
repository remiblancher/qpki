package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
)

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
		store := NewFileStore(req.CADir)
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
	profileNames := extractProfileNames(req.Profiles)

	version, err := versionStore.CreateVersionWithID(newVersionID, profileNames)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create version: %w", err)
	}

	currentCAs := loadCurrentCAsForCrossSigning(versionStore, currentCerts, req)

	if err := createVersionDirectories(versionStore, version.ID); err != nil {
		return nil, nil, nil, err
	}

	versionDir := versionStore.VersionDir(version.ID)
	profileStore := NewFileStore(versionDir)
	rootStore := NewFileStore(req.CADir)

	certs := make(map[string]*x509.Certificate)
	crossSignedCerts := make(map[string]*x509.Certificate)

	for _, prof := range req.Profiles {
		newCA, err := initializeCAForProfile(prof, currentCerts, profileStore, rootStore, req.Passphrase)
		if err != nil {
			return nil, nil, nil, err
		}

		algoFamily := prof.GetAlgorithmFamily()
		certs[algoFamily] = newCA.Certificate()

		if err := addCertRefToVersion(versionStore, version.ID, prof, newCA); err != nil {
			return nil, nil, nil, err
		}

		// Add key references to root CAInfo
		if err := addKeyRefsToVersionMulti(req.CADir, version.ID, prof, newCA); err != nil {
			return nil, nil, nil, err
		}

		if crossCert, err := crossSignIfRequested(currentCAs, newCA, algoFamily, versionDir, req.CrossSign); err != nil {
			return nil, nil, nil, err
		} else if crossCert != nil {
			crossSignedCerts[algoFamily] = crossCert
		}
	}

	if err := finalizeRotation(versionStore, version.ID, req.CADir, profileNames, crossSignedCerts); err != nil {
		return nil, nil, nil, err
	}

	version, err = versionStore.GetVersion(version.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to reload version: %w", err)
	}

	return version, certs, crossSignedCerts, nil
}

// extractProfileNames extracts profile names from rotation profiles.
func extractProfileNames(profiles []*profile.Profile) []string {
	names := make([]string, 0, len(profiles))
	for _, prof := range profiles {
		names = append(names, prof.Name)
	}
	return names
}

// loadCurrentCAsForCrossSigning loads current CAs if cross-signing is needed.
func loadCurrentCAsForCrossSigning(versionStore *VersionStore, currentCerts map[string]*CertRef, req MultiProfileRotateRequest) map[string]*CA {
	if len(currentCerts) == 0 || !req.CrossSign {
		return nil
	}
	currentCAs := make(map[string]*CA)
	for _, certRef := range currentCerts {
		versionDir := versionStore.VersionDir(versionStore.getActiveVersionID())
		store := NewFileStore(versionDir)
		ca, err := New(store)
		if err != nil {
			continue
		}
		if err := ca.LoadSigner(req.Passphrase); err != nil {
			continue
		}
		currentCAs[certRef.AlgorithmFamily] = ca
	}
	return currentCAs
}

// createVersionDirectories creates the keys/ and certs/ directories for a version.
func createVersionDirectories(versionStore *VersionStore, versionID string) error {
	if err := os.MkdirAll(versionStore.KeysDir(versionID), 0755); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(versionStore.CertsDir(versionID), 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}
	return nil
}

// initializeCAForProfile initializes a CA based on the profile type.
func initializeCAForProfile(prof *profile.Profile, currentCerts map[string]*CertRef, profileStore, rootStore *FileStore, passphrase string) (*CA, error) {
	algoFamily := prof.GetAlgorithmFamily()
	algorithm := prof.GetAlgorithm()

	cn := getSubjectCN(currentCerts, algoFamily)
	validityYears := int(prof.Validity.Hours() / 24 / 365)

	if prof.IsCatalyst() {
		return initializeCatalystCA(prof, cn, validityYears, passphrase, profileStore, rootStore)
	}
	if prof.IsComposite() {
		return initializeCompositeCA(prof, cn, validityYears, passphrase, profileStore, rootStore)
	}
	if algorithm.IsPQC() {
		return initializePQCCA(algorithm, cn, validityYears, passphrase, profileStore, rootStore)
	}
	return initializeClassicalCA(prof, algorithm, cn, validityYears, passphrase, profileStore, rootStore)
}

// getSubjectCN gets the subject CN from current certs or generates a default.
func getSubjectCN(currentCerts map[string]*CertRef, algoFamily string) string {
	if certRef, ok := currentCerts[algoFamily]; ok && certRef.Subject != "" {
		return certRef.Subject
	}
	return "CA " + algoFamily
}

// initializeCatalystCA initializes a Catalyst (hybrid) CA.
func initializeCatalystCA(prof *profile.Profile, cn string, validityYears int, passphrase string, profileStore, rootStore *FileStore) (*CA, error) {
	cfg := HybridCAConfig{
		CommonName:         cn,
		ClassicalAlgorithm: prof.Algorithms[0],
		PQCAlgorithm:       prof.Algorithms[1],
		ValidityYears:      validityYears,
		Passphrase:         passphrase,
	}
	return initializeHybridInStore(profileStore, rootStore, cfg)
}

// initializeCompositeCA initializes a Composite CA.
func initializeCompositeCA(prof *profile.Profile, cn string, validityYears int, passphrase string, profileStore, rootStore *FileStore) (*CA, error) {
	cfg := CompositeCAConfig{
		CommonName:         cn,
		ClassicalAlgorithm: prof.Algorithms[0],
		PQCAlgorithm:       prof.Algorithms[1],
		ValidityYears:      validityYears,
		Passphrase:         passphrase,
	}
	compAlg, err := GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported composite algorithm: %w", err)
	}
	return initializeCompositeInStore(profileStore, rootStore, cfg, compAlg)
}

// initializePQCCA initializes a PQC CA.
func initializePQCCA(algorithm pkicrypto.AlgorithmID, cn string, validityYears int, passphrase string, profileStore, rootStore *FileStore) (*CA, error) {
	cfg := PQCCAConfig{
		CommonName:    cn,
		Algorithm:     algorithm,
		ValidityYears: validityYears,
		Passphrase:    passphrase,
	}
	return initializePQCInStore(profileStore, rootStore, cfg)
}

// initializeClassicalCA initializes a classical CA.
func initializeClassicalCA(prof *profile.Profile, algorithm pkicrypto.AlgorithmID, cn string, validityYears int, passphrase string, profileStore, rootStore *FileStore) (*CA, error) {
	cfg := Config{
		CommonName:    cn,
		Algorithm:     algorithm,
		ValidityYears: validityYears,
		Passphrase:    passphrase,
		Profile:       prof.Name,
	}
	ca, _, _, err := initializeInStore(profileStore, rootStore, cfg)
	return ca, err
}

// addCertRefToVersion adds a certificate reference to the version store.
func addCertRefToVersion(versionStore *VersionStore, versionID string, prof *profile.Profile, ca *CA) error {
	cert := ca.Certificate()
	certRef := CertRef{
		Profile:         prof.Name,
		Algorithm:       string(prof.GetAlgorithm()),
		AlgorithmFamily: prof.GetAlgorithmFamily(),
		Subject:         cert.Subject.String(),
		Serial:          fmt.Sprintf("%X", cert.SerialNumber.Bytes()),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
	}
	if err := versionStore.AddCertificateRef(versionID, certRef); err != nil {
		return fmt.Errorf("failed to add certificate reference for %s: %w", prof.GetAlgorithmFamily(), err)
	}
	return nil
}

// crossSignIfRequested performs cross-signing if requested and a current CA exists.
func crossSignIfRequested(currentCAs map[string]*CA, newCA *CA, algoFamily, versionDir string, doCrossSign bool) (*x509.Certificate, error) {
	if !doCrossSign || currentCAs == nil {
		return nil, nil
	}
	currentCA, ok := currentCAs[algoFamily]
	if !ok {
		return nil, nil
	}

	crossSignedCert, err := crossSign(currentCA, newCA)
	if err != nil {
		return nil, fmt.Errorf("failed to cross-sign for %s: %w", algoFamily, err)
	}

	crossSignPath := filepath.Join(versionDir, "cross-signed", "by-previous.crt")
	if err := saveCrossSignedCert(crossSignPath, crossSignedCert); err != nil {
		return nil, fmt.Errorf("failed to save cross-signed cert for %s: %w", algoFamily, err)
	}

	return crossSignedCert, nil
}

// finalizeRotation updates metadata and logs the rotation.
func finalizeRotation(versionStore *VersionStore, versionID, caDir string, profileNames []string, crossSignedCerts map[string]*x509.Certificate) error {
	if len(crossSignedCerts) > 0 {
		if err := versionStore.AddCrossSignedBy(versionID, "previous"); err != nil {
			return err
		}
	}
	return audit.LogCARotated(caDir, versionID, strings.Join(profileNames, ", "), len(crossSignedCerts) > 0)
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

// addKeyRefsToVersionMulti adds key references to the root CAInfo for multi-profile rotation.
func addKeyRefsToVersionMulti(caDir string, versionID string, prof *profile.Profile, newCA *CA) error {
	// Load CAInfo from root CA directory
	info, err := LoadCAInfo(caDir)
	if err != nil || info == nil {
		return fmt.Errorf("failed to load CA info: %w", err)
	}

	// If newCA has keyRefs (from HSM initialization), use those
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
