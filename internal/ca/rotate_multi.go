package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
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
		for _, certRef := range currentCerts {
			// Load CA from the version directory
			versionDir := versionStore.VersionDir(versionStore.getActiveVersionID())
			store := NewFileStore(versionDir)
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

	// Create version directory structure (keys/ and certs/)
	keysDir := versionStore.KeysDir(version.ID)
	certsDir := versionStore.CertsDir(version.ID)
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	versionDir := versionStore.VersionDir(version.ID)
	profileStore := NewFileStore(versionDir)

	// Get root store for serial numbers
	rootStore := NewFileStore(req.CADir)

	// Create certificates for each profile
	for _, prof := range req.Profiles {
		algoFamily := prof.GetAlgorithmFamily()
		algorithm := prof.GetAlgorithm()

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

		// Initialize CA based on profile type using the new refactored functions
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
			newCA, err = initializeHybridInStore(profileStore, rootStore, cfg)
		} else if prof.IsComposite() {
			cfg := CompositeCAConfig{
				CommonName:         cn,
				Organization:       org,
				Country:            country,
				ClassicalAlgorithm: prof.Algorithms[0],
				PQCAlgorithm:       prof.Algorithms[1],
				ValidityYears:      int(prof.Validity.Hours() / 24 / 365),
				PathLen:            pathLen,
				Passphrase:         req.Passphrase,
			}
			var compAlg *CompositeAlgorithm
			compAlg, err = GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("unsupported composite algorithm: %w", err)
			}
			newCA, err = initializeCompositeInStore(profileStore, rootStore, cfg, compAlg)
		} else if algorithm.IsPQC() {
			cfg := PQCCAConfig{
				CommonName:    cn,
				Organization:  org,
				Country:       country,
				Algorithm:     algorithm,
				ValidityYears: int(prof.Validity.Hours() / 24 / 365),
				PathLen:       pathLen,
				Passphrase:    req.Passphrase,
			}
			newCA, err = initializePQCInStore(profileStore, rootStore, cfg)
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
			newCA, _, _, err = initializeInStore(profileStore, rootStore, cfg)
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
			crossSignPath := filepath.Join(versionDir, "cross-signed", "by-previous.crt")
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
