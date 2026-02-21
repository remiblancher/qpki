package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"

	"github.com/remiblancher/qpki/pkg/ca"
	"github.com/remiblancher/qpki/pkg/credential"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/profile"
)

// configureHSMKeyProvider configures the CA with an HSM key provider if HSM config is specified.
func configureHSMKeyProvider(caInstance *ca.CA, hsmConfigPath, keyLabel string) error {
	if hsmConfigPath == "" {
		return nil
	}

	hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	keyCfg := pkicrypto.KeyStorageConfig{
		Type:           pkicrypto.KeyProviderTypePKCS11,
		PKCS11Lib:      hsmCfg.PKCS11.Lib,
		PKCS11Token:    hsmCfg.PKCS11.Token,
		PKCS11Slot:     hsmCfg.PKCS11.Slot,
		PKCS11Pin:      pin,
		PKCS11KeyLabel: keyLabel,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	caInstance.SetKeyProvider(km, keyCfg)

	return nil
}

// loadEnrollProfiles loads profiles from profile names or file paths.
func loadEnrollProfiles(caDir string, profileNames []string) ([]*profile.Profile, error) {
	// Load profile store
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return nil, fmt.Errorf("failed to load profiles: %w", err)
	}

	profiles := make([]*profile.Profile, 0, len(profileNames))
	for _, name := range profileNames {
		var prof *profile.Profile
		var err error

		// Check if it's a file path (contains path separator or ends with .yaml/.yml)
		if strings.Contains(name, string(os.PathSeparator)) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			prof, err = profile.LoadProfile(name)
			if err != nil {
				return nil, fmt.Errorf("failed to load profile from path %s: %w", name, err)
			}
		} else {
			var ok bool
			prof, ok = profileStore.Get(name)
			if !ok {
				return nil, fmt.Errorf("profile not found: %s", name)
			}
		}
		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// resolveProfilesTemplates resolves template variables in profile extensions and validity.
func resolveProfilesTemplates(profiles []*profile.Profile, varValues profile.VariableValues) ([]*profile.Profile, error) {
	result := make([]*profile.Profile, len(profiles))
	copy(result, profiles)

	for i, prof := range profiles {
		profileCopy := *prof
		modified := false

		// Resolve extensions (SAN, CDP, AIA, CPS)
		resolvedExtensions, err := profile.ResolveProfileExtensions(prof, varValues)
		if err != nil {
			return nil, fmt.Errorf("profile %s extensions: %w", prof.Name, err)
		}
		if resolvedExtensions != nil {
			profileCopy.Extensions = resolvedExtensions
			modified = true
		}

		// Resolve validity template
		if prof.ValidityTemplate != "" {
			validity, err := profile.ResolveProfileValidity(prof, varValues)
			if err != nil {
				return nil, fmt.Errorf("profile %s validity: %w", prof.Name, err)
			}
			profileCopy.Validity = validity
			profileCopy.ValidityTemplate = "" // Mark as resolved
			modified = true
		}

		if modified {
			result[i] = &profileCopy
		}
	}

	return result, nil
}

// resolveProfilesToObjects resolves profile names to profile objects.
func resolveProfilesToObjects(profileStore *profile.FileStore, names []string) ([]*profile.Profile, error) {
	profiles := make([]*profile.Profile, 0, len(names))
	for _, pName := range names {
		prof, ok := profileStore.Get(pName)
		if !ok {
			return nil, fmt.Errorf("profile %q not found", pName)
		}
		profiles = append(profiles, prof)
	}
	return profiles, nil
}

// formatRotateKeyInfo returns a human-readable key info string for rotation.
func formatRotateKeyInfo(keepKeys, hsmEnabled bool) string {
	if keepKeys {
		return "existing keys"
	}
	if hsmEnabled {
		return "new keys (HSM)"
	}
	return "new keys"
}

// validateEnrollVariables validates variables against profile constraints.
func validateEnrollVariables(profiles []*profile.Profile, varValues profile.VariableValues) (profile.VariableValues, error) {
	if len(profiles) == 0 || len(profiles[0].Variables) == 0 {
		return varValues, nil
	}

	engine, err := profile.NewTemplateEngine(profiles[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create template engine: %w", err)
	}
	rendered, err := engine.Render(varValues)
	if err != nil {
		return nil, fmt.Errorf("variable validation failed: %w", err)
	}
	return rendered.ResolvedValues, nil
}

// executeEnrollment executes single or multi-profile enrollment.
func executeEnrollment(caInstance *ca.CA, subject pkix.Name, profiles []*profile.Profile) (*credential.EnrollmentResult, error) {
	req := credential.EnrollmentRequest{Subject: subject}

	if len(profiles) == 1 {
		return credential.EnrollWithProfile(caInstance, req, profiles[0])
	}
	return credential.EnrollMulti(caInstance, req, profiles)
}

// printEnrollmentSuccess prints the enrollment success message.
func printEnrollmentSuccess(result *credential.EnrollmentResult, hsmConfig string) {
	fmt.Println("Credential created successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", result.Credential.ID)
	fmt.Printf("Subject:   %s\n", result.Credential.Subject.CommonName)

	activeVer := result.Credential.ActiveVersion()
	if activeVer != nil {
		fmt.Printf("Profiles:  %s\n", strings.Join(activeVer.Profiles, ", "))
		fmt.Printf("Valid:     %s to %s\n",
			activeVer.NotBefore.Format("2006-01-02"),
			activeVer.NotAfter.Format("2006-01-02"))
	}
	if hsmConfig != "" {
		fmt.Printf("Storage:   HSM (PKCS#11)\n")
	}
	fmt.Println()

	fmt.Printf("Certificates issued: %d\n", len(result.Certificates))
	for i, cert := range result.Certificates {
		fmt.Printf("  [%d] Serial: %X\n", i+1, cert.SerialNumber.Bytes())
		if len(result.StorageRefs) > i && result.StorageRefs[i].Type == "pkcs11" {
			fmt.Printf("      Key:     HSM label=%s\n", result.StorageRefs[i].Label)
		}
	}
}

// prepareEnrollVariablesAndProfiles loads variables and profiles for enrollment.
func prepareEnrollVariablesAndProfiles(caDir string, profileNames []string, varFile string, vars []string) ([]*profile.Profile, pkix.Name, error) {
	profiles, err := loadEnrollProfiles(caDir, profileNames)
	if err != nil {
		return nil, pkix.Name{}, err
	}

	varValues, err := profile.LoadVariables(varFile, vars)
	if err != nil {
		return nil, pkix.Name{}, fmt.Errorf("failed to load variables: %w", err)
	}

	varValues, err = validateEnrollVariables(profiles, varValues)
	if err != nil {
		return nil, pkix.Name{}, err
	}

	// Use first profile for subject defaults (if any)
	var firstProfile *profile.Profile
	if len(profiles) > 0 {
		firstProfile = profiles[0]
	}
	subject, err := profile.BuildSubjectFromProfile(firstProfile, varValues)
	if err != nil {
		return nil, pkix.Name{}, fmt.Errorf("invalid subject: %w", err)
	}

	profiles, err = resolveProfilesTemplates(profiles, varValues)
	if err != nil {
		return nil, pkix.Name{}, err
	}

	return profiles, subject, nil
}

// Unused import fix - ensure x509 is used
var _ *x509.Certificate
