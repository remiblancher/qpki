package credential

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// MultiProfileEnrollRequest holds parameters for multi-profile versioned enrollment.
type MultiProfileEnrollRequest struct {
	// Subject is the certificate subject.
	Subject pkix.Name

	// Profiles are the profiles to use (one certificate per profile).
	Profiles []*profile.Profile

	// DNSNames are optional DNS SANs.
	DNSNames []string

	// EmailAddresses are optional email SANs.
	EmailAddresses []string

	// Passphrase for encrypting private keys.
	Passphrase []byte

	// CredentialStore to save the credential.
	CredentialStore Store

	// AutoActivate activates the credential immediately (default: false = PENDING).
	AutoActivate bool
}

// MultiProfileEnrollResult holds the result of a multi-profile enrollment.
type MultiProfileEnrollResult struct {
	// Credential is the created credential.
	Credential *Credential

	// Version is the created version.
	Version *Version

	// Certificates are the issued certificates (one per profile).
	Certificates []*x509.Certificate

	// Signers are the generated private key signers.
	Signers []pkicrypto.Signer

	// StorageRefs describes where each key is stored.
	StorageRefs []pkicrypto.StorageRef
}

// EnrollmentRequest holds the parameters for enrolling with a profile.
type EnrollmentRequest struct {
	// Subject is the certificate subject.
	Subject pkix.Name

	// ProfileName is the name of the profile to use.
	ProfileName string

	// DNSNames are optional DNS SANs.
	DNSNames []string

	// EmailAddresses are optional email SANs.
	EmailAddresses []string
}

// EnrollmentResult holds the result of an enrollment.
type EnrollmentResult struct {
	// Credential is the created credential.
	Credential *Credential

	// Certificates are the issued certificates.
	Certificates []*x509.Certificate

	// Signers are the generated private key signers.
	Signers []pkicrypto.Signer

	// StorageRefs describes where each key is stored (matches Signers order).
	// For software keys: path is filled by FileStore.Save().
	// For HSM keys: contains PKCS#11 config, label, and key ID.
	StorageRefs []pkicrypto.StorageRef
}

// Enroll creates a certificate according to a single profile.
// Design: 1 profile = 1 certificate.
// For credentials with multiple certificates, use EnrollMulti.
func Enroll(caInstance *ca.CA, req EnrollmentRequest, profileStore profile.Store) (*EnrollmentResult, error) {
	if caInstance.Signer() == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Load profile
	prof, ok := profileStore.Get(req.ProfileName)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", req.ProfileName)
	}

	return EnrollWithProfile(caInstance, req, prof)
}

// EnrollWithProfile creates a certificate with the given profile.
func EnrollWithProfile(caInstance *ca.CA, req EnrollmentRequest, prof *profile.Profile) (*EnrollmentResult, error) {
	if caInstance.Signer() == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Create credential ID
	credentialID := GenerateCredentialID(req.Subject.CommonName)

	// Create credential
	cred := NewCredential(credentialID, SubjectFromPkixName(req.Subject))

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(prof.Validity)

	// Create initial version with validity
	algo := profileAlgoFamily(prof)
	cred.CreateInitialVersion([]string{prof.Name}, []string{algo})
	ver := cred.Versions[cred.Active]
	ver.NotBefore = notBefore
	ver.NotAfter = notAfter
	cred.Versions[cred.Active] = ver

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Issue certificate based on mode
	var cert *x509.Certificate
	var signers []pkicrypto.Signer
	var storageRefs []pkicrypto.StorageRef
	var err error
	keyIndex := 0

	if prof.IsCatalyst() {
		cert, signers, storageRefs, err = issueCatalystCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
	} else if prof.IsComposite() {
		cert, signers, storageRefs, err = issueCompositeCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
	} else {
		var signer pkicrypto.Signer
		var storageRef pkicrypto.StorageRef
		cert, signer, storageRef, err = issueSimpleCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
		if signer != nil {
			signers = []pkicrypto.Signer{signer}
			storageRefs = []pkicrypto.StorageRef{storageRef}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	result.Certificates = append(result.Certificates, cert)
	result.Signers = append(result.Signers, signers...)
	result.StorageRefs = append(result.StorageRefs, storageRefs...)

	return result, nil
}

// EnrollWithCompiledProfile creates a certificate using a pre-compiled profile.
// This is optimized for high-throughput scenarios where profiles are pre-compiled
// at startup, avoiding per-certificate parsing overhead.
func EnrollWithCompiledProfile(caInstance *ca.CA, req EnrollmentRequest, cp *profile.CompiledProfile) (*EnrollmentResult, error) {
	if caInstance.Signer() == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Create credential ID
	credentialID := GenerateCredentialID(req.Subject.CommonName)

	// Create credential
	cred := NewCredential(credentialID, SubjectFromPkixName(req.Subject))

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(cp.Validity)

	// Create initial version with validity
	algo := compiledProfileAlgoFamily(cp)
	cred.CreateInitialVersion([]string{cp.Name}, []string{algo})
	ver := cred.Versions[cred.Active]
	ver.NotBefore = notBefore
	ver.NotAfter = notAfter
	cred.Versions[cred.Active] = ver

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Issue certificate using compiled profile
	var cert *x509.Certificate
	var signers []pkicrypto.Signer
	var storageRefs []pkicrypto.StorageRef
	var err error
	keyIndex := 0

	if cp.IsCatalyst() {
		cert, signers, storageRefs, err = issueCatalystCertFromCompiledProfile(caInstance, req, cp, notBefore, notAfter, credentialID, keyIndex)
	} else if cp.IsComposite() {
		cert, signers, storageRefs, err = issueCompositeCertFromCompiledProfile(caInstance, req, cp, notBefore, notAfter, credentialID, keyIndex)
	} else {
		var signer pkicrypto.Signer
		var storageRef pkicrypto.StorageRef
		cert, signer, storageRef, err = issueSimpleCertFromCompiledProfile(caInstance, req, cp, notBefore, notAfter, credentialID, keyIndex)
		if signer != nil {
			signers = []pkicrypto.Signer{signer}
			storageRefs = []pkicrypto.StorageRef{storageRef}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	result.Certificates = append(result.Certificates, cert)
	result.Signers = append(result.Signers, signers...)
	result.StorageRefs = append(result.StorageRefs, storageRefs...)

	return result, nil
}

// issueSimpleCertFromCompiledProfile issues a simple certificate using a pre-compiled profile.
// Extensions are already parsed, avoiding runtime parsing overhead.
func issueSimpleCertFromCompiledProfile(caInstance *ca.CA, req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, pkicrypto.Signer, pkicrypto.StorageRef, error) {
	alg := cp.GetAlgorithm()

	// Generate key pair using KeyProvider
	signer, storageRef, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), alg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, fmt.Errorf("failed to generate key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := caInstance.Issue(context.Background(), ca.IssueRequest{
		Template:  template,
		PublicKey: signer.Public(),
		Validity:  cp.Validity,
	})
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, err
	}

	return cert, signer, storageRef, nil
}

// issueCatalystCertFromCompiledProfile issues a Catalyst certificate using a pre-compiled profile.
func issueCatalystCertFromCompiledProfile(caInstance *ca.CA, req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !cp.IsCatalyst() || len(cp.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := cp.Algorithms[0]
	pqcAlg := cp.Algorithms[1]

	// Generate classical key pair using KeyProvider
	classicalSigner, classicalStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyProvider
	pqcSigner, pqcStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := caInstance.IssueCatalyst(context.Background(), ca.CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		PQCAlgorithm:       pqcAlg,
		Validity:           cp.Validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, []pkicrypto.StorageRef{classicalStorage, pqcStorage}, nil
}

// issueCompositeCertFromCompiledProfile issues a Composite certificate using a pre-compiled profile.
func issueCompositeCertFromCompiledProfile(caInstance *ca.CA, req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !cp.IsComposite() || len(cp.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid composite profile: requires exactly 2 algorithms")
	}

	classicalAlg := cp.Algorithms[0]
	pqcAlg := cp.Algorithms[1]

	// Generate classical key pair using KeyProvider
	classicalSigner, classicalStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyProvider
	pqcSigner, pqcStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := caInstance.IssueComposite(ca.CompositeRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       classicalAlg,
		PQCAlg:             pqcAlg,
		Validity:           cp.Validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, []pkicrypto.StorageRef{classicalStorage, pqcStorage}, nil
}

// EnrollMulti creates a credential with multiple certificates from multiple profiles.
// This is the main enrollment function for creating credentials.
// Profiles are processed in order. For KEM certificates, a signature
// certificate must be issued first (per RFC 9883).
func EnrollMulti(caInstance *ca.CA, req EnrollmentRequest, profiles []*profile.Profile) (*EnrollmentResult, error) {
	if caInstance.Signer() == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Create credential ID
	credentialID := GenerateCredentialID(req.Subject.CommonName)

	// Build profile names and collect algorithm families
	profileNames := make([]string, len(profiles))
	algoFamilies := make(map[string]bool)
	for i, p := range profiles {
		profileNames[i] = p.Name
		algoFamilies[profileAlgoFamily(p)] = true
	}
	algos := make([]string, 0, len(algoFamilies))
	for algo := range algoFamilies {
		algos = append(algos, algo)
	}

	// Create credential
	cred := NewCredential(credentialID, SubjectFromPkixName(req.Subject))

	// Determine validity from first profile
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(profiles[0].Validity)

	// Create initial version with validity
	cred.CreateInitialVersion(profileNames, algos)
	ver := cred.Versions[cred.Active]
	ver.NotBefore = notBefore
	ver.NotAfter = notAfter
	cred.Versions[cred.Active] = ver

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Track first signature certificate for KEM attestation
	var sigCert *x509.Certificate
	keyIndex := 0

	for _, prof := range profiles {
		// KEM requires a signature certificate first (RFC 9883)
		if prof.IsKEM() && sigCert == nil {
			return nil, fmt.Errorf("KEM profile %q requires a signature profile first (RFC 9883)", prof.Name)
		}

		// Issue certificate
		var cert *x509.Certificate
		var signers []pkicrypto.Signer
		var storageRefs []pkicrypto.StorageRef
		var err error

		if prof.IsCatalyst() {
			cert, signers, storageRefs, err = issueCatalystCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2 // Catalyst uses 2 keys
		} else if prof.IsComposite() {
			cert, signers, storageRefs, err = issueCompositeCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2 // Composite uses 2 keys
		} else {
			var signer pkicrypto.Signer
			var storageRef pkicrypto.StorageRef
			cert, signer, storageRef, err = issueSimpleCertFromProfile(caInstance, req, prof, notBefore, notAfter, credentialID, keyIndex)
			if signer != nil {
				signers = []pkicrypto.Signer{signer}
				storageRefs = []pkicrypto.StorageRef{storageRef}
			}
			keyIndex++
		}

		if err != nil {
			return nil, fmt.Errorf("failed to issue certificate for profile %q: %w", prof.Name, err)
		}

		// Track first signature certificate
		if sigCert == nil && prof.IsSignature() {
			sigCert = cert
		}

		result.Certificates = append(result.Certificates, cert)
		result.Signers = append(result.Signers, signers...)
		result.StorageRefs = append(result.StorageRefs, storageRefs...)
	}

	return result, nil
}

// EnrollMultiProfileVersioned creates a versioned credential with multiple certificates.
// Each profile results in a separate certificate, stored in version directories by algorithm family.
func EnrollMultiProfileVersioned(caInstance *ca.CA, req MultiProfileEnrollRequest) (*MultiProfileEnrollResult, error) {
	if caInstance.Signer() == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	if len(req.Profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	if req.CredentialStore == nil {
		return nil, fmt.Errorf("credential store is required")
	}

	// Create credential ID
	credentialID := GenerateCredentialID(req.Subject.CommonName)

	// Build profile names and collect algorithm families
	profileNames := make([]string, len(req.Profiles))
	algoFamilies := make(map[string]bool)
	for i, p := range req.Profiles {
		profileNames[i] = p.Name
		algoFamilies[profileAlgoFamily(p)] = true
	}
	algos := make([]string, 0, len(algoFamilies))
	for algo := range algoFamilies {
		algos = append(algos, algo)
	}

	// Create credential
	cred := NewCredential(credentialID, SubjectFromPkixName(req.Subject))

	// Determine validity from first profile
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(req.Profiles[0].Validity)

	// Create initial version with validity
	cred.CreateInitialVersion(profileNames, algos)
	ver := cred.Versions[cred.Active]
	ver.NotBefore = notBefore
	ver.NotAfter = notAfter
	cred.Versions[cred.Active] = ver

	// Set base path for credential
	credDir := CredentialPath(req.CredentialStore.BasePath(), credentialID)
	cred.SetBasePath(credDir)

	result := &MultiProfileEnrollResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0, len(req.Profiles)),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Track first signature certificate for KEM attestation
	var sigCert *x509.Certificate
	keyIndex := 0

	enrollReq := EnrollmentRequest{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
	}

	for _, prof := range req.Profiles {
		// KEM requires a signature certificate first (RFC 9883)
		if prof.IsKEM() && sigCert == nil {
			return nil, fmt.Errorf("KEM profile %q requires a signature profile first (RFC 9883)", prof.Name)
		}

		// Issue certificate
		var cert *x509.Certificate
		var signers []pkicrypto.Signer
		var storageRefs []pkicrypto.StorageRef
		var issueErr error

		if prof.IsCatalyst() {
			cert, signers, storageRefs, issueErr = issueCatalystCertFromProfile(caInstance, enrollReq, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2
		} else if prof.IsComposite() {
			cert, signers, storageRefs, issueErr = issueCompositeCertFromProfile(caInstance, enrollReq, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2
		} else {
			var signer pkicrypto.Signer
			var storageRef pkicrypto.StorageRef
			cert, signer, storageRef, issueErr = issueSimpleCertFromProfile(caInstance, enrollReq, prof, notBefore, notAfter, credentialID, keyIndex)
			if signer != nil {
				signers = []pkicrypto.Signer{signer}
				storageRefs = []pkicrypto.StorageRef{storageRef}
			}
			keyIndex++
		}

		if issueErr != nil {
			return nil, fmt.Errorf("failed to issue certificate for profile %q: %w", prof.Name, issueErr)
		}

		// Track first signature certificate
		if sigCert == nil && prof.IsSignature() {
			sigCert = cert
		}

		result.Certificates = append(result.Certificates, cert)
		result.Signers = append(result.Signers, signers...)
		result.StorageRefs = append(result.StorageRefs, storageRefs...)

		// Get algorithm family and save to version directory
		algoFamily := profileAlgoFamily(prof)
		if err := SaveVersion(req.CredentialStore.BasePath(), credentialID, cred.Active, algoFamily,
			[]*x509.Certificate{cert}, signers, req.Passphrase); err != nil {
			return nil, fmt.Errorf("failed to save version files for %s: %w", algoFamily, err)
		}
	}

	// Save credential metadata
	if err := cred.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	return result, nil
}

// issueSimpleCertFromProfile issues a simple certificate from a profile.
func issueSimpleCertFromProfile(caInstance *ca.CA, req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, pkicrypto.Signer, pkicrypto.StorageRef, error) {
	alg := prof.GetAlgorithm()

	// Generate key pair using KeyProvider
	signer, storageRef, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), alg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.Certificate{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	cert, err := caInstance.Issue(context.Background(), ca.IssueRequest{
		Template:   template,
		PublicKey:  signer.Public(),
		Extensions: prof.Extensions,
		Validity:   prof.Validity,
	})
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, err
	}

	return cert, signer, storageRef, nil
}

// issueCatalystCertFromProfile issues a Catalyst certificate from a profile.
func issueCatalystCertFromProfile(caInstance *ca.CA, req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !prof.IsCatalyst() || len(prof.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate classical key pair using KeyProvider
	classicalSigner, classicalStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyProvider
	pqcSigner, pqcStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	template := &x509.Certificate{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	cert, err := caInstance.IssueCatalyst(context.Background(), ca.CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		PQCAlgorithm:       pqcAlg,
		Extensions:         prof.Extensions,
		Validity:           prof.Validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Return both signers and storage refs for Catalyst
	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, []pkicrypto.StorageRef{classicalStorage, pqcStorage}, nil
}

// issueCompositeCertFromProfile issues an IETF Composite certificate from a profile.
func issueCompositeCertFromProfile(caInstance *ca.CA, req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !prof.IsComposite() || len(prof.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid composite profile: requires exactly 2 algorithms")
	}

	// Compile profile to get parsed extensions
	cp, err := prof.Compile()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compile profile: %w", err)
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate classical key pair using KeyProvider
	classicalSigner, classicalStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyProvider
	pqcSigner, pqcStorage, err := GenerateKey(caInstance.KeyProvider(), caInstance.KeyStorageConfig(), pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := caInstance.IssueComposite(ca.CompositeRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       classicalAlg,
		PQCAlg:             pqcAlg,
		Validity:           prof.Validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Return both signers and storage refs for Composite
	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, []pkicrypto.StorageRef{classicalStorage, pqcStorage}, nil
}

// profileAlgoFamily extracts the algorithm family from a profile.
func profileAlgoFamily(p *profile.Profile) string {
	alg := p.GetAlgorithm()
	return alg.Family()
}

// compiledProfileAlgoFamily extracts the algorithm family from a compiled profile.
func compiledProfileAlgoFamily(cp *profile.CompiledProfile) string {
	alg := cp.GetAlgorithm()
	return alg.Family()
}

// GetProfileAlgoFamily returns the algorithm family for a profile.
// This is used to group certificates by cryptosystem in version directories.
func GetProfileAlgoFamily(prof *profile.Profile) string {
	alg := prof.GetAlgorithm()

	// Map algorithm to family
	algStr := strings.ToLower(string(alg))

	switch {
	case strings.HasPrefix(algStr, "ecdsa") || strings.HasPrefix(algStr, "ec-"):
		return "ec"
	case strings.HasPrefix(algStr, "rsa"):
		return "rsa"
	case strings.HasPrefix(algStr, "ed25519") || strings.HasPrefix(algStr, "ed448"):
		return "ed"
	case strings.HasPrefix(algStr, "ml-dsa") || strings.HasPrefix(algStr, "mldsa"):
		return "ml-dsa"
	case strings.HasPrefix(algStr, "slh-dsa") || strings.HasPrefix(algStr, "slhdsa"):
		return "slh-dsa"
	case strings.HasPrefix(algStr, "ml-kem") || strings.HasPrefix(algStr, "mlkem"):
		return "ml-kem"
	case strings.HasPrefix(algStr, "hybrid"):
		return "hybrid"
	default:
		// Use first part of algorithm name as family
		parts := strings.Split(algStr, "-")
		if len(parts) > 0 {
			return parts[0]
		}
		return "unknown"
	}
}
