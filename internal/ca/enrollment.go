package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// KeyRotationMode controls key handling during credential rotation.
type KeyRotationMode int

const (
	// KeyRotateNew generates new keys (default, recommended for crypto-agility).
	KeyRotateNew KeyRotationMode = iota

	// KeyRotateKeep reuses existing keys (only for certificate renewal).
	KeyRotateKeep
)

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
	Credential *credential.Credential

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
func (ca *CA) Enroll(req EnrollmentRequest, profileStore *profile.ProfileStore) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Load profile
	prof, ok := profileStore.Get(req.ProfileName)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", req.ProfileName)
	}

	return ca.EnrollWithProfile(req, prof)
}

// EnrollWithProfile creates a certificate with the given profile.
func (ca *CA) EnrollWithProfile(req EnrollmentRequest, prof *profile.Profile) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Create credential ID
	credentialID := generateCredentialID(req.Subject.CommonName)

	// Create credential
	cred := credential.NewCredential(credentialID, credential.SubjectFromPkixName(req.Subject), []string{prof.Name})

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(prof.Validity)
	cred.SetValidity(notBefore, notAfter)

	// Issue certificate based on mode
	var cert *x509.Certificate
	var signers []pkicrypto.Signer
	var storageRefs []pkicrypto.StorageRef
	var err error
	keyIndex := 0

	if prof.IsCatalyst() {
		cert, signers, storageRefs, err = ca.issueCatalystCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
	} else if prof.IsComposite() {
		cert, signers, storageRefs, err = ca.issueCompositeCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
	} else {
		var signer pkicrypto.Signer
		var storageRef pkicrypto.StorageRef
		cert, signer, storageRef, err = ca.issueSimpleCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
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

	// Add to credential with storage refs
	role := credential.RoleSignature
	if prof.IsKEM() {
		role = credential.RoleEncryption
	}
	altAlg := ""
	if prof.IsCatalyst() {
		altAlg = string(prof.GetAlternativeAlgorithm())
	}
	ref := credential.CertificateRefFromCert(cert, role, prof.IsCatalyst(), altAlg, storageRefs...)
	ref.Profile = prof.Name
	cred.AddCertificate(ref)

	// Activate credential
	cred.Activate()

	return result, nil
}

// EnrollWithCompiledProfile creates a certificate using a pre-compiled profile.
// This is optimized for high-throughput scenarios where profiles are pre-compiled
// at startup, avoiding per-certificate parsing overhead.
func (ca *CA) EnrollWithCompiledProfile(req EnrollmentRequest, cp *profile.CompiledProfile) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Create credential ID
	credentialID := generateCredentialID(req.Subject.CommonName)

	// Create credential
	cred := credential.NewCredential(credentialID, credential.SubjectFromPkixName(req.Subject), []string{cp.Profile.Name})

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(cp.Profile.Validity)
	cred.SetValidity(notBefore, notAfter)

	// Issue certificate using compiled profile
	var cert *x509.Certificate
	var signers []pkicrypto.Signer
	var storageRefs []pkicrypto.StorageRef
	var err error
	keyIndex := 0

	if cp.Profile.IsCatalyst() {
		cert, signers, storageRefs, err = ca.issueCatalystCertFromCompiledProfile(req, cp, notBefore, notAfter, credentialID, keyIndex)
	} else if cp.Profile.IsComposite() {
		cert, signers, storageRefs, err = ca.issueCompositeCertFromCompiledProfile(req, cp, notBefore, notAfter, credentialID, keyIndex)
	} else {
		var signer pkicrypto.Signer
		var storageRef pkicrypto.StorageRef
		cert, signer, storageRef, err = ca.issueSimpleCertFromCompiledProfile(req, cp, notBefore, notAfter, credentialID, keyIndex)
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

	// Add to credential with storage refs
	role := credential.RoleSignature
	if cp.Profile.IsKEM() {
		role = credential.RoleEncryption
	}
	altAlg := ""
	if cp.Profile.IsCatalyst() {
		altAlg = string(cp.Profile.GetAlternativeAlgorithm())
	}
	ref := credential.CertificateRefFromCert(cert, role, cp.Profile.IsCatalyst(), altAlg, storageRefs...)
	ref.Profile = cp.Profile.Name
	cred.AddCertificate(ref)

	// Activate credential
	cred.Activate()

	return result, nil
}

// issueSimpleCertFromCompiledProfile issues a simple certificate using a pre-compiled profile.
// Extensions are already parsed, avoiding runtime parsing overhead.
func (ca *CA) issueSimpleCertFromCompiledProfile(req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, pkicrypto.Signer, pkicrypto.StorageRef, error) {
	alg := cp.Profile.GetAlgorithm()

	// Generate key pair using KeyManager
	signer, storageRef, err := ca.GenerateCredentialKey(alg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, fmt.Errorf("failed to generate key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: signer.Public(),
		Validity:  cp.Profile.Validity,
	})
	if err != nil {
		return nil, nil, pkicrypto.StorageRef{}, err
	}

	return cert, signer, storageRef, nil
}

// issueCatalystCertFromCompiledProfile issues a Catalyst certificate using a pre-compiled profile.
func (ca *CA) issueCatalystCertFromCompiledProfile(req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !cp.Profile.IsCatalyst() || len(cp.Profile.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := cp.Profile.Algorithms[0]
	pqcAlg := cp.Profile.Algorithms[1]

	// Generate classical key pair using KeyManager
	classicalSigner, classicalStorage, err := ca.GenerateCredentialKey(classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyManager
	pqcSigner, pqcStorage, err := ca.GenerateCredentialKey(pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := ca.IssueCatalyst(CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		PQCAlgorithm:       pqcAlg,
		Validity:           cp.Profile.Validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, []pkicrypto.StorageRef{classicalStorage, pqcStorage}, nil
}

// issueCompositeCertFromCompiledProfile issues a Composite certificate using a pre-compiled profile.
func (ca *CA) issueCompositeCertFromCompiledProfile(req EnrollmentRequest, cp *profile.CompiledProfile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !cp.Profile.IsComposite() || len(cp.Profile.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid composite profile: requires exactly 2 algorithms")
	}

	classicalAlg := cp.Profile.Algorithms[0]
	pqcAlg := cp.Profile.Algorithms[1]

	// Generate classical key pair using KeyManager
	classicalSigner, classicalStorage, err := ca.GenerateCredentialKey(classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyManager
	pqcSigner, pqcStorage, err := ca.GenerateCredentialKey(pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := ca.IssueComposite(CompositeRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       classicalAlg,
		PQCAlg:             pqcAlg,
		Validity:           cp.Profile.Validity,
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
func (ca *CA) EnrollMulti(req EnrollmentRequest, profiles []*profile.Profile) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Create credential ID
	credentialID := generateCredentialID(req.Subject.CommonName)

	// Use first profile name for credential (could be enhanced to use all names)
	profileNames := make([]string, len(profiles))
	for i, p := range profiles {
		profileNames[i] = p.Name
	}

	// Create credential
	cred := credential.NewCredential(credentialID, credential.SubjectFromPkixName(req.Subject), profileNames)

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
		StorageRefs:  make([]pkicrypto.StorageRef, 0),
	}

	// Track first signature certificate for KEM attestation
	var sigCert *x509.Certificate
	var notBefore, notAfter time.Time
	keyIndex := 0

	for i, prof := range profiles {
		// Use validity from first profile for all (could be enhanced)
		if i == 0 {
			notBefore = time.Now().UTC()
			notAfter = notBefore.Add(prof.Validity)
			cred.SetValidity(notBefore, notAfter)
		}

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
			cert, signers, storageRefs, err = ca.issueCatalystCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2 // Catalyst uses 2 keys
		} else if prof.IsComposite() {
			cert, signers, storageRefs, err = ca.issueCompositeCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
			keyIndex += 2 // Composite uses 2 keys
		} else {
			var signer pkicrypto.Signer
			var storageRef pkicrypto.StorageRef
			cert, signer, storageRef, err = ca.issueSimpleCertFromProfile(req, prof, notBefore, notAfter, credentialID, keyIndex)
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

		// Add to credential with storage refs
		role := credential.RoleSignature
		if prof.IsKEM() {
			role = credential.RoleEncryption
		}
		altAlg := ""
		if prof.IsCatalyst() {
			altAlg = string(prof.GetAlternativeAlgorithm())
		}
		ref := credential.CertificateRefFromCert(cert, role, prof.IsCatalyst(), altAlg, storageRefs...)
		ref.Profile = prof.Name

		// Link to first signature certificate if this is encryption
		if prof.IsKEM() && sigCert != nil {
			ref.RelatedSerial = fmt.Sprintf("0x%X", sigCert.SerialNumber.Bytes())
		}

		cred.AddCertificate(ref)
	}

	// Activate credential
	cred.Activate()

	return result, nil
}

// issueSimpleCertFromProfile issues a simple certificate from a profile.
func (ca *CA) issueSimpleCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, pkicrypto.Signer, pkicrypto.StorageRef, error) {
	alg := prof.GetAlgorithm()

	// Generate key pair using KeyManager
	signer, storageRef, err := ca.GenerateCredentialKey(alg, credentialID, keyIndex)
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

	cert, err := ca.Issue(IssueRequest{
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
func (ca *CA) issueCatalystCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
	if !prof.IsCatalyst() || len(prof.Algorithms) != 2 {
		return nil, nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate classical key pair using KeyManager
	classicalSigner, classicalStorage, err := ca.GenerateCredentialKey(classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyManager
	pqcSigner, pqcStorage, err := ca.GenerateCredentialKey(pqcAlg, credentialID, keyIndex+1)
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

	cert, err := ca.IssueCatalyst(CatalystRequest{
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
func (ca *CA) issueCompositeCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, credentialID string, keyIndex int) (*x509.Certificate, []pkicrypto.Signer, []pkicrypto.StorageRef, error) {
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

	// Generate classical key pair using KeyManager
	classicalSigner, classicalStorage, err := ca.GenerateCredentialKey(classicalAlg, credentialID, keyIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair using KeyManager
	pqcSigner, pqcStorage, err := ca.GenerateCredentialKey(pqcAlg, credentialID, keyIndex+1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Use CompiledProfile.ApplyToTemplate for pre-parsed extensions
	template := cp.ApplyToTemplate(req.Subject, req.DNSNames, nil, req.EmailAddresses)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	cert, err := ca.IssueComposite(CompositeRequest{
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

// generateCredentialID generates a unique credential ID.
func generateCredentialID(commonName string) string {
	// Use a timestamp and random suffix
	timestamp := time.Now().Format("20060102-150405")

	// Generate a short random suffix
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)

	// Clean common name for use in ID
	cleanName := ""
	for _, c := range commonName {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			cleanName += string(c)
		}
	}
	if len(cleanName) > 16 {
		cleanName = cleanName[:16]
	}

	return fmt.Sprintf("%s-%s-%x", cleanName, timestamp, randBytes)
}

// RotateCredential rotates all certificates in a credential.
// keyMode controls whether to generate new keys (KeyRotateNew) or reuse existing (KeyRotateKeep).
// If newProfiles is provided, use those instead of existing profiles (crypto-agility).
func (ca *CA) RotateCredential(credentialID string, credentialStore *credential.FileStore, profileStore *profile.ProfileStore, passphrase []byte, keyMode KeyRotationMode, newProfiles []string) (*EnrollmentResult, error) {
	// Load existing credential
	existingCredential, err := credentialStore.Load(credentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential: %w", err)
	}

	// Use new profiles if provided (crypto-agility), otherwise use existing
	profileNames := existingCredential.Profiles
	if len(newProfiles) > 0 {
		profileNames = newProfiles
	}

	if len(profileNames) == 0 {
		return nil, fmt.Errorf("no profiles found in credential or provided")
	}

	// Load profiles
	profiles := make([]*profile.Profile, 0, len(profileNames))
	for _, name := range profileNames {
		prof, ok := profileStore.Get(name)
		if !ok {
			return nil, fmt.Errorf("profile not found: %s", name)
		}
		profiles = append(profiles, prof)
	}

	// Create new enrollment request from credential
	req := EnrollmentRequest{
		Subject: existingCredential.Subject.ToPkixName(),
	}

	var result *EnrollmentResult

	if keyMode == KeyRotateKeep {
		// Load existing keys to reuse
		existingSigners, err := credentialStore.LoadKeys(credentialID, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing keys: %w", err)
		}
		if len(existingSigners) == 0 {
			return nil, fmt.Errorf("no keys found in credential for --keep-keys")
		}

		// Issue new certificates with existing keys
		result, err = ca.rotateWithExistingKeys(req, profiles, existingSigners)
		if err != nil {
			return nil, fmt.Errorf("failed to rotate with existing keys: %w", err)
		}
	} else {
		// Generate new keys (default)
		if len(profiles) == 1 {
			result, err = ca.EnrollWithProfile(req, profiles[0])
		} else {
			result, err = ca.EnrollMulti(req, profiles)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to enroll: %w", err)
		}
	}

	// Save new credential
	if err := credentialStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	// Mark old credential as expired (non-fatal if it fails)
	_ = credentialStore.UpdateStatus(credentialID, credential.StatusExpired, "rotated")

	return result, nil
}

// rotateWithExistingKeys issues new certificates using existing signers.
// Used for certificate renewal when keeping the same keys.
func (ca *CA) rotateWithExistingKeys(req EnrollmentRequest, profiles []*profile.Profile, existingSigners []pkicrypto.Signer) (*EnrollmentResult, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Build algorithm -> signer map for matching
	signersByAlg := make(map[pkicrypto.AlgorithmID][]pkicrypto.Signer)
	for _, s := range existingSigners {
		alg := s.Algorithm()
		signersByAlg[alg] = append(signersByAlg[alg], s)
	}

	// Create credential ID
	credentialID := generateCredentialID(req.Subject.CommonName)

	// Build profile names
	profileNames := make([]string, len(profiles))
	for i, p := range profiles {
		profileNames[i] = p.Name
	}

	// Create credential
	cred := credential.NewCredential(credentialID, credential.SubjectFromPkixName(req.Subject), profileNames)

	result := &EnrollmentResult{
		Credential:   cred,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
	}

	// Track used signers to avoid reusing
	usedSignerIndex := make(map[pkicrypto.AlgorithmID]int)

	// Track first signature certificate for KEM attestation
	var sigCert *x509.Certificate
	var notBefore, notAfter time.Time

	for i, prof := range profiles {
		// Use validity from first profile
		if i == 0 {
			notBefore = time.Now().UTC()
			notAfter = notBefore.Add(prof.Validity)
			cred.SetValidity(notBefore, notAfter)
		}

		// KEM requires a signature certificate first (RFC 9883)
		if prof.IsKEM() && sigCert == nil {
			return nil, fmt.Errorf("KEM profile %q requires a signature profile first (RFC 9883)", prof.Name)
		}

		// Issue certificate with existing keys
		var cert *x509.Certificate
		var signers []pkicrypto.Signer
		var err error

		if prof.IsCatalyst() {
			cert, signers, err = ca.issueCatalystCertWithExistingKeys(req, prof, notBefore, notAfter, signersByAlg, usedSignerIndex)
		} else if prof.IsComposite() {
			cert, signers, err = ca.issueCompositeCertWithExistingKeys(req, prof, notBefore, notAfter, signersByAlg, usedSignerIndex)
		} else {
			var signer pkicrypto.Signer
			cert, signer, err = ca.issueSimpleCertWithExistingSigner(req, prof, notBefore, notAfter, signersByAlg, usedSignerIndex)
			if signer != nil {
				signers = []pkicrypto.Signer{signer}
			}
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

		// Add to credential
		role := credential.RoleSignature
		if prof.IsKEM() {
			role = credential.RoleEncryption
		}
		altAlg := ""
		if prof.IsCatalyst() {
			altAlg = string(prof.GetAlternativeAlgorithm())
		}
		ref := credential.CertificateRefFromCert(cert, role, prof.IsCatalyst(), altAlg)
		ref.Profile = prof.Name

		// Link to first signature certificate if this is encryption
		if prof.IsKEM() && sigCert != nil {
			ref.RelatedSerial = fmt.Sprintf("0x%X", sigCert.SerialNumber.Bytes())
		}

		cred.AddCertificate(ref)
	}

	// Activate credential
	cred.Activate()

	return result, nil
}

// getSignerForAlgorithm finds a signer matching the algorithm, tracking usage.
func getSignerForAlgorithm(alg pkicrypto.AlgorithmID, signersByAlg map[pkicrypto.AlgorithmID][]pkicrypto.Signer, usedIndex map[pkicrypto.AlgorithmID]int) (pkicrypto.Signer, error) {
	signers := signersByAlg[alg]
	idx := usedIndex[alg]

	if idx >= len(signers) {
		return nil, fmt.Errorf("no signer available for algorithm %s (need more keys for --keep-keys)", alg)
	}

	signer := signers[idx]
	usedIndex[alg] = idx + 1
	return signer, nil
}

// issueSimpleCertWithExistingSigner issues a certificate reusing an existing signer.
func (ca *CA) issueSimpleCertWithExistingSigner(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, signersByAlg map[pkicrypto.AlgorithmID][]pkicrypto.Signer, usedIndex map[pkicrypto.AlgorithmID]int) (*x509.Certificate, pkicrypto.Signer, error) {
	alg := prof.GetAlgorithm()

	// Get existing signer
	signer, err := getSignerForAlgorithm(alg, signersByAlg, usedIndex)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	cert, err := ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  signer.Public(),
		Extensions: prof.Extensions,
		Validity:   prof.Validity,
	})
	if err != nil {
		return nil, nil, err
	}

	return cert, signer, nil
}

// issueCatalystCertWithExistingKeys issues a Catalyst certificate reusing existing signers.
func (ca *CA) issueCatalystCertWithExistingKeys(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, signersByAlg map[pkicrypto.AlgorithmID][]pkicrypto.Signer, usedIndex map[pkicrypto.AlgorithmID]int) (*x509.Certificate, []pkicrypto.Signer, error) {
	if !prof.IsCatalyst() || len(prof.Algorithms) != 2 {
		return nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Get existing signers
	classicalSigner, err := getSignerForAlgorithm(classicalAlg, signersByAlg, usedIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("classical key: %w", err)
	}

	pqcSigner, err := getSignerForAlgorithm(pqcAlg, signersByAlg, usedIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("PQC key: %w", err)
	}

	template := &x509.Certificate{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	cert, err := ca.IssueCatalyst(CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		PQCAlgorithm:       pqcAlg,
		Extensions:         prof.Extensions,
		Validity:           prof.Validity,
	})
	if err != nil {
		return nil, nil, err
	}

	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, nil
}

// issueCompositeCertWithExistingKeys issues a Composite certificate reusing existing signers.
func (ca *CA) issueCompositeCertWithExistingKeys(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, signersByAlg map[pkicrypto.AlgorithmID][]pkicrypto.Signer, usedIndex map[pkicrypto.AlgorithmID]int) (*x509.Certificate, []pkicrypto.Signer, error) {
	if !prof.IsComposite() || len(prof.Algorithms) != 2 {
		return nil, nil, fmt.Errorf("invalid composite profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Get existing signers
	classicalSigner, err := getSignerForAlgorithm(classicalAlg, signersByAlg, usedIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("classical key: %w", err)
	}

	pqcSigner, err := getSignerForAlgorithm(pqcAlg, signersByAlg, usedIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("PQC key: %w", err)
	}

	template := &x509.Certificate{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	cert, err := ca.IssueComposite(CompositeRequest{
		Template:           template,
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       classicalAlg,
		PQCAlg:             pqcAlg,
		Extensions:         prof.Extensions,
		Validity:           prof.Validity,
	})
	if err != nil {
		return nil, nil, err
	}

	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, nil
}

// RevokeCredential revokes all certificates in a credential.
func (ca *CA) RevokeCredential(credentialID string, reason RevocationReason, credentialStore *credential.FileStore) error {
	// Load credential
	cred, err := credentialStore.Load(credentialID)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	// Revoke each certificate by serial number
	for _, certRef := range cred.Certificates {
		// Parse serial from hex string (e.g., "0x01" -> big.Int)
		serial, ok := parseSerialHex(certRef.Serial)
		if !ok {
			continue
		}

		// Convert big.Int to bytes for Revoke
		if err := ca.Revoke(serial.Bytes(), reason); err != nil {
			// Log but continue with other certificates
			continue
		}
	}

	// Update credential status
	if err := credentialStore.UpdateStatus(credentialID, credential.StatusRevoked, reason.String()); err != nil {
		return fmt.Errorf("failed to update credential status: %w", err)
	}

	return nil
}

// parseSerialHex parses a hex string like "0x01" or "01" to a big.Int.
func parseSerialHex(s string) (*big.Int, bool) {
	// Remove "0x" prefix if present
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	n := new(big.Int)
	_, ok := n.SetString(s, 16)
	return n, ok
}
