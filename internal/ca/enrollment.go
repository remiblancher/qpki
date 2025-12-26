package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/remiblancher/pki/internal/bundle"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
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
	// Bundle is the created bundle.
	Bundle *bundle.Bundle

	// Certificates are the issued certificates.
	Certificates []*x509.Certificate

	// Signers are the generated private key signers.
	Signers []pkicrypto.Signer
}

// Enroll creates a certificate according to a single profile.
// Design: 1 profile = 1 certificate.
// For bundles with multiple certificates, use EnrollMulti.
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

	// Create bundle ID
	bundleID := generateBundleID(req.Subject.CommonName)

	// Create bundle
	b := bundle.NewBundle(bundleID, bundle.SubjectFromPkixName(req.Subject), []string{prof.Name})

	result := &EnrollmentResult{
		Bundle:       b,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
	}

	// Set validity
	notBefore := time.Now()
	notAfter := notBefore.Add(prof.Validity)
	b.SetValidity(notBefore, notAfter)

	// Issue certificate based on mode
	var cert *x509.Certificate
	var signers []pkicrypto.Signer
	var err error

	if prof.IsCatalyst() {
		cert, signers, err = ca.issueCatalystCertFromProfile(req, prof, notBefore, notAfter)
	} else if prof.IsComposite() {
		cert, signers, err = ca.issueCompositeCertFromProfile(req, prof, notBefore, notAfter)
	} else {
		var signer pkicrypto.Signer
		cert, signer, err = ca.issueSimpleCertFromProfile(req, prof, notBefore, notAfter)
		if signer != nil {
			signers = []pkicrypto.Signer{signer}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	result.Certificates = append(result.Certificates, cert)
	result.Signers = append(result.Signers, signers...)

	// Add to bundle
	role := bundle.RoleSignature
	if prof.IsKEM() {
		role = bundle.RoleEncryption
	}
	altAlg := ""
	if prof.IsCatalyst() {
		altAlg = string(prof.GetAlternativeAlgorithm())
	}
	ref := bundle.CertificateRefFromCert(cert, role, prof.IsCatalyst(), altAlg)
	ref.Profile = prof.Name
	b.AddCertificate(ref)

	// Activate bundle
	b.Activate()

	return result, nil
}

// EnrollMulti creates a bundle with multiple certificates from multiple profiles.
// This is the main enrollment function for creating bundles.
// Profiles are processed in order. For KEM certificates, a signature
// certificate must be issued first (per RFC 9883).
func (ca *CA) EnrollMulti(req EnrollmentRequest, profiles []*profile.Profile) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Create bundle ID
	bundleID := generateBundleID(req.Subject.CommonName)

	// Use first profile name for bundle (could be enhanced to use all names)
	profileNames := make([]string, len(profiles))
	for i, p := range profiles {
		profileNames[i] = p.Name
	}

	// Create bundle
	b := bundle.NewBundle(bundleID, bundle.SubjectFromPkixName(req.Subject), profileNames)

	result := &EnrollmentResult{
		Bundle:       b,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
	}

	// Track first signature certificate for KEM attestation
	var sigCert *x509.Certificate
	var notBefore, notAfter time.Time

	for i, prof := range profiles {
		// Use validity from first profile for all (could be enhanced)
		if i == 0 {
			notBefore = time.Now()
			notAfter = notBefore.Add(prof.Validity)
			b.SetValidity(notBefore, notAfter)
		}

		// KEM requires a signature certificate first (RFC 9883)
		if prof.IsKEM() && sigCert == nil {
			return nil, fmt.Errorf("KEM profile %q requires a signature profile first (RFC 9883)", prof.Name)
		}

		// Issue certificate
		var cert *x509.Certificate
		var signers []pkicrypto.Signer
		var err error

		if prof.IsCatalyst() {
			cert, signers, err = ca.issueCatalystCertFromProfile(req, prof, notBefore, notAfter)
		} else if prof.IsComposite() {
			cert, signers, err = ca.issueCompositeCertFromProfile(req, prof, notBefore, notAfter)
		} else {
			var signer pkicrypto.Signer
			cert, signer, err = ca.issueSimpleCertFromProfile(req, prof, notBefore, notAfter)
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

		// Add to bundle
		role := bundle.RoleSignature
		if prof.IsKEM() {
			role = bundle.RoleEncryption
		}
		altAlg := ""
		if prof.IsCatalyst() {
			altAlg = string(prof.GetAlternativeAlgorithm())
		}
		ref := bundle.CertificateRefFromCert(cert, role, prof.IsCatalyst(), altAlg)
		ref.Profile = prof.Name

		// Link to first signature certificate if this is encryption
		if prof.IsKEM() && sigCert != nil {
			ref.RelatedSerial = fmt.Sprintf("0x%X", sigCert.SerialNumber.Bytes())
		}

		b.AddCertificate(ref)
	}

	// Activate bundle
	b.Activate()

	return result, nil
}

// issueSimpleCertFromProfile issues a simple certificate from a profile.
func (ca *CA) issueSimpleCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time) (*x509.Certificate, pkicrypto.Signer, error) {
	alg := prof.GetAlgorithm()

	// Generate key pair
	signer, err := pkicrypto.GenerateSoftwareSigner(alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
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

// issueCatalystCertFromProfile issues a Catalyst certificate from a profile.
func (ca *CA) issueCatalystCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time) (*x509.Certificate, []pkicrypto.Signer, error) {
	if !prof.IsCatalyst() || len(prof.Algorithms) != 2 {
		return nil, nil, fmt.Errorf("invalid catalyst profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate classical key pair
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(classicalAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pqcAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
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

	// Return both signers for Catalyst
	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, nil
}

// issueCompositeCertFromProfile issues an IETF Composite certificate from a profile.
func (ca *CA) issueCompositeCertFromProfile(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time) (*x509.Certificate, []pkicrypto.Signer, error) {
	if !prof.IsComposite() || len(prof.Algorithms) != 2 {
		return nil, nil, fmt.Errorf("invalid composite profile: requires exactly 2 algorithms")
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Generate classical key pair
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(classicalAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pqcAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate PQC key: %w", err)
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

	// Return both signers for Composite
	return cert, []pkicrypto.Signer{classicalSigner, pqcSigner}, nil
}

// generateBundleID generates a unique bundle ID.
func generateBundleID(commonName string) string {
	// Use a timestamp and random suffix
	timestamp := time.Now().Format("20060102-150405")

	// Generate a short random suffix
	b := make([]byte, 4)
	_, _ = rand.Read(b)

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

	return fmt.Sprintf("%s-%s-%x", cleanName, timestamp, b)
}

// RenewBundle renews all certificates in a bundle.
// If newProfiles is provided, use those instead of existing profiles (crypto-agility).
func (ca *CA) RenewBundle(bundleID string, bundleStore *bundle.FileStore, profileStore *profile.ProfileStore, passphrase []byte, newProfiles []string) (*EnrollmentResult, error) {
	// Load existing bundle
	existingBundle, err := bundleStore.Load(bundleID)
	if err != nil {
		return nil, fmt.Errorf("failed to load bundle: %w", err)
	}

	// Use new profiles if provided (crypto-agility), otherwise use existing
	profileNames := existingBundle.Profiles
	if len(newProfiles) > 0 {
		profileNames = newProfiles
	}

	if len(profileNames) == 0 {
		return nil, fmt.Errorf("no profiles found in bundle or provided")
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

	// Create new enrollment request from bundle
	req := EnrollmentRequest{
		Subject: existingBundle.Subject.ToPkixName(),
	}

	// Enroll with profiles
	var result *EnrollmentResult
	if len(profiles) == 1 {
		result, err = ca.EnrollWithProfile(req, profiles[0])
	} else {
		result, err = ca.EnrollMulti(req, profiles)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to enroll: %w", err)
	}

	// Save new bundle
	if err := bundleStore.Save(result.Bundle, result.Certificates, result.Signers, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save bundle: %w", err)
	}

	// Mark old bundle as expired (non-fatal if it fails)
	_ = bundleStore.UpdateStatus(bundleID, bundle.StatusExpired, "renewed")

	return result, nil
}

// RevokeBundle revokes all certificates in a bundle.
func (ca *CA) RevokeBundle(bundleID string, reason RevocationReason, bundleStore *bundle.FileStore) error {
	// Load bundle
	b, err := bundleStore.Load(bundleID)
	if err != nil {
		return fmt.Errorf("failed to load bundle: %w", err)
	}

	// Revoke each certificate by serial number
	for _, certRef := range b.Certificates {
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

	// Update bundle status
	if err := bundleStore.UpdateStatus(bundleID, bundle.StatusRevoked, reason.String()); err != nil {
		return fmt.Errorf("failed to update bundle status: %w", err)
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
