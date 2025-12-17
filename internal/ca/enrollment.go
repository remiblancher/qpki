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

// Enroll creates a bundle of certificates according to a profile.
//
// This is the main enrollment function that:
//  1. Loads the profile configuration
//  2. Generates the required key pairs
//  3. Issues the certificates (Catalyst, linked, or simple)
//  4. Creates and stores the bundle
//
// The CA must have the signer loaded before calling this function.
func (ca *CA) Enroll(req EnrollmentRequest, profileStore *profile.ProfileStore) (*EnrollmentResult, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded")
	}

	// Load profile
	prof, ok := profileStore.Get(req.ProfileName)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", req.ProfileName)
	}

	// Create bundle ID
	bundleID := generateBundleID(req.Subject.CommonName)

	// Create bundle
	b := bundle.NewBundle(bundleID, bundle.SubjectFromPkixName(req.Subject), prof.Name)

	result := &EnrollmentResult{
		Bundle:       b,
		Certificates: make([]*x509.Certificate, 0),
		Signers:      make([]pkicrypto.Signer, 0),
	}

	// Set validity
	notBefore := time.Now()
	notAfter := notBefore.Add(prof.Validity)
	b.SetValidity(notBefore, notAfter)

	// Issue signature certificates
	sigCerts, sigSigners, err := ca.enrollSignature(req, prof, notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll signature: %w", err)
	}

	for i, cert := range sigCerts {
		result.Certificates = append(result.Certificates, cert)
		result.Signers = append(result.Signers, sigSigners[i])

		// Add to bundle
		role := bundle.RoleSignature
		isCatalyst := prof.IsCatalystSignature()
		altAlg := ""

		if prof.Signature.Mode == profile.SignatureHybridSeparate {
			if i == 0 {
				role = bundle.RoleSignatureClassical
			} else {
				role = bundle.RoleSignaturePQC
			}
		}

		if isCatalyst {
			altAlg = string(prof.Signature.Algorithms.Alternative)
		}

		ref := bundle.CertificateRefFromCert(cert, role, isCatalyst, altAlg)
		b.AddCertificate(ref)
	}

	// Issue encryption certificates if required
	if prof.RequiresEncryption() {
		encCerts, encSigners, err := ca.enrollEncryption(req, prof, notBefore, notAfter, sigCerts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to enroll encryption: %w", err)
		}

		for i, cert := range encCerts {
			result.Certificates = append(result.Certificates, cert)
			result.Signers = append(result.Signers, encSigners[i])

			role := bundle.RoleEncryption
			isCatalyst := prof.IsCatalystEncryption()
			altAlg := ""

			if prof.Encryption.Mode == profile.EncryptionHybridSeparate {
				if i == 0 {
					role = bundle.RoleEncryptionClassical
				} else {
					role = bundle.RoleEncryptionPQC
				}
			}

			if isCatalyst {
				altAlg = string(prof.Encryption.Algorithms.Alternative)
			}

			ref := bundle.CertificateRefFromCert(cert, role, isCatalyst, altAlg)
			// Link to signature certificate
			ref.RelatedSerial = fmt.Sprintf("0x%X", sigCerts[0].SerialNumber.Bytes())
			b.AddCertificate(ref)
		}
	}

	// Activate bundle
	b.Activate()

	return result, nil
}

// enrollSignature issues signature certificates according to the profile.
func (ca *CA) enrollSignature(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time) ([]*x509.Certificate, []pkicrypto.Signer, error) {
	var certs []*x509.Certificate
	var signers []pkicrypto.Signer

	switch prof.Signature.Mode {
	case profile.SignatureSimple:
		cert, signer, err := ca.issueSimpleCert(req, prof.Signature.Algorithms.Primary, notBefore, notAfter, prof.Extensions, prof.Validity)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		signers = append(signers, signer)

	case profile.SignatureHybridCombined:
		// Issue Catalyst certificate
		cert, classicalSigner, pqcSigner, err := ca.issueCatalystCert(req, prof.Signature.Algorithms, notBefore, notAfter, prof.Extensions, prof.Validity)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		// For Catalyst, we have a hybrid signer
		hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
		if err != nil {
			return nil, nil, err
		}
		signers = append(signers, hybridSigner)

	case profile.SignatureHybridSeparate:
		// Issue two separate certificates linked together
		classicalCert, classicalSigner, err := ca.issueSimpleCert(req, prof.Signature.Algorithms.Primary, notBefore, notAfter, prof.Extensions, prof.Validity)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, classicalCert)
		signers = append(signers, classicalSigner)

		// Issue PQC certificate linked to classical
		pqcCert, pqcSigner, err := ca.issueLinkedCert(req, prof.Signature.Algorithms.Alternative, notBefore, notAfter, prof.Extensions, prof.Validity, classicalCert)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, pqcCert)
		signers = append(signers, pqcSigner)

	default:
		return nil, nil, fmt.Errorf("unsupported signature mode: %s", prof.Signature.Mode)
	}

	return certs, signers, nil
}

// enrollEncryption issues encryption certificates according to the profile.
func (ca *CA) enrollEncryption(req EnrollmentRequest, prof *profile.Profile, notBefore, notAfter time.Time, sigCert *x509.Certificate) ([]*x509.Certificate, []pkicrypto.Signer, error) {
	var certs []*x509.Certificate
	var signers []pkicrypto.Signer

	// Note: Encryption certificates are linked to the signature certificate

	switch prof.Encryption.Mode {
	case profile.EncryptionSimple:
		cert, signer, err := ca.issueLinkedCert(req, prof.Encryption.Algorithms.Primary, notBefore, notAfter, prof.Extensions, prof.Validity, sigCert)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		signers = append(signers, signer)

	case profile.EncryptionHybridCombined:
		// Catalyst encryption certificate
		return nil, nil, fmt.Errorf("Catalyst encryption not yet implemented")

	case profile.EncryptionHybridSeparate:
		// Two separate encryption certificates
		classicalCert, classicalSigner, err := ca.issueLinkedCert(req, prof.Encryption.Algorithms.Primary, notBefore, notAfter, prof.Extensions, prof.Validity, sigCert)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, classicalCert)
		signers = append(signers, classicalSigner)

		pqcCert, pqcSigner, err := ca.issueLinkedCert(req, prof.Encryption.Algorithms.Alternative, notBefore, notAfter, prof.Extensions, prof.Validity, classicalCert)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, pqcCert)
		signers = append(signers, pqcSigner)

	default:
		return nil, nil, fmt.Errorf("unsupported encryption mode: %s", prof.Encryption.Mode)
	}

	return certs, signers, nil
}

// issueSimpleCert issues a simple certificate with a single algorithm.
func (ca *CA) issueSimpleCert(req EnrollmentRequest, alg pkicrypto.AlgorithmID, notBefore, notAfter time.Time, extensions *profile.ExtensionsConfig, validity time.Duration) (*x509.Certificate, pkicrypto.Signer, error) {
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
		Extensions: extensions,
		Validity:   validity,
	})
	if err != nil {
		return nil, nil, err
	}

	return cert, signer, nil
}

// issueCatalystCert issues a Catalyst certificate with dual keys.
func (ca *CA) issueCatalystCert(req EnrollmentRequest, algs profile.AlgorithmPair, notBefore, notAfter time.Time, extensions *profile.ExtensionsConfig, validity time.Duration) (*x509.Certificate, pkicrypto.Signer, pkicrypto.Signer, error) {
	// Generate classical key pair
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(algs.Primary)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	// Generate PQC key pair
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(algs.Alternative)
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
		PQCAlgorithm:       algs.Alternative,
		Extensions:         extensions,
		Validity:           validity,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, classicalSigner, pqcSigner, nil
}

// issueLinkedCert issues a certificate linked to another certificate.
func (ca *CA) issueLinkedCert(req EnrollmentRequest, alg pkicrypto.AlgorithmID, notBefore, notAfter time.Time, extensions *profile.ExtensionsConfig, validity time.Duration, relatedCert *x509.Certificate) (*x509.Certificate, pkicrypto.Signer, error) {
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

	cert, err := ca.IssueLinked(LinkedCertRequest{
		Template:    template,
		PublicKey:   signer.Public(),
		Extensions:  extensions,
		Validity:    validity,
		RelatedCert: relatedCert,
	})
	if err != nil {
		return nil, nil, err
	}

	return cert, signer, nil
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
func (ca *CA) RenewBundle(bundleID string, bundleStore *bundle.FileStore, profileStore *profile.ProfileStore, passphrase []byte) (*EnrollmentResult, error) {
	// Load existing bundle
	existingBundle, err := bundleStore.Load(bundleID)
	if err != nil {
		return nil, fmt.Errorf("failed to load bundle: %w", err)
	}

	// Create new enrollment request from bundle
	req := EnrollmentRequest{
		Subject:     existingBundle.Subject.ToPkixName(),
		ProfileName: existingBundle.Gamme, // Legacy field name in bundle
	}

	// Enroll with the same profile
	result, err := ca.Enroll(req, profileStore)
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
