package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// IssueRequest holds the parameters for issuing a certificate.
type IssueRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// SubjectConfig is the optional subject DN encoding configuration.
	// If set, controls how DN attribute strings are encoded (UTF8, PrintableString, etc.).
	// If nil, uses Go's default encoding.
	SubjectConfig *profile.SubjectConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration

	// SignatureAlgorithm optionally specifies the signature algorithm.
	// If zero, it's inferred from the CA's key type.
	// Use this to specify RSA-PSS instead of PKCS#1 v1.5, or SHA-3 variants.
	SignatureAlgorithm x509.SignatureAlgorithm

	// HybridPQCKey is the optional PQC public key for hybrid certificates.
	HybridPQCKey []byte

	// HybridAlgorithm is the PQC algorithm for hybrid certificates.
	HybridAlgorithm pkicrypto.AlgorithmID

	// HybridPolicy is the hybrid verification policy.
	HybridPolicy x509util.HybridPolicy
}

// prepareTemplate initializes the certificate template with issuer and extensions.
func (ca *CA) prepareTemplate(req IssueRequest) (*x509.Certificate, error) {
	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	template.Issuer = ca.cert.Subject
	return template, nil
}

// setSerialNumber generates and sets the certificate serial number.
func (ca *CA) setSerialNumber(template *x509.Certificate) error {
	serialBytes, err := ca.store.NextSerial(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)
	return nil
}

// setKeyIdentifiers sets the authority and subject key identifiers.
func (ca *CA) setKeyIdentifiers(template *x509.Certificate, pubKey crypto.PublicKey) error {
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(pubKey)
		if err != nil {
			return fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}
	return nil
}

// setValidity sets NotBefore and NotAfter if not already set.
func setValidity(template *x509.Certificate, validity time.Duration) {
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if validity > 0 {
			template.NotAfter = template.NotBefore.Add(validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}
}

// addHybridExtension adds the hybrid PQC extension if provided.
func addHybridExtension(template *x509.Certificate, req IssueRequest) error {
	if len(req.HybridPQCKey) == 0 {
		return nil
	}
	ext, err := x509util.EncodeHybridExtension(req.HybridAlgorithm, req.HybridPQCKey, req.HybridPolicy)
	if err != nil {
		return fmt.Errorf("failed to encode hybrid extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, ext)
	return nil
}

// signAndStoreCert signs the certificate, stores it, and logs the audit event.
func (ca *CA) signAndStoreCert(template *x509.Certificate, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pubKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if err := ca.store.SaveCert(context.Background(), cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"",
		cert.SignatureAlgorithm.String(),
		true,
	); err != nil {
		return nil, err
	}

	return cert, nil
}

// Issue issues a new certificate.
// For PQC CAs, this automatically delegates to IssuePQC() which uses manual DER construction.
func (ca *CA) Issue(ctx context.Context, req IssueRequest) (*x509.Certificate, error) {
	_ = ctx // TODO: use for cancellation
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// For PQC signers or PQC subject keys, use manual DER construction
	if ca.IsPQCSigner() || IsPQCPublicKey(req.PublicKey) {
		return ca.IssuePQC(ctx, req)
	}

	template, err := ca.prepareTemplate(req)
	if err != nil {
		return nil, err
	}

	if err := ca.setSerialNumber(template); err != nil {
		return nil, err
	}

	if err := ca.setKeyIdentifiers(template, req.PublicKey); err != nil {
		return nil, err
	}

	setValidity(template, req.Validity)

	if err := addHybridExtension(template, req); err != nil {
		return nil, err
	}

	if req.SignatureAlgorithm != 0 {
		template.SignatureAlgorithm = req.SignatureAlgorithm
	}

	return ca.signAndStoreCert(template, req.PublicKey)
}
