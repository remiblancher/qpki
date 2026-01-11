package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// LinkedCertRequest holds the parameters for issuing a certificate linked to another.
// This is used for separate hybrid certificates where multiple certificates are
// bound together using the RelatedCertificate extension.
type LinkedCertRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration

	// RelatedCert is the certificate to link to.
	// The new certificate will contain a RelatedCertificate extension
	// pointing to this certificate.
	RelatedCert *x509.Certificate
}

// IssueLinked issues a certificate that is linked to another certificate.
//
// The issued certificate contains a RelatedCertificate extension that binds it
// to the provided related certificate. This is used for:
//   - Linking a PQC signature certificate to a classical signature certificate
//   - Linking an encryption certificate to a signature certificate
//   - Any other multi-certificate scenarios
//
// The related certificate must be valid and issued by the same CA (or a trusted CA).
func (ca *CA) IssueLinked(ctx context.Context, req LinkedCertRequest) (*x509.Certificate, error) {
	_ = ctx // TODO: use for cancellation
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	if req.RelatedCert == nil {
		return nil, fmt.Errorf("related certificate is required for linked issuance")
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply extensions from profile
	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Set issuer
	template.Issuer = ca.cert.Subject

	// Generate serial number
	serialBytes, err := ca.store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	// Set authority key ID
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	// Set subject key ID
	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}

	// Set validity if not already set
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if req.Validity > 0 {
			template.NotAfter = template.NotBefore.Add(req.Validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}

	// Add RelatedCertificate extension
	relCertExt, err := x509util.EncodeRelatedCertificate(req.RelatedCert)
	if err != nil {
		return nil, fmt.Errorf("failed to encode RelatedCertificate extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, relCertExt)

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(context.Background(), cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit: linked certificate issued
	relSerial := fmt.Sprintf("0x%X", req.RelatedCert.SerialNumber.Bytes())
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"linked to "+relSerial,
		cert.SignatureAlgorithm.String(),
		true,
	); err != nil {
		return nil, err
	}

	return cert, nil
}
