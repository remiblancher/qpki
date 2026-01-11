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
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// IssueRequest holds the parameters for issuing a certificate.
type IssueRequest struct {
	// Template is the certificate template.
	Template *x509.Certificate

	// PublicKey is the subject's public key.
	PublicKey crypto.PublicKey

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

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

// Issue issues a new certificate.
// For PQC CAs, this automatically delegates to IssuePQC() which uses manual DER construction.
func (ca *CA) Issue(ctx context.Context, req IssueRequest) (*x509.Certificate, error) {
	_ = ctx // TODO: use for cancellation
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// For PQC signers or PQC subject keys, use manual DER construction
	// since Go's x509 doesn't support PQC algorithms
	if ca.IsPQCSigner() || IsPQCPublicKey(req.PublicKey) {
		return ca.IssuePQC(ctx, req)
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

	// Add hybrid PQC extension if provided
	if len(req.HybridPQCKey) > 0 {
		ext, err := x509util.EncodeHybridExtension(req.HybridAlgorithm, req.HybridPQCKey, req.HybridPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to encode hybrid extension: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	// Set signature algorithm if specified (e.g., for RSA-PSS or SHA-3)
	if req.SignatureAlgorithm != 0 {
		template.SignatureAlgorithm = req.SignatureAlgorithm
	}

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

	// Audit: certificate issued successfully
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
