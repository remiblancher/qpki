package cose

import (
	"context"
	"crypto/x509"
	"fmt"

	gocose "github.com/veraison/go-cose"
)

// IssueCWT creates a CWT (CBOR Web Token) with the given claims.
// For hybrid mode, it creates a COSE Sign message with multiple signatures.
func IssueCWT(ctx context.Context, config *CWTConfig) ([]byte, error) {
	_ = ctx // TODO: use for cancellation

	if config.Claims == nil {
		return nil, fmt.Errorf("claims are required for CWT")
	}

	claims := config.Claims

	// Note: IssuedAt is already set in NewClaims(), no need to set it again

	// Auto-generate CWT ID if requested
	if config.AutoCWTID && len(claims.CWTID) == 0 {
		serialGen := config.SerialGenerator
		if serialGen == nil {
			serialGen = DefaultSerialGenerator
		}
		id, err := serialGen.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to generate CWT ID: %w", err)
		}
		claims.CWTID = id
	}

	// Marshal claims to CBOR
	payload, err := claims.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Determine signing mode
	mode := config.Mode()

	// Set content type for CWT
	cfg := config.MessageConfig
	if cfg.ContentType == "" {
		cfg.ContentType = "application/cwt"
	}

	switch mode {
	case ModeHybrid:
		return issueSign(ctx, payload, &cfg)
	default:
		return issueSign1(ctx, payload, &cfg)
	}
}

// IssueSign1 creates a COSE Sign1 message (single signature).
func IssueSign1(ctx context.Context, payload []byte, config *MessageConfig) ([]byte, error) {
	return issueSign1(ctx, payload, config)
}

// issueSign1 creates a COSE Sign1 message.
func issueSign1(ctx context.Context, payload []byte, config *MessageConfig) ([]byte, error) {
	_ = ctx // TODO: use for cancellation

	// Determine which signer to use
	signer := config.Signer
	cert := config.Certificate
	if signer == nil {
		signer = config.PQCSigner
		cert = config.PQCCertificate
	}

	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	// Create COSE signer
	coseSigner, err := NewSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	// Build protected headers
	protected := gocose.Headers{
		Protected: gocose.ProtectedHeader{
			gocose.HeaderLabelAlgorithm: coseSigner.Algorithm(),
		},
	}

	// Add Key ID (certificate fingerprint)
	if cert != nil {
		protected.Protected[gocose.HeaderLabelKeyID] = CertificateFingerprint(cert)
	}

	// Add content type if specified
	if config.ContentType != "" {
		protected.Protected[gocose.HeaderLabelContentType] = config.ContentType
	}

	// Add certificate chain if requested
	if config.IncludeCertChain && cert != nil {
		protected.Protected[HeaderX5Chain] = [][]byte{cert.Raw}
	}

	// Create Sign1 message
	msg := gocose.NewSign1Message()
	msg.Headers = protected
	msg.Payload = payload

	// Sign the message (rand, external data, signer)
	if err := msg.Sign(nil, nil, coseSigner); err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Marshal the message - go-cose handles CBOR tagging internally
	return msg.MarshalCBOR()
}

// IssueSign creates a COSE Sign message (multiple signatures, for hybrid mode).
func IssueSign(ctx context.Context, payload []byte, config *MessageConfig) ([]byte, error) {
	return issueSign(ctx, payload, config)
}

// issueSign creates a COSE Sign message with multiple signatures.
func issueSign(ctx context.Context, payload []byte, config *MessageConfig) ([]byte, error) {
	_ = ctx // TODO: use for cancellation

	if config.Signer == nil && config.PQCSigner == nil {
		return nil, fmt.Errorf("at least one signer is required")
	}

	// Create COSE signers
	var signers []*signatureConfig

	// Add classical signer if present
	if config.Signer != nil {
		coseSigner, err := NewSigner(config.Signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create classical COSE signer: %w", err)
		}
		signers = append(signers, &signatureConfig{
			signer: coseSigner,
			cert:   config.Certificate,
		})
	}

	// Add PQC signer if present
	if config.PQCSigner != nil {
		coseSigner, err := NewSigner(config.PQCSigner)
		if err != nil {
			return nil, fmt.Errorf("failed to create PQC COSE signer: %w", err)
		}
		signers = append(signers, &signatureConfig{
			signer: coseSigner,
			cert:   config.PQCCertificate,
		})
	}

	// Build protected headers for the message
	protected := gocose.ProtectedHeader{}
	if config.ContentType != "" {
		protected[gocose.HeaderLabelContentType] = config.ContentType
	}

	// Create Sign message
	msg := &gocose.SignMessage{
		Headers: gocose.Headers{
			Protected: protected,
		},
		Payload: payload,
	}

	// Add signatures
	for _, sc := range signers {
		sigProtected := gocose.ProtectedHeader{
			gocose.HeaderLabelAlgorithm: sc.signer.Algorithm(),
		}
		if sc.cert != nil {
			sigProtected[gocose.HeaderLabelKeyID] = CertificateFingerprint(sc.cert)
			if config.IncludeCertChain {
				sigProtected[HeaderX5Chain] = [][]byte{sc.cert.Raw}
			}
		}

		sig := gocose.NewSignature()
		sig.Headers = gocose.Headers{
			Protected: sigProtected,
		}
		msg.Signatures = append(msg.Signatures, sig)
	}

	// Create signer list for go-cose
	var gocoseSigners []gocose.Signer
	for _, sc := range signers {
		gocoseSigners = append(gocoseSigners, sc.signer)
	}

	// Sign all signatures at once
	if err := msg.Sign(nil, nil, gocoseSigners...); err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Marshal the message - go-cose handles CBOR tagging internally
	return msg.MarshalCBOR()
}

// signatureConfig holds configuration for each signature in a Sign message.
type signatureConfig struct {
	signer *Signer
	cert   *x509.Certificate
}
