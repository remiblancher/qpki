package cose

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	gocose "github.com/veraison/go-cose"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// VerifyCWT verifies a CWT and returns the result.
func VerifyCWT(data []byte, config *VerifyConfig) (*VerifyResult, error) {
	msg, err := ParseCWT(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CWT: %w", err)
	}

	result, err := verifyMessage(data, msg, config)
	if err != nil {
		return nil, err
	}

	// Validate claims if requested
	if config.CheckExpiration && msg.Claims != nil {
		checkTime := config.CurrentTime
		if checkTime.IsZero() {
			checkTime = time.Now()
		}
		if err := msg.Claims.ValidateAt(checkTime); err != nil {
			result.Valid = false
			result.Warnings = append(result.Warnings, err.Error())
		}
	}

	result.Claims = msg.Claims
	return result, nil
}

// VerifySign1 verifies a COSE Sign1 message.
func VerifySign1(data []byte, config *VerifyConfig) (*VerifyResult, error) {
	msg, err := ParseSign1(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Sign1 message: %w", err)
	}

	return verifyMessage(data, msg, config)
}

// VerifySign verifies a COSE Sign message (multi-signature/hybrid).
func VerifySign(data []byte, config *VerifyConfig) (*VerifyResult, error) {
	msg, err := ParseSign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Sign message: %w", err)
	}

	return verifyMessage(data, msg, config)
}

// verifyMessage performs signature verification on a parsed message.
func verifyMessage(data []byte, msg *Message, config *VerifyConfig) (*VerifyResult, error) {
	result := &VerifyResult{
		Valid:     true,
		Mode:      msg.Mode,
		Algorithms: make([]gocose.Algorithm, 0, len(msg.Signatures)),
	}

	switch msg.Type {
	case TypeSign1:
		return verifySign1Message(data, msg, config, result)
	case TypeCWT:
		if msg.Mode == ModeHybrid {
			// Hybrid CWT uses COSE Sign (multi-signature)
			return verifySignMessage(data, msg, config, result)
		}
		return verifySign1Message(data, msg, config, result)
	case TypeSign:
		return verifySignMessage(data, msg, config, result)
	default:
		return nil, fmt.Errorf("unsupported message type: %v", msg.Type)
	}
}

// verifySign1Message verifies a Sign1 message.
func verifySign1Message(data []byte, msg *Message, config *VerifyConfig, result *VerifyResult) (*VerifyResult, error) {
	if len(msg.Signatures) == 0 {
		return nil, fmt.Errorf("no signature found")
	}

	sigInfo := msg.Signatures[0]
	result.Algorithms = append(result.Algorithms, sigInfo.Algorithm)

	// Get public key for verification
	pubKey, cert, err := resolvePublicKey(sigInfo, config)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve public key: %w", err)
	}

	// Verify certificate chain if roots are provided
	if config.Roots != nil && cert != nil {
		if err := verifyCertificateChain(cert, config); err != nil {
			result.Valid = false
			result.Warnings = append(result.Warnings, fmt.Sprintf("certificate verification failed: %v", err))
		}
	}

	// Parse and verify the Sign1 message
	var sign1 gocose.Sign1Message
	if err := cbor.Unmarshal(data, &sign1); err != nil {
		return nil, fmt.Errorf("failed to parse Sign1 for verification: %w", err)
	}

	verifier := NewVerifierWithAlgorithm(pubKey, sigInfo.Algorithm)
	if err := sign1.Verify(nil, verifier); err != nil {
		result.Valid = false
		result.Warnings = append(result.Warnings, fmt.Sprintf("signature verification failed: %v", err))
	}

	if cert != nil {
		result.Certificates = append(result.Certificates, cert)
	}

	return result, nil
}

// verifySignMessage verifies a Sign message (multi-signature/hybrid).
func verifySignMessage(data []byte, msg *Message, config *VerifyConfig, result *VerifyResult) (*VerifyResult, error) {
	if len(msg.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	// Parse the Sign message
	var sign gocose.SignMessage
	if err := cbor.Unmarshal(data, &sign); err != nil {
		return nil, fmt.Errorf("failed to parse Sign for verification: %w", err)
	}

	// Build verifiers list - for hybrid mode, ALL signatures must be valid
	var verifiers []gocose.Verifier
	for i, sigInfo := range msg.Signatures {
		result.Algorithms = append(result.Algorithms, sigInfo.Algorithm)

		// Get public key for this signature
		pubKey, cert, err := resolvePublicKeyForSignature(i, sigInfo, config)
		if err != nil {
			result.Valid = false
			result.Warnings = append(result.Warnings, fmt.Sprintf("failed to resolve public key for signature %d: %v", i, err))
			continue
		}

		// Verify certificate chain if roots are provided
		if config.Roots != nil && cert != nil {
			if err := verifyCertificateChain(cert, config); err != nil {
				result.Valid = false
				result.Warnings = append(result.Warnings, fmt.Sprintf("certificate %d verification failed: %v", i, err))
			}
		}

		verifier := NewVerifierWithAlgorithm(pubKey, sigInfo.Algorithm)
		verifiers = append(verifiers, verifier)

		if cert != nil {
			result.Certificates = append(result.Certificates, cert)
		}
	}

	// Verify all signatures at once - go-cose requires all verifiers to match their signatures
	if err := sign.Verify(nil, verifiers...); err != nil {
		result.Valid = false
		result.Warnings = append(result.Warnings, fmt.Sprintf("signature verification failed: %v", err))
	}

	return result, nil
}

// resolvePublicKey resolves the public key for verification from config or message.
func resolvePublicKey(sigInfo SignatureInfo, config *VerifyConfig) (crypto.PublicKey, *x509.Certificate, error) {
	// For PQC algorithms, check PQC keys first
	if IsPQCAlgorithm(sigInfo.Algorithm) {
		if config.PQCPublicKey != nil {
			return config.PQCPublicKey, config.PQCCertificate, nil
		}
		if config.PQCCertificate != nil {
			return config.PQCCertificate.PublicKey, config.PQCCertificate, nil
		}
	}

	// For classical algorithms, check classical keys
	if config.PublicKey != nil {
		return config.PublicKey, config.Certificate, nil
	}

	if config.Certificate != nil {
		pubKey, err := getPublicKeyFromCert(config.Certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract public key from config certificate: %w", err)
		}
		return pubKey, config.Certificate, nil
	}

	if sigInfo.Certificate != nil {
		pubKey, err := getPublicKeyFromCert(sigInfo.Certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract public key from message certificate: %w", err)
		}
		return pubKey, sigInfo.Certificate, nil
	}

	// Try to find certificate by Key ID in roots
	if config.Roots != nil && len(sigInfo.KeyID) > 0 {
		cert := findCertByKeyID(config.Roots, sigInfo.KeyID)
		if cert != nil {
			return cert.PublicKey, cert, nil
		}
	}

	return nil, nil, fmt.Errorf("no public key available for verification")
}

// resolvePublicKeyForSignature resolves the public key for a specific signature in a Sign message.
func resolvePublicKeyForSignature(idx int, sigInfo SignatureInfo, config *VerifyConfig) (crypto.PublicKey, *x509.Certificate, error) {
	// For hybrid mode, use PQC keys for PQC signatures
	if IsPQCAlgorithm(sigInfo.Algorithm) {
		if config.PQCPublicKey != nil {
			return config.PQCPublicKey, config.PQCCertificate, nil
		}
		if config.PQCCertificate != nil {
			pubKey, err := getPublicKeyFromCert(config.PQCCertificate)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extract PQC public key: %w", err)
			}
			return pubKey, config.PQCCertificate, nil
		}
	} else {
		if config.PublicKey != nil {
			return config.PublicKey, config.Certificate, nil
		}
		if config.Certificate != nil {
			pubKey, err := getPublicKeyFromCert(config.Certificate)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extract public key: %w", err)
			}
			return pubKey, config.Certificate, nil
		}
	}

	// Fall back to certificate in message
	if sigInfo.Certificate != nil {
		pubKey, err := getPublicKeyFromCert(sigInfo.Certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract public key from message certificate: %w", err)
		}
		return pubKey, sigInfo.Certificate, nil
	}

	// Try to find by Key ID
	if config.Roots != nil && len(sigInfo.KeyID) > 0 {
		cert := findCertByKeyID(config.Roots, sigInfo.KeyID)
		if cert != nil {
			pubKey, err := getPublicKeyFromCert(cert)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extract public key: %w", err)
			}
			return pubKey, cert, nil
		}
	}

	return nil, nil, fmt.Errorf("no public key available for signature %d", idx)
}

// verifyCertificateChain verifies a certificate against the configured roots.
func verifyCertificateChain(cert *x509.Certificate, config *VerifyConfig) error {
	// First try Go's standard verification
	opts := x509.VerifyOptions{
		Roots:         config.Roots,
		Intermediates: config.Intermediates,
		KeyUsages:     config.KeyUsages,
	}

	if !config.CurrentTime.IsZero() {
		opts.CurrentTime = config.CurrentTime
	}

	_, err := cert.Verify(opts)
	if err == nil {
		return nil
	}

	// If standard verification fails with "unknown authority", try PQC verification
	// This happens when the certificate uses a PQC signature algorithm that Go doesn't support
	certType := x509util.GetCertificateType(cert)
	if certType == x509util.CertTypePQC || certType == x509util.CertTypeComposite || certType == x509util.CertTypeCatalyst {
		// Try PQC chain verification if we have root certificates
		if len(config.RootCerts) > 0 {
			for _, rootCert := range config.RootCerts {
				// Verify the certificate signature against this root
				if verifyErr := verifyPQCCertSignature(cert, rootCert); verifyErr == nil {
					return nil
				}
			}
		}
	}

	return err
}

// verifyPQCCertSignature verifies a PQC certificate's signature against an issuer.
func verifyPQCCertSignature(cert, issuer *x509.Certificate) error {
	// Extract the signature algorithm OID from the certificate
	sigAlgOID, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return fmt.Errorf("failed to extract signature algorithm: %w", err)
	}

	// Get the issuer's public key
	issuerPubKey, err := getPublicKeyFromCert(issuer)
	if err != nil {
		return fmt.Errorf("failed to get issuer public key: %w", err)
	}

	// Determine the algorithm
	alg := pkicrypto.AlgorithmFromOID(sigAlgOID)
	if alg == pkicrypto.AlgUnknown {
		return fmt.Errorf("unknown signature algorithm OID: %v", sigAlgOID)
	}

	// Extract TBS (To Be Signed) data and signature from the certificate
	tbsData, signature, err := x509util.ExtractTBSAndSignature(cert.Raw)
	if err != nil {
		return fmt.Errorf("failed to extract TBS data: %w", err)
	}

	// Verify the signature
	if err := pkicrypto.VerifySignature(issuerPubKey, alg, tbsData, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// findCertByKeyID finds a certificate by its SHA-256 fingerprint (Key ID).
func findCertByKeyID(pool *x509.CertPool, keyID []byte) *x509.Certificate {
	if pool == nil || len(keyID) == 0 {
		return nil
	}

	// x509.CertPool doesn't expose certificates directly
	// This would need to be implemented differently in practice
	// For now, return nil
	return nil
}

// VerifyWithTime verifies a message at a specific time (useful for testing).
func VerifyWithTime(data []byte, config *VerifyConfig, t time.Time) (*VerifyResult, error) {
	configCopy := *config
	configCopy.CurrentTime = t
	return VerifyCWT(data, &configCopy)
}

// QuickVerify performs a quick verification with a single public key.
func QuickVerify(data []byte, pub crypto.PublicKey) error {
	msg, err := Parse(data)
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	if len(msg.Signatures) == 0 {
		return fmt.Errorf("no signatures found")
	}

	config := &VerifyConfig{
		PublicKey: pub,
	}

	result, err := verifyMessage(data, msg, config)
	if err != nil {
		return err
	}

	if !result.Valid {
		if len(result.Warnings) > 0 {
			return fmt.Errorf("verification failed: %s", result.Warnings[0])
		}
		return fmt.Errorf("verification failed")
	}

	return nil
}

// MatchKeyID checks if a certificate fingerprint matches a Key ID.
func MatchKeyID(cert *x509.Certificate, keyID []byte) bool {
	if cert == nil || len(keyID) == 0 {
		return false
	}
	fp := CertificateFingerprint(cert)
	return bytes.Equal(fp, keyID)
}

// getPublicKeyFromCert extracts the public key from a certificate.
// For classical certificates, it returns cert.PublicKey directly.
// For PQC certificates (where Go doesn't know the key type), it extracts
// the public key from RawSubjectPublicKeyInfo using our crypto package.
func getPublicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Check certificate type
	certType := x509util.GetCertificateType(cert)

	switch certType {
	case x509util.CertTypeClassical:
		// Classical certificates have the public key parsed by Go
		if cert.PublicKey != nil {
			return cert.PublicKey, nil
		}
		return nil, fmt.Errorf("classical certificate has no public key")

	case x509util.CertTypePQC:
		// PQC certificates need manual extraction from SPKI
		return extractPQCPublicKey(cert)

	case x509util.CertTypeCatalyst:
		// Catalyst certificates have classical primary key
		if cert.PublicKey != nil {
			return cert.PublicKey, nil
		}
		return nil, fmt.Errorf("catalyst certificate has no primary public key")

	case x509util.CertTypeComposite:
		// Composite certificates have a combined key - extract it
		return extractPQCPublicKey(cert)

	default:
		// Try classical first, then PQC extraction
		if cert.PublicKey != nil {
			return cert.PublicKey, nil
		}
		return extractPQCPublicKey(cert)
	}
}

// extractPQCPublicKey extracts a PQC public key from a certificate's RawSubjectPublicKeyInfo.
func extractPQCPublicKey(cert *x509.Certificate) (crypto.PublicKey, error) {
	raw := cert.RawSubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	// Determine algorithm from OID
	alg := pkicrypto.AlgorithmFromOID(spki.Algorithm.Algorithm)
	if alg == pkicrypto.AlgUnknown {
		return nil, fmt.Errorf("unknown algorithm OID: %v", spki.Algorithm.Algorithm)
	}

	// Parse the public key
	pubKey, err := pkicrypto.ParsePublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}
