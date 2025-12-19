package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// VerifyConfig contains options for verifying a CMS signature.
type VerifyConfig struct {
	// Roots is the pool of trusted CA certificates
	Roots *x509.CertPool
	// Intermediates is the pool of intermediate CA certificates
	Intermediates *x509.CertPool
	// CurrentTime is the time to use for verification (default: now)
	CurrentTime time.Time
	// Data is the original data for detached signatures
	Data []byte
	// SkipCertVerify skips certificate chain verification
	SkipCertVerify bool
}

// VerifyResult contains the result of signature verification.
type VerifyResult struct {
	// SignerCert is the certificate that signed the content
	SignerCert *x509.Certificate
	// Content is the signed content (nil for detached signatures)
	Content []byte
	// SigningTime is the signing time from signed attributes (if present)
	SigningTime time.Time
	// ContentType is the content type OID
	ContentType asn1.ObjectIdentifier
}

// Verify verifies a CMS SignedData signature.
func Verify(signedDataDER []byte, config *VerifyConfig) (*VerifyResult, error) {
	if config == nil {
		config = &VerifyConfig{}
	}

	// Parse ContentInfo
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("not a SignedData structure, got OID %v", contentInfo.ContentType)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Extract signer certificate
	signerCert, err := extractSignerCert(&signedData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signer certificate: %w", err)
	}

	// Verify the certificate chain (unless skipped)
	if !config.SkipCertVerify && config.Roots != nil {
		if err := verifyCertChain(signerCert, config); err != nil {
			return nil, fmt.Errorf("certificate chain verification failed: %w", err)
		}
	}

	// Verify signature
	if len(signedData.SignerInfos) == 0 {
		return nil, fmt.Errorf("no signer info in SignedData")
	}

	signerInfo := signedData.SignerInfos[0]

	// Get content for verification
	content := getContent(&signedData, config)

	if err := verifySignature(&signedData, &signerInfo, signerCert, content); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	result := &VerifyResult{
		SignerCert:  signerCert,
		ContentType: signedData.EncapContentInfo.EContentType,
	}

	// Extract content if present
	if signedData.EncapContentInfo.EContent.Bytes != nil {
		if signedData.EncapContentInfo.EContent.Tag == asn1.TagOctetString {
			result.Content = signedData.EncapContentInfo.EContent.Bytes
		} else {
			var content []byte
			_, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &content)
			if err == nil {
				result.Content = content
			} else {
				result.Content = signedData.EncapContentInfo.EContent.Bytes
			}
		}
	}

	// Extract signing time from signed attributes
	result.SigningTime = extractSigningTime(signerInfo.SignedAttrs)

	return result, nil
}

// getContent returns the content to verify (from SignedData or config for detached).
func getContent(signedData *SignedData, config *VerifyConfig) []byte {
	// For detached signatures, use provided data
	if len(config.Data) > 0 {
		return config.Data
	}

	// Extract from encapsulated content
	if signedData.EncapContentInfo.EContent.Tag == asn1.TagOctetString {
		return signedData.EncapContentInfo.EContent.Bytes
	}

	// Try to unmarshal as OCTET STRING
	var content []byte
	_, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &content)
	if err == nil {
		return content
	}

	return signedData.EncapContentInfo.EContent.Bytes
}

// extractSignerCert extracts the signer certificate from SignedData or config.
func extractSignerCert(signedData *SignedData, config *VerifyConfig) (*x509.Certificate, error) {
	// Try to extract from embedded certificates
	if len(signedData.Certificates.Raw) > 0 {
		// The Raw field contains [0] IMPLICIT wrapped certificates
		// We need to parse it as a RawValue to get the inner bytes
		var rawVal asn1.RawValue
		_, err := asn1.Unmarshal(signedData.Certificates.Raw, &rawVal)
		if err == nil && len(rawVal.Bytes) > 0 {
			certs, err := parseCertificates(rawVal.Bytes)
			if err == nil && len(certs) > 0 {
				return certs[0], nil
			}
		}
	}

	return nil, fmt.Errorf("no signer certificate found in SignedData")
}

// parseCertificates parses the raw certificates from CMS.
func parseCertificates(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(raw) > 0 {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			// Try to parse as a sequence of certificates
			var certData asn1.RawValue
			rest, err := asn1.Unmarshal(raw, &certData)
			if err != nil {
				break
			}
			cert, err = x509.ParseCertificate(certData.FullBytes)
			if err != nil {
				raw = rest
				continue
			}
			raw = rest
		} else {
			raw = nil
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

// verifyCertChain verifies the certificate chain.
func verifyCertChain(cert *x509.Certificate, config *VerifyConfig) error {
	opts := x509.VerifyOptions{
		Roots:         config.Roots,
		Intermediates: config.Intermediates,
	}
	if !config.CurrentTime.IsZero() {
		opts.CurrentTime = config.CurrentTime
	}

	_, err := cert.Verify(opts)
	return err
}

// verifySignature verifies the CMS signature.
func verifySignature(signedData *SignedData, signerInfo *SignerInfo, cert *x509.Certificate, content []byte) error {
	// Determine the hash algorithm
	hashAlg, err := oidToHash(signerInfo.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	// If signed attributes exist, verify they contain the correct message digest
	if len(signerInfo.SignedAttrs) > 0 {
		// Compute content digest
		contentDigest, err := computeDigest(content, hashAlg)
		if err != nil {
			return fmt.Errorf("failed to compute content digest: %w", err)
		}

		// Find and verify message digest attribute
		found := false
		for _, attr := range signerInfo.SignedAttrs {
			if attr.Type.Equal(OIDMessageDigest) && len(attr.Values) > 0 {
				var md []byte
				_, err := asn1.Unmarshal(attr.Values[0].FullBytes, &md)
				if err != nil {
					return fmt.Errorf("failed to parse message digest: %w", err)
				}
				if !bytes.Equal(md, contentDigest) {
					return fmt.Errorf("message digest mismatch")
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no message digest attribute found")
		}

		// Marshal signed attributes for signature verification
		signedAttrsDER, err := MarshalSignedAttrs(signerInfo.SignedAttrs)
		if err != nil {
			return fmt.Errorf("failed to marshal signed attributes: %w", err)
		}

		return verifySignatureBytes(signedAttrsDER, signerInfo.Signature, cert, hashAlg, signerInfo.SignatureAlgorithm.Algorithm)
	}

	// No signed attributes - verify signature over content directly
	return verifySignatureBytes(content, signerInfo.Signature, cert, hashAlg, signerInfo.SignatureAlgorithm.Algorithm)
}

// verifySignatureBytes verifies a signature over data.
func verifySignatureBytes(data, signature []byte, cert *x509.Certificate, hashAlg crypto.Hash, sigAlgOID asn1.ObjectIdentifier) error {
	pub := cert.PublicKey

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		digest, err := computeDigest(data, hashAlg)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(pubKey, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		if !ed25519.Verify(pubKey, data, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		digest, err := computeDigest(data, hashAlg)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashAlg, digest, signature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	default:
		// Try PQC verification
		return verifyPQCSignature(data, signature, cert, sigAlgOID)
	}
}

// verifyPQCSignature attempts to verify a PQC signature.
func verifyPQCSignature(data, signature []byte, cert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	typeName := fmt.Sprintf("%T", cert.PublicKey)

	switch {
	case sigAlgOID.Equal(OIDMLDSA44), sigAlgOID.Equal(OIDMLDSA65), sigAlgOID.Equal(OIDMLDSA87):
		if verifier, ok := cert.PublicKey.(interface {
			Verify(message, sig []byte) bool
		}); ok {
			if !verifier.Verify(data, signature) {
				return fmt.Errorf("ML-DSA signature verification failed")
			}
			return nil
		}
		return fmt.Errorf("ML-DSA verification not implemented for key type: %s", typeName)

	default:
		return fmt.Errorf("unsupported public key type for verification: %s", typeName)
	}
}

// oidToHash converts a hash algorithm OID to crypto.Hash.
func oidToHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDSHA512):
		return crypto.SHA512, nil
	case oid.Equal(OIDSHA3_256):
		return crypto.SHA3_256, nil
	case oid.Equal(OIDSHA3_384):
		return crypto.SHA3_384, nil
	case oid.Equal(OIDSHA3_512):
		return crypto.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", oid)
	}
}

// Note: computeDigest is defined in signer.go and shared across the package

// extractSigningTime extracts the signing time from signed attributes.
func extractSigningTime(attrs []Attribute) time.Time {
	for _, attr := range attrs {
		if attr.Type.Equal(OIDSigningTime) && len(attr.Values) > 0 {
			var t time.Time
			_, err := asn1.Unmarshal(attr.Values[0].FullBytes, &t)
			if err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// ParseCertificates exports the certificate parsing for external use.
func ParseCertificates(raw []byte) ([]*x509.Certificate, error) {
	return parseCertificates(raw)
}
