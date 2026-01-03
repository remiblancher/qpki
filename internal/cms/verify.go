package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
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
	// RootCertRaw is the raw DER-encoded root CA certificate for PQC verification
	// This is needed because Go's x509 package doesn't support PQC signatures
	RootCertRaw []byte
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
	if err == nil {
		return nil
	}

	// If Go's x509 fails with "unknown authority", try PQC/Composite verification
	// This happens when the CA uses a PQC algorithm that Go doesn't support
	if strings.Contains(err.Error(), "unknown authority") && len(config.RootCertRaw) > 0 {
		// Parse the root certificate (Go parses structure but PublicKey may be nil for PQC)
		rootCert, parseErr := x509.ParseCertificate(config.RootCertRaw)
		if parseErr == nil {
			// Extract signature algorithm OID from the certificate being verified
			sigAlgOID, extractErr := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
			if extractErr == nil && x509util.IsCompositeOID(sigAlgOID) {
				// Use Composite certificate verification
				result, compErr := ca.VerifyCompositeCertificate(cert, rootCert)
				if compErr == nil && result.Valid {
					return nil
				}
			} else {
				// Use PQC certificate verification for pure PQC algorithms
				valid, pqcErr := ca.VerifyPQCCertificateRaw(cert.Raw, rootCert)
				if pqcErr == nil && valid {
					return nil
				}
			}
		}
	}

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

// validateAlgorithmKeyMatch validates that the declared signature algorithm OID
// is compatible with the certificate's public key type.
//
// SECURITY: This is critical to prevent algorithm confusion attacks.
// The algorithm used for verification MUST be determined by the OID,
// not by the Go key type. This function rejects mismatches before any
// cryptographic verification is attempted.
//
// See: CVE-2024-49958 (Linux kernel), CVE-2022-21449 (Java psychic signatures)
func validateAlgorithmKeyMatch(sigAlgOID asn1.ObjectIdentifier, pub crypto.PublicKey, hashAlg crypto.Hash) error {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		// ECDSA key - OID must be ECDSA with matching hash
		switch {
		case sigAlgOID.Equal(OIDECDSAWithSHA256):
			if hashAlg != crypto.SHA256 {
				return fmt.Errorf("algorithm mismatch: ECDSA-SHA256 OID but hash is %v", hashAlg)
			}
			return nil
		case sigAlgOID.Equal(OIDECDSAWithSHA384):
			if hashAlg != crypto.SHA384 {
				return fmt.Errorf("algorithm mismatch: ECDSA-SHA384 OID but hash is %v", hashAlg)
			}
			return nil
		case sigAlgOID.Equal(OIDECDSAWithSHA512):
			if hashAlg != crypto.SHA512 {
				return fmt.Errorf("algorithm mismatch: ECDSA-SHA512 OID but hash is %v", hashAlg)
			}
			return nil
		default:
			return fmt.Errorf("algorithm mismatch: OID %v is not valid for ECDSA key", sigAlgOID)
		}

	case ed25519.PublicKey:
		// Ed25519 key - OID must be Ed25519
		if !sigAlgOID.Equal(OIDEd25519) {
			return fmt.Errorf("algorithm mismatch: OID %v is not valid for Ed25519 key", sigAlgOID)
		}
		return nil

	case *rsa.PublicKey:
		// RSA key - OID must be RSA with matching hash
		switch {
		case sigAlgOID.Equal(OIDSHA256WithRSA):
			if hashAlg != crypto.SHA256 {
				return fmt.Errorf("algorithm mismatch: RSA-SHA256 OID but hash is %v", hashAlg)
			}
			return nil
		case sigAlgOID.Equal(OIDSHA384WithRSA):
			if hashAlg != crypto.SHA384 {
				return fmt.Errorf("algorithm mismatch: RSA-SHA384 OID but hash is %v", hashAlg)
			}
			return nil
		case sigAlgOID.Equal(OIDSHA512WithRSA):
			if hashAlg != crypto.SHA512 {
				return fmt.Errorf("algorithm mismatch: RSA-SHA512 OID but hash is %v", hashAlg)
			}
			return nil
		default:
			return fmt.Errorf("algorithm mismatch: OID %v is not valid for RSA key", sigAlgOID)
		}

	default:
		// PQC keys - validate OID matches the key type
		// The circl library uses mldsa44, mldsa65, mldsa87 for FIPS 204 ML-DSA
		typeName := fmt.Sprintf("%T", pub)
		switch {
		case sigAlgOID.Equal(OIDMLDSA44):
			if typeName != "*mldsa44.PublicKey" && pub != nil {
				return fmt.Errorf("algorithm mismatch: ML-DSA-44 OID but key is %s", typeName)
			}
			return nil
		case sigAlgOID.Equal(OIDMLDSA65):
			if typeName != "*mldsa65.PublicKey" && pub != nil {
				return fmt.Errorf("algorithm mismatch: ML-DSA-65 OID but key is %s", typeName)
			}
			return nil
		case sigAlgOID.Equal(OIDMLDSA87):
			if typeName != "*mldsa87.PublicKey" && pub != nil {
				return fmt.Errorf("algorithm mismatch: ML-DSA-87 OID but key is %s", typeName)
			}
			return nil
		// SLH-DSA variants (Go x509 doesn't parse SLH-DSA keys, so pub will be nil)
		case sigAlgOID.Equal(OIDSLHDSA128s), sigAlgOID.Equal(OIDSLHDSA128f),
			sigAlgOID.Equal(OIDSLHDSA192s), sigAlgOID.Equal(OIDSLHDSA192f),
			sigAlgOID.Equal(OIDSLHDSA256s), sigAlgOID.Equal(OIDSLHDSA256f):
			// SLH-DSA - pub may be nil since Go doesn't parse it, we'll extract from raw cert later
			return nil
		default:
			// Unknown OID - reject for security
			return fmt.Errorf("unknown or unsupported signature algorithm OID: %v for key type %s", sigAlgOID, typeName)
		}
	}
}

// verifySignatureBytes verifies a signature over data.
// The CERTIFICATE type dictates the verification method:
// - Catalyst: classical verification only (ignore alternative signature in extension)
// - Composite: composite verification (both ML-DSA + ECDSA)
// - PQC: PQC verification (ML-DSA or SLH-DSA)
// - Classical: classical verification (ECDSA, RSA, Ed25519)
func verifySignatureBytes(data, signature []byte, cert *x509.Certificate, hashAlg crypto.Hash, sigAlgOID asn1.ObjectIdentifier) error {
	// Check certificate type to determine verification method
	certType := x509util.GetCertificateType(cert)

	switch certType {
	case x509util.CertTypeCatalyst:
		// Catalyst: use classical verification only
		// The signature OID should be classical (ECDSA/RSA)
		return verifyClassicalSignature(data, signature, cert, hashAlg, sigAlgOID)

	case x509util.CertTypeComposite:
		// Composite: use composite verification
		if !x509util.IsCompositeOID(sigAlgOID) {
			return fmt.Errorf("composite certificate but signature OID %v is not composite", sigAlgOID)
		}
		return ca.VerifyCompositeSignature(data, signature, cert, sigAlgOID)

	case x509util.CertTypePQC:
		// PQC: use PQC verification
		return verifyPQCSignature(data, signature, cert, sigAlgOID)

	default:
		// Classical: use classical verification
		return verifyClassicalSignature(data, signature, cert, hashAlg, sigAlgOID)
	}
}

// verifyClassicalSignature verifies a classical signature (ECDSA, RSA, Ed25519).
func verifyClassicalSignature(data, signature []byte, cert *x509.Certificate, hashAlg crypto.Hash, sigAlgOID asn1.ObjectIdentifier) error {
	pub := cert.PublicKey

	// SECURITY: Validate that the declared OID matches the key type
	// BEFORE attempting cryptographic verification
	if err := validateAlgorithmKeyMatch(sigAlgOID, pub, hashAlg); err != nil {
		return err
	}

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
		return fmt.Errorf("unsupported public key type for classical verification: %T", pub)
	}
}

// verifyPQCSignature attempts to verify a PQC signature.
func verifyPQCSignature(data, signature []byte, cert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	// Check for Composite signature (ML-DSA + ECDSA)
	if x509util.IsCompositeOID(sigAlgOID) {
		return ca.VerifyCompositeSignature(data, signature, cert, sigAlgOID)
	}

	// First, try to use Go's parsed public key (if available)
	if cert.PublicKey != nil {
		if verifier, ok := cert.PublicKey.(interface {
			Verify(message, sig []byte) bool
		}); ok {
			if !verifier.Verify(data, signature) {
				return fmt.Errorf("ML-DSA signature verification failed")
			}
			return nil
		}
	}

	// Go couldn't parse the PQC public key - extract it from RawSubjectPublicKeyInfo
	pubKey, alg, err := extractPQCPublicKey(cert)
	if err != nil {
		return fmt.Errorf("failed to extract PQC public key: %w", err)
	}

	// Verify the signature using our crypto package
	if err := pkicrypto.VerifySignature(pubKey, alg, data, signature); err != nil {
		return fmt.Errorf("PQC signature verification failed: %w", err)
	}

	return nil
}

// extractPQCPublicKey extracts a PQC public key from a certificate's RawSubjectPublicKeyInfo.
func extractPQCPublicKey(cert *x509.Certificate) (crypto.PublicKey, pkicrypto.AlgorithmID, error) {
	raw := cert.RawSubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return nil, "", fmt.Errorf("failed to parse SPKI: %w", err)
	}

	// Determine algorithm from OID
	alg := pkicrypto.AlgorithmFromOID(spki.Algorithm.Algorithm)
	if alg == pkicrypto.AlgUnknown {
		return nil, "", fmt.Errorf("unknown algorithm OID: %v", spki.Algorithm.Algorithm)
	}

	// Parse the public key
	pubKey, err := pkicrypto.ParsePublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, alg, nil
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
