// Package tsa implements RFC 3161 Time-Stamp Protocol.
package tsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/cms"
)

// VerifyConfig contains options for verifying a timestamp token.
type VerifyConfig struct {
	// Roots is the pool of trusted CA certificates
	Roots *x509.CertPool
	// Intermediates is the pool of intermediate CA certificates
	Intermediates *x509.CertPool
	// CurrentTime is the time to use for verification (default: now)
	CurrentTime time.Time
	// Data is the original data that was timestamped (optional)
	Data []byte
	// Hash is the hash of the original data (alternative to Data)
	Hash []byte
}

// VerifyResult contains the result of token verification.
type VerifyResult struct {
	// Token is the parsed timestamp token
	Token *Token
	// SignerCert is the certificate that signed the token
	SignerCert *x509.Certificate
	// Verified is true if the signature is valid
	Verified bool
	// HashMatch is true if the data hash matches (only if Data or Hash provided)
	HashMatch bool
}

// Verify verifies a timestamp token.
func Verify(tokenData []byte, config *VerifyConfig) (*VerifyResult, error) {
	// Parse the token
	token, err := ParseToken(tokenData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Parse the CMS structure for signature verification
	var contentInfo cms.ContentInfo
	_, err = asn1.Unmarshal(tokenData, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	var signedData cms.SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Extract signer certificate
	signerCert, err := extractSignerCert(&signedData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signer certificate: %w", err)
	}

	// Verify the signer certificate has timeStamping EKU
	if err := verifyTSAEKU(signerCert); err != nil {
		return nil, err
	}

	// Verify the certificate chain
	if config.Roots != nil {
		if err := verifyCertChain(signerCert, config); err != nil {
			return nil, fmt.Errorf("certificate chain verification failed: %w", err)
		}
	}

	// Verify the signature
	if len(signedData.SignerInfos) == 0 {
		return nil, fmt.Errorf("no signer info in SignedData")
	}

	signerInfo := signedData.SignerInfos[0]
	if err := verifySignature(&signedData, &signerInfo, signerCert); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	result := &VerifyResult{
		Token:      token,
		SignerCert: signerCert,
		Verified:   true,
	}

	// Verify data hash if provided
	if len(config.Data) > 0 || len(config.Hash) > 0 {
		hashMatch, err := verifyDataHash(token, config)
		if err != nil {
			return nil, err
		}
		result.HashMatch = hashMatch
	}

	return result, nil
}

// extractSignerCert extracts the signer certificate from SignedData or config.
func extractSignerCert(signedData *cms.SignedData, config *VerifyConfig) (*x509.Certificate, error) {
	// Try to extract from embedded certificates
	if len(signedData.Certificates.Raw) > 0 {
		certs, err := parseCertificates(signedData.Certificates.Raw)
		if err == nil && len(certs) > 0 {
			return certs[0], nil
		}
	}

	// Try to find in intermediates pool
	if config.Intermediates != nil {
		// Cannot easily extract from CertPool, return error
		return nil, fmt.Errorf("no embedded certificate and cannot search intermediates pool")
	}

	return nil, fmt.Errorf("no signer certificate found")
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

// verifyTSAEKU checks that the certificate has the timeStamping EKU.
func verifyTSAEKU(cert *x509.Certificate) error {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return nil
		}
	}
	// Also check unknown EKUs
	tsaOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(tsaOID) {
			return nil
		}
	}
	return fmt.Errorf("certificate does not have timeStamping EKU")
}

// verifyCertChain verifies the certificate chain.
func verifyCertChain(cert *x509.Certificate, config *VerifyConfig) error {
	opts := x509.VerifyOptions{
		Roots:         config.Roots,
		Intermediates: config.Intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if !config.CurrentTime.IsZero() {
		opts.CurrentTime = config.CurrentTime
	}

	_, err := cert.Verify(opts)
	return err
}

// verifySignature verifies the CMS signature.
func verifySignature(signedData *cms.SignedData, signerInfo *cms.SignerInfo, cert *x509.Certificate) error {
	// Get the content to verify
	var content []byte
	if signedData.EncapContentInfo.EContent.Tag == asn1.TagOctetString {
		content = signedData.EncapContentInfo.EContent.Bytes
	} else {
		_, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &content)
		if err != nil {
			content = signedData.EncapContentInfo.EContent.Bytes
		}
	}

	// Determine the hash algorithm
	hashAlg, err := oidToHashCrypto(signerInfo.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	// If signed attributes exist, verify they contain the correct message digest
	if len(signerInfo.SignedAttrs) > 0 {
		// Compute content digest
		contentDigest, err := computeHash(content, hashAlg)
		if err != nil {
			return fmt.Errorf("failed to compute content digest: %w", err)
		}

		// Find and verify message digest attribute
		found := false
		for _, attr := range signerInfo.SignedAttrs {
			if attr.Type.Equal(cms.OIDMessageDigest) && len(attr.Values) > 0 {
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
		signedAttrsDER, err := cms.MarshalSignedAttrs(signerInfo.SignedAttrs)
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

	// Handle different key types
	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		digest, err := computeHash(data, hashAlg)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(pubKey, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		// Ed25519 signs the data directly
		if !ed25519.Verify(pubKey, data, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		digest, err := computeHash(data, hashAlg)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashAlg, digest, signature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	default:
		// Try to use PQC verification through the certificate's public key
		return verifyPQCSignature(data, signature, cert, sigAlgOID)
	}
}

// verifyPQCSignature attempts to verify a PQC signature.
func verifyPQCSignature(data, signature []byte, cert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	// For PQC algorithms, we need to use the circl library
	// This is a placeholder - actual implementation depends on the crypto package
	typeName := fmt.Sprintf("%T", cert.PublicKey)

	switch {
	case sigAlgOID.Equal(cms.OIDMLDSA44), sigAlgOID.Equal(cms.OIDMLDSA65), sigAlgOID.Equal(cms.OIDMLDSA87):
		// ML-DSA verification would be handled here
		// For now, check if we can verify through crypto.PublicKey interface
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

// oidToHashCrypto converts a hash algorithm OID to crypto.Hash.
func oidToHashCrypto(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(cms.OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(cms.OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(cms.OIDSHA512):
		return crypto.SHA512, nil
	case oid.Equal(cms.OIDSHA3_256):
		return crypto.SHA3_256, nil
	case oid.Equal(cms.OIDSHA3_384):
		return crypto.SHA3_384, nil
	case oid.Equal(cms.OIDSHA3_512):
		return crypto.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", oid)
	}
}

// computeHash computes a hash of data using the specified algorithm.
func computeHash(data []byte, alg crypto.Hash) ([]byte, error) {
	var h hash.Hash
	switch alg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", alg)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// verifyDataHash verifies that the token's message imprint matches the data.
func verifyDataHash(token *Token, config *VerifyConfig) (bool, error) {
	if token.Info == nil {
		return false, fmt.Errorf("no TSTInfo in token")
	}

	expectedHash := config.Hash
	if len(expectedHash) == 0 && len(config.Data) > 0 {
		// Compute hash of data
		hashAlg, err := oidToHashCrypto(token.Info.MessageImprint.HashAlgorithm.Algorithm)
		if err != nil {
			return false, err
		}
		expectedHash, err = computeHash(config.Data, hashAlg)
		if err != nil {
			return false, err
		}
	}

	if len(expectedHash) == 0 {
		return false, fmt.Errorf("no data or hash provided for verification")
	}

	return bytes.Equal(token.Info.MessageImprint.HashedMessage, expectedHash), nil
}
