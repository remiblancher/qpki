package ocsp

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
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// VerifyConfig contains options for verifying an OCSP response.
type VerifyConfig struct {
	// IssuerCert is the CA certificate that issued the certificate being checked.
	IssuerCert *x509.Certificate

	// ResponderCert is the expected OCSP responder certificate.
	// If nil, it will be extracted from the response.
	ResponderCert *x509.Certificate

	// Certificate is the certificate being checked (optional, for CertID validation).
	Certificate *x509.Certificate

	// CurrentTime is the time to use for validation (default: now).
	CurrentTime time.Time

	// SkipSignatureVerify skips signature verification.
	SkipSignatureVerify bool
}

// VerifyResult contains the result of OCSP response verification.
type VerifyResult struct {
	// Status is the overall response status.
	Status ResponseStatus

	// CertStatus is the certificate's revocation status.
	CertStatus CertStatus

	// RevocationTime is when the certificate was revoked (if revoked).
	RevocationTime time.Time

	// RevocationReason is why the certificate was revoked (if revoked).
	RevocationReason RevocationReason

	// ProducedAt is when the response was generated.
	ProducedAt time.Time

	// ThisUpdate is when this status was known to be correct.
	ThisUpdate time.Time

	// NextUpdate is when new status information will be available.
	NextUpdate time.Time

	// ResponderCert is the certificate that signed the response.
	ResponderCert *x509.Certificate

	// SerialNumber is the serial number of the certificate checked.
	SerialNumber *big.Int
}

// ParseResponse parses a DER-encoded OCSP response.
func ParseResponse(data []byte) (*OCSPResponse, error) {
	var resp OCSPResponse
	rest, err := asn1.Unmarshal(data, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after OCSP response")
	}

	return &resp, nil
}

// Verify verifies an OCSP response.
func Verify(responseData []byte, config *VerifyConfig) (*VerifyResult, error) {
	if config == nil {
		config = &VerifyConfig{}
	}
	if config.CurrentTime.IsZero() {
		config.CurrentTime = time.Now()
	}

	// Parse the response
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}

	// Check response status
	status := ResponseStatus(resp.Status)
	if status != StatusSuccessful {
		return &VerifyResult{Status: status}, nil
	}

	// Parse BasicOCSPResponse
	if !resp.ResponseBytes.ResponseType.Equal(OIDOcspBasic) {
		return nil, fmt.Errorf("unsupported response type: %v", resp.ResponseBytes.ResponseType)
	}

	var basicResp BasicOCSPResponse
	if _, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp); err != nil {
		return nil, fmt.Errorf("failed to parse BasicOCSPResponse: %w", err)
	}

	// Extract responder certificate
	var responderCert *x509.Certificate
	var isCAResponder bool
	if config.ResponderCert != nil {
		responderCert = config.ResponderCert
	} else if len(basicResp.Certs) > 0 {
		cert, err := x509.ParseCertificate(basicResp.Certs[0].FullBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse responder certificate: %w", err)
		}
		responderCert = cert
	} else if config.IssuerCert != nil {
		// CA-signed response
		responderCert = config.IssuerCert
		isCAResponder = true
	}

	// Verify responder authorization (RFC 6960 Section 4.2.2.2)
	// A delegated OCSP responder must have the id-kp-OCSPSigning EKU
	if responderCert != nil && !isCAResponder && config.IssuerCert != nil {
		// Check if this is a delegated responder (not the CA itself)
		if !bytes.Equal(responderCert.Raw, config.IssuerCert.Raw) {
			if err := verifyResponderAuthorization(responderCert); err != nil {
				return nil, fmt.Errorf("responder authorization failed: %w", err)
			}
		}
	}

	// Verify signature
	if !config.SkipSignatureVerify {
		if responderCert == nil {
			return nil, fmt.Errorf("no responder certificate available for verification")
		}

		tbsData, err := asn1.Marshal(basicResp.TBSResponseData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TBS response data: %w", err)
		}

		if err := verifySignature(tbsData, basicResp.Signature.Bytes,
			responderCert, basicResp.SignatureAlgorithm.Algorithm); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Check we have at least one response
	if len(basicResp.TBSResponseData.Responses) == 0 {
		return nil, fmt.Errorf("no single responses in OCSP response")
	}

	// Get the first single response (most common case)
	singleResp := basicResp.TBSResponseData.Responses[0]

	// Parse certificate status
	certStatus, revTime, revReason, err := parseCertStatus(singleResp.CertStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate status: %w", err)
	}

	// Validate times
	if config.CurrentTime.Before(singleResp.ThisUpdate) {
		return nil, fmt.Errorf("response not yet valid (thisUpdate is in the future)")
	}
	if !singleResp.NextUpdate.IsZero() && config.CurrentTime.After(singleResp.NextUpdate) {
		return nil, fmt.Errorf("response has expired (nextUpdate has passed)")
	}

	// Validate CertID if certificate provided
	if config.Certificate != nil && config.IssuerCert != nil {
		if !singleResp.CertID.MatchesCertID(config.IssuerCert, config.Certificate.SerialNumber) {
			return nil, fmt.Errorf("response CertID does not match certificate")
		}
	}

	return &VerifyResult{
		Status:           StatusSuccessful,
		CertStatus:       certStatus,
		RevocationTime:   revTime,
		RevocationReason: revReason,
		ProducedAt:       basicResp.TBSResponseData.ProducedAt,
		ThisUpdate:       singleResp.ThisUpdate,
		NextUpdate:       singleResp.NextUpdate,
		ResponderCert:    responderCert,
		SerialNumber:     singleResp.CertID.SerialNumber,
	}, nil
}

// parseCertStatus parses the certificate status from the ASN.1 CHOICE.
func parseCertStatus(raw asn1.RawValue) (CertStatus, time.Time, RevocationReason, error) {
	switch raw.Tag {
	case 0: // good [0] IMPLICIT NULL
		return CertStatusGood, time.Time{}, 0, nil

	case 1: // revoked [1] IMPLICIT RevokedInfo
		var revokedInfo RevokedInfo
		if _, err := asn1.Unmarshal(raw.Bytes, &revokedInfo); err != nil {
			return 0, time.Time{}, 0, fmt.Errorf("failed to parse RevokedInfo: %w", err)
		}
		return CertStatusRevoked, revokedInfo.RevocationTime, RevocationReason(revokedInfo.RevocationReason), nil

	case 2: // unknown [2] IMPLICIT NULL
		return CertStatusUnknown, time.Time{}, 0, nil

	default:
		return 0, time.Time{}, 0, fmt.Errorf("unknown cert status tag: %d", raw.Tag)
	}
}

// verifyResponderAuthorization checks that a delegated OCSP responder has the
// required id-kp-OCSPSigning extended key usage (RFC 6960 Section 4.2.2.2).
func verifyResponderAuthorization(cert *x509.Certificate) error {
	// Check for ExtKeyUsageOCSPSigning in the standard EKU field
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return nil
		}
	}

	// Also check in UnknownExtKeyUsage for PQC certificates where Go might not parse the EKU
	// OID for id-kp-OCSPSigning is 1.3.6.1.5.5.7.3.9
	ocspSigningOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(ocspSigningOID) {
			return nil
		}
	}

	return fmt.Errorf("responder certificate does not have id-kp-OCSPSigning EKU")
}

// verifySignature verifies the signature on the response.
// The CERTIFICATE type dictates the verification method:
// - Catalyst: classical verification only
// - Composite: composite verification (ML-DSA + ECDSA)
// - PQC: PQC verification (ML-DSA or SLH-DSA)
// - Classical: classical verification (ECDSA, RSA, Ed25519)
func verifySignature(data, signature []byte, cert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	certType := x509util.GetCertificateType(cert)

	switch certType {
	case x509util.CertTypeCatalyst:
		// Catalyst: use classical verification only
		return verifyClassicalSignature(data, signature, cert, sigAlgOID)

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
		return verifyClassicalSignature(data, signature, cert, sigAlgOID)
	}
}

// verifyClassicalSignature verifies a classical signature (ECDSA, RSA, Ed25519).
func verifyClassicalSignature(data, signature []byte, cert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	pub := cert.PublicKey

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		var hashAlg crypto.Hash
		switch {
		case sigAlgOID.Equal(OIDECDSAWithSHA256):
			hashAlg = crypto.SHA256
		case sigAlgOID.Equal(OIDECDSAWithSHA384):
			hashAlg = crypto.SHA384
		case sigAlgOID.Equal(OIDECDSAWithSHA512):
			hashAlg = crypto.SHA512
		default:
			return fmt.Errorf("unsupported ECDSA signature algorithm: %v", sigAlgOID)
		}

		digest := computeDigest(data, hashAlg)
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
		var hashAlg crypto.Hash
		switch {
		case sigAlgOID.Equal(OIDSHA256WithRSA):
			hashAlg = crypto.SHA256
		case sigAlgOID.Equal(OIDSHA384WithRSA):
			hashAlg = crypto.SHA384
		case sigAlgOID.Equal(OIDSHA512WithRSA):
			hashAlg = crypto.SHA512
		default:
			return fmt.Errorf("unsupported RSA signature algorithm: %v", sigAlgOID)
		}

		digest := computeDigest(data, hashAlg)
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

	// Check if the public key has a Verify method (ML-DSA, SLH-DSA)
	if verifier, ok := cert.PublicKey.(interface {
		Verify(message, sig []byte) bool
	}); ok {
		if !verifier.Verify(data, signature) {
			return fmt.Errorf("PQC signature verification failed")
		}
		return nil
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

// GetNonce extracts the nonce from an OCSP response.
func GetResponseNonce(responseData []byte) ([]byte, error) {
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}

	if ResponseStatus(resp.Status) != StatusSuccessful {
		return nil, nil
	}

	var basicResp BasicOCSPResponse
	if _, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp); err != nil {
		return nil, err
	}

	for _, ext := range basicResp.TBSResponseData.ResponseExtensions {
		if ext.Id.Equal(OIDOcspNonce) {
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				return nonce, nil
			}
			return ext.Value, nil
		}
	}

	return nil, nil
}

// GetResponseStatus extracts the response status from raw OCSP response data.
func GetResponseStatus(responseData []byte) (ResponseStatus, error) {
	resp, err := ParseResponse(responseData)
	if err != nil {
		return 0, err
	}
	return ResponseStatus(resp.Status), nil
}

// IsGood checks if the OCSP response indicates the certificate is good.
func IsGood(responseData []byte) (bool, error) {
	result, err := Verify(responseData, &VerifyConfig{SkipSignatureVerify: true})
	if err != nil {
		return false, err
	}
	return result.CertStatus == CertStatusGood, nil
}

// IsRevoked checks if the OCSP response indicates the certificate is revoked.
func IsRevoked(responseData []byte) (bool, error) {
	result, err := Verify(responseData, &VerifyConfig{SkipSignatureVerify: true})
	if err != nil {
		return false, err
	}
	return result.CertStatus == CertStatusRevoked, nil
}

// ExtractCertificates extracts certificates from an OCSP response.
func ExtractCertificates(responseData []byte) ([]*x509.Certificate, error) {
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}

	if ResponseStatus(resp.Status) != StatusSuccessful {
		return nil, nil
	}

	var basicResp BasicOCSPResponse
	if _, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp); err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, rawCert := range basicResp.Certs {
		cert, err := x509.ParseCertificate(rawCert.FullBytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// ResponseInfo contains parsed information from an OCSP response.
type ResponseInfo struct {
	Status         ResponseStatus
	CertStatuses   []SingleResponseInfo
	ProducedAt     time.Time
	ResponderID    []byte
	Nonce          []byte
	ResponderCerts []*x509.Certificate
	SignatureAlg   string
}

// SingleResponseInfo contains information about a single certificate status.
type SingleResponseInfo struct {
	SerialNumber     *big.Int
	Status           CertStatus
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevocationTime   time.Time
	RevocationReason RevocationReason
}

// GetResponseInfo extracts detailed information from an OCSP response.
func GetResponseInfo(responseData []byte) (*ResponseInfo, error) {
	resp, err := ParseResponse(responseData)
	if err != nil {
		return nil, err
	}

	info := &ResponseInfo{
		Status: ResponseStatus(resp.Status),
	}

	if info.Status != StatusSuccessful {
		return info, nil
	}

	var basicResp BasicOCSPResponse
	if _, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp); err != nil {
		return nil, err
	}

	info.ProducedAt = basicResp.TBSResponseData.ProducedAt
	info.ResponderID = basicResp.TBSResponseData.ResponderID.Bytes
	info.SignatureAlg = basicResp.SignatureAlgorithm.Algorithm.String()

	// Extract nonce
	for _, ext := range basicResp.TBSResponseData.ResponseExtensions {
		if ext.Id.Equal(OIDOcspNonce) {
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				info.Nonce = nonce
			} else {
				info.Nonce = ext.Value
			}
			break
		}
	}

	// Parse single responses
	for _, sr := range basicResp.TBSResponseData.Responses {
		certStatus, revTime, revReason, err := parseCertStatus(sr.CertStatus)
		if err != nil {
			continue
		}

		info.CertStatuses = append(info.CertStatuses, SingleResponseInfo{
			SerialNumber:     sr.CertID.SerialNumber,
			Status:           certStatus,
			ThisUpdate:       sr.ThisUpdate,
			NextUpdate:       sr.NextUpdate,
			RevocationTime:   revTime,
			RevocationReason: revReason,
		})
	}

	// Extract responder certificates
	for _, rawCert := range basicResp.Certs {
		cert, err := x509.ParseCertificate(rawCert.FullBytes)
		if err != nil {
			continue
		}
		info.ResponderCerts = append(info.ResponderCerts, cert)
	}

	return info, nil
}

// ValidateNonce checks if the response nonce matches the request nonce.
func ValidateNonce(requestData, responseData []byte) error {
	req, err := ParseRequest(requestData)
	if err != nil {
		return fmt.Errorf("failed to parse request: %w", err)
	}

	reqNonce := req.GetNonce()
	if len(reqNonce) == 0 {
		// No nonce in request, nothing to validate
		return nil
	}

	respNonce, err := GetResponseNonce(responseData)
	if err != nil {
		return fmt.Errorf("failed to get response nonce: %w", err)
	}

	if len(respNonce) == 0 {
		return fmt.Errorf("request contains nonce but response does not")
	}

	if !bytes.Equal(reqNonce, respNonce) {
		return fmt.Errorf("nonce mismatch")
	}

	return nil
}
