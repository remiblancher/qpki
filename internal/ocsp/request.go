package ocsp

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// OCSPRequest represents an OCSP request (RFC 6960 §4.1.1).
// OCSPRequest ::= SEQUENCE {
//
//	tbsRequest                  TBSRequest,
//	optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
type OCSPRequest struct {
	TBSRequest        TBSRequest
	OptionalSignature Signature `asn1:"optional,explicit,tag:0"`
}

// TBSRequest is the to-be-signed part of an OCSP request.
// TBSRequest ::= SEQUENCE {
//
//	version             [0]     EXPLICIT Version DEFAULT v1,
//	requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
//	requestList                 SEQUENCE OF Request,
//	requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
type TBSRequest struct {
	Version           int              `asn1:"optional,explicit,tag:0,default:0"`
	RequestorName     asn1.RawValue    `asn1:"optional,explicit,tag:1"`
	RequestList       []Request        `asn1:"sequence"`
	RequestExtensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
}

// Request represents a single certificate status request.
// Request ::= SEQUENCE {
//
//	reqCert                     CertID,
//	singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
type Request struct {
	ReqCert                   CertID
	SingleRequestExtensions   []pkix.Extension `asn1:"optional,explicit,tag:0"`
}

// CertID identifies a certificate for which status is requested.
// CertID ::= SEQUENCE {
//
//	hashAlgorithm       AlgorithmIdentifier,
//	issuerNameHash      OCTET STRING,
//	issuerKeyHash       OCTET STRING,
//	serialNumber        CertificateSerialNumber }
type CertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// Signature represents an optional signature on the request.
// Signature ::= SEQUENCE {
//
//	signatureAlgorithm      AlgorithmIdentifier,
//	signature               BIT STRING,
//	certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
type Signature struct {
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// ParseRequest parses a DER-encoded OCSP request.
func ParseRequest(data []byte) (*OCSPRequest, error) {
	var req OCSPRequest
	rest, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after OCSP request")
	}

	// Validate version
	if req.TBSRequest.Version != 0 {
		return nil, fmt.Errorf("unsupported OCSP request version: %d", req.TBSRequest.Version)
	}

	// Must have at least one request
	if len(req.TBSRequest.RequestList) == 0 {
		return nil, fmt.Errorf("OCSP request contains no certificate requests")
	}

	return &req, nil
}

// ParseRequestFromHTTP parses an OCSP request from an HTTP request.
// Supports both GET (base64 URL-encoded in path) and POST (binary body).
func ParseRequestFromHTTP(r *http.Request) (*OCSPRequest, error) {
	switch r.Method {
	case http.MethodGet:
		return parseRequestFromGET(r)
	case http.MethodPost:
		return parseRequestFromPOST(r)
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", r.Method)
	}
}

// parseRequestFromGET parses an OCSP request from a GET request.
// The request is base64 URL-encoded in the path.
func parseRequestFromGET(r *http.Request) (*OCSPRequest, error) {
	// Get the path after the base URL
	path := r.URL.Path
	if path == "" || path == "/" {
		return nil, fmt.Errorf("empty OCSP request in GET path")
	}

	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// URL-decode the path (handles %XX escapes)
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return nil, fmt.Errorf("failed to URL-decode OCSP request: %w", err)
	}

	// Base64 decode (URL-safe base64)
	// Try standard base64 first, then URL-safe
	var data []byte
	data, err = base64.StdEncoding.DecodeString(decoded)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(decoded)
		if err != nil {
			// Try without padding
			data, err = base64.RawURLEncoding.DecodeString(decoded)
			if err != nil {
				return nil, fmt.Errorf("failed to base64-decode OCSP request: %w", err)
			}
		}
	}

	return ParseRequest(data)
}

// parseRequestFromPOST parses an OCSP request from a POST request body.
func parseRequestFromPOST(r *http.Request) (*OCSPRequest, error) {
	// Check content type
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/ocsp-request") {
		// Be lenient - some clients might not set the header
		if contentType != "" && !strings.HasPrefix(contentType, "application/") {
			return nil, fmt.Errorf("invalid content type: %s", contentType)
		}
	}

	// Read body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty OCSP request body")
	}

	return ParseRequest(data)
}

// GetNonce extracts the nonce extension from the request, if present.
func (req *OCSPRequest) GetNonce() []byte {
	for _, ext := range req.TBSRequest.RequestExtensions {
		if ext.Id.Equal(OIDOcspNonce) {
			// Nonce is an OCTET STRING
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				return nonce
			}
			// If unmarshal fails, return the raw value
			return ext.Value
		}
	}
	return nil
}

// NewCertID creates a CertID for a certificate issued by the given issuer.
func NewCertID(hashAlg crypto.Hash, issuer, cert *x509.Certificate) (*CertID, error) {
	return NewCertIDFromSerial(hashAlg, issuer, cert.SerialNumber)
}

// NewCertIDFromSerial creates a CertID for a serial number from the given issuer.
func NewCertIDFromSerial(hashAlg crypto.Hash, issuer *x509.Certificate, serial *big.Int) (*CertID, error) {
	var hashOID asn1.ObjectIdentifier
	var h func() []byte

	switch hashAlg {
	case crypto.SHA1:
		hashOID = OIDSHA1
		h = func() []byte {
			sum := sha1.Sum(issuer.RawSubject)
			return sum[:]
		}
	case crypto.SHA256:
		hashOID = OIDSHA256
		h = func() []byte {
			sum := sha256.Sum256(issuer.RawSubject)
			return sum[:]
		}
	case crypto.SHA384:
		hashOID = OIDSHA384
		h = func() []byte {
			sum := sha512.Sum384(issuer.RawSubject)
			return sum[:]
		}
	case crypto.SHA512:
		hashOID = OIDSHA512
		h = func() []byte {
			sum := sha512.Sum512(issuer.RawSubject)
			return sum[:]
		}
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hashAlg)
	}

	issuerNameHash := h()

	// Hash the issuer's public key (SubjectPublicKeyInfo.subjectPublicKey)
	// RFC 6960: issuerKeyHash is the hash of the issuer's public key. The hash
	// shall be calculated over the value (excluding tag and length) of the
	// subject public key field in the issuer's certificate.
	// This matches how SubjectKeyIdentifier is computed per RFC 5280.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse issuer SubjectPublicKeyInfo: %w", err)
	}
	pubKeyBytes := spki.PublicKey.Bytes

	var issuerKeyHash []byte
	switch hashAlg {
	case crypto.SHA1:
		sum := sha1.Sum(pubKeyBytes)
		issuerKeyHash = sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256(pubKeyBytes)
		issuerKeyHash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(pubKeyBytes)
		issuerKeyHash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(pubKeyBytes)
		issuerKeyHash = sum[:]
	}

	return &CertID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: hashOID,
		},
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   serial,
	}, nil
}

// CreateRequest creates an OCSP request for the given certificates.
func CreateRequest(issuer *x509.Certificate, certs []*x509.Certificate, hashAlg crypto.Hash) (*OCSPRequest, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	requests := make([]Request, len(certs))
	for i, cert := range certs {
		certID, err := NewCertID(hashAlg, issuer, cert)
		if err != nil {
			return nil, fmt.Errorf("failed to create CertID for certificate %d: %w", i, err)
		}
		requests[i] = Request{
			ReqCert: *certID,
		}
	}

	return &OCSPRequest{
		TBSRequest: TBSRequest{
			Version:     0,
			RequestList: requests,
		},
	}, nil
}

// CreateRequestWithNonce creates an OCSP request with a nonce extension.
func CreateRequestWithNonce(issuer *x509.Certificate, certs []*x509.Certificate, hashAlg crypto.Hash, nonce []byte) (*OCSPRequest, error) {
	req, err := CreateRequest(issuer, certs, hashAlg)
	if err != nil {
		return nil, err
	}

	// Add nonce extension
	nonceValue, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal nonce: %w", err)
	}

	req.TBSRequest.RequestExtensions = append(req.TBSRequest.RequestExtensions, pkix.Extension{
		Id:       OIDOcspNonce,
		Critical: false,
		Value:    nonceValue,
	})

	return req, nil
}

// Marshal encodes the OCSP request to DER format.
func (req *OCSPRequest) Marshal() ([]byte, error) {
	return asn1.Marshal(*req)
}

// MatchesCertID checks if a CertID matches a certificate from the given issuer.
func (id *CertID) MatchesCertID(issuer *x509.Certificate, serial *big.Int) bool {
	// Determine hash algorithm from the CertID
	var hashAlg crypto.Hash
	switch {
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA1):
		hashAlg = crypto.SHA1
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA256):
		hashAlg = crypto.SHA256
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA384):
		hashAlg = crypto.SHA384
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA512):
		hashAlg = crypto.SHA512
	default:
		return false
	}

	// Create a CertID for comparison
	expected, err := NewCertIDFromSerial(hashAlg, issuer, serial)
	if err != nil {
		return false
	}

	// Compare
	return string(id.IssuerNameHash) == string(expected.IssuerNameHash) &&
		string(id.IssuerKeyHash) == string(expected.IssuerKeyHash) &&
		id.SerialNumber.Cmp(serial) == 0
}

// MatchesIssuer checks if the CertID's issuer hashes match the given issuer.
func (id *CertID) MatchesIssuer(issuer *x509.Certificate) bool {
	// Determine hash algorithm from the CertID
	var hashAlg crypto.Hash
	switch {
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA1):
		hashAlg = crypto.SHA1
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA256):
		hashAlg = crypto.SHA256
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA384):
		hashAlg = crypto.SHA384
	case id.HashAlgorithm.Algorithm.Equal(OIDSHA512):
		hashAlg = crypto.SHA512
	default:
		return false
	}

	// Create a CertID for comparison (with dummy serial)
	expected, err := NewCertIDFromSerial(hashAlg, issuer, big.NewInt(0))
	if err != nil {
		return false
	}

	return string(id.IssuerNameHash) == string(expected.IssuerNameHash) &&
		string(id.IssuerKeyHash) == string(expected.IssuerKeyHash)
}
