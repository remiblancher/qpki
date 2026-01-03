package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// ResponseStatus represents the status of an OCSP response.
type ResponseStatus int

const (
	StatusSuccessful       ResponseStatus = 0
	StatusMalformedRequest ResponseStatus = 1
	StatusInternalError    ResponseStatus = 2
	StatusTryLater         ResponseStatus = 3
	// 4 is not used
	StatusSigRequired  ResponseStatus = 5
	StatusUnauthorized ResponseStatus = 6
)

// String returns a human-readable status string.
func (s ResponseStatus) String() string {
	switch s {
	case StatusSuccessful:
		return "successful"
	case StatusMalformedRequest:
		return "malformedRequest"
	case StatusInternalError:
		return "internalError"
	case StatusTryLater:
		return "tryLater"
	case StatusSigRequired:
		return "sigRequired"
	case StatusUnauthorized:
		return "unauthorized"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// CertStatus represents the revocation status of a certificate.
type CertStatus int

const (
	CertStatusGood    CertStatus = 0
	CertStatusRevoked CertStatus = 1
	CertStatusUnknown CertStatus = 2
)

// String returns a human-readable status string.
func (s CertStatus) String() string {
	switch s {
	case CertStatusGood:
		return "good"
	case CertStatusRevoked:
		return "revoked"
	case CertStatusUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// RevocationReason per RFC 5280 §5.3.1
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	// 7 is not used
	ReasonRemoveFromCRL      RevocationReason = 8
	ReasonPrivilegeWithdrawn RevocationReason = 9
	ReasonAACompromise       RevocationReason = 10
)

// OCSPResponse represents an OCSP response (RFC 6960 §4.2.1).
// OCSPResponse ::= SEQUENCE {
//
//	responseStatus         OCSPResponseStatus,
//	responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
type OCSPResponse struct {
	Status        asn1.Enumerated
	ResponseBytes responseBytes `asn1:"optional,explicit,tag:0"`
}

// responseBytes holds the actual response data.
// ResponseBytes ::= SEQUENCE {
//
//	responseType   OBJECT IDENTIFIER,
//	response       OCTET STRING }
type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// BasicOCSPResponse is the standard response type (RFC 6960 §4.2.1).
// BasicOCSPResponse ::= SEQUENCE {
//
//	tbsResponseData      ResponseData,
//	signatureAlgorithm   AlgorithmIdentifier,
//	signature            BIT STRING,
//	certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
type BasicOCSPResponse struct {
	TBSResponseData    ResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// ResponseData contains the response information to be signed.
// ResponseData ::= SEQUENCE {
//
//	version              [0] EXPLICIT Version DEFAULT v1,
//	responderID              ResponderID,
//	producedAt               GeneralizedTime,
//	responses                SEQUENCE OF SingleResponse,
//	responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
type ResponseData struct {
	Version            int              `asn1:"optional,explicit,tag:0,default:0"`
	ResponderID        asn1.RawValue    // CHOICE: byName [1] or byKey [2]
	ProducedAt         time.Time        `asn1:"generalized"`
	Responses          []SingleResponse `asn1:"sequence"`
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// SingleResponse contains status for a single certificate.
// SingleResponse ::= SEQUENCE {
//
//	certID                       CertID,
//	certStatus                   CertStatus,
//	thisUpdate                   GeneralizedTime,
//	nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
//	singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }
type SingleResponse struct {
	CertID           CertID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"optional,explicit,tag:0,generalized"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// RevokedInfo contains revocation details.
// RevokedInfo ::= SEQUENCE {
//
//	revocationTime              GeneralizedTime,
//	revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
type RevokedInfo struct {
	RevocationTime   time.Time       `asn1:"generalized"`
	RevocationReason asn1.Enumerated `asn1:"optional,explicit,tag:0"`
}

// ResponseBuilder helps construct OCSP responses.
type ResponseBuilder struct {
	responderCert *x509.Certificate
	signer        crypto.Signer
	producedAt    time.Time
	responses     []SingleResponse
	extensions    []pkix.Extension
	includeCerts  bool
}

// NewResponseBuilder creates a new response builder.
func NewResponseBuilder(responderCert *x509.Certificate, signer crypto.Signer) *ResponseBuilder {
	return &ResponseBuilder{
		responderCert: responderCert,
		signer:        signer,
		producedAt:    time.Now().UTC(),
		includeCerts:  true,
	}
}

// SetProducedAt sets the producedAt time.
func (b *ResponseBuilder) SetProducedAt(t time.Time) *ResponseBuilder {
	b.producedAt = t.UTC()
	return b
}

// IncludeCerts sets whether to include the responder certificate.
func (b *ResponseBuilder) IncludeCerts(include bool) *ResponseBuilder {
	b.includeCerts = include
	return b
}

// AddGood adds a "good" status for a certificate.
func (b *ResponseBuilder) AddGood(certID *CertID, thisUpdate, nextUpdate time.Time) *ResponseBuilder {
	// good [0] IMPLICIT NULL
	certStatus := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      nil,
	}

	b.responses = append(b.responses, SingleResponse{
		CertID:     *certID,
		CertStatus: certStatus,
		ThisUpdate: thisUpdate.UTC(),
		NextUpdate: nextUpdate.UTC(),
	})
	return b
}

// AddRevoked adds a "revoked" status for a certificate.
func (b *ResponseBuilder) AddRevoked(certID *CertID, thisUpdate, nextUpdate time.Time, revocationTime time.Time, reason RevocationReason) *ResponseBuilder {
	// revoked [1] IMPLICIT RevokedInfo
	revokedInfo := RevokedInfo{
		RevocationTime:   revocationTime.UTC(),
		RevocationReason: asn1.Enumerated(reason),
	}
	revokedBytes, _ := asn1.Marshal(revokedInfo)

	certStatus := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      revokedBytes,
	}

	b.responses = append(b.responses, SingleResponse{
		CertID:     *certID,
		CertStatus: certStatus,
		ThisUpdate: thisUpdate.UTC(),
		NextUpdate: nextUpdate.UTC(),
	})
	return b
}

// AddUnknown adds an "unknown" status for a certificate.
func (b *ResponseBuilder) AddUnknown(certID *CertID, thisUpdate, nextUpdate time.Time) *ResponseBuilder {
	// unknown [2] IMPLICIT NULL
	certStatus := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: false,
		Bytes:      nil,
	}

	b.responses = append(b.responses, SingleResponse{
		CertID:     *certID,
		CertStatus: certStatus,
		ThisUpdate: thisUpdate.UTC(),
		NextUpdate: nextUpdate.UTC(),
	})
	return b
}

// AddNonce adds a nonce extension to the response.
func (b *ResponseBuilder) AddNonce(nonce []byte) *ResponseBuilder {
	if len(nonce) > 0 {
		nonceValue, _ := asn1.Marshal(nonce)
		b.extensions = append(b.extensions, pkix.Extension{
			Id:       OIDOcspNonce,
			Critical: false,
			Value:    nonceValue,
		})
	}
	return b
}

// Build creates and signs the OCSP response.
func (b *ResponseBuilder) Build() ([]byte, error) {
	if len(b.responses) == 0 {
		return nil, fmt.Errorf("no responses added")
	}

	// Build responder ID (byKey [2])
	// ResponderID ::= CHOICE {
	//    byName   [1] Name,
	//    byKey    [2] KeyHash }
	// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key (RFC 6960)
	//
	// RFC 6960 Section 4.2.1: KeyHash is SHA-1 hash of the value of the BIT STRING
	// subjectPublicKey (excluding tag, length, and unused bits octet).
	// This matches how SubjectKeyIdentifier is computed per RFC 5280.
	//
	// The [2] tag is EXPLICIT (constructed), wrapping an OCTET STRING.
	//
	// Extract public key bytes from SubjectPublicKeyInfo
	// SubjectPublicKeyInfo ::= SEQUENCE {
	//     algorithm AlgorithmIdentifier,
	//     subjectPublicKey BIT STRING }
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(b.responderCert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	keyHash := sha1.Sum(spki.PublicKey.Bytes)

	// Marshal as OCTET STRING first, then wrap in EXPLICIT [2] tag
	octetString, err := asn1.Marshal(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key hash: %w", err)
	}

	responderID := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,    // EXPLICIT tag is constructed
		Bytes:      octetString, // Contains the OCTET STRING
	}

	// Build ResponseData
	responseData := ResponseData{
		Version:            0,
		ResponderID:        responderID,
		ProducedAt:         b.producedAt,
		Responses:          b.responses,
		ResponseExtensions: b.extensions,
	}

	// Marshal ResponseData for signing
	tbsData, err := asn1.Marshal(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	// Sign the response
	signature, sigAlg, err := b.sign(tbsData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Build BasicOCSPResponse
	basicResp := BasicOCSPResponse{
		TBSResponseData:    responseData,
		SignatureAlgorithm: sigAlg,
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	// Include responder certificate if requested
	if b.includeCerts {
		basicResp.Certs = []asn1.RawValue{{FullBytes: b.responderCert.Raw}}
	}

	// Marshal BasicOCSPResponse
	basicRespBytes, err := asn1.Marshal(basicResp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal basic response: %w", err)
	}

	// Build final OCSPResponse
	response := OCSPResponse{
		Status: asn1.Enumerated(StatusSuccessful),
		ResponseBytes: responseBytes{
			ResponseType: OIDOcspBasic,
			Response:     basicRespBytes,
		},
	}

	return asn1.Marshal(response)
}

// sign signs the data with the responder's key.
func (b *ResponseBuilder) sign(data []byte) ([]byte, pkix.AlgorithmIdentifier, error) {
	// Check for HybridSigner (Composite)
	if hybridSigner, ok := b.signer.(pkicrypto.HybridSigner); ok {
		classical := hybridSigner.ClassicalSigner()
		pqc := hybridSigner.PQCSigner()
		compAlg, err := ca.GetCompositeAlgorithm(classical.Algorithm(), pqc.Algorithm())
		if err == nil {
			// Valid Composite algorithm - create composite signature
			sig, err := ca.CreateCompositeSignature(data, compAlg, pqc, classical)
			if err != nil {
				return nil, pkix.AlgorithmIdentifier{}, err
			}
			return sig, pkix.AlgorithmIdentifier{Algorithm: compAlg.OID}, nil
		}
		// Not a valid Composite combination (e.g., Catalyst uses P-384 + ML-DSA-65)
		// Fall back to classical signature only
		return b.signClassical(data, classical)
	}

	pub := b.signer.Public()

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		// Use SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521
		var hashAlg crypto.Hash
		var sigAlg pkix.AlgorithmIdentifier

		switch pubKey.Curve.Params().BitSize {
		case 256:
			hashAlg = crypto.SHA256
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256}
		case 384:
			hashAlg = crypto.SHA384
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA384}
		case 521:
			hashAlg = crypto.SHA512
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA512}
		default:
			return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported ECDSA curve size: %d", pubKey.Curve.Params().BitSize)
		}

		digest := computeDigest(data, hashAlg)
		sig, err := b.signer.Sign(rand.Reader, digest, hashAlg)
		return sig, sigAlg, err

	case ed25519.PublicKey:
		sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
		return sig, pkix.AlgorithmIdentifier{Algorithm: OIDEd25519}, err

	case *rsa.PublicKey:
		hashAlg := crypto.SHA256
		sigAlg := pkix.AlgorithmIdentifier{Algorithm: OIDSHA256WithRSA}
		digest := computeDigest(data, hashAlg)
		sig, err := b.signer.Sign(rand.Reader, digest, hashAlg)
		return sig, sigAlg, err

	default:
		// Try PQC signing (ML-DSA, SLH-DSA)
		// First check for SLH-DSA using type assertion
		switch slhPub := pub.(type) {
		case *slhdsa.PublicKey:
			sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
			return sig, pkix.AlgorithmIdentifier{Algorithm: slhdsaIDToOID(slhPub.ID)}, err
		case slhdsa.PublicKey:
			sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
			return sig, pkix.AlgorithmIdentifier{Algorithm: slhdsaIDToOID(slhPub.ID)}, err
		}

		// The circl library uses mode2, mode3, mode5 for ML-DSA-44, ML-DSA-65, ML-DSA-87
		typeName := fmt.Sprintf("%T", pub)
		switch typeName {
		case "*mode2.PublicKey":
			sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
			return sig, pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA44}, err
		case "*mode3.PublicKey":
			sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
			return sig, pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65}, err
		case "*mode5.PublicKey":
			sig, err := b.signer.Sign(rand.Reader, data, crypto.Hash(0))
			return sig, pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA87}, err
		default:
			return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported key type: %T", pub)
		}
	}
}

// signClassical signs data using a classical signer (for Catalyst fallback).
func (b *ResponseBuilder) signClassical(data []byte, signer pkicrypto.Signer) ([]byte, pkix.AlgorithmIdentifier, error) {
	pub := signer.Public()

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		var hashAlg crypto.Hash
		var sigAlg pkix.AlgorithmIdentifier

		switch pubKey.Curve.Params().BitSize {
		case 256:
			hashAlg = crypto.SHA256
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256}
		case 384:
			hashAlg = crypto.SHA384
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA384}
		case 521:
			hashAlg = crypto.SHA512
			sigAlg = pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA512}
		default:
			return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported ECDSA curve size: %d", pubKey.Curve.Params().BitSize)
		}

		digest := computeDigest(data, hashAlg)
		sig, err := signer.Sign(rand.Reader, digest, hashAlg)
		return sig, sigAlg, err

	case *rsa.PublicKey:
		hashAlg := crypto.SHA256
		sigAlg := pkix.AlgorithmIdentifier{Algorithm: OIDSHA256WithRSA}
		digest := computeDigest(data, hashAlg)
		sig, err := signer.Sign(rand.Reader, digest, hashAlg)
		return sig, sigAlg, err

	case ed25519.PublicKey:
		sig, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
		return sig, pkix.AlgorithmIdentifier{Algorithm: OIDEd25519}, err

	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported classical key type: %T", pub)
	}
}

// slhdsaIDToOID maps SLH-DSA ID to the corresponding OID.
func slhdsaIDToOID(id slhdsa.ID) asn1.ObjectIdentifier {
	switch id {
	case slhdsa.SHA2_128s:
		return OIDSLHDSA128s
	case slhdsa.SHA2_128f:
		return OIDSLHDSA128f
	case slhdsa.SHA2_192s:
		return OIDSLHDSA192s
	case slhdsa.SHA2_192f:
		return OIDSLHDSA192f
	case slhdsa.SHA2_256s:
		return OIDSLHDSA256s
	case slhdsa.SHA2_256f:
		return OIDSLHDSA256f
	default:
		return nil
	}
}

func computeDigest(data []byte, alg crypto.Hash) []byte {
	var h hash.Hash
	switch alg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write(data)
	return h.Sum(nil)
}

// NewErrorResponse creates an error OCSP response (no signature).
func NewErrorResponse(status ResponseStatus) ([]byte, error) {
	if status == StatusSuccessful {
		return nil, fmt.Errorf("cannot create error response with successful status")
	}

	response := OCSPResponse{
		Status: asn1.Enumerated(status),
	}

	return asn1.Marshal(response)
}

// NewMalformedResponse creates a malformedRequest response.
func NewMalformedResponse() ([]byte, error) {
	return NewErrorResponse(StatusMalformedRequest)
}

// NewInternalErrorResponse creates an internalError response.
func NewInternalErrorResponse() ([]byte, error) {
	return NewErrorResponse(StatusInternalError)
}

// NewUnauthorizedResponse creates an unauthorized response.
func NewUnauthorizedResponse() ([]byte, error) {
	return NewErrorResponse(StatusUnauthorized)
}
