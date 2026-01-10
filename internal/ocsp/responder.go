package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
)

// ResponderConfig contains configuration for the OCSP responder.
type ResponderConfig struct {
	// ResponderCert is the OCSP responder certificate (with EKU OCSPSigning).
	// If nil, the CA certificate is used directly (CA-signed mode).
	ResponderCert *x509.Certificate

	// Signer is the private key for signing OCSP responses.
	Signer crypto.Signer

	// CACert is the CA certificate that issued the certificates being checked.
	CACert *x509.Certificate

	// CAStore provides access to the certificate index.
	CAStore ca.Store

	// Validity is the duration for which responses are valid.
	// Default: 1 hour
	Validity time.Duration

	// CopyNonce indicates whether to copy the request nonce to the response.
	CopyNonce bool

	// IncludeCerts indicates whether to include the responder certificate.
	IncludeCerts bool
}

// Responder handles OCSP requests using the CA's certificate index.
type Responder struct {
	config *ResponderConfig
}

// NewResponder creates a new OCSP responder.
func NewResponder(config *ResponderConfig) (*Responder, error) {
	if config.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if config.CACert == nil {
		return nil, fmt.Errorf("CA certificate is required")
	}
	if config.CAStore == nil {
		return nil, fmt.Errorf("CA store is required")
	}

	// Use CA cert as responder cert if not specified (CA-signed mode)
	if config.ResponderCert == nil {
		config.ResponderCert = config.CACert
	}

	// Set defaults
	if config.Validity == 0 {
		config.Validity = time.Hour
	}

	return &Responder{config: config}, nil
}

// Respond processes an OCSP request and generates a response.
func (r *Responder) Respond(req *OCSPRequest) ([]byte, error) {
	if req == nil {
		return NewMalformedResponse()
	}

	if len(req.TBSRequest.RequestList) == 0 {
		return NewMalformedResponse()
	}

	// Create response builder
	builder := NewResponseBuilder(r.config.ResponderCert, r.config.Signer)
	builder.IncludeCerts(r.config.IncludeCerts)

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(r.config.Validity)

	// Process each certificate request
	for _, certReq := range req.TBSRequest.RequestList {
		status, err := r.CheckStatus(&certReq.ReqCert)
		if err != nil {
			// If we can't check status, mark as unknown
			builder.AddUnknown(&certReq.ReqCert, thisUpdate, nextUpdate)
			continue
		}

		switch status.Status {
		case CertStatusGood:
			builder.AddGood(&certReq.ReqCert, thisUpdate, nextUpdate)
		case CertStatusRevoked:
			builder.AddRevoked(&certReq.ReqCert, thisUpdate, nextUpdate,
				status.RevocationTime, status.RevocationReason)
		case CertStatusUnknown:
			builder.AddUnknown(&certReq.ReqCert, thisUpdate, nextUpdate)
		}
	}

	// Copy nonce if requested
	if r.config.CopyNonce {
		if nonce := req.GetNonce(); len(nonce) > 0 {
			builder.AddNonce(nonce)
		}
	}

	return builder.Build()
}

// StatusInfo contains information about a certificate's status.
type StatusInfo struct {
	Status           CertStatus
	RevocationTime   time.Time
	RevocationReason RevocationReason
}

// CheckStatus checks the revocation status of a certificate identified by CertID.
func (r *Responder) CheckStatus(certID *CertID) (*StatusInfo, error) {
	// Verify the CertID matches our CA
	if !certID.MatchesIssuer(r.config.CACert) {
		return &StatusInfo{Status: CertStatusUnknown}, nil
	}

	// Look up the certificate in the index
	entries, err := r.config.CAStore.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate index: %w", err)
	}

	// Find the certificate by serial number
	serial := certID.SerialNumber
	for _, entry := range entries {
		entrySerial := new(big.Int).SetBytes(entry.Serial)
		if entrySerial.Cmp(serial) == 0 {
			// Found the certificate
			return r.statusFromEntry(&entry), nil
		}
	}

	// Certificate not found in index - unknown
	return &StatusInfo{Status: CertStatusUnknown}, nil
}

// statusFromEntry converts an index entry to a StatusInfo.
func (r *Responder) statusFromEntry(entry *ca.IndexEntry) *StatusInfo {
	switch entry.Status {
	case "V": // Valid
		return &StatusInfo{Status: CertStatusGood}
	case "R": // Revoked
		return &StatusInfo{
			Status:           CertStatusRevoked,
			RevocationTime:   entry.Revocation,
			RevocationReason: ReasonUnspecified, // Index doesn't store reason
		}
	case "E": // Expired
		// Expired certificates are still "good" from OCSP perspective
		// (they were valid when active, just past their validity period)
		return &StatusInfo{Status: CertStatusGood}
	default:
		return &StatusInfo{Status: CertStatusUnknown}
	}
}

// CheckStatusBySerial checks the revocation status by serial number.
func (r *Responder) CheckStatusBySerial(serial *big.Int) (*StatusInfo, error) {
	// Create a CertID for the lookup
	certID, err := NewCertIDFromSerial(crypto.SHA256, r.config.CACert, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to create CertID: %w", err)
	}

	return r.CheckStatus(certID)
}

// CheckStatusBySerialHex checks the revocation status by hex-encoded serial.
func (r *Responder) CheckStatusBySerialHex(serialHex string) (*StatusInfo, error) {
	serialBytes, err := hex.DecodeString(serialHex)
	if err != nil {
		return nil, fmt.Errorf("invalid serial hex: %w", err)
	}

	serial := new(big.Int).SetBytes(serialBytes)
	return r.CheckStatusBySerial(serial)
}

// CreateResponseForSerial creates an OCSP response for a specific serial number.
func (r *Responder) CreateResponseForSerial(serial *big.Int, status CertStatus, revocationTime time.Time, reason RevocationReason) ([]byte, error) {
	certID, err := NewCertIDFromSerial(crypto.SHA256, r.config.CACert, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to create CertID: %w", err)
	}

	builder := NewResponseBuilder(r.config.ResponderCert, r.config.Signer)
	builder.IncludeCerts(r.config.IncludeCerts)

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(r.config.Validity)

	switch status {
	case CertStatusGood:
		builder.AddGood(certID, thisUpdate, nextUpdate)
	case CertStatusRevoked:
		builder.AddRevoked(certID, thisUpdate, nextUpdate, revocationTime, reason)
	case CertStatusUnknown:
		builder.AddUnknown(certID, thisUpdate, nextUpdate)
	}

	return builder.Build()
}

// CreateResponseForSerialHex creates an OCSP response for a hex-encoded serial.
func (r *Responder) CreateResponseForSerialHex(serialHex string, status CertStatus, revocationTime time.Time, reason RevocationReason) ([]byte, error) {
	serialBytes, err := hex.DecodeString(serialHex)
	if err != nil {
		return nil, fmt.Errorf("invalid serial hex: %w", err)
	}

	serial := new(big.Int).SetBytes(serialBytes)
	return r.CreateResponseForSerial(serial, status, revocationTime, reason)
}

// HTTPHandler returns an HTTP handler for the OCSP responder.
// This should be used with http.HandleFunc or http.Handle.
func (r *Responder) ServeOCSP(reqData []byte) ([]byte, error) {
	req, err := ParseRequest(reqData)
	if err != nil {
		return NewMalformedResponse()
	}

	return r.Respond(req)
}

// VerifyResponderCert checks if the responder certificate is valid for OCSP signing.
func VerifyResponderCert(cert *x509.Certificate, issuer *x509.Certificate) error {
	// Check EKU
	hasOCSPSigning := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}

	// If not a CA and doesn't have OCSP Signing EKU, it's invalid
	if !cert.IsCA && !hasOCSPSigning {
		return fmt.Errorf("certificate does not have OCSP Signing extended key usage")
	}

	// Verify the certificate was issued by the CA
	if issuer != nil {
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
			return fmt.Errorf("certificate was not issued by the specified CA")
		}

		// Verify signature
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("certificate signature verification failed: %w", err)
		}
	}

	// Check validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}
