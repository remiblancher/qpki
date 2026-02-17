// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/ocsp"
)

// OCSPService provides OCSP operations for the REST API.
type OCSPService struct {
	baseDir string
}

// NewOCSPService creates a new OCSPService.
func NewOCSPService(baseDir string) *OCSPService {
	return &OCSPService{baseDir: baseDir}
}

// Query creates an OCSP response for a certificate status query.
func (s *OCSPService) Query(ctx context.Context, req *dto.OCSPQueryRequest) (*dto.OCSPQueryResponse, error) {
	// Determine the serial number to check
	var serial *big.Int
	if req.Serial != "" {
		// Parse serial from hex
		serialBytes, err := hex.DecodeString(req.Serial)
		if err != nil {
			return nil, fmt.Errorf("invalid serial number: %w", err)
		}
		serial = new(big.Int).SetBytes(serialBytes)
	} else if req.Certificate != nil {
		// Extract serial from certificate
		certData, err := req.Certificate.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
		cert, err := parseCertificateOCSP(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		serial = cert.SerialNumber
	} else {
		return nil, fmt.Errorf("serial number or certificate is required")
	}

	// Load OCSP responder
	responder, err := s.loadOCSPResponder(ctx, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load OCSP responder: %w", err)
	}

	// Check certificate status
	status, err := responder.CheckStatusBySerial(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate status: %w", err)
	}

	// Create OCSP response
	var certStatus ocsp.CertStatus
	var revocationTime time.Time
	var revocationReason ocsp.RevocationReason

	switch status.Status {
	case ocsp.CertStatusGood:
		certStatus = ocsp.CertStatusGood
	case ocsp.CertStatusRevoked:
		certStatus = ocsp.CertStatusRevoked
		revocationTime = status.RevocationTime
		revocationReason = status.RevocationReason
	default:
		certStatus = ocsp.CertStatusUnknown
	}

	responseData, err := responder.CreateResponseForSerial(serial, certStatus, revocationTime, revocationReason)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", err)
	}

	// Build response DTO
	now := time.Now().UTC()
	resp := &dto.OCSPQueryResponse{
		Response: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(responseData),
			Encoding: "base64",
		},
		Status: dto.OCSPStatus{
			Status: certStatusToString(certStatus),
		},
		ProducedAt: now.Format(time.RFC3339),
		ThisUpdate: now.Format(time.RFC3339),
		NextUpdate: now.Add(time.Hour).Format(time.RFC3339),
	}

	if certStatus == ocsp.CertStatusRevoked {
		resp.Status.RevokedAt = revocationTime.Format(time.RFC3339)
		resp.Status.RevocationReason = revocationReasonToString(revocationReason)
	}

	return resp, nil
}

// Verify verifies an OCSP response.
func (s *OCSPService) Verify(ctx context.Context, req *dto.OCSPVerifyRequest) (*dto.OCSPVerifyResponse, error) {
	// Decode response
	responseData, err := req.Response.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode OCSP response: %w", err)
	}

	// Build verify config
	config := &ocsp.VerifyConfig{}

	// Parse issuer certificate if provided
	if req.IssuerCert != nil {
		issuerData, err := req.IssuerCert.Decode()
		if err == nil {
			issuer, err := parseCertificateOCSP(issuerData)
			if err == nil {
				config.IssuerCert = issuer
			}
		}
	}

	// Parse certificate being checked if provided
	if req.Certificate != nil {
		certData, err := req.Certificate.Decode()
		if err == nil {
			cert, err := parseCertificateOCSP(certData)
			if err == nil {
				config.Certificate = cert
			}
		}
	}

	// Verify response
	result, err := ocsp.Verify(responseData, config)
	if err != nil {
		return &dto.OCSPVerifyResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	resp := &dto.OCSPVerifyResponse{
		Valid: result.Status == ocsp.StatusSuccessful,
		Status: &dto.OCSPStatus{
			Status: certStatusToString(result.CertStatus),
		},
	}

	if result.CertStatus == ocsp.CertStatusRevoked {
		resp.Status.RevokedAt = result.RevocationTime.Format(time.RFC3339)
		resp.Status.RevocationReason = revocationReasonToString(result.RevocationReason)
	}

	// Add responder info
	if result.ResponderCert != nil {
		resp.ResponderInfo = &dto.OCSPResponderInfo{
			Name: result.ResponderCert.Subject.String(),
			Certificate: &dto.CertChainItem{
				Subject:  result.ResponderCert.Subject.String(),
				Issuer:   result.ResponderCert.Issuer.String(),
				Serial:   hex.EncodeToString(result.ResponderCert.SerialNumber.Bytes()),
				NotAfter: result.ResponderCert.NotAfter.Format(time.RFC3339),
			},
		}
	}

	return resp, nil
}

// loadOCSPResponder creates an OCSP responder using the default CA.
func (s *OCSPService) loadOCSPResponder(ctx context.Context, passphrase string) (*ocsp.Responder, error) {
	// Find the default CA
	caPath, err := s.findDefaultCA()
	if err != nil {
		return nil, fmt.Errorf("failed to find CA: %w", err)
	}

	// Load CA info
	caInfo, err := ca.LoadCAInfo(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	// Get active version
	activeVer := caInfo.ActiveVersion()
	if activeVer == nil {
		return nil, fmt.Errorf("no active version for CA")
	}

	if len(activeVer.Algos) == 0 {
		return nil, fmt.Errorf("no algorithms in active version")
	}

	algo := activeVer.Algos[0]
	certPath := caInfo.CertPath(caInfo.Active, algo)
	keyPath := caInfo.KeyPath(caInfo.Active, algo)

	// Load CA certificate
	caCert, err := loadCertFromFileOCSP(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load signer
	signer, err := pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Create CA store for index access
	store := ca.NewFileStore(caPath)

	// Create responder
	config := &ocsp.ResponderConfig{
		ResponderCert: caCert,
		Signer:        signer,
		CACert:        caCert,
		CAStore:       store,
		Validity:      time.Hour,
		IncludeCerts:  true,
	}

	return ocsp.NewResponder(config)
}

// findDefaultCA finds the default CA directory.
func (s *OCSPService) findDefaultCA() (string, error) {
	// Check for default CA in standard locations
	possiblePaths := []string{
		filepath.Join(s.baseDir, "ca"),
		filepath.Join(s.baseDir, "root-ca"),
		s.baseDir,
	}

	for _, p := range possiblePaths {
		if credential.CredentialExists(p) {
			return p, nil
		}
	}

	// Search for any CA directory
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to read base directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			caPath := filepath.Join(s.baseDir, entry.Name())
			if credential.CredentialExists(caPath) {
				return caPath, nil
			}
		}
	}

	return "", fmt.Errorf("no CA found in %s", s.baseDir)
}

// loadCertFromFileOCSP loads a certificate from a PEM file.
func loadCertFromFileOCSP(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificateOCSP(data)
}

// parseCertificateOCSP parses a certificate from PEM or DER format.
func parseCertificateOCSP(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}

// certStatusToString converts an OCSP cert status to string.
func certStatusToString(status ocsp.CertStatus) string {
	switch status {
	case ocsp.CertStatusGood:
		return "good"
	case ocsp.CertStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// revocationReasonToString converts a revocation reason to string.
func revocationReasonToString(reason ocsp.RevocationReason) string {
	switch reason {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "caCompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aaCompromise"
	default:
		return "unknown"
	}
}
