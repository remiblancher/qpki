// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
)

// CertService provides certificate operations for the REST API.
type CertService struct {
	baseDir string
}

// NewCertService creates a new CertService.
func NewCertService(baseDir string) *CertService {
	return &CertService{baseDir: baseDir}
}

// Issue issues a new certificate.
func (s *CertService) Issue(ctx context.Context, caID string, req *dto.CertIssueRequest) (*dto.CertIssueResponse, error) {
	// Load the CA
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}
	defer func() { _ = caInstance.Close() }()

	// Load signer
	if err := caInstance.LoadSigner(req.Passphrase); err != nil {
		return nil, fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load profile
	prof, err := profile.LoadProfile(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile %s: %w", req.Profile, err)
	}

	// Parse CSR if provided
	var csr *x509.CertificateRequest
	if req.CSR != nil {
		csrData, err := req.CSR.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode CSR: %w", err)
		}

		block, _ := pem.Decode(csrData)
		if block == nil {
			// Try DER
			csr, err = x509.ParseCertificateRequest(csrData)
		} else {
			csr, err = x509.ParseCertificateRequest(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSR: %w", err)
		}

		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("CSR signature verification failed: %w", err)
		}
	}

	// Build certificate template
	template := &x509.Certificate{}

	// Set subject from CSR or variables
	if csr != nil {
		template.Subject = csr.Subject
		template.DNSNames = csr.DNSNames
		template.EmailAddresses = csr.EmailAddresses
		template.IPAddresses = csr.IPAddresses
		template.URIs = csr.URIs
	} else if len(req.Variables) > 0 {
		varValues := make(profile.VariableValues)
		for k, v := range req.Variables {
			varValues[k] = v
		}
		subject, err := profile.BuildSubjectFromProfile(prof, varValues)
		if err != nil {
			return nil, fmt.Errorf("failed to build subject: %w", err)
		}
		template.Subject = subject
	} else {
		return nil, fmt.Errorf("either CSR or variables must be provided")
	}

	// Set validity
	validity := prof.Validity
	if req.ValidityDays > 0 {
		validity = time.Duration(req.ValidityDays) * 24 * time.Hour
	}

	// Get public key
	var pubKey interface{}
	if csr != nil {
		pubKey = csr.PublicKey
	} else {
		return nil, fmt.Errorf("CSR is required for certificate issuance")
	}

	// Issue certificate
	issueReq := ca.IssueRequest{
		Template:   template,
		PublicKey:  pubKey,
		Extensions: prof.Extensions,
		Validity:   validity,
	}

	cert, err := caInstance.Issue(ctx, issueReq)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	// Build response
	fingerprint := sha256.Sum256(cert.Raw)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Get CA certificate for chain
	caCert := caInstance.Certificate()
	chainPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	return &dto.CertIssueResponse{
		Serial:  hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: subjectToDTO(cert.Subject),
		Issuer:  subjectToDTO(cert.Issuer),
		Algorithm: dto.AlgorithmInfo{
			ID:          getAlgorithmName(cert),
			Description: cert.SignatureAlgorithm.String(),
		},
		Validity: dto.ValidityInfo{
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
		},
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		Certificate: string(certPEM),
		Chain:       string(chainPEM),
	}, nil
}

// List returns a list of certificates for a CA.
func (s *CertService) List(ctx context.Context, caID string, pagination *dto.PaginationRequest) (*dto.CertListResponse, error) {
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	// Read index
	entries, err := store.ReadIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate index: %w", err)
	}

	// Build list items
	var items []dto.CertListItem
	now := time.Now()
	for _, entry := range entries {
		status := "valid"
		if entry.Status == "R" {
			status = "revoked"
		} else if entry.Expiry.Before(now) {
			status = "expired"
		}

		items = append(items, dto.CertListItem{
			Serial:    hex.EncodeToString(entry.Serial),
			Subject:   entry.Subject,
			Status:    status,
			NotAfter:  entry.Expiry.Format(time.RFC3339),
			Algorithm: "", // Would need to load cert for this
		})
	}

	// Apply pagination
	total := len(items)
	limit := 100
	offset := 0
	if pagination != nil {
		if pagination.Limit > 0 {
			limit = pagination.Limit
		}
		offset = pagination.Offset
	}

	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return &dto.CertListResponse{
		Certificates: items[start:end],
		Pagination: dto.PaginationResponse{
			Total:   total,
			Limit:   limit,
			Offset:  offset,
			HasMore: end < total,
		},
	}, nil
}

// Get returns information about a certificate.
func (s *CertService) Get(ctx context.Context, caID string, serial string) (*dto.CertInfoResponse, error) {
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	// Parse serial
	serialBytes, err := hex.DecodeString(serial)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}

	// Load certificate
	cert, err := store.LoadCert(ctx, serialBytes)
	if err != nil {
		return nil, ca.ErrCertNotFound
	}

	// Get status from index
	entries, err := store.ReadIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate index: %w", err)
	}

	status := "valid"
	var revInfo *dto.RevocationInfo
	now := time.Now()

	for _, entry := range entries {
		if hex.EncodeToString(entry.Serial) == serial {
			if entry.Status == "R" {
				status = "revoked"
				revInfo = &dto.RevocationInfo{
					RevokedAt:  entry.Revocation.Format(time.RFC3339),
					Reason:     entry.RevocationReason.String(),
					ReasonCode: int(entry.RevocationReason),
				}
			} else if entry.Expiry.Before(now) {
				status = "expired"
			}
			break
		}
	}

	fingerprint := sha256.Sum256(cert.Raw)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	resp := &dto.CertInfoResponse{
		Serial:  serial,
		Subject: subjectToDTO(cert.Subject),
		Issuer:  subjectToDTO(cert.Issuer),
		Algorithm: dto.AlgorithmInfo{
			ID:          getAlgorithmName(cert),
			Description: cert.SignatureAlgorithm.String(),
		},
		Validity: dto.ValidityInfo{
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
		},
		Fingerprint:    hex.EncodeToString(fingerprint[:]),
		Status:         status,
		RevocationInfo: revInfo,
		KeyUsage:       keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:    extKeyUsageToStrings(cert.ExtKeyUsage),
		Certificate:    string(certPEM),
	}

	// Add SANs if present
	if len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 || len(cert.IPAddresses) > 0 || len(cert.URIs) > 0 {
		resp.SANs = &dto.SANInfo{
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
		for _, ip := range cert.IPAddresses {
			resp.SANs.IPAddresses = append(resp.SANs.IPAddresses, ip.String())
		}
		for _, uri := range cert.URIs {
			resp.SANs.URIs = append(resp.SANs.URIs, uri.String())
		}
	}

	return resp, nil
}

// Revoke revokes a certificate.
func (s *CertService) Revoke(ctx context.Context, caID string, serial string, req *dto.CertRevokeRequest) (*dto.CertRevokeResponse, error) {
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}
	defer func() { _ = caInstance.Close() }()

	// Load signer
	passphrase := ""
	if req != nil {
		passphrase = req.Passphrase
	}
	if err := caInstance.LoadSigner(passphrase); err != nil {
		return nil, fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Parse serial
	serialBytes, err := hex.DecodeString(serial)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}

	// Parse reason
	reason := ca.ReasonUnspecified
	if req != nil && req.Reason != "" {
		reason, err = ca.ParseRevocationReason(req.Reason)
		if err != nil {
			return nil, fmt.Errorf("invalid revocation reason: %w", err)
		}
	}

	// Revoke
	if err := caInstance.Revoke(serialBytes, reason); err != nil {
		return nil, fmt.Errorf("failed to revoke certificate: %w", err)
	}

	return &dto.CertRevokeResponse{
		Serial:    serial,
		RevokedAt: time.Now().Format(time.RFC3339),
		Reason:    reason.String(),
	}, nil
}

// Verify verifies a certificate against the CA.
func (s *CertService) Verify(ctx context.Context, caID string, req *dto.CertVerifyRequest) (*dto.CertVerifyResponse, error) {
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	// Decode certificate
	certData, err := req.Certificate.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	var cert *x509.Certificate
	if block == nil {
		cert, err = x509.ParseCertificate(certData)
	} else {
		cert, err = x509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := store.LoadCACert(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Determine verification time
	verifyTime := time.Now()
	if req.At != "" {
		verifyTime, err = time.Parse(time.RFC3339, req.At)
		if err != nil {
			return nil, fmt.Errorf("invalid verification time: %w", err)
		}
	}

	// Build response
	resp := &dto.CertVerifyResponse{
		Valid:  true,
		Errors: []string{},
		Chain: []dto.CertChainItem{
			{
				Subject:  cert.Subject.String(),
				Issuer:   cert.Issuer.String(),
				Serial:   hex.EncodeToString(cert.SerialNumber.Bytes()),
				NotAfter: cert.NotAfter.Format(time.RFC3339),
			},
			{
				Subject:  caCert.Subject.String(),
				Issuer:   caCert.Issuer.String(),
				Serial:   hex.EncodeToString(caCert.SerialNumber.Bytes()),
				NotAfter: caCert.NotAfter.Format(time.RFC3339),
			},
		},
	}

	// Verify chain
	verifyErr := ca.VerifyChain(ca.VerifyChainConfig{
		Leaf: cert,
		Root: caCert,
		Time: verifyTime,
	})
	if verifyErr != nil {
		resp.Valid = false
		resp.Errors = append(resp.Errors, verifyErr.Error())
	}

	// Check revocation if requested
	if req.CheckRevocation {
		entries, err := store.ReadIndex(ctx)
		if err == nil {
			certSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
			for _, entry := range entries {
				if hex.EncodeToString(entry.Serial) == certSerial && entry.Status == "R" {
					resp.Valid = false
					resp.Errors = append(resp.Errors, "certificate has been revoked")
					resp.RevocationStatus = &dto.RevocationStatus{
						Checked: true,
						Revoked: true,
						Method:  "index",
						Details: []dto.RevocationDetail{
							{
								Serial:    certSerial,
								Status:    "revoked",
								RevokedAt: entry.Revocation.Format(time.RFC3339),
								Reason:    entry.RevocationReason.String(),
							},
						},
					}
					break
				}
			}
			if resp.RevocationStatus == nil {
				resp.RevocationStatus = &dto.RevocationStatus{
					Checked: true,
					Revoked: false,
					Method:  "index",
				}
			}
		}
	}

	return resp, nil
}

// Helper functions

func keyUsageToStrings(ku x509.KeyUsage) []string {
	var result []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		result = append(result, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		result = append(result, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		result = append(result, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		result = append(result, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		result = append(result, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		result = append(result, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		result = append(result, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		result = append(result, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		result = append(result, "decipherOnly")
	}
	return result
}

func extKeyUsageToStrings(ekus []x509.ExtKeyUsage) []string {
	var result []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			result = append(result, "any")
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "emailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			result = append(result, "ipsecEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			result = append(result, "ipsecTunnel")
		case x509.ExtKeyUsageIPSECUser:
			result = append(result, "ipsecUser")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "ocspSigning")
		default:
			result = append(result, fmt.Sprintf("unknown(%d)", eku))
		}
	}
	return result
}
