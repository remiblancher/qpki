// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
)

// CredentialService provides credential operations for the REST API.
type CredentialService struct {
	baseDir string
}

// NewCredentialService creates a new CredentialService.
func NewCredentialService(baseDir string) *CredentialService {
	return &CredentialService{baseDir: baseDir}
}

// List returns all credentials.
func (s *CredentialService) List(ctx context.Context, pagination *dto.PaginationRequest) (*dto.CredentialListResponse, error) {
	credDir := filepath.Join(s.baseDir, "credentials")

	entries, err := os.ReadDir(credDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &dto.CredentialListResponse{
				Credentials: []dto.CredentialListItem{},
				Pagination:  dto.PaginationResponse{Total: 0},
			}, nil
		}
		return nil, fmt.Errorf("failed to read credentials directory: %w", err)
	}

	var credentials []dto.CredentialListItem
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		credPath := filepath.Join(credDir, entry.Name())
		if !credential.CredentialExists(credPath) {
			continue
		}

		cred, err := credential.LoadCredential(credPath)
		if err != nil {
			continue
		}

		item := dto.CredentialListItem{
			ID:     entry.Name(),
			Status: "valid",
		}

		// Get info from active version
		activeVer := cred.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			algo := activeVer.Algos[0]
			certPath := cred.CertPath(cred.Active, algo)
			cert, err := loadCertFromFileCred(certPath)
			if err == nil {
				item.Subject = cert.Subject.CommonName
				item.ExpiresAt = cert.NotAfter.Format(time.RFC3339)
				item.Algorithm = algo

				// Check status
				if time.Now().After(cert.NotAfter) {
					item.Status = "expired"
				}
			}
		}

		credentials = append(credentials, item)
	}

	return &dto.CredentialListResponse{
		Credentials: credentials,
		Pagination: dto.PaginationResponse{
			Total: len(credentials),
		},
	}, nil
}

// Get returns information about a specific credential.
func (s *CredentialService) Get(ctx context.Context, credID string) (*dto.CredentialInfoResponse, error) {
	credPath := filepath.Join(s.baseDir, "credentials", credID)
	if !credential.CredentialExists(credPath) {
		return nil, fmt.Errorf("credential not found: %s", credID)
	}

	cred, err := credential.LoadCredential(credPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential: %w", err)
	}

	resp := &dto.CredentialInfoResponse{
		ID:     credID,
		Status: "valid",
	}

	// Get info from active version
	activeVer := cred.ActiveVersion()
	if activeVer != nil && len(activeVer.Algos) > 0 {
		algo := activeVer.Algos[0]
		certPath := cred.CertPath(cred.Active, algo)
		cert, err := loadCertFromFileCred(certPath)
		if err == nil {
			resp.Subject = dto.SubjectInfo{
				CommonName:         cert.Subject.CommonName,
				Organization:       firstOrEmpty(cert.Subject.Organization),
				OrganizationalUnit: firstOrEmpty(cert.Subject.OrganizationalUnit),
				Country:            firstOrEmpty(cert.Subject.Country),
			}
			resp.Issuer = dto.SubjectInfo{
				CommonName:   cert.Issuer.CommonName,
				Organization: firstOrEmpty(cert.Issuer.Organization),
			}
			resp.Serial = hex.EncodeToString(cert.SerialNumber.Bytes())
			resp.Validity = dto.ValidityInfo{
				NotBefore: cert.NotBefore.Format(time.RFC3339),
				NotAfter:  cert.NotAfter.Format(time.RFC3339),
			}
			resp.Algorithm = dto.AlgorithmInfo{
				ID: algo,
			}

			// Check status
			if time.Now().After(cert.NotAfter) {
				resp.Status = "expired"
			}

			// Key usage
			resp.KeyUsage = keyUsageToStrings(cert.KeyUsage)
			resp.ExtKeyUsage = extKeyUsageToStrings(cert.ExtKeyUsage)

			// Include certificate PEM
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			resp.Certificate = string(certPEM)
		}
	}

	return resp, nil
}

// loadCertFromFileCred loads a certificate from a PEM file.
func loadCertFromFileCred(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}

