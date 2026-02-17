// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// CAService provides CA operations for the REST API.
type CAService struct {
	baseDir string
}

// NewCAService creates a new CAService.
func NewCAService(baseDir string) *CAService {
	return &CAService{baseDir: baseDir}
}

// Initialize creates a new CA.
func (s *CAService) Initialize(ctx context.Context, req *dto.CAInitRequest) (*dto.CAInitResponse, error) {
	// Determine profiles to use
	profiles := req.Profiles
	if len(profiles) == 0 && req.Profile != "" {
		profiles = []string{req.Profile}
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("profile is required")
	}

	// Load and validate profile
	prof, err := profile.LoadProfile(profiles[0])
	if err != nil {
		return nil, fmt.Errorf("failed to load profile %s: %w", profiles[0], err)
	}

	// Convert variables to profile.VariableValues
	varValues := make(profile.VariableValues)
	for k, v := range req.Variables {
		varValues[k] = v
	}

	// Build subject from variables
	subject, err := profile.BuildSubjectFromProfile(prof, varValues)
	if err != nil {
		return nil, fmt.Errorf("failed to build subject: %w", err)
	}

	// Get algorithm info
	alg := prof.GetAlgorithm()
	if alg == "" {
		return nil, fmt.Errorf("profile %s has no algorithm defined", profiles[0])
	}

	// Determine CA directory
	caDir := filepath.Join(s.baseDir, sanitizeCAName(subject.CommonName))
	if _, err := os.Stat(caDir); err == nil {
		return nil, fmt.Errorf("CA already exists at %s", caDir)
	}

	// Create store
	store := ca.NewFileStore(caDir)

	// Build config - convert validity duration to years
	validityYears := int(prof.Validity.Hours() / 24 / 365)
	if validityYears <= 0 {
		validityYears = 10 // Default to 10 years
	}
	if req.ValidityYears > 0 {
		validityYears = req.ValidityYears
	}

	// Get path length from extensions
	pathLen := 1 // Default
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
		pathLen = *prof.Extensions.BasicConstraints.PathLen
	}
	if req.PathLen > 0 {
		pathLen = req.PathLen
	}

	cfg := ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     alg,
		ValidityYears: validityYears,
		PathLen:       pathLen,
		Passphrase:    req.Passphrase,
		Profile:       profiles[0],
		Extensions:    prof.Extensions,
	}

	// Handle subordinate CA
	if req.ParentCA != "" {
		return s.initializeSubordinate(ctx, store, cfg, req, prof)
	}

	// Initialize root CA
	newCA, err := ca.Initialize(store, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}
	defer func() { _ = newCA.Close() }()

	return buildCAInitResponse(newCA, caDir)
}

// initializeSubordinate creates a subordinate CA signed by a parent.
func (s *CAService) initializeSubordinate(ctx context.Context, store *ca.FileStore, cfg ca.Config, req *dto.CAInitRequest, prof *profile.Profile) (*dto.CAInitResponse, error) {
	// Load parent CA
	parentStore := ca.NewFileStore(req.ParentCA)
	if !parentStore.Exists() {
		return nil, fmt.Errorf("parent CA not found at %s", req.ParentCA)
	}

	parentCA, err := ca.New(parentStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load parent CA: %w", err)
	}
	defer func() { _ = parentCA.Close() }()

	// Load parent signer
	if err := parentCA.LoadSigner(req.ParentPassphrase); err != nil {
		return nil, fmt.Errorf("failed to load parent CA signer: %w", err)
	}

	// TODO: Implement subordinate CA initialization
	// This requires IssueCertificate functionality
	return nil, fmt.Errorf("subordinate CA initialization not yet implemented via API")
}

// Get returns information about a CA.
func (s *CAService) Get(ctx context.Context, caID string) (*dto.CAInfoResponse, error) {
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

	return buildCAInfoResponse(caInstance, caID)
}

// List returns a list of CAs.
func (s *CAService) List(ctx context.Context, pagination *dto.PaginationRequest) (*dto.CAListResponse, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &dto.CAListResponse{
				CAs: []dto.CAListItem{},
				Pagination: dto.PaginationResponse{
					Total:   0,
					Limit:   100,
					Offset:  0,
					HasMore: false,
				},
			}, nil
		}
		return nil, fmt.Errorf("failed to read CA directory: %w", err)
	}

	var items []dto.CAListItem
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		caDir := filepath.Join(s.baseDir, entry.Name())
		store := ca.NewFileStore(caDir)
		if !store.Exists() {
			continue
		}

		cert, err := store.LoadCACert(ctx)
		if err != nil {
			continue
		}

		caType := "root"
		if cert.Subject.String() != cert.Issuer.String() {
			caType = "subordinate"
		}

		items = append(items, dto.CAListItem{
			ID:        entry.Name(),
			Subject:   cert.Subject.CommonName,
			Type:      caType,
			Algorithm: getAlgorithmName(cert),
			ExpiresAt: cert.NotAfter.Format(time.RFC3339),
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

	return &dto.CAListResponse{
		CAs: items[start:end],
		Pagination: dto.PaginationResponse{
			Total:   total,
			Limit:   limit,
			Offset:  offset,
			HasMore: end < total,
		},
	}, nil
}

// Export exports CA certificates.
func (s *CAService) Export(ctx context.Context, caID string, req *dto.CAExportRequest) (*dto.CAExportResponse, error) {
	caDir := filepath.Join(s.baseDir, caID)
	store := ca.NewFileStore(caDir)
	if !store.Exists() {
		return nil, ca.ErrCANotInitialized
	}

	bundle := req.Bundle
	if bundle == "" {
		bundle = "ca"
	}

	var certs []*x509.Certificate

	switch bundle {
	case "ca":
		cert, err := store.LoadCACert(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		certs = []*x509.Certificate{cert}

	case "chain":
		chainPath := filepath.Join(caDir, "chain.crt")
		chainData, err := os.ReadFile(chainPath)
		if err != nil {
			// No chain file, return just CA cert
			cert, err := store.LoadCACert(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to load CA certificate: %w", err)
			}
			certs = []*x509.Certificate{cert}
		} else {
			certs, err = parseCertificatesPEM(chainData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse chain: %w", err)
			}
		}

	case "root":
		// Find root in chain or return CA if it's root
		chainPath := filepath.Join(caDir, "chain.crt")
		chainData, err := os.ReadFile(chainPath)
		if err != nil {
			cert, err := store.LoadCACert(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to load CA certificate: %w", err)
			}
			certs = []*x509.Certificate{cert}
		} else {
			chain, err := parseCertificatesPEM(chainData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse chain: %w", err)
			}
			// Root is last in chain
			if len(chain) > 0 {
				certs = []*x509.Certificate{chain[len(chain)-1]}
			}
		}

	default:
		return nil, fmt.Errorf("invalid bundle type: %s", bundle)
	}

	// Encode certificates
	var certDatas []dto.BinaryData
	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		certDatas = append(certDatas, dto.BinaryData{
			Data:     string(pem.EncodeToMemory(pemBlock)),
			Encoding: "pem",
		})
	}

	return &dto.CAExportResponse{
		Certificates: certDatas,
		Bundle:       bundle,
	}, nil
}

// Helper functions

func buildCAInitResponse(caInstance *ca.CA, caDir string) (*dto.CAInitResponse, error) {
	cert := caInstance.Certificate()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	fingerprint := sha256.Sum256(cert.Raw)

	return &dto.CAInitResponse{
		ID:      filepath.Base(caDir),
		Subject: subjectToDTO(cert.Subject),
		Algorithm: dto.AlgorithmInfo{
			ID:          getAlgorithmName(cert),
			Description: cert.SignatureAlgorithm.String(),
		},
		Validity: dto.ValidityInfo{
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
		},
		Serial:      hex.EncodeToString(cert.SerialNumber.Bytes()),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		Certificate: string(certPEM),
		CADir:       caDir,
	}, nil
}

func buildCAInfoResponse(caInstance *ca.CA, caID string) (*dto.CAInfoResponse, error) {
	cert := caInstance.Certificate()

	fingerprint := sha256.Sum256(cert.Raw)

	isRoot := cert.Subject.String() == cert.Issuer.String()

	pathLen := -1
	if cert.MaxPathLenZero || cert.MaxPathLen >= 0 {
		pathLen = cert.MaxPathLen
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	resp := &dto.CAInfoResponse{
		ID:      caID,
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
		Serial:      hex.EncodeToString(cert.SerialNumber.Bytes()),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		IsRoot:      isRoot,
		PathLen:     pathLen,
		Certificate: string(certPEM),
	}

	// Add version info if available
	info := caInstance.Info()
	if info != nil && len(info.Versions) > 0 {
		for versionID, version := range info.Versions {
			resp.Versions = append(resp.Versions, dto.CAVersionInfo{
				ID:         versionID,
				Algorithms: version.Algos,
				Profiles:   version.Profiles,
				CreatedAt:  version.Created.Format(time.RFC3339),
				Active:     versionID == info.Active,
			})
		}
		resp.ActiveVersion = info.Active
	}

	return resp, nil
}

func subjectToDTO(name pkix.Name) dto.SubjectInfo {
	return dto.SubjectInfo{
		CommonName:         name.CommonName,
		Organization:       firstOrEmpty(name.Organization),
		OrganizationalUnit: firstOrEmpty(name.OrganizationalUnit),
		Country:            firstOrEmpty(name.Country),
		State:              firstOrEmpty(name.Province),
		Locality:           firstOrEmpty(name.Locality),
	}
}

func getAlgorithmName(cert *x509.Certificate) string {
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}

	// For PQC algorithms, extract OID from raw certificate
	oid, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return "Unknown"
	}

	return x509util.AlgorithmName(oid)
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func sanitizeCAName(name string) string {
	// Replace spaces and special chars with hyphens
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ToLower(name)
	return name
}

func parseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		data = rest
	}
	return certs, nil
}
