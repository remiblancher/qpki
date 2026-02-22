// Package pki provides the public API for qpki.
// This file exposes CA operations from internal/ca.
package pki

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/remiblancher/qpki/internal/ca"
	"github.com/remiblancher/qpki/internal/profile"
)

// Re-export types from internal/ca
type (
	// CA represents a Certificate Authority.
	CA = ca.CA

	// FileStore is a file-based certificate store.
	FileStore = ca.FileStore

	// Config holds CA initialization configuration.
	Config = ca.Config

	// IssueRequest holds parameters for certificate issuance.
	IssueRequest = ca.IssueRequest

	// ProfileInitConfig holds configuration for profile-based initialization.
	ProfileInitConfig = ca.ProfileInitConfig

	// MultiProfileInitConfig holds configuration for multi-profile initialization.
	MultiProfileInitConfig = ca.MultiProfileInitConfig

	// MultiProfileInitResult holds results from multi-profile initialization.
	MultiProfileInitResult = ca.MultiProfileInitResult

	// VerifyChainConfig holds configuration for chain verification.
	VerifyChainConfig = ca.VerifyChainConfig

	// IndexEntry represents an entry in the certificate index.
	IndexEntry = ca.IndexEntry

	// CAError wraps CA operation errors with context.
	CAError = ca.CAError

	// RevocationReason represents reasons for certificate revocation.
	CARevocationReason = ca.RevocationReason

	// CAInfo holds CA metadata.
	CAInfo = ca.CAInfo

	// CAVersion holds version info.
	CAVersion = ca.CAVersion
)

// Re-export sentinel errors from internal/ca
var (
	ErrCertNotFoundCA     = ca.ErrCertNotFound
	ErrCertRevokedCA      = ca.ErrCertRevoked
	ErrCertExpiredCA      = ca.ErrCertExpired
	ErrCANotInitializedCA = ca.ErrCANotInitialized
	ErrInvalidCSRCA       = ca.ErrInvalidCSR
	ErrProfileNotFoundCA  = ca.ErrProfileNotFound
	ErrChainVerification  = ca.ErrChainVerification
	ErrKeyMismatch        = ca.ErrKeyMismatch
)

// Re-export revocation reason constants
const (
	CAReasonUnspecified          = ca.ReasonUnspecified
	CAReasonKeyCompromise        = ca.ReasonKeyCompromise
	CAReasonCACompromise         = ca.ReasonCACompromise
	CAReasonAffiliationChanged   = ca.ReasonAffiliationChanged
	CAReasonSuperseded           = ca.ReasonSuperseded
	CAReasonCessationOfOperation = ca.ReasonCessationOfOperation
	CAReasonCertificateHold      = ca.ReasonCertificateHold
	CAReasonRemoveFromCRL        = ca.ReasonRemoveFromCRL
	CAReasonPrivilegeWithdrawn   = ca.ReasonPrivilegeWithdrawn
	CAReasonAACompromise         = ca.ReasonAACompromise
)

// NewFileStore creates a new file-based certificate store.
func NewFileStore(dir string) *FileStore {
	return ca.NewFileStore(dir)
}

// NewCA creates a new CA instance from a store.
func NewCA(store *FileStore) (*CA, error) {
	return ca.New(store)
}

// InitializeCA initializes a new CA with the given configuration.
func InitializeCA(store *FileStore, cfg Config) (*CA, error) {
	return ca.Initialize(store, cfg)
}

// InitializeMultiProfile initializes a CA with multiple profiles.
func InitializeMultiProfile(dir string, cfg MultiProfileInitConfig) (*MultiProfileInitResult, error) {
	return ca.InitializeMultiProfile(dir, cfg)
}

// VerifyChain verifies a certificate chain.
func VerifyChain(cfg VerifyChainConfig) error {
	return ca.VerifyChain(cfg)
}

// ParseRevocationReason parses a revocation reason string.
func ParseRevocationReason(s string) (CARevocationReason, error) {
	return ca.ParseRevocationReason(s)
}

// LoadCAInfo loads CA info from a file path.
func LoadCAInfo(basePath string) (*CAInfo, error) {
	return ca.LoadCAInfo(basePath)
}

// CAService wraps a CA instance for service layer usage.
type CAService struct {
	ca    *CA
	store *FileStore
}

// NewCAService creates a CA service from a directory.
func NewCAService(dir string) (*CAService, error) {
	store := ca.NewFileStore(dir)
	if !store.Exists() {
		return nil, ErrCANotInitialized
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return nil, err
	}

	return &CAService{
		ca:    caInstance,
		store: store,
	}, nil
}

// CA returns the underlying CA instance.
func (s *CAService) CA() *CA {
	return s.ca
}

// Store returns the underlying store.
func (s *CAService) Store() *FileStore {
	return s.store
}

// Close releases resources.
func (s *CAService) Close() error {
	return s.ca.Close()
}

// LoadSigner loads the CA's signing key.
func (s *CAService) LoadSigner(passphrase string) error {
	return s.ca.LoadSigner(passphrase)
}

// Certificate returns the CA certificate.
func (s *CAService) Certificate() *x509.Certificate {
	return s.ca.Certificate()
}

// Issue issues a new certificate.
func (s *CAService) Issue(ctx context.Context, req IssueRequest) (*x509.Certificate, error) {
	return s.ca.Issue(ctx, req)
}

// Revoke revokes a certificate.
func (s *CAService) Revoke(serial []byte, reason CARevocationReason) error {
	return s.ca.Revoke(serial, reason)
}

// ReadIndex returns all certificate index entries.
func (s *CAService) ReadIndex(ctx context.Context) ([]IndexEntry, error) {
	return s.store.ReadIndex(ctx)
}

// LoadCert loads a certificate by serial.
func (s *CAService) LoadCert(ctx context.Context, serial []byte) (*x509.Certificate, error) {
	return s.store.LoadCert(ctx, serial)
}

// LoadCACert loads the CA certificate.
func (s *CAService) LoadCACert(ctx context.Context) (*x509.Certificate, error) {
	return s.store.LoadCACert(ctx)
}

// Info returns CA metadata.
func (s *CAService) Info() *ca.CAInfo {
	return s.ca.Info()
}

// ProfileService wraps profile operations.
type ProfileService struct{}

// NewProfileService creates a profile service.
func NewProfileService() *ProfileService {
	return &ProfileService{}
}

// LoadProfile loads a profile by name.
func (s *ProfileService) LoadProfile(name string) (*profile.Profile, error) {
	return profile.LoadProfile(name)
}

// ListProfiles lists all available profiles.
func (s *ProfileService) ListProfiles() ([]string, error) {
	return profile.ListBuiltinProfileNames()
}

// BuildSubject builds a certificate subject from profile and variables.
func (s *ProfileService) BuildSubject(prof *profile.Profile, vars map[string]interface{}) (*x509.Certificate, error) {
	varValues := make(profile.VariableValues)
	for k, v := range vars {
		varValues[k] = v
	}
	subject, err := profile.BuildSubjectFromProfile(prof, varValues)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		Subject:  subject,
		NotAfter: time.Now().Add(prof.Validity),
	}, nil
}
