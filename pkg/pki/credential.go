// Package pki provides the public API for qpki.
// This file exposes credential operations from internal/credential.
package pki

import (
	"context"
	"crypto/x509"

	"github.com/remiblancher/qpki/internal/credential"
	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
)

// Re-export credential types
type (
	// CredentialStore is the interface for credential storage.
	CredentialStore = credential.Store

	// CredentialFileStore is a file-based credential store.
	CredentialFileStore = credential.FileStore

	// Credential represents a certificate/key credential.
	Credential = credential.Credential

	// CredentialSubject holds credential subject info.
	CredentialSubject = credential.Subject

	// CertificateRef references a certificate.
	CertificateRef = credential.CertificateRef

	// CredVersion represents a credential version.
	CredVersion = credential.CredVersion

	// EnrollmentRequest holds enrollment parameters.
	EnrollmentRequest = credential.EnrollmentRequest

	// EnrollmentResult holds enrollment results.
	EnrollmentResult = credential.EnrollmentResult

	// MultiProfileEnrollRequest holds multi-profile enrollment parameters.
	MultiProfileEnrollRequest = credential.MultiProfileEnrollRequest

	// MultiProfileEnrollResult holds multi-profile enrollment results.
	MultiProfileEnrollResult = credential.MultiProfileEnrollResult

	// PKISigner is a signer with algorithm info.
	PKISigner = pkicrypto.Signer
)

// NewCredentialFileStore creates a new file-based credential store.
func NewCredentialFileStore(dir string) *CredentialFileStore {
	return credential.NewFileStore(dir)
}

// NewCredential creates a new credential.
func NewCredential(id string, subject CredentialSubject) *Credential {
	return credential.NewCredential(id, subject)
}

// LoadCredential loads a credential from disk.
func LoadCredential(basePath string) (*Credential, error) {
	return credential.LoadCredential(basePath)
}

// CredentialExists checks if a credential exists at the given path.
func CredentialExists(basePath string) bool {
	return credential.CredentialExists(basePath)
}

// CredentialLoadSigner loads a signing credential.
func CredentialLoadSigner(ctx context.Context, store CredentialStore, credID string, passphrase []byte) (*x509.Certificate, PKISigner, error) {
	return credential.LoadSigner(ctx, store, credID, passphrase)
}

// CredentialLoadDecryptionKey loads a decryption key.
func CredentialLoadDecryptionKey(ctx context.Context, store CredentialStore, credID string, passphrase []byte) (*x509.Certificate, interface{}, error) {
	return credential.LoadDecryptionKey(ctx, store, credID, passphrase)
}

// CredentialLoad loads a credential from disk (alias for LoadCredential).
func CredentialLoad(basePath string) (*Credential, error) {
	return credential.LoadCredential(basePath)
}
