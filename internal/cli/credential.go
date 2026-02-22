package cli

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/qpki/internal/credential"
)

// LoadCredentialVersionCerts loads all certificates from a credential version.
func LoadCredentialVersionCerts(credID, versionID string, versionStore *credential.VersionStore, credStore *credential.FileStore) ([]*x509.Certificate, error) {
	version, err := versionStore.GetVersion(versionID)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	// Try new structure first (certs/ directory)
	certsDir := versionStore.CertsDir(versionID)
	entries, err := os.ReadDir(certsDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "credential.") || !strings.HasSuffix(name, ".pem") {
				continue
			}

			certPath := filepath.Join(certsDir, name)
			data, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}

			profileCerts, err := credential.DecodeCertificatesPEM(data)
			if err != nil {
				continue
			}

			certs = append(certs, profileCerts...)
		}
	}

	// Fallback to old structure if no certs found
	if len(certs) == 0 {
		for _, certRef := range version.Certificates {
			profileDir := versionStore.ProfileDir(versionID, certRef.AlgorithmFamily)
			certPath := filepath.Join(profileDir, "certificates.pem")

			data, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}

			profileCerts, err := credential.DecodeCertificatesPEM(data)
			if err != nil {
				continue
			}

			certs = append(certs, profileCerts...)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in version %s", versionID)
	}

	return certs, nil
}
