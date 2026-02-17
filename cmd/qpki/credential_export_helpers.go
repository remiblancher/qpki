package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	"github.com/remiblancher/post-quantum-pki/pkg/credential"
)

// validateExportFlags validates the format and bundle flags for export.
func validateExportFlags(format, bundle string) error {
	if format != "pem" && format != "der" {
		return fmt.Errorf("invalid format: %s (use: pem, der)", format)
	}
	if bundle != "cert" && bundle != "chain" && bundle != "all" {
		return fmt.Errorf("invalid bundle: %s (use: cert, chain, all)", bundle)
	}
	return nil
}

// loadCredentialCertsForExport loads certificates based on version settings.
func loadCredentialCertsForExport(
	credID string,
	version string,
	credStore *credential.FileStore,
	versionStore *credential.VersionStore,
) ([]*x509.Certificate, error) {
	if version != "" {
		return loadCredentialVersionCerts(credID, version, versionStore, credStore)
	}

	if versionStore.IsVersioned() {
		activeVersion, err := versionStore.GetActiveVersion()
		if err != nil {
			return nil, fmt.Errorf("failed to get active version: %w", err)
		}
		return loadCredentialVersionCerts(credID, activeVersion.ID, versionStore, credStore)
	}

	// Non-versioned credential
	return credStore.LoadCertificates(context.Background(), credID)
}

// appendCAChainIfNeeded appends CA certificates to the chain if bundle=chain.
func appendCAChainIfNeeded(certs []*x509.Certificate, bundle, caDir string) ([]*x509.Certificate, error) {
	if bundle != "chain" {
		return certs, nil
	}

	caStore := ca.NewFileStore(caDir)
	caCerts, err := caStore.LoadAllCACerts(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificates for chain: %w", err)
	}
	return append(certs, caCerts...), nil
}

// encodeExportCerts encodes certificates to the specified format.
func encodeExportCerts(certs []*x509.Certificate, format string) ([]byte, error) {
	if format == "der" {
		if len(certs) > 1 {
			return nil, fmt.Errorf("DER format only supports single certificate (use PEM for multiple)")
		}
		if len(certs) > 0 {
			return certs[0].Raw, nil
		}
		return nil, nil
	}

	return credential.EncodeCertificatesPEM(certs)
}

// writeCredExportOutput writes the export data to file or stdout.
func writeCredExportOutput(data []byte, outPath, format string) error {
	if outPath == "" {
		if format == "der" {
			return fmt.Errorf("DER format requires --out file")
		}
		fmt.Print(string(data))
		return nil
	}

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	fmt.Printf("Exported to %s\n", outPath)
	return nil
}
