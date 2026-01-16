package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// crlInfo holds information about a CRL for display.
type crlInfo struct {
	Name       string
	Algorithm  string
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    int
	Status     string
}

// parseCRLFile reads and parses a CRL file, returning its info.
func parseCRLFile(path string, now time.Time) (*crlInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var der []byte
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		der = block.Bytes
	} else {
		der = data
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}

	status := "valid"
	if now.After(crl.NextUpdate) {
		status = "EXPIRED"
	}

	return &crlInfo{
		ThisUpdate: crl.ThisUpdate,
		NextUpdate: crl.NextUpdate,
		Revoked:    len(crl.RevokedCertificateEntries),
		Status:     status,
	}, nil
}

// scanCRLDirectory scans a CRL directory and returns all CRL info.
func scanCRLDirectory(crlDir string, now time.Time) ([]crlInfo, error) {
	entries, err := os.ReadDir(crlDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No CRL directory is not an error
		}
		return nil, fmt.Errorf("failed to read CRL directory: %w", err)
	}

	var crls []crlInfo

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() {
			algoCRLs := scanAlgorithmCRLDir(filepath.Join(crlDir, name), name, now)
			crls = append(crls, algoCRLs...)
			continue
		}

		if !strings.HasSuffix(name, ".crl") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		info, err := parseCRLFile(filepath.Join(crlDir, name), now)
		if err == nil {
			info.Name = name
			info.Algorithm = ""
			crls = append(crls, *info)
		}
	}

	return crls, nil
}

// scanAlgorithmCRLDir scans an algorithm-specific CRL subdirectory.
func scanAlgorithmCRLDir(algoDir, algoName string, now time.Time) []crlInfo {
	var crls []crlInfo

	algoEntries, err := os.ReadDir(algoDir)
	if err != nil {
		return crls
	}

	for _, algoEntry := range algoEntries {
		name := algoEntry.Name()
		if !strings.HasSuffix(name, ".crl") {
			continue
		}

		info, err := parseCRLFile(filepath.Join(algoDir, name), now)
		if err == nil {
			info.Name = name
			info.Algorithm = algoName
			crls = append(crls, *info)
		}
	}

	return crls
}

// printCRLList prints the CRL list in table format.
func printCRLList(crls []crlInfo) {
	fmt.Printf("%-12s %-16s %-18s %-18s %-8s %s\n", "ALGORITHM", "NAME", "THIS UPDATE", "NEXT UPDATE", "REVOKED", "STATUS")
	fmt.Printf("%-12s %-16s %-18s %-18s %-8s %s\n", "---------", "----", "-----------", "-----------", "-------", "------")

	for _, c := range crls {
		algo := c.Algorithm
		if algo == "" {
			algo = "(root)"
		}
		fmt.Printf("%-12s %-16s %-18s %-18s %-8d %s\n",
			algo,
			c.Name,
			c.ThisUpdate.Format("2006-01-02 15:04"),
			c.NextUpdate.Format("2006-01-02 15:04"),
			c.Revoked,
			c.Status,
		)
	}

	fmt.Printf("\nTotal: %d CRL(s)\n", len(crls))
}
