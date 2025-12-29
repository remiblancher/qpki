package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
)

// RevocationReason represents the reason for certificate revocation.
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
	ReasonPrivilegeWithdrawn   RevocationReason = 9
	ReasonAACompromise         RevocationReason = 10
)

// String returns a human-readable name for the reason.
func (r RevocationReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonCACompromise:
		return "caCompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	case ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ReasonAACompromise:
		return "aaCompromise"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// ParseRevocationReason parses a reason string.
func ParseRevocationReason(s string) (RevocationReason, error) {
	switch strings.ToLower(s) {
	case "unspecified", "":
		return ReasonUnspecified, nil
	case "keycompromise", "key-compromise":
		return ReasonKeyCompromise, nil
	case "cacompromise", "ca-compromise":
		return ReasonCACompromise, nil
	case "affiliationchanged", "affiliation-changed":
		return ReasonAffiliationChanged, nil
	case "superseded":
		return ReasonSuperseded, nil
	case "cessationofoperation", "cessation":
		return ReasonCessationOfOperation, nil
	case "certificatehold", "hold":
		return ReasonCertificateHold, nil
	case "privilegewithdrawn":
		return ReasonPrivilegeWithdrawn, nil
	default:
		return 0, fmt.Errorf("unknown revocation reason: %s", s)
	}
}

// RevokedCertificate represents a revoked certificate.
type RevokedCertificate struct {
	Serial    []byte
	RevokedAt time.Time
	Reason    RevocationReason
	Subject   string
}

// Revoke revokes a certificate by its serial number.
func (ca *CA) Revoke(serial []byte, reason RevocationReason) error {
	if ca.signer == nil {
		return fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// Try to get the certificate subject for audit logging
	subject := ""
	if cert, err := ca.store.LoadCert(serial); err == nil && cert != nil {
		subject = cert.Subject.String()
	}

	// Update index file
	if err := ca.store.MarkRevoked(serial, reason); err != nil {
		return fmt.Errorf("failed to mark certificate as revoked: %w", err)
	}

	// Audit: certificate revoked successfully
	if err := audit.LogCertRevoked(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", serial),
		subject,
		reason.String(),
		true,
	); err != nil {
		return err
	}

	return nil
}

// GenerateCRL generates a Certificate Revocation List.
//
// For PQC signers (ML-DSA, SLH-DSA), this delegates to GeneratePQCCRL since
// Go's crypto/x509.CreateRevocationList doesn't support PQC algorithms.
func (ca *CA) GenerateCRL(nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// Delegate to PQC implementation if using a PQC signer
	if ca.IsPQCSigner() {
		crlDER, err := ca.GeneratePQCCRL(nextUpdate)
		if err != nil {
			return nil, err
		}

		// Save CRL
		if err := ca.store.SaveCRL(crlDER); err != nil {
			return nil, fmt.Errorf("failed to save CRL: %w", err)
		}

		// Get count of revoked certs for audit
		entries, _ := ca.store.ReadIndex()
		revokedCount := 0
		for _, e := range entries {
			if e.Status == "R" {
				revokedCount++
			}
		}

		// Audit: CRL generated successfully
		if err := audit.LogCRLGenerated(ca.store.BasePath(), revokedCount, true); err != nil {
			return nil, err
		}

		return crlDER, nil
	}

	// Get all revoked certificates
	entries, err := ca.store.ReadIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		revoked := pkix.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		}
		revokedCerts = append(revokedCerts, revoked)
	}

	// Get CRL number
	crlNumber, err := ca.store.NextCRLNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	template := &x509.RevocationList{
		RevokedCertificates: revokedCerts,
		Number:              new(big.Int).SetBytes(crlNumber),
		ThisUpdate:          time.Now(),
		NextUpdate:          nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	// Save CRL
	if err := ca.store.SaveCRL(crlDER); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedCerts), true); err != nil {
		return nil, err
	}

	return crlDER, nil
}

// MarkRevoked marks a certificate as revoked in the index file.
func (s *Store) MarkRevoked(serial []byte, reason RevocationReason) error {
	indexPath := filepath.Join(s.basePath, "index.txt")

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index file: %w", err)
	}

	serialHex := hex.EncodeToString(serial)
	lines := splitLines(string(data))
	var newLines []string
	found := false

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := splitTabs(line)
		if len(parts) >= 4 && parts[3] == serialHex {
			// Update this line - change V to R and add revocation date
			parts[0] = "R"
			parts[2] = time.Now().UTC().Format("060102150405Z")
			line = strings.Join(parts, "\t")
			found = true
		}
		newLines = append(newLines, line)
	}

	if !found {
		return fmt.Errorf("certificate with serial %s not found", serialHex)
	}

	content := strings.Join(newLines, "\n") + "\n"
	if err := os.WriteFile(indexPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write index file: %w", err)
	}

	return nil
}

// NextCRLNumber returns the next CRL number and increments the counter.
func (s *Store) NextCRLNumber() ([]byte, error) {
	crlNumPath := filepath.Join(s.basePath, "crlnumber")

	// Initialize if doesn't exist
	if _, err := os.Stat(crlNumPath); os.IsNotExist(err) {
		if err := os.WriteFile(crlNumPath, []byte("01\n"), 0644); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(crlNumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read crlnumber file: %w", err)
	}

	numHex := strings.TrimSpace(string(data))
	num, err := hex.DecodeString(numHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL number: %w", err)
	}

	// Increment for next use
	next := incrementSerial(num)
	if err := os.WriteFile(crlNumPath, []byte(hex.EncodeToString(next)+"\n"), 0644); err != nil {
		return nil, err
	}

	return num, nil
}

// SaveCRL saves the CRL to the store.
func (s *Store) SaveCRL(crlDER []byte) error {
	crlPath := filepath.Join(s.basePath, "crl", "ca.crl")

	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}

	f, err := os.OpenFile(crlPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create CRL file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Also save as DER
	derPath := filepath.Join(s.basePath, "crl", "ca.crl.der")
	if err := os.WriteFile(derPath, crlDER, 0644); err != nil {
		return fmt.Errorf("failed to write DER CRL: %w", err)
	}

	return nil
}

// CRLPath returns the path to the current CRL.
func (s *Store) CRLPath() string {
	return filepath.Join(s.basePath, "crl", "ca.crl")
}

// LoadCRL loads the current CRL from the store.
func (s *Store) LoadCRL() (*x509.RevocationList, error) {
	data, err := os.ReadFile(s.CRLPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No CRL yet
		}
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("no CRL found in file")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

// ListRevoked returns all revoked certificates.
func (s *Store) ListRevoked() ([]RevokedCertificate, error) {
	entries, err := s.ReadIndex()
	if err != nil {
		return nil, err
	}

	var revoked []RevokedCertificate
	for _, e := range entries {
		if e.Status != "R" {
			continue
		}

		revoked = append(revoked, RevokedCertificate{
			Serial:    e.Serial,
			RevokedAt: e.Revocation,
			Subject:   e.Subject,
		})
	}

	return revoked, nil
}

// IsRevoked checks if a certificate is revoked.
func (s *Store) IsRevoked(serial []byte) (bool, error) {
	entries, err := s.ReadIndex()
	if err != nil {
		return false, err
	}

	serialHex := hex.EncodeToString(serial)
	for _, e := range entries {
		if hex.EncodeToString(e.Serial) == serialHex {
			return e.Status == "R", nil
		}
	}

	return false, fmt.Errorf("certificate not found")
}
