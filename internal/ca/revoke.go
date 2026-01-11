package ca

import (
	"context"
	"fmt"
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
	if cert, err := ca.store.LoadCert(context.Background(), serial); err == nil && cert != nil {
		subject = cert.Subject.String()
	}

	// Update index file
	if err := ca.store.MarkRevoked(context.Background(), serial, reason); err != nil {
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
