package cose

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// Info contains formatted information about a COSE message.
type Info struct {
	Type        string
	Mode        string
	ContentType string
	Signatures  []SignatureDisplay
	Claims      *ClaimsDisplay
	PayloadSize int
	PayloadHex  string // First 32 bytes in hex
}

// SignatureDisplay contains formatted signature information.
type SignatureDisplay struct {
	Index       int
	Algorithm   string
	AlgorithmID int64
	KeyID       string
	Certificate *CertificateDisplay
}

// CertificateDisplay contains formatted certificate information.
type CertificateDisplay struct {
	Subject    string
	Issuer     string
	NotBefore  string
	NotAfter   string
	SerialHex  string
	Thumbprint string
}

// ClaimsDisplay contains formatted CWT claims information.
type ClaimsDisplay struct {
	Issuer     string
	Subject    string
	Audience   string
	Expiration string
	NotBefore  string
	IssuedAt   string
	CWTID      string
	Custom     map[string]string
	IsExpired  bool
	IsValid    bool
}

// GetInfo returns formatted information about a COSE message.
func GetInfo(data []byte) (*Info, error) {
	msg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	info := &Info{
		Type:        msg.Type.String(),
		Mode:        msg.Mode.String(),
		ContentType: msg.ContentType,
		PayloadSize: len(msg.Payload),
	}

	// Show first 32 bytes of payload in hex
	if len(msg.Payload) > 0 {
		n := 32
		if len(msg.Payload) < n {
			n = len(msg.Payload)
		}
		info.PayloadHex = hex.EncodeToString(msg.Payload[:n])
		if len(msg.Payload) > 32 {
			info.PayloadHex += "..."
		}
	}

	// Add signature info
	for i, sig := range msg.Signatures {
		sigDisplay := SignatureDisplay{
			Index:       i,
			Algorithm:   AlgorithmName(sig.Algorithm),
			AlgorithmID: int64(sig.Algorithm),
		}

		if len(sig.KeyID) > 0 {
			sigDisplay.KeyID = hex.EncodeToString(sig.KeyID)
		}

		if sig.Certificate != nil {
			sigDisplay.Certificate = &CertificateDisplay{
				Subject:    sig.Certificate.Subject.String(),
				Issuer:     sig.Certificate.Issuer.String(),
				NotBefore:  sig.Certificate.NotBefore.Format(time.RFC3339),
				NotAfter:   sig.Certificate.NotAfter.Format(time.RFC3339),
				SerialHex:  sig.Certificate.SerialNumber.Text(16),
				Thumbprint: hex.EncodeToString(CertificateFingerprint(sig.Certificate)),
			}
		}

		info.Signatures = append(info.Signatures, sigDisplay)
	}

	// Add claims info if CWT
	if msg.Claims != nil {
		claims := msg.Claims
		info.Claims = &ClaimsDisplay{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  claims.Audience,
			IsExpired: claims.IsExpired(),
			IsValid:   claims.Validate() == nil,
			Custom:    make(map[string]string),
		}

		if !claims.Expiration.IsZero() {
			info.Claims.Expiration = claims.Expiration.Format(time.RFC3339)
		}
		if !claims.NotBefore.IsZero() {
			info.Claims.NotBefore = claims.NotBefore.Format(time.RFC3339)
		}
		if !claims.IssuedAt.IsZero() {
			info.Claims.IssuedAt = claims.IssuedAt.Format(time.RFC3339)
		}
		if len(claims.CWTID) > 0 {
			info.Claims.CWTID = hex.EncodeToString(claims.CWTID)
		}

		// Format custom claims
		for k, v := range claims.Custom {
			info.Claims.Custom[fmt.Sprintf("%d", k)] = fmt.Sprintf("%v", v)
		}
	}

	return info, nil
}

// Print writes formatted message information to the given writer.
//
//nolint:errcheck // fmt.Fprintf errors are ignored for output formatting
func (info *Info) Print(w io.Writer) {
	fmt.Fprintf(w, "COSE Message Info\n")
	fmt.Fprintf(w, "=================\n\n")

	fmt.Fprintf(w, "Type:         %s\n", info.Type)
	fmt.Fprintf(w, "Mode:         %s\n", info.Mode)
	if info.ContentType != "" {
		fmt.Fprintf(w, "Content-Type: %s\n", info.ContentType)
	}
	fmt.Fprintf(w, "Payload Size: %d bytes\n", info.PayloadSize)
	if info.PayloadHex != "" {
		fmt.Fprintf(w, "Payload:      %s\n", info.PayloadHex)
	}

	fmt.Fprintf(w, "\nSignatures (%d):\n", len(info.Signatures))
	for _, sig := range info.Signatures {
		fmt.Fprintf(w, "  [%d] Algorithm: %s (id=%d)\n", sig.Index, sig.Algorithm, sig.AlgorithmID)
		if sig.KeyID != "" {
			fmt.Fprintf(w, "      Key ID:    %s\n", sig.KeyID)
		}
		if sig.Certificate != nil {
			fmt.Fprintf(w, "      Certificate:\n")
			fmt.Fprintf(w, "        Subject:    %s\n", sig.Certificate.Subject)
			fmt.Fprintf(w, "        Issuer:     %s\n", sig.Certificate.Issuer)
			fmt.Fprintf(w, "        Not Before: %s\n", sig.Certificate.NotBefore)
			fmt.Fprintf(w, "        Not After:  %s\n", sig.Certificate.NotAfter)
			fmt.Fprintf(w, "        Serial:     %s\n", sig.Certificate.SerialHex)
			fmt.Fprintf(w, "        Thumbprint: %s\n", sig.Certificate.Thumbprint)
		}
	}

	if info.Claims != nil {
		fmt.Fprintf(w, "\nCWT Claims:\n")
		if info.Claims.Issuer != "" {
			fmt.Fprintf(w, "  Issuer (iss):     %s\n", info.Claims.Issuer)
		}
		if info.Claims.Subject != "" {
			fmt.Fprintf(w, "  Subject (sub):    %s\n", info.Claims.Subject)
		}
		if info.Claims.Audience != "" {
			fmt.Fprintf(w, "  Audience (aud):   %s\n", info.Claims.Audience)
		}
		if info.Claims.Expiration != "" {
			status := ""
			if info.Claims.IsExpired {
				status = " [EXPIRED]"
			}
			fmt.Fprintf(w, "  Expiration (exp): %s%s\n", info.Claims.Expiration, status)
		}
		if info.Claims.NotBefore != "" {
			fmt.Fprintf(w, "  Not Before (nbf): %s\n", info.Claims.NotBefore)
		}
		if info.Claims.IssuedAt != "" {
			fmt.Fprintf(w, "  Issued At (iat):  %s\n", info.Claims.IssuedAt)
		}
		if info.Claims.CWTID != "" {
			fmt.Fprintf(w, "  CWT ID (cti):     %s\n", info.Claims.CWTID)
		}

		if len(info.Claims.Custom) > 0 {
			fmt.Fprintf(w, "  Custom Claims:\n")
			for k, v := range info.Claims.Custom {
				fmt.Fprintf(w, "    [%s]: %s\n", k, v)
			}
		}

		fmt.Fprintf(w, "\n  Validation: ")
		if info.Claims.IsValid {
			fmt.Fprintf(w, "VALID\n")
		} else {
			fmt.Fprintf(w, "INVALID\n")
		}
	}
}

// String returns the formatted message information as a string.
func (info *Info) String() string {
	var sb strings.Builder
	info.Print(&sb)
	return sb.String()
}

// PrintMessage parses and prints information about a COSE message.
func PrintMessage(w io.Writer, data []byte) error {
	info, err := GetInfo(data)
	if err != nil {
		return err
	}
	info.Print(w)
	return nil
}
