package cli

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/remiblancher/qpki/internal/ca"
	"github.com/remiblancher/qpki/internal/ocsp"
)

// CheckCRL checks if a certificate is revoked using a CRL file.
func CheckCRL(cert, issuer *x509.Certificate, crlPath string) (revoked bool, reason string, revokedAt time.Time, err error) {
	// Read CRL file
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to read CRL: %w", err)
	}

	// Try PEM first
	var crlDER []byte
	if block, _ := pem.Decode(data); block != nil {
		crlDER = block.Bytes
	} else {
		// Assume DER
		crlDER = data
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify CRL signature - handle PQC and classical algorithms
	var sigErr error

	// Check if CRL uses a PQC signature algorithm
	sigAlgOID, extractErr := ca.ExtractCRLSignatureAlgorithmOID(crlDER)
	if extractErr == nil && ca.IsPQCSignatureOID(sigAlgOID) {
		// Use PQC verification
		valid, verifyErr := ca.VerifyPQCCRL(crlDER, issuer)
		if verifyErr != nil {
			sigErr = verifyErr
		} else if !valid {
			sigErr = fmt.Errorf("PQC signature verification failed")
		}
	} else {
		// Use standard Go verification for classical algorithms
		sigErr = crl.CheckSignatureFrom(issuer)
	}

	if sigErr != nil {
		return false, "", time.Time{}, fmt.Errorf("CRL signature verification failed: %w", sigErr)
	}

	// Check if CRL is current
	if time.Now().After(crl.NextUpdate) {
		fmt.Printf("%sWarning: CRL has expired (NextUpdate: %s)%s\n",
			ColorYellow, crl.NextUpdate.Format("2006-01-02"), ColorReset)
	}

	// Search for certificate serial in revoked list
	for _, revCert := range crl.RevokedCertificateEntries {
		if revCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			reasonStr := GetRevocationReasonString(revCert.ReasonCode)
			return true, reasonStr, revCert.RevocationTime, nil
		}
	}

	return false, "", time.Time{}, nil
}

// CheckOCSP checks if a certificate is revoked using OCSP.
func CheckOCSP(cert, issuer *x509.Certificate, ocspURL string) (revoked bool, reason string, revokedAt time.Time, err error) {
	// Generate nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create OCSP request
	req, err := ocsp.CreateRequestWithNonce(issuer, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	reqData, err := req.Marshal()
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to marshal OCSP request: %w", err)
	}

	// Send HTTP request
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(reqData))
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("OCSP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, "", time.Time{}, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	// Verify response
	verifyConfig := &ocsp.VerifyConfig{
		IssuerCert:  issuer,
		Certificate: cert,
	}

	result, err := ocsp.Verify(respData, verifyConfig)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("OCSP verification failed: %w", err)
	}

	if result.CertStatus == ocsp.CertStatusRevoked {
		reasonStr := GetOCSPRevocationReasonString(result.RevocationReason)
		return true, reasonStr, result.RevocationTime, nil
	}

	return false, "", time.Time{}, nil
}

// GetRevocationReasonString returns a human-readable revocation reason from CRL.
func GetRevocationReasonString(code int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}
	if r, ok := reasons[code]; ok {
		return r
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// GetOCSPRevocationReasonString returns a human-readable revocation reason from OCSP.
func GetOCSPRevocationReasonString(reason ocsp.RevocationReason) string {
	reasons := map[ocsp.RevocationReason]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}
	if r, ok := reasons[reason]; ok {
		return r
	}
	return fmt.Sprintf("unknown (%d)", reason)
}
