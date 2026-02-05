package credential

import (
	"crypto/x509"
	"fmt"
)

// ValidateForUsage validates that a certificate has the required Extended Key Usage.
// Returns nil if the certificate is valid for the specified usage.
func ValidateForUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// If no EKUs are specified, the certificate is valid for any usage
	if len(cert.ExtKeyUsage) == 0 {
		return nil
	}

	// Check if the required usage is present
	for _, eku := range cert.ExtKeyUsage {
		if eku == usage {
			return nil
		}
		// ExtKeyUsageAny allows any usage
		if eku == x509.ExtKeyUsageAny {
			return nil
		}
	}

	return fmt.Errorf("certificate does not have required EKU: %s", ekuToString(usage))
}

// ValidateForTimestamping validates that a certificate can be used for timestamping.
// This is a convenience wrapper for ValidateForUsage with ExtKeyUsageTimeStamping.
func ValidateForTimestamping(cert *x509.Certificate) error {
	return ValidateForUsage(cert, x509.ExtKeyUsageTimeStamping)
}

// ValidateForCodeSigning validates that a certificate can be used for code signing.
func ValidateForCodeSigning(cert *x509.Certificate) error {
	return ValidateForUsage(cert, x509.ExtKeyUsageCodeSigning)
}

// ValidateForEmailProtection validates that a certificate can be used for S/MIME.
func ValidateForEmailProtection(cert *x509.Certificate) error {
	return ValidateForUsage(cert, x509.ExtKeyUsageEmailProtection)
}

// ekuToString returns a human-readable name for an ExtKeyUsage.
func ekuToString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsecEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsecTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsecUser"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocspSigning"
	default:
		return fmt.Sprintf("unknown(%d)", usage)
	}
}
