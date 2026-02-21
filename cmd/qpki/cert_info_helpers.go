package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/remiblancher/qpki/pkg/ca"
)

// keyUsageNames maps KeyUsage bits to their string names.
var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// getKeyUsageNames converts KeyUsage flags to a list of string names.
func getKeyUsageNames(ku x509.KeyUsage) []string {
	var result []string
	for _, item := range keyUsageNames {
		if ku&item.bit != 0 {
			result = append(result, item.name)
		}
	}
	return result
}

// extKeyUsageNames maps ExtKeyUsage values to their string names.
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
}

// getExtKeyUsageNames converts ExtKeyUsage values to a list of string names.
func getExtKeyUsageNames(ekus []x509.ExtKeyUsage) []string {
	var result []string
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			result = append(result, name)
		}
	}
	return result
}

// formatSANs extracts all Subject Alternative Names from a certificate.
func formatSANs(cert *x509.Certificate) []string {
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "Email:"+email)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}
	return sans
}

// getCertStatus determines the status of a certificate from the CA index.
func getCertStatus(entries []ca.IndexEntry, serialHex string) string {
	for _, e := range entries {
		if hex.EncodeToString(e.Serial) != serialHex {
			continue
		}
		switch e.Status {
		case "V":
			if !e.Expiry.IsZero() && e.Expiry.Before(time.Now()) {
				return "Expired"
			}
			return "Valid"
		case "R":
			if !e.Revocation.IsZero() {
				return fmt.Sprintf("Revoked (%s)", e.Revocation.Format("2006-01-02"))
			}
			return "Revoked"
		case "E":
			return "Expired"
		}
	}
	return "Valid"
}

// formatPathLen formats the path length constraint for display.
func formatPathLen(cert *x509.Certificate) string {
	if !cert.IsCA {
		return ""
	}
	if cert.MaxPathLen >= 0 && cert.MaxPathLenZero {
		return "0"
	}
	if cert.MaxPathLen >= 0 {
		return fmt.Sprintf("%d", cert.MaxPathLen)
	}
	return "unlimited"
}
