// Package pki provides the public API for qpki.
// This file exposes x509 utilities from internal/x509util.
package pki

import (
	"encoding/asn1"

	"github.com/remiblancher/qpki/internal/x509util"
)

// ExtractSignatureAlgorithmOID extracts the signature algorithm OID from a certificate.
func ExtractSignatureAlgorithmOID(rawCert []byte) (asn1.ObjectIdentifier, error) {
	return x509util.ExtractSignatureAlgorithmOID(rawCert)
}

// AlgorithmName returns the human-readable name for an algorithm OID.
func AlgorithmName(oid asn1.ObjectIdentifier) string {
	return x509util.AlgorithmName(oid)
}
