package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"path/filepath"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// crossSign creates a cross-signed certificate for newCA signed by oldCA.
func crossSign(oldCA, newCA *CA) (*x509.Certificate, error) {
	// Check if new CA has a PQC public key (Go returns nil for PQC public keys)
	if newCA.cert.PublicKey == nil {
		return crossSignPQC(oldCA, newCA)
	}

	// Create a certificate with the new CA's public key, signed by the old CA
	template := &x509.Certificate{
		SerialNumber:          newCA.cert.SerialNumber,
		Subject:               newCA.cert.Subject,
		NotBefore:             newCA.cert.NotBefore,
		NotAfter:              newCA.cert.NotAfter,
		KeyUsage:              newCA.cert.KeyUsage,
		ExtKeyUsage:           newCA.cert.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            newCA.cert.MaxPathLen,
		MaxPathLenZero:        newCA.cert.MaxPathLenZero,
		SubjectKeyId:          newCA.cert.SubjectKeyId,
	}

	// Copy extensions (except signature-related)
	for _, ext := range newCA.cert.Extensions {
		// Skip extensions that will be overwritten
		if ext.Id.Equal(x509util.OIDAltSignatureValue) ||
			ext.Id.Equal(x509util.OIDExtAuthorityKeyId) {
			continue
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	// Sign with old CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, oldCA.cert, newCA.cert.PublicKey, oldCA.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create cross-signed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-signed certificate: %w", err)
	}

	return cert, nil
}

// crossSignPQC creates a cross-signed certificate for a PQC CA signed by oldCA.
// This is needed because Go's x509.CreateCertificate doesn't support PQC public keys.
func crossSignPQC(oldCA, newCA *CA) (*x509.Certificate, error) {
	// Get the signer algorithm from old CA
	signerAlg := oldCA.signer.Algorithm()

	// For hybrid signers, use the classical signer
	var signer pkicrypto.Signer
	if hs, ok := oldCA.signer.(pkicrypto.HybridSigner); ok {
		signer = hs.ClassicalSigner()
		signerAlg = hs.ClassicalSigner().Algorithm()
	} else {
		signer = oldCA.signer
	}

	// Get signature algorithm OID
	sigAlgOID := signerAlg.OID()
	if sigAlgOID == nil {
		return nil, fmt.Errorf("unsupported signer algorithm: %s has no OID", signerAlg)
	}

	// Parse the new CA's SPKI to get the public key info
	var newCAPubKey publicKeyInfo
	_, err := asn1.Unmarshal(newCA.cert.RawSubjectPublicKeyInfo, &newCAPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse new CA's public key info: %w", err)
	}

	// Build TBSCertificate manually using the new CA's public key
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: newCA.cert.SerialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer:    asn1.RawValue{FullBytes: oldCA.cert.RawSubject}, // Signed by old CA
		Validity:  validity{NotBefore: newCA.cert.NotBefore, NotAfter: newCA.cert.NotAfter},
		Subject:   asn1.RawValue{FullBytes: newCA.cert.RawSubject}, // Same subject as new CA
		PublicKey: newCAPubKey,
	}

	// Copy extensions from new CA, filtering out those we'll replace
	for _, ext := range newCA.cert.Extensions {
		// Skip AltSignatureValue (it's specific to the self-signed cert)
		// Skip AuthorityKeyIdentifier (we'll add our own)
		if ext.Id.Equal(x509util.OIDAltSignatureValue) ||
			ext.Id.Equal(x509util.OIDExtAuthorityKeyId) {
			continue
		}
		tbs.Extensions = append(tbs.Extensions, ext)
	}

	// Add Authority Key Identifier from old CA
	if len(oldCA.cert.SubjectKeyId) > 0 {
		akid := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{
			KeyIdentifier: oldCA.cert.SubjectKeyId,
		}
		akidDER, err := asn1.Marshal(akid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authority key identifier: %w", err)
		}
		tbs.Extensions = append(tbs.Extensions, pkix.Extension{
			Id:       x509util.OIDExtAuthorityKeyId,
			Critical: false,
			Value:    akidDER,
		})
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign with old CA using appropriate options for the algorithm
	signerOpts := pkicrypto.DefaultSignerOpts(signerAlg)
	var digest []byte
	if signerOpts.Hash != 0 {
		// Classical algorithm - hash the TBS first
		h := signerOpts.Hash.New()
		h.Write(tbsDER)
		digest = h.Sum(nil)
	} else {
		// PQC or Ed25519 - sign the full message
		digest = tbsDER
	}

	signature, err := signer.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cross-signed certificate: %w", err)
	}

	// Assemble final certificate
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cross-signed certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cross-signed certificate: %w", err)
	}

	return parsedCert, nil
}

// saveCrossSignedCert saves a cross-signed certificate to file.
func saveCrossSignedCert(path string, cert *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	store := &FileStore{}
	return store.saveCert(path, cert)
}
