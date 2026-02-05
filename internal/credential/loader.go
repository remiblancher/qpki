package credential

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// LoadSigner loads the signing certificate and signer from a credential.
// It returns the active signing certificate and the corresponding signer.
// For hybrid credentials, it returns a HybridSigner combining classical and PQC keys.
func LoadSigner(ctx context.Context, store Store, credID string, passphrase []byte) (*x509.Certificate, pkicrypto.Signer, error) {
	// Load credential metadata
	cred, err := store.Load(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load credential %s: %w", credID, err)
	}

	// Check credential is valid (not revoked, not expired)
	if cred.RevokedAt != nil {
		return nil, nil, fmt.Errorf("credential %s is revoked: %s", credID, cred.RevocationReason)
	}

	// Load certificates
	certs, err := store.LoadCertificates(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificates for %s: %w", credID, err)
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found for credential %s", credID)
	}

	// Load signers
	signers, err := store.LoadKeys(ctx, credID, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keys for %s: %w", credID, err)
	}

	if len(signers) == 0 {
		return nil, nil, fmt.Errorf("no signing keys found for credential %s", credID)
	}

	// Find the signing certificate and match with signer
	return matchSignerToCertificate(certs, signers)
}

// matchSignerToCertificate finds the appropriate certificate and signer pair.
// For hybrid credentials (2 signers: classical + PQC), it creates a HybridSigner.
// For single-key credentials, it returns the first signing certificate and its signer.
func matchSignerToCertificate(certs []*x509.Certificate, signers []pkicrypto.Signer) (*x509.Certificate, pkicrypto.Signer, error) {
	// Case 1: Single signer - find matching certificate
	if len(signers) == 1 {
		cert, err := findCertificateForSigner(certs, signers[0])
		if err != nil {
			return nil, nil, err
		}
		return cert, signers[0], nil
	}

	// Case 2: Two signers - check if hybrid (classical + PQC)
	if len(signers) == 2 {
		var classical, pqc pkicrypto.Signer
		for _, s := range signers {
			if s.Algorithm().IsPQC() {
				pqc = s
			} else {
				classical = s
			}
		}

		// If we have both classical and PQC, create hybrid signer
		if classical != nil && pqc != nil {
			hybridSigner, err := pkicrypto.NewHybridSigner(classical, pqc)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create hybrid signer: %w", err)
			}

			// For hybrid, use the classical certificate (it contains the primary key)
			cert, err := findCertificateForSigner(certs, classical)
			if err != nil {
				return nil, nil, err
			}
			return cert, hybridSigner, nil
		}
	}

	// Case 3: Multiple signers but not hybrid - use the first signing certificate
	// Find first certificate that has a matching signer
	for _, cert := range certs {
		for _, signer := range signers {
			if publicKeysMatch(cert.PublicKey, signer.Public()) {
				return cert, signer, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no matching certificate found for any signer")
}

// findCertificateForSigner finds the certificate whose public key matches the signer.
func findCertificateForSigner(certs []*x509.Certificate, signer pkicrypto.Signer) (*x509.Certificate, error) {
	for _, cert := range certs {
		if publicKeysMatch(cert.PublicKey, signer.Public()) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("no certificate found matching signer with algorithm %s", signer.Algorithm())
}

// publicKeysMatch compares two public keys for equality.
func publicKeysMatch(pub1, pub2 interface{}) bool {
	// Use the crypto/subtle approach via marshaling
	bytes1, err1 := x509.MarshalPKIXPublicKey(pub1)
	bytes2, err2 := x509.MarshalPKIXPublicKey(pub2)

	if err1 != nil || err2 != nil {
		// For PQC keys that can't be marshaled via standard x509,
		// fall back to direct comparison via Public() interface
		return fmt.Sprintf("%v", pub1) == fmt.Sprintf("%v", pub2)
	}

	if len(bytes1) != len(bytes2) {
		return false
	}
	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			return false
		}
	}
	return true
}

// LoadDecryptionKey loads a decryption key from a credential.
// It looks for encryption certificates (RoleEncryption, RoleEncryptionClassical, RoleEncryptionPQC)
// and returns the corresponding private key.
func LoadDecryptionKey(ctx context.Context, store Store, credID string, passphrase []byte) (*x509.Certificate, interface{}, error) {
	// Load credential metadata
	cred, err := store.Load(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load credential %s: %w", credID, err)
	}

	// Check credential is valid
	if cred.RevokedAt != nil {
		return nil, nil, fmt.Errorf("credential %s is revoked: %s", credID, cred.RevocationReason)
	}

	// Load certificates
	certs, err := store.LoadCertificates(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificates for %s: %w", credID, err)
	}

	// Load signers (which also includes KEM keys)
	signers, err := store.LoadKeys(ctx, credID, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keys for %s: %w", credID, err)
	}

	// Find encryption certificate and matching key
	for _, cert := range certs {
		// Check if this is an encryption certificate (has keyEncipherment or keyAgreement)
		if cert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) != 0 {
			for _, signer := range signers {
				if publicKeysMatch(cert.PublicKey, signer.Public()) {
					// Return the private key from the signer
					if ss, ok := signer.(*pkicrypto.SoftwareSigner); ok {
						return cert, ss.PrivateKey(), nil
					}
					if ks, ok := signer.(*pkicrypto.KEMSigner); ok {
						return cert, ks.PrivateKey(), nil
					}
				}
			}
		}
	}

	// If no encryption-specific cert found, try to use any cert with matching key
	for _, cert := range certs {
		for _, signer := range signers {
			if publicKeysMatch(cert.PublicKey, signer.Public()) {
				if ss, ok := signer.(*pkicrypto.SoftwareSigner); ok {
					return cert, ss.PrivateKey(), nil
				}
				if ks, ok := signer.(*pkicrypto.KEMSigner); ok {
					return cert, ks.PrivateKey(), nil
				}
			}
		}
	}

	return nil, nil, fmt.Errorf("no encryption key found for credential %s", credID)
}

// =============================================================================
// Multi-Version Decryption Support
// =============================================================================

// IssuerAndSerial identifies a certificate by its issuer DN and serial number.
// This matches the KeyTransRecipientInfo.rid.issuerAndSerialNumber in CMS.
type IssuerAndSerial struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

// RecipientMatcher identifies a CMS recipient for key lookup.
// It can match by IssuerAndSerialNumber (KeyTransRecipientInfo) or
// SubjectKeyIdentifier (KeyAgreeRecipientInfo, KEKRecipientInfo).
type RecipientMatcher struct {
	// IssuerAndSerialNumber matches certificates by issuer DN and serial number.
	IssuerAndSerialNumber *IssuerAndSerial

	// SubjectKeyIdentifier matches certificates by SKI extension.
	SubjectKeyIdentifier []byte
}

// MatchesCertificate returns true if the matcher matches the given certificate.
func (m *RecipientMatcher) MatchesCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	// Match by IssuerAndSerialNumber
	if m.IssuerAndSerialNumber != nil {
		var certIssuer pkix.RDNSequence
		if _, err := asn1Unmarshal(cert.RawIssuer, &certIssuer); err == nil {
			if issuerEqual(certIssuer, m.IssuerAndSerialNumber.Issuer) &&
				cert.SerialNumber.Cmp(m.IssuerAndSerialNumber.SerialNumber) == 0 {
				return true
			}
		}
	}

	// Match by SubjectKeyIdentifier
	if len(m.SubjectKeyIdentifier) > 0 && len(cert.SubjectKeyId) > 0 {
		if bytes.Equal(cert.SubjectKeyId, m.SubjectKeyIdentifier) {
			return true
		}
	}

	return false
}

// issuerEqual compares two RDNSequences for equality using DER encoding.
// This is more robust than field-by-field comparison as it handles
// different string encodings (UTF8String vs PrintableString) correctly.
func issuerEqual(a, b pkix.RDNSequence) bool {
	// Fast path: if lengths differ, they can't be equal
	if len(a) != len(b) {
		return false
	}

	// Compare by DER encoding for robustness
	aBytes, errA := asn1.Marshal(a)
	bBytes, errB := asn1.Marshal(b)
	if errA != nil || errB != nil {
		// Fallback to field-by-field comparison if marshaling fails
		return issuerEqualFieldByField(a, b)
	}
	return bytes.Equal(aBytes, bBytes)
}

// issuerEqualFieldByField compares RDNSequences field by field.
// Used as fallback when DER comparison fails.
func issuerEqualFieldByField(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if !a[i][j].Type.Equal(b[i][j].Type) {
				return false
			}
			if a[i][j].Value != b[i][j].Value {
				return false
			}
		}
	}
	return true
}

// asn1Unmarshal is a wrapper for encoding/asn1.Unmarshal.
func asn1Unmarshal(data []byte, val interface{}) ([]byte, error) {
	return asn1.Unmarshal(data, val)
}

// FindDecryptionKeyByRecipient searches for a decryption key matching the recipient info.
// Unlike LoadDecryptionKey, this searches ALL versions of the credential,
// not just the active one. This is essential for decrypting data that was
// encrypted with an older key before a rotation.
func FindDecryptionKeyByRecipient(ctx context.Context, store Store, credID string, matcher *RecipientMatcher, passphrase []byte) (*x509.Certificate, interface{}, error) {
	// Load credential metadata (just to verify it exists and isn't revoked)
	cred, err := store.Load(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load credential %s: %w", credID, err)
	}

	// Note: For decryption, we allow revoked credentials since we may need
	// to decrypt old data. The revocation only prevents NEW operations.

	// Get all versions
	versions, err := store.ListVersions(ctx, credID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list versions for %s: %w", credID, err)
	}

	// Search through all versions to find matching certificate
	for _, versionID := range versions {
		// Load certificates for this version
		certs, err := store.LoadCertificatesForVersion(ctx, credID, versionID)
		if err != nil {
			continue // Skip versions with errors
		}

		// Check each certificate against the matcher
		for _, cert := range certs {
			if matcher.MatchesCertificate(cert) {
				// Found matching certificate! Load the corresponding key
				signers, err := store.LoadKeysForVersion(ctx, credID, versionID, passphrase)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to load keys for %s version %s: %w", credID, versionID, err)
				}

				// Find the key matching this certificate
				for _, signer := range signers {
					if publicKeysMatch(cert.PublicKey, signer.Public()) {
						if ss, ok := signer.(*pkicrypto.SoftwareSigner); ok {
							return cert, ss.PrivateKey(), nil
						}
						if ks, ok := signer.(*pkicrypto.KEMSigner); ok {
							return cert, ks.PrivateKey(), nil
						}
					}
				}
			}
		}
	}

	_ = cred // Used for existence check above
	return nil, nil, fmt.Errorf("no matching decryption key found for credential %s", credID)
}

// FindAllDecryptionKeys returns all decryption keys from all versions.
// This is useful when the caller wants to try each key sequentially.
func FindAllDecryptionKeys(ctx context.Context, store Store, credID string, passphrase []byte) ([]DecryptionKeyEntry, error) {
	// Load credential metadata
	cred, err := store.Load(ctx, credID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential %s: %w", credID, err)
	}

	// Get all versions
	versions, err := store.ListVersions(ctx, credID)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions for %s: %w", credID, err)
	}

	var entries []DecryptionKeyEntry

	for _, versionID := range versions {
		// Load certificates for this version
		certs, err := store.LoadCertificatesForVersion(ctx, credID, versionID)
		if err != nil {
			continue
		}

		// Load keys for this version
		signers, err := store.LoadKeysForVersion(ctx, credID, versionID, passphrase)
		if err != nil {
			continue
		}

		// Match certificates to keys
		for _, cert := range certs {
			for _, signer := range signers {
				if publicKeysMatch(cert.PublicKey, signer.Public()) {
					var privKey interface{}
					if ss, ok := signer.(*pkicrypto.SoftwareSigner); ok {
						privKey = ss.PrivateKey()
					} else if ks, ok := signer.(*pkicrypto.KEMSigner); ok {
						privKey = ks.PrivateKey()
					}

					if privKey != nil {
						entries = append(entries, DecryptionKeyEntry{
							Version:     versionID,
							Certificate: cert,
							PrivateKey:  privKey,
							IsActive:    cred.Active == versionID,
						})
					}
				}
			}
		}
	}

	return entries, nil
}

// DecryptionKeyEntry represents a decryption key from a specific version.
type DecryptionKeyEntry struct {
	// Version is the credential version ID (e.g., "v1", "v2").
	Version string

	// Certificate is the encryption certificate.
	Certificate *x509.Certificate

	// PrivateKey is the corresponding private key.
	PrivateKey interface{}

	// IsActive indicates if this is from the currently active version.
	IsActive bool
}
