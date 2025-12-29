// Package tsa implements RFC 3161 Time-Stamp Protocol.
package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/cms"
)

// TSTInfo represents the timestamp token info (RFC 3161 Section 2.4.2).
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Accuracy represents the accuracy of the timestamp (RFC 3161 Section 2.4.2).
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// IsZero returns true if the accuracy is zero.
func (a Accuracy) IsZero() bool {
	return a.Seconds == 0 && a.Millis == 0 && a.Micros == 0
}

// TokenConfig contains options for creating a timestamp token.
type TokenConfig struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	Policy      asn1.ObjectIdentifier
	Accuracy    Accuracy
	Ordering    bool
	IncludeTSA  bool
}

// SerialGenerator generates unique serial numbers for timestamps.
type SerialGenerator interface {
	Next() (*big.Int, error)
}

// RandomSerialGenerator generates random serial numbers.
type RandomSerialGenerator struct{}

// Next returns a random 128-bit serial number.
func (g *RandomSerialGenerator) Next() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// Token represents a complete timestamp token.
type Token struct {
	Info       *TSTInfo
	SignedData []byte // CMS SignedData containing the TSTInfo
}

// CreateToken creates a timestamp token from a request.
func CreateToken(req *TimeStampReq, config *TokenConfig, serialGen SerialGenerator) (*Token, error) {
	if config.Certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if config.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if len(config.Policy) == 0 {
		return nil, fmt.Errorf("policy OID is required")
	}

	// Generate serial number
	serial, err := serialGen.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	// Build TSTInfo
	tstInfo := TSTInfo{
		Version:        1,
		Policy:         config.Policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serial,
		GenTime:        time.Now().UTC(),
		Ordering:       config.Ordering,
	}

	// Copy nonce from request if present
	if req.Nonce != nil {
		tstInfo.Nonce = req.Nonce
	}

	// Set accuracy if specified
	if !config.Accuracy.IsZero() {
		tstInfo.Accuracy = config.Accuracy
	}

	// Include TSA name if requested
	if config.IncludeTSA && config.Certificate.Subject.String() != "" {
		// GeneralName with directoryName [4]
		tsaName, err := marshalGeneralName(config.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TSA name: %w", err)
		}
		tstInfo.TSA = tsaName
	}

	// Encode TSTInfo
	tstInfoDER, err := asn1.Marshal(tstInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TSTInfo: %w", err)
	}

	// Determine digest algorithm for CMS
	hashAlg, err := req.HashAlgorithm()
	if err != nil {
		// Use SHA-256 as fallback for CMS digest
		hashAlg = crypto.SHA256
	}

	// Create CMS SignedData
	signedData, err := cms.Sign(tstInfoDER, &cms.SignerConfig{
		Certificate:  config.Certificate,
		Signer:       config.Signer,
		DigestAlg:    hashAlg,
		IncludeCerts: req.CertReq,
		ContentType:  cms.OIDTSTInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SignedData: %w", err)
	}

	return &Token{
		Info:       &tstInfo,
		SignedData: signedData,
	}, nil
}

// marshalGeneralName creates a GeneralName with directoryName.
func marshalGeneralName(cert *x509.Certificate) (asn1.RawValue, error) {
	// GeneralName ::= CHOICE {
	//   directoryName [4] Name
	// }
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      cert.RawSubject,
	}, nil
}

// ParseToken parses a DER-encoded timestamp token (CMS SignedData).
func ParseToken(data []byte) (*Token, error) {
	// Parse ContentInfo
	var contentInfo cms.ContentInfo
	rest, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after ContentInfo")
	}

	// Check content type
	if !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		return nil, fmt.Errorf("unexpected content type: %v", contentInfo.ContentType)
	}

	// Parse SignedData
	var signedData cms.SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Check encapsulated content type
	if !signedData.EncapContentInfo.EContentType.Equal(cms.OIDTSTInfo) {
		return nil, fmt.Errorf("unexpected encapsulated content type: %v",
			signedData.EncapContentInfo.EContentType)
	}

	// Extract TSTInfo content
	var tstInfoDER []byte
	if signedData.EncapContentInfo.EContent.Tag == asn1.TagOctetString {
		tstInfoDER = signedData.EncapContentInfo.EContent.Bytes
	} else {
		// Try to extract from explicit tag
		_, err = asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &tstInfoDER)
		if err != nil {
			tstInfoDER = signedData.EncapContentInfo.EContent.Bytes
		}
	}

	// Parse TSTInfo
	var tstInfo TSTInfo
	_, err = asn1.Unmarshal(tstInfoDER, &tstInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	return &Token{
		Info:       &tstInfo,
		SignedData: data,
	}, nil
}

// GenTime returns the generation time of the token.
func (t *Token) GenTime() time.Time {
	if t.Info == nil {
		return time.Time{}
	}
	return t.Info.GenTime
}

// SerialNumber returns the serial number of the token.
func (t *Token) SerialNumber() *big.Int {
	if t.Info == nil {
		return nil
	}
	return t.Info.SerialNumber
}

// Policy returns the policy OID of the token.
func (t *Token) Policy() asn1.ObjectIdentifier {
	if t.Info == nil {
		return nil
	}
	return t.Info.Policy
}

// HashAlgorithm returns the hash algorithm used in the message imprint.
func (t *Token) HashAlgorithm() (crypto.Hash, error) {
	if t.Info == nil {
		return 0, fmt.Errorf("no TSTInfo")
	}
	return oidToHash(t.Info.MessageImprint.HashAlgorithm.Algorithm)
}

// HashedMessage returns the hashed message from the message imprint.
func (t *Token) HashedMessage() []byte {
	if t.Info == nil {
		return nil
	}
	return t.Info.MessageImprint.HashedMessage
}
