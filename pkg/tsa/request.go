// Package tsa implements RFC 3161 Time-Stamp Protocol.
package tsa

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/remiblancher/qpki/pkg/cms"
)

// TimeStampReq represents a timestamp request (RFC 3161 Section 2.4.1).
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// MessageImprint contains the hash of the data to be timestamped.
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// ParseRequest parses a DER-encoded TimeStampReq.
func ParseRequest(data []byte) (*TimeStampReq, error) {
	var req TimeStampReq
	rest, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TimeStampReq: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TimeStampReq")
	}

	// Validate version
	if req.Version != 1 {
		return nil, fmt.Errorf("unsupported TSP version: %d", req.Version)
	}

	// Validate hash algorithm
	if err := validateHashAlgorithm(req.MessageImprint.HashAlgorithm.Algorithm); err != nil {
		return nil, err
	}

	// Validate hash length matches algorithm
	expectedLen := getHashLength(req.MessageImprint.HashAlgorithm.Algorithm)
	if len(req.MessageImprint.HashedMessage) != expectedLen {
		return nil, fmt.Errorf("hash length mismatch: got %d, expected %d",
			len(req.MessageImprint.HashedMessage), expectedLen)
	}

	return &req, nil
}

// HashAlgorithm returns the crypto.Hash for the message imprint.
func (r *TimeStampReq) HashAlgorithm() (crypto.Hash, error) {
	return oidToHash(r.MessageImprint.HashAlgorithm.Algorithm)
}

// validateHashAlgorithm checks if the hash algorithm is supported.
func validateHashAlgorithm(oid asn1.ObjectIdentifier) error {
	switch {
	case oid.Equal(cms.OIDSHA256),
		oid.Equal(cms.OIDSHA384),
		oid.Equal(cms.OIDSHA512),
		oid.Equal(cms.OIDSHA3_256),
		oid.Equal(cms.OIDSHA3_384),
		oid.Equal(cms.OIDSHA3_512),
		oid.Equal(cms.OIDSHAKE256):
		return nil
	default:
		return fmt.Errorf("unsupported hash algorithm: %v", oid)
	}
}

// getHashLength returns the expected hash length for a hash algorithm OID.
func getHashLength(oid asn1.ObjectIdentifier) int {
	switch {
	case oid.Equal(cms.OIDSHA256), oid.Equal(cms.OIDSHA3_256):
		return 32
	case oid.Equal(cms.OIDSHA384), oid.Equal(cms.OIDSHA3_384):
		return 48
	case oid.Equal(cms.OIDSHA512), oid.Equal(cms.OIDSHA3_512):
		return 64
	case oid.Equal(cms.OIDSHAKE256):
		return 32 // Default output length for SHAKE256
	default:
		return 0
	}
}

// oidToHash converts a hash algorithm OID to crypto.Hash.
func oidToHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(cms.OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(cms.OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(cms.OIDSHA512):
		return crypto.SHA512, nil
	case oid.Equal(cms.OIDSHA3_256):
		return crypto.SHA3_256, nil
	case oid.Equal(cms.OIDSHA3_384):
		return crypto.SHA3_384, nil
	case oid.Equal(cms.OIDSHA3_512):
		return crypto.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", oid)
	}
}

// hashToOID converts crypto.Hash to an algorithm OID.
func hashToOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA256:
		return cms.OIDSHA256
	case crypto.SHA384:
		return cms.OIDSHA384
	case crypto.SHA512:
		return cms.OIDSHA512
	case crypto.SHA3_256:
		return cms.OIDSHA3_256
	case crypto.SHA3_384:
		return cms.OIDSHA3_384
	case crypto.SHA3_512:
		return cms.OIDSHA3_512
	default:
		return cms.OIDSHA256
	}
}

// NewMessageImprint creates a MessageImprint from a hash.
func NewMessageImprint(hash crypto.Hash, digest []byte) MessageImprint {
	return MessageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashToOID(hash)},
		HashedMessage: digest,
	}
}

// CreateRequest creates a new TimeStampReq for the given data.
func CreateRequest(data []byte, hashAlg crypto.Hash, nonce *big.Int, certReq bool) (*TimeStampReq, error) {
	// Compute hash of the data
	h := hashAlg.New()
	h.Write(data)
	digest := h.Sum(nil)

	req := &TimeStampReq{
		Version:        1,
		MessageImprint: NewMessageImprint(hashAlg, digest),
		CertReq:        certReq,
	}

	if nonce != nil {
		req.Nonce = nonce
	}

	return req, nil
}

// Marshal encodes the TimeStampReq as DER.
func (r *TimeStampReq) Marshal() ([]byte, error) {
	return asn1.Marshal(*r)
}
