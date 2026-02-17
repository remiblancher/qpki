package cose

import (
	"crypto/rand"
	"math/big"
)

// SerialGenerator generates unique identifiers for COSE messages.
type SerialGenerator interface {
	Next() ([]byte, error)
}

// RandomSerialGenerator generates random 128-bit serial numbers.
type RandomSerialGenerator struct{}

// Next returns a random 128-bit (16 byte) serial number.
func (g *RandomSerialGenerator) Next() ([]byte, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	// Ensure 16 bytes output
	b := n.Bytes()
	if len(b) < 16 {
		padded := make([]byte, 16)
		copy(padded[16-len(b):], b)
		return padded, nil
	}
	return b[:16], nil
}

// DefaultSerialGenerator is the default serial generator.
var DefaultSerialGenerator SerialGenerator = &RandomSerialGenerator{}
