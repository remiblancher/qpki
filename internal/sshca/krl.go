package sshca

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
)

// KRL constants matching OpenSSH PROTOCOL.krl specification.
const (
	krlMagic          = 0x5353484b524c0a00 // "SSHKRL\n\0"
	krlFormatVersion  = 1
	krlSectionCerts   = 1
	krlCertSerialList = 0x20
	krlCertBitmap     = 0x22
	krlCertKeyID      = 0x23
)

// KRL represents an OpenSSH Key Revocation List.
type KRL struct {
	Version       uint64
	GeneratedDate uint64
	Comment       string
	Sections      []KRLSection
}

// KRLSection is a section within a KRL.
type KRLSection interface {
	sectionType() byte
	marshal() []byte
}

// KRLCertificateSection revokes certificates signed by a specific CA.
type KRLCertificateSection struct {
	CAKey      ssh.PublicKey // nil = any CA
	Serials    []uint64
	KeyIDs     []string
}

func (s *KRLCertificateSection) sectionType() byte { return krlSectionCerts }

func (s *KRLCertificateSection) marshal() []byte {
	var buf []byte

	// CA public key (empty string = any CA)
	if s.CAKey != nil {
		caBlob := s.CAKey.Marshal()
		buf = appendSSHString(buf, caBlob)
	} else {
		buf = appendSSHString(buf, nil)
	}

	// Reserved (empty string)
	buf = appendSSHString(buf, nil)

	// Serial list subsection
	if len(s.Serials) > 0 {
		sorted := make([]uint64, len(s.Serials))
		copy(sorted, s.Serials)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		// Use bitmap encoding if serials are dense, serial list otherwise
		if shouldUseBitmap(sorted) {
			buf = append(buf, krlCertBitmap)
			buf = appendSSHString(buf, marshalSerialBitmap(sorted))
		} else {
			buf = append(buf, krlCertSerialList)
			buf = appendSSHString(buf, marshalSerialList(sorted))
		}
	}

	// Key ID subsection
	if len(s.KeyIDs) > 0 {
		buf = append(buf, krlCertKeyID)
		buf = appendSSHString(buf, marshalKeyIDs(s.KeyIDs))
	}

	return buf
}

// shouldUseBitmap returns true if bitmap encoding is more efficient.
func shouldUseBitmap(sortedSerials []uint64) bool {
	if len(sortedSerials) < 3 {
		return false
	}
	span := sortedSerials[len(sortedSerials)-1] - sortedSerials[0] + 1
	// Bitmap uses span/8 bytes; serial list uses 8*count bytes
	return span/8 < uint64(len(sortedSerials))*8
}

// marshalSerialList encodes serials as a flat list of uint64.
func marshalSerialList(serials []uint64) []byte {
	buf := make([]byte, 8*len(serials))
	for i, s := range serials {
		binary.BigEndian.PutUint64(buf[i*8:], s)
	}
	return buf
}

// marshalSerialBitmap encodes serials as offset + mpint bitmap.
func marshalSerialBitmap(sortedSerials []uint64) []byte {
	offset := sortedSerials[0]
	bitmap := new(big.Int)
	for _, s := range sortedSerials {
		bitmap.SetBit(bitmap, int(s-offset), 1)
	}

	var buf []byte
	// Offset
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, offset)
	buf = append(buf, b...)

	// Bitmap as SSH mpint
	bitmapBytes := bitmap.Bytes()
	// SSH mpint: prepend 0x00 if MSB is set (to indicate positive)
	if len(bitmapBytes) > 0 && bitmapBytes[0]&0x80 != 0 {
		bitmapBytes = append([]byte{0}, bitmapBytes...)
	}
	buf = appendSSHString(buf, bitmapBytes)

	return buf
}

// marshalKeyIDs encodes key IDs as consecutive SSH strings.
func marshalKeyIDs(keyIDs []string) []byte {
	var buf []byte
	for _, id := range keyIDs {
		buf = appendSSHString(buf, []byte(id))
	}
	return buf
}

// MarshalKRL encodes a KRL to binary format.
func MarshalKRL(krl *KRL) []byte {
	var buf []byte

	// Header
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, krlMagic)
	buf = append(buf, b...)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, krlFormatVersion)
	buf = append(buf, b...)

	b = make([]byte, 8)
	binary.BigEndian.PutUint64(b, krl.Version)
	buf = append(buf, b...)

	b = make([]byte, 8)
	binary.BigEndian.PutUint64(b, krl.GeneratedDate)
	buf = append(buf, b...)

	// Flags (reserved, 0)
	b = make([]byte, 8)
	buf = append(buf, b...)

	// Reserved (empty string)
	buf = appendSSHString(buf, nil)

	// Comment
	buf = appendSSHString(buf, []byte(krl.Comment))

	// Sections
	for _, section := range krl.Sections {
		buf = append(buf, section.sectionType())
		buf = appendSSHString(buf, section.marshal())
	}

	return buf
}

// ParseKRL decodes a KRL from binary format.
func ParseKRL(data []byte) (*KRL, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("KRL too short")
	}

	off := 0

	// Magic
	magic := binary.BigEndian.Uint64(data[off:])
	off += 8
	if magic != krlMagic {
		return nil, fmt.Errorf("invalid KRL magic: %x", magic)
	}

	// Format version
	fmtVer := binary.BigEndian.Uint32(data[off:])
	off += 4
	if fmtVer != krlFormatVersion {
		return nil, fmt.Errorf("unsupported KRL format version: %d", fmtVer)
	}

	krl := &KRL{}

	krl.Version = binary.BigEndian.Uint64(data[off:])
	off += 8

	krl.GeneratedDate = binary.BigEndian.Uint64(data[off:])
	off += 8

	// Flags (skip)
	off += 8

	// Reserved
	_, n, err := readSSHString(data[off:])
	if err != nil {
		return nil, fmt.Errorf("failed to read reserved field: %w", err)
	}
	off += n

	// Comment
	comment, n, err := readSSHString(data[off:])
	if err != nil {
		return nil, fmt.Errorf("failed to read comment: %w", err)
	}
	krl.Comment = string(comment)
	off += n

	// Sections
	for off < len(data) {
		sectionType := data[off]
		off++

		sectionData, n, err := readSSHString(data[off:])
		if err != nil {
			return nil, fmt.Errorf("failed to read section data: %w", err)
		}
		off += n

		switch sectionType {
		case krlSectionCerts:
			section, err := parseCertSection(sectionData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate section: %w", err)
			}
			krl.Sections = append(krl.Sections, section)
		default:
			// Skip unknown sections
		}
	}

	return krl, nil
}

// parseCertSection parses a certificate revocation section.
func parseCertSection(data []byte) (*KRLCertificateSection, error) {
	section := &KRLCertificateSection{}
	off := 0

	// CA key
	caKeyBlob, n, err := readSSHString(data[off:])
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}
	off += n

	if len(caKeyBlob) > 0 {
		pubKey, err := ssh.ParsePublicKey(caKeyBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA key: %w", err)
		}
		section.CAKey = pubKey
	}

	// Reserved
	_, n, err = readSSHString(data[off:])
	if err != nil {
		return nil, fmt.Errorf("failed to read reserved: %w", err)
	}
	off += n

	// Subsections
	for off < len(data) {
		subType := data[off]
		off++

		subData, n, err := readSSHString(data[off:])
		if err != nil {
			return nil, fmt.Errorf("failed to read subsection data: %w", err)
		}
		off += n

		switch subType {
		case krlCertSerialList:
			serials, err := parseSerialList(subData)
			if err != nil {
				return nil, err
			}
			section.Serials = append(section.Serials, serials...)

		case krlCertBitmap:
			serials, err := parseSerialBitmap(subData)
			if err != nil {
				return nil, err
			}
			section.Serials = append(section.Serials, serials...)

		case krlCertKeyID:
			ids, err := parseKeyIDs(subData)
			if err != nil {
				return nil, err
			}
			section.KeyIDs = append(section.KeyIDs, ids...)
		}
	}

	return section, nil
}

// parseSerialList parses a serial list subsection.
func parseSerialList(data []byte) ([]uint64, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("invalid serial list length: %d", len(data))
	}
	serials := make([]uint64, len(data)/8)
	for i := range serials {
		serials[i] = binary.BigEndian.Uint64(data[i*8:])
	}
	return serials, nil
}

// parseSerialBitmap parses a serial bitmap subsection.
func parseSerialBitmap(data []byte) ([]uint64, error) {
	if len(data) < 12 { // 8 (offset) + 4 (min string length)
		return nil, fmt.Errorf("bitmap subsection too short")
	}

	offset := binary.BigEndian.Uint64(data[:8])

	bitmapBytes, _, err := readSSHString(data[8:])
	if err != nil {
		return nil, fmt.Errorf("failed to read bitmap: %w", err)
	}

	bitmap := new(big.Int).SetBytes(bitmapBytes)

	var serials []uint64
	for i := 0; i < bitmap.BitLen(); i++ {
		if bitmap.Bit(i) == 1 {
			serials = append(serials, offset+uint64(i))
		}
	}
	return serials, nil
}

// parseKeyIDs parses a key ID subsection.
func parseKeyIDs(data []byte) ([]string, error) {
	var ids []string
	off := 0
	for off < len(data) {
		s, n, err := readSSHString(data[off:])
		if err != nil {
			return nil, fmt.Errorf("failed to read key ID: %w", err)
		}
		ids = append(ids, string(s))
		off += n
	}
	return ids, nil
}

// IsRevoked checks if a certificate serial is revoked by the KRL.
func (krl *KRL) IsRevoked(serial uint64) bool {
	for _, section := range krl.Sections {
		if cs, ok := section.(*KRLCertificateSection); ok {
			for _, s := range cs.Serials {
				if s == serial {
					return true
				}
			}
		}
	}
	return false
}

// SSH wire format helpers

func appendSSHString(buf, data []byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	buf = append(buf, b...)
	buf = append(buf, data...)
	return buf
}

func readSSHString(data []byte) ([]byte, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("data too short for SSH string")
	}
	length := binary.BigEndian.Uint32(data[:4])
	if uint64(length) > uint64(len(data)-4) {
		return nil, 0, fmt.Errorf("SSH string length %d exceeds available data %d", length, len(data)-4)
	}
	return data[4 : 4+length], 4 + int(length), nil
}

// GenerateKRL creates a KRL from the CA's revoked certificates.
func (ca *SSHCA) GenerateKRL(ctx context.Context, comment string) ([]byte, error) {
	entries, err := ca.store.ReadIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedSerials []uint64
	for _, e := range entries {
		if e.Status == "R" {
			revokedSerials = append(revokedSerials, e.Serial)
		}
	}

	krl := &KRL{
		Version:       1,
		GeneratedDate: uint64(time.Now().Unix()),
		Comment:       comment,
	}

	if len(revokedSerials) > 0 {
		krl.Sections = append(krl.Sections, &KRLCertificateSection{
			CAKey:   ca.sshSigner.PublicKey(),
			Serials: revokedSerials,
		})
	}

	return MarshalKRL(krl), nil
}

// Revoke marks a certificate as revoked in the index.
func (ca *SSHCA) Revoke(ctx context.Context, serial uint64) error {
	return ca.store.UpdateIndexStatus(ctx, serial, "R")
}
