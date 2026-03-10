package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestMarshalParseKRLRoundtrip(t *testing.T) {
	krl := &KRL{
		Version:       1,
		GeneratedDate: uint64(time.Now().Unix()),
		Comment:       "test KRL",
		Sections: []KRLSection{
			&KRLCertificateSection{
				Serials: []uint64{1, 3, 5, 10},
			},
		},
	}

	data := MarshalKRL(krl)
	if len(data) == 0 {
		t.Fatal("MarshalKRL() returned empty data")
	}

	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}

	if parsed.Version != krl.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, krl.Version)
	}
	if parsed.Comment != krl.Comment {
		t.Errorf("Comment = %q, want %q", parsed.Comment, krl.Comment)
	}
	if len(parsed.Sections) != 1 {
		t.Fatalf("Sections = %d, want 1", len(parsed.Sections))
	}

	cs := parsed.Sections[0].(*KRLCertificateSection)
	if len(cs.Serials) != 4 {
		t.Fatalf("Serials = %d, want 4", len(cs.Serials))
	}
}

func TestMarshalParseKRLWithCAKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	krl := &KRL{
		Version:       2,
		GeneratedDate: uint64(time.Now().Unix()),
		Comment:       "with CA key",
		Sections: []KRLSection{
			&KRLCertificateSection{
				CAKey:   sshPub,
				Serials: []uint64{42},
			},
		},
	}

	data := MarshalKRL(krl)
	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}

	cs := parsed.Sections[0].(*KRLCertificateSection)
	if cs.CAKey == nil {
		t.Fatal("CAKey should not be nil")
	}
	if ssh.FingerprintSHA256(cs.CAKey) != ssh.FingerprintSHA256(sshPub) {
		t.Error("CA key fingerprint mismatch")
	}
}

func TestMarshalParseKRLWithKeyIDs(t *testing.T) {
	krl := &KRL{
		Version:       1,
		GeneratedDate: uint64(time.Now().Unix()),
		Sections: []KRLSection{
			&KRLCertificateSection{
				KeyIDs: []string{"alice@example.com", "bob@example.com"},
			},
		},
	}

	data := MarshalKRL(krl)
	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}

	cs := parsed.Sections[0].(*KRLCertificateSection)
	if len(cs.KeyIDs) != 2 {
		t.Fatalf("KeyIDs = %d, want 2", len(cs.KeyIDs))
	}
	if cs.KeyIDs[0] != "alice@example.com" {
		t.Errorf("KeyIDs[0] = %q, want alice@example.com", cs.KeyIDs[0])
	}
}

func TestKRLIsRevoked(t *testing.T) {
	krl := &KRL{
		Version: 1,
		Sections: []KRLSection{
			&KRLCertificateSection{
				Serials: []uint64{1, 5, 10},
			},
		},
	}

	tests := []struct {
		serial uint64
		want   bool
	}{
		{1, true},
		{5, true},
		{10, true},
		{2, false},
		{0, false},
		{100, false},
	}

	for _, tt := range tests {
		if got := krl.IsRevoked(tt.serial); got != tt.want {
			t.Errorf("IsRevoked(%d) = %v, want %v", tt.serial, got, tt.want)
		}
	}
}

func TestKRLEmptySections(t *testing.T) {
	krl := &KRL{
		Version:       1,
		GeneratedDate: uint64(time.Now().Unix()),
		Comment:       "empty KRL",
	}

	data := MarshalKRL(krl)
	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}

	if len(parsed.Sections) != 0 {
		t.Errorf("Sections = %d, want 0", len(parsed.Sections))
	}
	if parsed.IsRevoked(1) {
		t.Error("empty KRL should not revoke anything")
	}
}

func TestKRLBitmapEncoding(t *testing.T) {
	// Create dense serials that should trigger bitmap encoding
	var serials []uint64
	for i := uint64(100); i < 200; i++ {
		serials = append(serials, i)
	}

	krl := &KRL{
		Version: 1,
		Sections: []KRLSection{
			&KRLCertificateSection{
				Serials: serials,
			},
		},
	}

	data := MarshalKRL(krl)
	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}

	cs := parsed.Sections[0].(*KRLCertificateSection)
	if len(cs.Serials) != 100 {
		t.Fatalf("Serials = %d, want 100", len(cs.Serials))
	}

	// Verify all serials are present
	for _, s := range serials {
		if !parsed.IsRevoked(s) {
			t.Errorf("serial %d should be revoked", s)
		}
	}
	// Verify non-revoked serial
	if parsed.IsRevoked(99) {
		t.Error("serial 99 should not be revoked")
	}
}

func TestParseKRLErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x01, 0x02, 0x03}},
		{"bad magic", make([]byte, 44)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKRL(tt.data)
			if err == nil {
				t.Error("ParseKRL() should fail")
			}
		})
	}
}

func TestSSHCAGenerateKRLAndRevoke(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Initialize CA
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCAPublicKey(ctx, caSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCAInfo(ctx, &CAInfo{
		Name:      "test-ca",
		Algorithm: "ed25519",
		CertType:  "user",
		PublicKey: ssh.FingerprintSHA256(caSigner.PublicKey()),
	}); err != nil {
		t.Fatal(err)
	}

	// Create a mock SSHCA
	ca := &SSHCA{
		store:     store,
		sshSigner: caSigner,
		info:      &CAInfo{Name: "test-ca"},
		certType:  ssh.UserCert,
	}

	// Issue two certificates
	for i := 0; i < 2; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sshPub, _ := ssh.NewPublicKey(pub)
		_, err := ca.Issue(ctx, IssueRequest{
			PublicKey:   sshPub,
			KeyID:       fmt.Sprintf("test-%d", i),
			Principals:  []string{"user"},
			ValidBefore: time.Now().Add(1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
	}

	// Generate KRL with no revocations
	krlData, err := ca.GenerateKRL(ctx, "test krl")
	if err != nil {
		t.Fatalf("GenerateKRL() error = %v", err)
	}
	parsed, err := ParseKRL(krlData)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}
	if parsed.IsRevoked(1) {
		t.Error("serial 1 should not be revoked yet")
	}

	// Revoke serial 1
	if err := ca.Revoke(ctx, 1); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate KRL again
	krlData, err = ca.GenerateKRL(ctx, "test krl")
	if err != nil {
		t.Fatalf("GenerateKRL() error = %v", err)
	}
	parsed, err = ParseKRL(krlData)
	if err != nil {
		t.Fatalf("ParseKRL() error = %v", err)
	}
	if !parsed.IsRevoked(1) {
		t.Error("serial 1 should be revoked")
	}
	if parsed.IsRevoked(2) {
		t.Error("serial 2 should not be revoked")
	}

	// Save and load KRL
	if err := store.SaveKRL(ctx, krlData); err != nil {
		t.Fatalf("SaveKRL() error = %v", err)
	}
	loaded, err := store.LoadKRL(ctx)
	if err != nil {
		t.Fatalf("LoadKRL() error = %v", err)
	}
	if len(loaded) != len(krlData) {
		t.Errorf("LoadKRL() size = %d, want %d", len(loaded), len(krlData))
	}
}

func TestUpdateIndexStatus(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}

	// Add an entry
	entry := IndexEntry{
		Status:  "V",
		Serial:  1,
		KeyID:   "test",
		CertType: "user",
	}
	if err := store.AppendIndex(ctx, entry); err != nil {
		t.Fatal(err)
	}

	// Update status
	if err := store.UpdateIndexStatus(ctx, 1, "R"); err != nil {
		t.Fatalf("UpdateIndexStatus() error = %v", err)
	}

	// Verify
	entries, err := store.ReadIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Status != "R" {
		t.Errorf("Status = %q, want R", entries[0].Status)
	}
}

func TestUpdateIndexStatusNotFound(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}

	err := store.UpdateIndexStatus(ctx, 999, "R")
	if err == nil {
		t.Fatal("UpdateIndexStatus() should fail for non-existent serial")
	}
}

func TestSaveLoadKRL(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}

	data := []byte("test krl data")
	if err := store.SaveKRL(ctx, data); err != nil {
		t.Fatalf("SaveKRL() error = %v", err)
	}

	loaded, err := store.LoadKRL(ctx)
	if err != nil {
		t.Fatalf("LoadKRL() error = %v", err)
	}
	if string(loaded) != string(data) {
		t.Errorf("LoadKRL() = %q, want %q", loaded, data)
	}
}

func TestLoadKRLNotExists(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	_, err := store.LoadKRL(ctx)
	if err == nil {
		t.Fatal("LoadKRL() should fail when KRL doesn't exist")
	}
}

func TestReadSSHStringErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"data too short", []byte{0x01, 0x02}},
		{"length exceeds available", []byte{0x00, 0x00, 0x00, 0x64}}, // length=100, 0 bytes follow
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := readSSHString(tt.data)
			if err == nil {
				t.Error("readSSHString() should fail")
			}
		})
	}
}

func TestParseSerialListError(t *testing.T) {
	_, err := parseSerialList([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("parseSerialList() should fail for non-multiple-of-8 length")
	}
}

func TestParseSerialBitmapErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x01, 0x02, 0x03}},
		{"malformed bitmap string", func() []byte {
			b := make([]byte, 12)
			binary.BigEndian.PutUint64(b, 0)       // offset = 0
			binary.BigEndian.PutUint32(b[8:], 100) // string length = 100, 0 bytes follow
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSerialBitmap(tt.data)
			if err == nil {
				t.Error("parseSerialBitmap() should fail")
			}
		})
	}
}

func TestParseKeyIDsError(t *testing.T) {
	_, err := parseKeyIDs([]byte{0x00, 0x00, 0x00, 0x64}) // length=100, 0 bytes follow
	if err == nil {
		t.Error("parseKeyIDs() should fail with truncated SSH string")
	}
}

func TestMarshalSerialBitmapMSB(t *testing.T) {
	// {0, 7} → bitmap bits 0 and 7 set → byte 0x81 → MSB set → padding 0x00 prepended
	serials := []uint64{0, 7}
	data := marshalSerialBitmap(serials)
	parsed, err := parseSerialBitmap(data)
	if err != nil {
		t.Fatalf("parseSerialBitmap() error = %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("len(parsed) = %d, want 2", len(parsed))
	}
	found := map[uint64]bool{}
	for _, s := range parsed {
		found[s] = true
	}
	if !found[0] || !found[7] {
		t.Errorf("parsed = %v, want {0, 7}", parsed)
	}
}

func TestParseKRLMalformed(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"bad format version", func() []byte {
			d := make([]byte, 44)
			binary.BigEndian.PutUint64(d, krlMagic)
			binary.BigEndian.PutUint32(d[8:], 99) // bad version
			return d
		}(), true},
		{"truncated reserved", func() []byte {
			d := make([]byte, 44)
			binary.BigEndian.PutUint64(d, krlMagic)
			binary.BigEndian.PutUint32(d[8:], krlFormatVersion)
			binary.BigEndian.PutUint32(d[36:], 100) // reserved says 100 bytes
			return d
		}(), true},
		{"truncated comment", func() []byte {
			d := make([]byte, 44)
			binary.BigEndian.PutUint64(d, krlMagic)
			binary.BigEndian.PutUint32(d[8:], krlFormatVersion)
			binary.BigEndian.PutUint32(d[36:], 0)   // reserved = empty
			binary.BigEndian.PutUint32(d[40:], 100)  // comment says 100 bytes
			return d
		}(), true},
		{"truncated section data", func() []byte {
			base := MarshalKRL(&KRL{Version: 1, Comment: "test"})
			base = append(base, krlSectionCerts)
			base = append(base, 0x00, 0x00, 0x01, 0x00) // length=256, no data
			return base
		}(), true},
		{"unknown section type skipped", func() []byte {
			base := MarshalKRL(&KRL{Version: 1, Comment: "test"})
			base = append(base, 0xFF)                    // unknown type
			base = append(base, 0x00, 0x00, 0x00, 0x00) // length=0
			return base
		}(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKRL(tt.data)
			if tt.wantErr && err == nil {
				t.Error("ParseKRL() should fail")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ParseKRL() unexpected error = %v", err)
			}
		})
	}
}

func TestParseCertSectionErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated CA key", []byte{0x00, 0x00, 0x01, 0x00}}, // length=256, no data
		{"invalid CA key", func() []byte {
			return appendSSHString(nil, []byte{0x01, 0x02, 0x03}) // garbage key blob
		}()},
		{"truncated reserved", func() []byte {
			var buf []byte
			buf = appendSSHString(buf, nil)       // empty CA key
			buf = append(buf, 0x00, 0x00, 0x00)   // truncated reserved length
			return buf
		}()},
		{"truncated subsection data", func() []byte {
			var buf []byte
			buf = appendSSHString(buf, nil)                        // CA key
			buf = appendSSHString(buf, nil)                        // reserved
			buf = append(buf, krlCertSerialList)                   // subsection type
			buf = append(buf, 0x00, 0x00, 0x01, 0x00)             // length=256, no data
			return buf
		}()},
		{"invalid serial list", func() []byte {
			var buf []byte
			buf = appendSSHString(buf, nil)
			buf = appendSSHString(buf, nil)
			buf = append(buf, krlCertSerialList)
			buf = appendSSHString(buf, []byte{0x01, 0x02, 0x03}) // 3 bytes, not multiple of 8
			return buf
		}()},
		{"invalid bitmap", func() []byte {
			var buf []byte
			buf = appendSSHString(buf, nil)
			buf = appendSSHString(buf, nil)
			buf = append(buf, krlCertBitmap)
			buf = appendSSHString(buf, []byte{0x01, 0x02}) // too short for bitmap
			return buf
		}()},
		{"invalid key ID", func() []byte {
			var buf []byte
			buf = appendSSHString(buf, nil)
			buf = appendSSHString(buf, nil)
			buf = append(buf, krlCertKeyID)
			// inner SSH string: length=100, 0 bytes follow
			buf = appendSSHString(buf, []byte{0x00, 0x00, 0x00, 0x64})
			return buf
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCertSection(tt.data)
			if err == nil {
				t.Error("parseCertSection() should fail")
			}
		})
	}
}

func TestShouldUseBitmap(t *testing.T) {
	tests := []struct {
		name    string
		serials []uint64
		want    bool
	}{
		{"few serials", []uint64{1, 2}, false},
		{"sparse", []uint64{1, 1000, 2000}, false},
		{"dense", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseBitmap(tt.serials); got != tt.want {
				t.Errorf("shouldUseBitmap() = %v, want %v", got, tt.want)
			}
		})
	}
}
