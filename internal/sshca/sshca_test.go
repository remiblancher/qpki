package sshca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
	"golang.org/x/crypto/ssh"
)

// testSigner wraps ed25519.PrivateKey to implement pkicrypto.Signer for tests.
type testSigner struct {
	priv ed25519.PrivateKey
}

func (s *testSigner) Public() crypto.PublicKey          { return s.priv.Public() }
func (s *testSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.priv.Sign(r, digest, opts)
}
func (s *testSigner) Algorithm() pkicrypto.AlgorithmID { return pkicrypto.AlgEd25519 }

func TestInitAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init a new SSH CA
	ca, err := Init(ctx, store, "test-user-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if ca.Info().Name != "test-user-ca" {
		t.Errorf("Name = %s, want test-user-ca", ca.Info().Name)
	}
	if ca.Info().CertType != "user" {
		t.Errorf("CertType = %s, want user", ca.Info().CertType)
	}
	if ca.Info().Algorithm != "ed25519" {
		t.Errorf("Algorithm = %s, want ed25519", ca.Info().Algorithm)
	}
	if ca.PublicKey() == nil {
		t.Error("PublicKey() returned nil")
	}

	// Init should fail if CA already exists
	_, err = Init(ctx, store, "test-user-ca", pkicrypto.AlgEd25519, "user")
	if err == nil {
		t.Fatal("Init() should fail when CA already exists")
	}
}

func TestInitPQCRejected(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	_, err := Init(ctx, store, "pqc-ca", pkicrypto.AlgMLDSA65, "user")
	if err == nil {
		t.Fatal("Init() should reject PQC algorithms")
	}
}

func TestInitInvalidCertType(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	_, err := Init(ctx, store, "bad-ca", pkicrypto.AlgEd25519, "invalid")
	if err == nil {
		t.Fatal("Init() should reject invalid cert type")
	}
}

func TestIssueUserCertificate(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-user-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Generate a user key pair
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	// Issue a certificate
	cert, err := ca.Issue(ctx, IssueRequest{
		PublicKey:  sshPub,
		KeyID:      "alice@example.com",
		Principals: []string{"alice", "deploy"},
		ValidBefore: time.Now().Add(8 * time.Hour),
		Extensions: DefaultUserExtensions(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Serial != 1 {
		t.Errorf("Serial = %d, want 1", cert.Serial)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want %d (UserCert)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId != "alice@example.com" {
		t.Errorf("KeyId = %s, want alice@example.com", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 2 || cert.ValidPrincipals[0] != "alice" {
		t.Errorf("Principals = %v, want [alice deploy]", cert.ValidPrincipals)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("permit-pty extension missing")
	}

	// Verify the certificate is signed by our CA
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CertChecker.CheckCert() error = %v", err)
	}

	// Verify the certificate was saved to disk
	loaded, err := store.LoadSSHCert(ctx, cert.Serial)
	if err != nil {
		t.Fatalf("LoadSSHCert() error = %v", err)
	}
	if loaded.Serial != cert.Serial {
		t.Errorf("Loaded serial = %d, want %d", loaded.Serial, cert.Serial)
	}

	// Verify index was updated
	entries, err := store.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("ReadIndex() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].KeyID != "alice@example.com" {
		t.Errorf("entry.KeyID = %s, want alice@example.com", entries[0].KeyID)
	}
}

func TestIssueHostCertificate(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-host-ca", pkicrypto.AlgEd25519, "host")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Generate a host key pair
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	sshPub, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	cert, err := ca.Issue(ctx, IssueRequest{
		PublicKey:   sshPub,
		KeyID:       "web01.example.com",
		Principals:  []string{"web01.example.com", "192.168.1.10"},
		ValidBefore: time.Now().Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want %d (HostCert)", cert.CertType, ssh.HostCert)
	}

	// Verify with CertChecker
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("web01.example.com", cert); err != nil {
		t.Errorf("CertChecker.CheckCert() error = %v", err)
	}
}

func TestIssueSerialIncrement(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Issue 3 certificates, verify serial increments
	for i := uint64(1); i <= 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sshPub, _ := ssh.NewPublicKey(pub)

		cert, err := ca.Issue(ctx, IssueRequest{
			PublicKey:   sshPub,
			KeyID:       "user",
			Principals:  []string{"user"},
			ValidBefore: time.Now().Add(1 * time.Hour),
			Extensions:  DefaultUserExtensions(),
		})
		if err != nil {
			t.Fatalf("Issue() #%d error = %v", i, err)
		}
		if cert.Serial != i {
			t.Errorf("cert #%d Serial = %d, want %d", i, cert.Serial, i)
		}
	}
}

func TestIssueValidation(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)

	tests := []struct {
		name string
		req  IssueRequest
	}{
		{"no public key", IssueRequest{KeyID: "test", Principals: []string{"user"}, ValidBefore: time.Now().Add(1 * time.Hour)}},
		{"no key ID", IssueRequest{PublicKey: sshPub, Principals: []string{"user"}, ValidBefore: time.Now().Add(1 * time.Hour)}},
		{"no principals", IssueRequest{PublicKey: sshPub, KeyID: "test", ValidBefore: time.Now().Add(1 * time.Hour)}},
		{"no validity", IssueRequest{PublicKey: sshPub, KeyID: "test", Principals: []string{"user"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ca.Issue(ctx, tt.req)
			if err == nil {
				t.Errorf("Issue() should fail for %s", tt.name)
			}
		})
	}
}

func TestLoadCA(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init a CA first
	ca, err := Init(ctx, store, "load-test-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Load the CA using the same signer
	loaded, err := Load(ctx, store, ca.signer)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Info().Name != "load-test-ca" {
		t.Errorf("loaded Name = %s, want load-test-ca", loaded.Info().Name)
	}
	if loaded.Info().CertType != "user" {
		t.Errorf("loaded CertType = %s, want user", loaded.Info().CertType)
	}
	if loaded.Store().BasePath() != dir {
		t.Errorf("Store().BasePath() = %s, want %s", loaded.Store().BasePath(), dir)
	}

	// Issue a cert with the loaded CA to verify it works
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	cert, err := loaded.Issue(ctx, IssueRequest{
		PublicKey:   sshPub,
		KeyID:       "test-loaded",
		Principals:  []string{"user"},
		ValidBefore: time.Now().Add(1 * time.Hour),
		Extensions:  DefaultUserExtensions(),
	})
	if err != nil {
		t.Fatalf("Issue() with loaded CA error = %v", err)
	}
	if cert.Serial != 1 {
		t.Errorf("cert.Serial = %d, want 1", cert.Serial)
	}
}

func TestLoadCANotFound(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	// Create a mock signer — won't be used since Load fails early
	signer := &testSigner{priv: priv}

	_, err := Load(ctx, store, signer)
	if err == nil {
		t.Fatal("Load() should fail when CA not found")
	}
}

func TestLoadInfo(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	_, err := Init(ctx, store, "info-test-ca", pkicrypto.AlgEd25519, "host")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	info, err := LoadInfo(ctx, store)
	if err != nil {
		t.Fatalf("LoadInfo() error = %v", err)
	}
	if info.Name != "info-test-ca" {
		t.Errorf("Name = %s, want info-test-ca", info.Name)
	}
	if info.CertType != "host" {
		t.Errorf("CertType = %s, want host", info.CertType)
	}
}

func TestDefaultHostExtensions(t *testing.T) {
	exts := DefaultHostExtensions()
	if exts != nil {
		t.Errorf("DefaultHostExtensions() should return nil, got %v", exts)
	}
}

func TestFileStoreLoadCAPublicKey(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init a CA to get a public key saved
	ca, err := Init(ctx, store, "pubkey-test", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Load it back
	pubKey, err := store.LoadCAPublicKey(ctx)
	if err != nil {
		t.Fatalf("LoadCAPublicKey() error = %v", err)
	}

	// Compare with original
	if string(pubKey.Marshal()) != string(ca.PublicKey().Marshal()) {
		t.Error("loaded public key doesn't match original")
	}
}

func TestFileStoreLoadCAInfo(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	_, err := Init(ctx, store, "meta-test", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	info, err := store.LoadCAInfo(ctx)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}
	if info.Name != "meta-test" {
		t.Errorf("Name = %s, want meta-test", info.Name)
	}
	if info.Algorithm != "ed25519" {
		t.Errorf("Algorithm = %s, want ed25519", info.Algorithm)
	}
}

func TestIssueWithExplicitValidAfter(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)

	validAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validBefore := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)

	cert, err := ca.Issue(ctx, IssueRequest{
		PublicKey:   sshPub,
		KeyID:       "explicit-time",
		Principals:  []string{"user"},
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
		Extensions:  DefaultUserExtensions(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.ValidAfter != uint64(validAfter.Unix()) {
		t.Errorf("ValidAfter = %d, want %d", cert.ValidAfter, validAfter.Unix())
	}
	if cert.ValidBefore != uint64(validBefore.Unix()) {
		t.Errorf("ValidBefore = %d, want %d", cert.ValidBefore, validBefore.Unix())
	}
}

func TestIssueWithCriticalOptions(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	ca, err := Init(ctx, store, "test-ca", pkicrypto.AlgEd25519, "user")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)

	cert, err := ca.Issue(ctx, IssueRequest{
		PublicKey:  sshPub,
		KeyID:      "restricted",
		Principals: []string{"deploy"},
		ValidBefore: time.Now().Add(1 * time.Hour),
		CriticalOptions: map[string]string{
			"force-command":  "/usr/bin/deploy.sh",
			"source-address": "10.0.0.0/8",
		},
		Extensions: map[string]string{
			"permit-pty": "",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.CriticalOptions["force-command"] != "/usr/bin/deploy.sh" {
		t.Errorf("force-command = %q, want /usr/bin/deploy.sh", cert.CriticalOptions["force-command"])
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("source-address = %q, want 10.0.0.0/8", cert.CriticalOptions["source-address"])
	}
}

func TestLoadWithCorruptCAInfo(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init the store structure
	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Write a corrupt meta file so Exists() returns true but LoadCAInfo fails
	metaPath := dir + "/ssh-ca.meta.json"
	if err := os.WriteFile(metaPath, []byte("not json"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := &testSigner{priv: priv}

	_, err := Load(ctx, store, signer)
	if err == nil {
		t.Fatal("Load() should fail with corrupt CA info")
	}
}

func TestLoadWithInvalidCertTypeInMeta(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init the store
	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Write meta with invalid cert_type
	info := &CAInfo{Name: "bad", Algorithm: "ed25519", CertType: "invalid"}
	if err := store.SaveCAInfo(ctx, info); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := &testSigner{priv: priv}

	_, err := Load(ctx, store, signer)
	if err == nil {
		t.Fatal("Load() should fail with invalid cert type in meta")
	}
}

func TestFileStoreOperations(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Test Exists before init
	if store.Exists() {
		t.Error("Exists() should be false before init")
	}

	if err := store.Init(ctx); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Check directories exist
	for _, sub := range []string{"certs", "krl"} {
		path := dir + "/" + sub
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("directory %s not created", sub)
		}
	}

	// Test serial increment
	for i := uint64(1); i <= 3; i++ {
		serial, err := store.NextSerial(ctx)
		if err != nil {
			t.Fatalf("NextSerial() error = %v", err)
		}
		if serial != i {
			t.Errorf("NextSerial() = %d, want %d", serial, i)
		}
	}
}

func TestFileStoreInitCancelledContext(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.Init(ctx)
	if err == nil {
		t.Fatal("Init() should fail with cancelled context")
	}
}

func TestFileStoreNextSerialCancelledContext(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.NextSerial(ctxCancel)
	if err == nil {
		t.Fatal("NextSerial() should fail with cancelled context")
	}
}

func TestFileStoreNextSerialCorruptFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Corrupt the serial file
	serialPath := dir + "/serial"
	if err := os.WriteFile(serialPath, []byte("not_a_number\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := store.NextSerial(ctx)
	if err == nil {
		t.Fatal("NextSerial() should fail with corrupt serial file")
	}
}

func TestFileStoreNextSerialMissingFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Don't call Init - serial file doesn't exist
	_, err := store.NextSerial(ctx)
	if err == nil {
		t.Fatal("NextSerial() should fail when serial file is missing")
	}
}

func TestFileStoreSaveSSHCertCancelledContext(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cert := &ssh.Certificate{Serial: 1}
	err := store.SaveSSHCert(ctx, cert)
	if err == nil {
		t.Fatal("SaveSSHCert() should fail with cancelled context")
	}
}

func TestFileStoreLoadSSHCertErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Load non-existent cert
	_, err := store.LoadSSHCert(ctx, 999)
	if err == nil {
		t.Fatal("LoadSSHCert() should fail for non-existent cert")
	}

	// Write invalid cert data
	certPath := dir + "/certs/42-cert.pub"
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = store.LoadSSHCert(ctx, 42)
	if err == nil {
		t.Fatal("LoadSSHCert() should fail with invalid cert data")
	}

	// Write a valid public key (not a cert) to trigger type assertion error
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	pubData := ssh.MarshalAuthorizedKey(sshPub)
	certPath2 := dir + "/certs/43-cert.pub"
	if err := os.WriteFile(certPath2, pubData, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = store.LoadSSHCert(ctx, 43)
	if err == nil {
		t.Fatal("LoadSSHCert() should fail when file contains a plain key, not a cert")
	}

	// Cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.LoadSSHCert(ctxCancel, 1)
	if err == nil {
		t.Fatal("LoadSSHCert() should fail with cancelled context")
	}
}

func TestFileStoreLoadCAPublicKeyErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Missing file
	_, err := store.LoadCAPublicKey(ctx)
	if err == nil {
		t.Fatal("LoadCAPublicKey() should fail when file is missing")
	}

	// Corrupt file
	pubPath := dir + "/ssh-ca.pub"
	if err := os.WriteFile(pubPath, []byte("not a key"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = store.LoadCAPublicKey(ctx)
	if err == nil {
		t.Fatal("LoadCAPublicKey() should fail with corrupt data")
	}
}

func TestFileStoreLoadCAInfoErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Missing file
	_, err := store.LoadCAInfo(ctx)
	if err == nil {
		t.Fatal("LoadCAInfo() should fail when file is missing")
	}

	// Corrupt JSON
	metaPath := dir + "/ssh-ca.meta.json"
	if err := os.WriteFile(metaPath, []byte("{invalid"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = store.LoadCAInfo(ctx)
	if err == nil {
		t.Fatal("LoadCAInfo() should fail with corrupt JSON")
	}
}

func TestFileStoreAppendIndexErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Missing index file
	err := store.AppendIndex(ctx, IndexEntry{Serial: 1, KeyID: "test"})
	if err == nil {
		t.Fatal("AppendIndex() should fail when index file is missing")
	}

	// Corrupt index file
	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}
	indexPath := dir + "/index.json"
	if err := os.WriteFile(indexPath, []byte("not json"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err = store.AppendIndex(ctx, IndexEntry{Serial: 1, KeyID: "test"})
	if err == nil {
		t.Fatal("AppendIndex() should fail with corrupt index")
	}
}

func TestFileStoreReadIndexErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Missing index file
	_, err := store.ReadIndex(ctx)
	if err == nil {
		t.Fatal("ReadIndex() should fail when index file is missing")
	}

	// Corrupt index file
	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}
	indexPath := dir + "/index.json"
	if err := os.WriteFile(indexPath, []byte("[invalid"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = store.ReadIndex(ctx)
	if err == nil {
		t.Fatal("ReadIndex() should fail with corrupt index")
	}
}

func TestFileStoreSaveCAPublicKeyError(t *testing.T) {
	// Use a read-only directory to trigger write errors
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Make dir read-only after creation so WriteFile fails
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)

	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	err := store.SaveCAPublicKey(ctx, sshPub)
	if err == nil {
		t.Fatal("SaveCAPublicKey() should fail on read-only dir")
	}
}

func TestFileStoreSaveCAInfoError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	info := &CAInfo{Name: "test", Algorithm: "ed25519", CertType: "user"}

	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	err := store.SaveCAInfo(ctx, info)
	if err == nil {
		t.Fatal("SaveCAInfo() should fail on read-only dir")
	}
}

func TestFileStoreSaveSSHCertWriteError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Make certs dir read-only
	certsDir := dir + "/certs"
	if err := os.Chmod(certsDir, 0555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(certsDir, 0755) })

	// Create a valid signed cert to save
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	cert := &ssh.Certificate{
		Key:       sshPub,
		Serial:    1,
		CertType:  ssh.UserCert,
		KeyId:     "test",
		ValidPrincipals: []string{"user"},
		ValidAfter:  uint64(time.Now().Unix()),
		ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}

	err := store.SaveSSHCert(ctx, cert)
	if err == nil {
		t.Fatal("SaveSSHCert() should fail on read-only certs dir")
	}
}

func TestFileStoreNextSerialWriteError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Make serial file read-only
	serialPath := dir + "/serial"
	if err := os.Chmod(serialPath, 0444); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(serialPath, 0644) })

	_, err := store.NextSerial(ctx)
	if err == nil {
		t.Fatal("NextSerial() should fail when serial file is read-only")
	}
}

func TestFileStoreAppendIndexWriteError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatalf("store.Init() error = %v", err)
	}

	// Make index file read-only
	indexPath := dir + "/index.json"
	if err := os.Chmod(indexPath, 0444); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(indexPath, 0644) })

	err := store.AppendIndex(ctx, IndexEntry{Serial: 1, KeyID: "test"})
	if err == nil {
		t.Fatal("AppendIndex() should fail when index file is read-only")
	}
}

func TestFileStoreInitWriteErrors(t *testing.T) {
	dir := t.TempDir()
	subDir := dir + "/readonly"
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Make parent read-only so MkdirAll fails for nested dirs
	if err := os.Chmod(subDir, 0555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subDir, 0755) })

	store := NewFileStore(subDir + "/nested")
	ctx := context.Background()

	err := store.Init(ctx)
	if err == nil {
		t.Fatal("Init() should fail when cannot create directories")
	}
}

func TestFileStoreInitIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	// Init twice should not fail (serial and index already exist)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("first Init() error = %v", err)
	}
	if err := store.Init(ctx); err != nil {
		t.Fatalf("second Init() error = %v", err)
	}
}

// --- Store error path tests ---

func TestUpdateIndexStatusReadError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	// Don't init — index file missing
	err := store.UpdateIndexStatus(context.Background(), 1, "R")
	if err == nil {
		t.Fatal("UpdateIndexStatus() should fail when index file is missing")
	}
}

func TestUpdateIndexStatusCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/index.json", []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	err := store.UpdateIndexStatus(ctx, 1, "R")
	if err == nil {
		t.Fatal("UpdateIndexStatus() should fail with corrupt JSON")
	}
}

func TestUpdateIndexStatusWriteError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendIndex(ctx, IndexEntry{Serial: 1, KeyID: "test", Status: "V"}); err != nil {
		t.Fatal(err)
	}

	indexPath := dir + "/index.json"
	if err := os.Chmod(indexPath, 0444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(indexPath, 0644) })

	err := store.UpdateIndexStatus(ctx, 1, "R")
	if err == nil {
		t.Fatal("UpdateIndexStatus() should fail when index is read-only")
	}
}

func TestSaveKRLWriteError(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}

	krlDir := dir + "/krl"
	if err := os.Chmod(krlDir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(krlDir, 0755) })

	err := store.SaveKRL(ctx, []byte("test data"))
	if err == nil {
		t.Fatal("SaveKRL() should fail on read-only krl dir")
	}
}

func TestFileStoreInitSerialWriteError(t *testing.T) {
	dir := t.TempDir()
	basePath := dir + "/ca"

	// Pre-create directories so MkdirAll is a no-op
	_ = os.MkdirAll(basePath+"/certs", 0755)
	_ = os.MkdirAll(basePath+"/krl", 0755)

	// Make basePath read-only so serial file can't be created
	if err := os.Chmod(basePath, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(basePath, 0755) })

	store := NewFileStore(basePath)
	err := store.Init(context.Background())
	if err == nil {
		t.Fatal("Init() should fail when serial file can't be written")
	}
}

func TestFileStoreInitIndexWriteError(t *testing.T) {
	dir := t.TempDir()
	basePath := dir + "/ca"

	// Pre-create directories and serial file
	_ = os.MkdirAll(basePath+"/certs", 0755)
	_ = os.MkdirAll(basePath+"/krl", 0755)
	_ = os.WriteFile(basePath+"/serial", []byte("1\n"), 0644)

	// Make basePath read-only so index file can't be created
	if err := os.Chmod(basePath, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(basePath, 0755) })

	store := NewFileStore(basePath)
	err := store.Init(context.Background())
	if err == nil {
		t.Fatal("Init() should fail when index file can't be written")
	}
}

// --- failStore: mock Store for SSHCA error path tests ---

type failStore struct {
	Store // embedded for delegation to a real store when needed

	initErr            error
	existsOverride     *bool
	nextSerialVal      uint64
	nextSerialErr      error
	saveSSHCertErr     error
	saveCAPublicKeyErr error
	saveCAInfoErr      error
	appendIndexErr     error
	readIndexEntries   []IndexEntry
	readIndexErr       error
}

func (s *failStore) Init(ctx context.Context) error {
	if s.initErr != nil {
		return s.initErr
	}
	if s.Store != nil {
		return s.Store.Init(ctx)
	}
	return nil
}

func (s *failStore) Exists() bool {
	if s.existsOverride != nil {
		return *s.existsOverride
	}
	if s.Store != nil {
		return s.Store.Exists()
	}
	return false
}

func (s *failStore) BasePath() string {
	if s.Store != nil {
		return s.Store.BasePath()
	}
	return ""
}

func (s *failStore) NextSerial(ctx context.Context) (uint64, error) {
	if s.nextSerialErr != nil {
		return 0, s.nextSerialErr
	}
	if s.nextSerialVal > 0 {
		return s.nextSerialVal, nil
	}
	if s.Store != nil {
		return s.Store.NextSerial(ctx)
	}
	return 0, fmt.Errorf("no underlying store")
}

func (s *failStore) SaveSSHCert(ctx context.Context, cert *ssh.Certificate) error {
	if s.saveSSHCertErr != nil {
		return s.saveSSHCertErr
	}
	if s.Store != nil {
		return s.Store.SaveSSHCert(ctx, cert)
	}
	return nil
}

func (s *failStore) SaveCAPublicKey(ctx context.Context, pubKey ssh.PublicKey) error {
	if s.saveCAPublicKeyErr != nil {
		return s.saveCAPublicKeyErr
	}
	if s.Store != nil {
		return s.Store.SaveCAPublicKey(ctx, pubKey)
	}
	return nil
}

func (s *failStore) SaveCAInfo(ctx context.Context, info *CAInfo) error {
	if s.saveCAInfoErr != nil {
		return s.saveCAInfoErr
	}
	if s.Store != nil {
		return s.Store.SaveCAInfo(ctx, info)
	}
	return nil
}

func (s *failStore) AppendIndex(ctx context.Context, entry IndexEntry) error {
	if s.appendIndexErr != nil {
		return s.appendIndexErr
	}
	if s.Store != nil {
		return s.Store.AppendIndex(ctx, entry)
	}
	return nil
}

func (s *failStore) ReadIndex(ctx context.Context) ([]IndexEntry, error) {
	if s.readIndexErr != nil {
		return nil, s.readIndexErr
	}
	if s.readIndexEntries != nil {
		return s.readIndexEntries, nil
	}
	if s.Store != nil {
		return s.Store.ReadIndex(ctx)
	}
	return nil, fmt.Errorf("no underlying store")
}

// --- SSHCA error path tests via failStore ---

func TestInitStoreInitError(t *testing.T) {
	fs := &failStore{initErr: fmt.Errorf("disk full")}
	_, err := Init(context.Background(), fs, "test", pkicrypto.AlgEd25519, "user")
	if err == nil {
		t.Fatal("Init() should fail when store.Init fails")
	}
}

func TestInitSaveCAPublicKeyError(t *testing.T) {
	dir := t.TempDir()
	real := NewFileStore(dir)
	fs := &failStore{Store: real, saveCAPublicKeyErr: fmt.Errorf("write error")}
	_, err := Init(context.Background(), fs, "test", pkicrypto.AlgEd25519, "user")
	if err == nil {
		t.Fatal("Init() should fail when SaveCAPublicKey fails")
	}
}

func TestInitSaveCAInfoError(t *testing.T) {
	dir := t.TempDir()
	real := NewFileStore(dir)
	fs := &failStore{Store: real, saveCAInfoErr: fmt.Errorf("write error")}
	_, err := Init(context.Background(), fs, "test", pkicrypto.AlgEd25519, "user")
	if err == nil {
		t.Fatal("Init() should fail when SaveCAInfo fails")
	}
}

func TestIssueStoreErrors(t *testing.T) {
	ctx := context.Background()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)

	req := IssueRequest{
		PublicKey:   sshPub,
		KeyID:       "test",
		Principals:  []string{"user"},
		ValidBefore: time.Now().Add(1 * time.Hour),
	}

	t.Run("NextSerial fails", func(t *testing.T) {
		ca := &SSHCA{
			store:     &failStore{nextSerialErr: fmt.Errorf("serial fail")},
			sshSigner: caSigner,
			info:      &CAInfo{Name: "test"},
			certType:  ssh.UserCert,
		}
		_, err := ca.Issue(ctx, req)
		if err == nil {
			t.Fatal("Issue() should fail when NextSerial fails")
		}
	})

	t.Run("SaveSSHCert fails", func(t *testing.T) {
		ca := &SSHCA{
			store:     &failStore{nextSerialVal: 1, saveSSHCertErr: fmt.Errorf("save fail")},
			sshSigner: caSigner,
			info:      &CAInfo{Name: "test"},
			certType:  ssh.UserCert,
		}
		_, err := ca.Issue(ctx, req)
		if err == nil {
			t.Fatal("Issue() should fail when SaveSSHCert fails")
		}
	})

	t.Run("AppendIndex fails", func(t *testing.T) {
		dir := t.TempDir()
		real := NewFileStore(dir)
		if err := real.Init(ctx); err != nil {
			t.Fatal(err)
		}
		ca := &SSHCA{
			store:     &failStore{Store: real, nextSerialVal: 1, appendIndexErr: fmt.Errorf("index fail")},
			sshSigner: caSigner,
			info:      &CAInfo{Name: "test"},
			certType:  ssh.UserCert,
		}
		_, err := ca.Issue(ctx, req)
		if err == nil {
			t.Fatal("Issue() should fail when AppendIndex fails")
		}
	})
}

func TestGenerateKRLReadIndexError(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)

	ca := &SSHCA{
		store:     &failStore{readIndexErr: fmt.Errorf("read fail")},
		sshSigner: caSigner,
		info:      &CAInfo{Name: "test"},
		certType:  ssh.UserCert,
	}
	_, err := ca.GenerateKRL(context.Background(), "test")
	if err == nil {
		t.Fatal("GenerateKRL() should fail when ReadIndex fails")
	}
}
