package main

import (
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
)

// Note: t.Parallel() is not used because Cobra commands share global flag state.
// Running tests in parallel causes race conditions with flag access.

// =============================================================================
// CMS Sign Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Sign(t *testing.T) {
	tests := []struct {
		name      string
		hash      string
		detached  string
		wantErr   bool
		checkSize int // minimum expected size, 0 to skip
	}{
		{
			name:      "[Functional] CMSSign: DefaultHash",
			hash:      "",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: SHA384",
			hash:      "sha384",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: SHA512",
			hash:      "sha512",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: AttachedSignature",
			hash:      "",
			detached:  "false",
			wantErr:   false,
			checkSize: 100, // attached should be larger
		},
		{
			name:    "[Functional] CMSSign: InvalidHash",
			hash:    "md5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "Test content for "+tt.name)
			outputPath := tc.path("signature.p7s")

			args := []string{"cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", outputPath,
			}

			if tt.hash != "" {
				args = append(args, "--hash", tt.hash)
			}
			if tt.detached != "" {
				args = append(args, "--detached="+tt.detached)
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if _, err := os.Stat(outputPath); os.IsNotExist(err) {
					t.Error("signature file was not created")
				}
				if tt.checkSize > 0 {
					data, _ := os.ReadFile(outputPath)
					if len(data) < tt.checkSize {
						t.Errorf("signature size = %d, want >= %d", len(data), tt.checkSize)
					}
				}
			}
		})
	}
}

func TestF_CMS_Sign_MissingFiles(t *testing.T) {
	tests := []struct {
		name        string
		missingFile string // "data", "cert", or "key"
	}{
		{"[Functional] CMSSign: MissingData", "data"},
		{"[Functional] CMSSign: MissingCert", "cert"},
		{"[Functional] CMSSign: MissingKey", "key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "test")
			outputPath := tc.path("signature.p7s")

			// Override with nonexistent path based on test case
			switch tt.missingFile {
			case "data":
				dataPath = tc.path("nonexistent.txt")
			case "cert":
				certPath = tc.path("nonexistent.crt")
			case "key":
				keyPath = tc.path("nonexistent.key")
			}

			_, err := executeCommand(rootCmd, "cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", outputPath,
			)

			if err == nil {
				t.Errorf("expected error for %s", tt.missingFile)
			}
		})
	}
}

// =============================================================================
// CMS Verify Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Verify(t *testing.T) {
	tests := []struct {
		name        string
		detached    bool
		useCA       bool
		provideData bool
		wantErr     bool
	}{
		{
			name:        "[Functional] CMSVerify: DetachedSignature",
			detached:    true,
			useCA:       false,
			provideData: true,
			wantErr:     false,
		},
		{
			name:        "[Functional] CMSVerify: AttachedSignature",
			detached:    false,
			useCA:       false,
			provideData: false,
			wantErr:     false,
		},
		{
			name:        "[Functional] CMSVerify: WithCACert",
			detached:    true,
			useCA:       true,
			provideData: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Create signature first
			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "Content for "+tt.name)
			sigPath := tc.path("signature.p7s")

			signArgs := []string{"cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", sigPath,
			}
			if !tt.detached {
				signArgs = append(signArgs, "--detached=false")
			}

			if _, err := executeCommand(rootCmd, signArgs...); err != nil {
				t.Fatalf("failed to create signature: %v", err)
			}

			resetCMSFlags()

			// Build verify command
			verifyArgs := []string{"cms", "verify", sigPath}
			if tt.provideData {
				verifyArgs = append(verifyArgs, "--data", dataPath)
			}
			if tt.useCA {
				verifyArgs = append(verifyArgs, "--ca", certPath)
			}

			_, err := executeCommand(rootCmd, verifyArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestF_CMS_Verify_Errors(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testContext) (sigPath, dataPath string)
	}{
		{
			name: "[Functional] CMSVerify: SignatureNotFound",
			setupFunc: func(tc *testContext) (string, string) {
				dataPath := tc.writeFile("data.txt", "test")
				return tc.path("nonexistent.p7s"), dataPath
			},
		},
		{
			name: "[Functional] CMSVerify: WrongData",
			setupFunc: func(tc *testContext) (string, string) {
				// Create valid signature
				certPath, keyPath := tc.setupSigningPair()
				dataPath := tc.writeFile("data.txt", "Original content")
				sigPath := tc.path("signature.p7s")

				resetCMSFlags()
				_, _ = executeCommand(rootCmd, "cms", "sign",
					"--data", dataPath,
					"--cert", certPath,
					"--key", keyPath,
					"--out", sigPath,
				)

				// Return wrong data
				wrongDataPath := tc.writeFile("wrong.txt", "Different content")
				return sigPath, wrongDataPath
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			sigPath, dataPath := tt.setupFunc(tc)

			resetCMSFlags()
			_, err := executeCommand(rootCmd, "cms", "verify",
				sigPath,
				"--data", dataPath,
			)

			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// =============================================================================
// CMS Round Trip Tests (Table-Driven)
// =============================================================================

func TestF_CMS_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string // "ecdsa" or "rsa"
		dataSize int    // 0 for default small content
	}{
		{
			name:    "[Functional] CMSRoundTrip: ECDSA",
			keyType: "ecdsa",
		},
		{
			name:    "[Functional] CMSRoundTrip: RSA",
			keyType: "rsa",
		},
		{
			name:     "[Functional] CMSRoundTrip: LargeFile",
			keyType:  "ecdsa",
			dataSize: 10 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup key pair based on type
			var certPath, keyPath string
			if tt.keyType == "rsa" {
				priv, pub := generateRSAKeyPair(tc.t, 2048)
				cert := generateSelfSignedCert(tc.t, priv, pub)
				certPath = tc.writeCertPEM("test.crt", cert)
				keyPath = tc.writeKeyPEM("test.key", priv)
			} else {
				certPath, keyPath = tc.setupSigningPair()
			}

			// Create data file
			var dataPath string
			if tt.dataSize > 0 {
				content := make([]byte, tt.dataSize)
				for i := range content {
					content[i] = byte(i % 256)
				}
				dataPath = tc.path("data.bin")
				if err := os.WriteFile(dataPath, content, 0644); err != nil {
					t.Fatalf("failed to create data file: %v", err)
				}
			} else {
				dataPath = tc.writeFile("data.txt", "Round trip content for "+tt.name)
			}

			sigPath := tc.path("signature.p7s")

			// Sign
			_, err := executeCommand(rootCmd, "cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", sigPath,
			)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			resetCMSFlags()

			// Verify
			_, err = executeCommand(rootCmd, "cms", "verify",
				sigPath,
				"--data", dataPath,
			)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}

// =============================================================================
// CMS Encrypt Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Encrypt(t *testing.T) {
	tests := []struct {
		name       string
		contentEnc string
		wantErr    bool
	}{
		{
			name:       "[Functional] CMSEncrypt: DefaultAES256GCM",
			contentEnc: "",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: AES256CBC",
			contentEnc: "aes-256-cbc",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: AES128GCM",
			contentEnc: "aes-128-gcm",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: InvalidAlgorithm",
			contentEnc: "invalid-algorithm",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup RSA recipient (needed for encryption)
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			recipientPath := tc.writeCertPEM("recipient.crt", cert)

			// Create input data
			inputPath := tc.writeFile("plaintext.txt", "Secret content for "+tt.name)
			outputPath := tc.path("encrypted.p7m")

			// Build encrypt command
			args := []string{"cms", "encrypt",
				"--recipient", recipientPath,
				"--in", inputPath,
				"--out", outputPath,
			}
			if tt.contentEnc != "" {
				args = append(args, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assertFileExists(t, outputPath)
				assertFileNotEmpty(t, outputPath)
			}
		})
	}
}

func TestF_CMS_Encrypt_MissingFlags(t *testing.T) {
	tests := []struct {
		name    string
		missing string // "recipient", "in", or "out"
	}{
		{"[Functional] CMSEncrypt: MissingRecipient", "recipient"},
		{"[Functional] CMSEncrypt: MissingInput", "in"},
		{"[Functional] CMSEncrypt: MissingOutput", "out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup valid values
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			recipientPath := tc.writeCertPEM("recipient.crt", cert)
			inputPath := tc.writeFile("plaintext.txt", "test content")
			outputPath := tc.path("encrypted.p7m")

			// Build args, skipping the missing one
			var args []string
			args = append(args, "cms", "encrypt")
			if tt.missing != "recipient" {
				args = append(args, "--recipient", recipientPath)
			}
			if tt.missing != "in" {
				args = append(args, "--in", inputPath)
			}
			if tt.missing != "out" {
				args = append(args, "--out", outputPath)
			}

			_, err := executeCommand(rootCmd, args...)
			assertError(t, err)
		})
	}
}

func TestF_CMS_Encrypt_RecipientNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	inputPath := tc.writeFile("plaintext.txt", "test content")

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", tc.path("nonexistent.crt"),
		"--in", inputPath,
		"--out", tc.path("encrypted.p7m"),
	)
	assertError(t, err)
}

func TestF_CMS_Encrypt_InputNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	recipientPath := tc.writeCertPEM("recipient.crt", cert)

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientPath,
		"--in", tc.path("nonexistent.txt"),
		"--out", tc.path("encrypted.p7m"),
	)
	assertError(t, err)
}

func TestF_CMS_Encrypt_MultipleRecipients(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Create two recipients
	priv1, pub1 := generateRSAKeyPair(tc.t, 2048)
	cert1 := generateSelfSignedCert(tc.t, priv1, pub1)
	recipient1Path := tc.writeCertPEM("recipient1.crt", cert1)

	priv2, pub2 := generateRSAKeyPair(tc.t, 2048)
	cert2 := generateSelfSignedCert(tc.t, priv2, pub2)
	recipient2Path := tc.writeCertPEM("recipient2.crt", cert2)

	inputPath := tc.writeFile("plaintext.txt", "Secret for multiple recipients")
	outputPath := tc.path("encrypted.p7m")

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipient1Path,
		"--recipient", recipient2Path,
		"--in", inputPath,
		"--out", outputPath,
	)
	assertNoError(t, err)
	assertFileExists(t, outputPath)
}

// =============================================================================
// CMS Decrypt Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Decrypt_MissingFlags(t *testing.T) {
	tests := []struct {
		name    string
		missing string // "key", "in", or "out"
	}{
		{"[Functional] CMSDecrypt: MissingKey", "key"},
		{"[Functional] CMSDecrypt: MissingInput", "in"},
		{"[Functional] CMSDecrypt: MissingOutput", "out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup valid values
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			tc.writeCertPEM("recipient.crt", cert)
			keyPath := tc.writeKeyPEM("recipient.key", priv)
			encryptedPath := tc.writeFile("encrypted.p7m", "dummy content")
			outputPath := tc.path("decrypted.txt")

			// Build args, skipping the missing one
			var args []string
			args = append(args, "cms", "decrypt")
			if tt.missing != "key" {
				args = append(args, "--key", keyPath)
			}
			if tt.missing != "in" {
				args = append(args, "--in", encryptedPath)
			}
			if tt.missing != "out" {
				args = append(args, "--out", outputPath)
			}

			_, err := executeCommand(rootCmd, args...)
			assertError(t, err)
		})
	}
}

func TestF_CMS_Decrypt_KeyNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	encryptedPath := tc.writeFile("encrypted.p7m", "dummy content")

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", tc.path("nonexistent.key"),
		"--in", encryptedPath,
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

func TestF_CMS_Decrypt_InputNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	tc.writeCertPEM("recipient.crt", cert)
	keyPath := tc.writeKeyPEM("recipient.key", priv)

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", keyPath,
		"--in", tc.path("nonexistent.p7m"),
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

func TestF_CMS_Decrypt_InvalidInput(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	tc.writeCertPEM("recipient.crt", cert)
	keyPath := tc.writeKeyPEM("recipient.key", priv)
	invalidPath := tc.writeFile("invalid.p7m", "not a valid CMS EnvelopedData")

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", keyPath,
		"--in", invalidPath,
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

// =============================================================================
// CMS Encrypt/Decrypt Round-Trip Tests
// =============================================================================

// setupCAWithKEMCredential creates a CA and enrolls a credential with key encipherment for CMS tests.
// Returns: caDir, recipientCertPath, recipientKeyPath
func setupCAWithKEMCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "rsa/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "rsa/email",
		"--var", "cn=recipient@test.local",
		"--var", "email=recipient@test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	credentialDir := filepath.Join(credentialsDir, entries[0].Name())
	recipientCert := filepath.Join(credentialDir, "certificates.pem")
	recipientKey := filepath.Join(credentialDir, "private-keys.pem")

	return caDir, recipientCert, recipientKey
}

// setupCAWithECDHCredential creates an EC CA and enrolls an ECDH encryption credential.
// Returns: caDir, recipientCertPath, recipientKeyPath
func setupCAWithECDHCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ec-ca")
	credentialsDir := tc.path("ec-credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test EC CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init EC CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/encryption",
		"--var", "cn=ECDH Recipient",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll ECDH credential: %v", err)
	}

	// Find the credential
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no ECDH credentials found")
	}

	credentialDir := filepath.Join(credentialsDir, entries[0].Name())
	recipientCert := filepath.Join(credentialDir, "certificates.pem")
	recipientKey := filepath.Join(credentialDir, "private-keys.pem")

	return caDir, recipientCert, recipientKey
}

// setupCAWithMLKEMCredential creates an ML-KEM CA and enrolls an ML-KEM encryption credential.
// Returns: caDir, recipientCertPath, recipientKeyPath
func setupCAWithMLKEMCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ml-ca")
	credentialsDir := tc.path("ml-credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ml/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test ML-KEM CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init ML-KEM CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ml/encryption",
		"--var", "cn=ML-KEM Recipient",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll ML-KEM credential: %v", err)
	}

	// Find the credential
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no ML-KEM credentials found")
	}

	credentialDir := filepath.Join(credentialsDir, entries[0].Name())
	recipientCert := filepath.Join(credentialDir, "certificates.pem")
	recipientKey := filepath.Join(credentialDir, "private-keys.pem")

	return caDir, recipientCert, recipientKey
}

func TestF_CMS_EncryptDecrypt_RoundTrip(t *testing.T) {
	tc := newTestContext(t)

	// Setup CA and recipient credential with proper extensions
	_, recipientCert, recipientKey := setupCAWithKEMCredential(tc)

	tests := []struct {
		name       string
		contentEnc string
		content    string
	}{
		{
			name:       "[Functional] CMSEncryptDecrypt: DefaultAES256GCM",
			contentEnc: "",
			content:    "Round trip test with default encryption",
		},
		{
			name:       "[Functional] CMSEncryptDecrypt: AES256CBC",
			contentEnc: "aes-256-cbc",
			content:    "Round trip test with AES-256-CBC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCMSFlags()

			// Create input
			inputPath := tc.writeFile("plaintext-"+tt.name+".txt", tt.content)
			encryptedPath := tc.path("encrypted-" + tt.name + ".p7m")
			decryptedPath := tc.path("decrypted-" + tt.name + ".txt")

			// Encrypt
			encryptArgs := []string{"cms", "encrypt",
				"--recipient", recipientCert,
				"--in", inputPath,
				"--out", encryptedPath,
			}
			if tt.contentEnc != "" {
				encryptArgs = append(encryptArgs, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, encryptArgs...)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			resetCMSFlags()

			// Decrypt with certificate for matching
			_, err = executeCommand(rootCmd, "cms", "decrypt",
				"--key", recipientKey,
				"--cert", recipientCert,
				"--in", encryptedPath,
				"--out", decryptedPath,
			)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			// Verify content matches
			decrypted, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Fatalf("failed to read decrypted file: %v", err)
			}

			if string(decrypted) != tt.content {
				t.Errorf("decrypted content mismatch: got %d bytes, want %d bytes",
					len(decrypted), len(tt.content))
			}
		})
	}
}

func TestF_CMS_EncryptDecrypt_WithCert(t *testing.T) {
	tc := newTestContext(t)

	// Setup CA and recipient credential
	_, recipientCert, recipientKey := setupCAWithKEMCredential(tc)

	resetCMSFlags()

	content := "Test with certificate matching"
	inputPath := tc.writeFile("plaintext.txt", content)
	encryptedPath := tc.path("encrypted.p7m")
	decryptedPath := tc.path("decrypted.txt")

	// Encrypt
	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientCert,
		"--in", inputPath,
		"--out", encryptedPath,
	)
	assertNoError(t, err)

	resetCMSFlags()

	// Decrypt with certificate for matching
	_, err = executeCommand(rootCmd, "cms", "decrypt",
		"--key", recipientKey,
		"--cert", recipientCert,
		"--in", encryptedPath,
		"--out", decryptedPath,
	)
	assertNoError(t, err)

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	assertNoError(t, err)
	if string(decrypted) != content {
		t.Error("decrypted content does not match original")
	}
}

// =============================================================================
// CMS Info Tests
// =============================================================================

func TestF_CMS_Info_SignedData(t *testing.T) {
	tc := newTestContext(t)

	// Create signed data
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for info")
	sigPath := tc.path("signature.p7s")

	resetCMSFlags()
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	assertNoError(t, err)

	// Get info about the signed data
	_, err = executeCommand(rootCmd, "cms", "info", sigPath)
	assertNoError(t, err)
}

func TestF_CMS_Info_EnvelopedData(t *testing.T) {
	tc := newTestContext(t)

	// Create enveloped data
	_, recipientCert, _ := setupCAWithKEMCredential(tc)
	inputPath := tc.writeFile("plaintext.txt", "secret content")
	encryptedPath := tc.path("encrypted.p7m")

	resetCMSFlags()
	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientCert,
		"--in", inputPath,
		"--out", encryptedPath,
	)
	assertNoError(t, err)

	// Get info about the enveloped data
	_, err = executeCommand(rootCmd, "cms", "info", encryptedPath)
	assertNoError(t, err)
}

func TestF_CMS_Info_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "cms", "info", tc.path("nonexistent.p7s"))
	assertError(t, err)
}

func TestF_CMS_Info_InvalidFile(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.p7s", "not a CMS message")
	_, err := executeCommand(rootCmd, "cms", "info", invalidPath)
	assertError(t, err)
}

func TestF_CMS_Info_ArgMissing(t *testing.T) {
	_, err := executeCommand(rootCmd, "cms", "info")
	assertError(t, err)
}

// =============================================================================
// CMS Encrypt/Decrypt Round-Trip Tests - ECDH
// =============================================================================

func TestF_CMS_EncryptDecrypt_ECDH(t *testing.T) {
	tc := newTestContext(t)

	// Setup EC CA and ECDH recipient credential
	_, recipientCert, recipientKey := setupCAWithECDHCredential(tc)

	tests := []struct {
		name       string
		contentEnc string
		content    string
	}{
		{
			name:       "[Functional] CMSEncryptDecrypt_ECDH: DefaultAES256GCM",
			contentEnc: "",
			content:    "ECDH round trip test with default encryption",
		},
		{
			name:       "[Functional] CMSEncryptDecrypt_ECDH: AES256CBC",
			contentEnc: "aes-256-cbc",
			content:    "ECDH round trip test with AES-256-CBC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCMSFlags()

			// Create input
			inputPath := tc.writeFile("ecdh-plaintext-"+tt.name+".txt", tt.content)
			encryptedPath := tc.path("ecdh-encrypted-" + tt.name + ".p7m")
			decryptedPath := tc.path("ecdh-decrypted-" + tt.name + ".txt")

			// Encrypt
			encryptArgs := []string{"cms", "encrypt",
				"--recipient", recipientCert,
				"--in", inputPath,
				"--out", encryptedPath,
			}
			if tt.contentEnc != "" {
				encryptArgs = append(encryptArgs, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, encryptArgs...)
			if err != nil {
				t.Fatalf("ECDH encrypt failed: %v", err)
			}

			resetCMSFlags()

			// Decrypt with certificate for matching
			_, err = executeCommand(rootCmd, "cms", "decrypt",
				"--key", recipientKey,
				"--cert", recipientCert,
				"--in", encryptedPath,
				"--out", decryptedPath,
			)
			if err != nil {
				t.Fatalf("ECDH decrypt failed: %v", err)
			}

			// Verify content matches
			decrypted, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Fatalf("failed to read decrypted file: %v", err)
			}

			if string(decrypted) != tt.content {
				t.Errorf("decrypted content mismatch: got %d bytes, want %d bytes",
					len(decrypted), len(tt.content))
			}
		})
	}
}

// =============================================================================
// CMS Encrypt/Decrypt Round-Trip Tests - ML-KEM (Post-Quantum)
// =============================================================================

func TestF_CMS_EncryptDecrypt_MLKEM(t *testing.T) {
	tc := newTestContext(t)

	// Setup ML-KEM CA and ML-KEM recipient credential
	_, recipientCert, recipientKey := setupCAWithMLKEMCredential(tc)

	tests := []struct {
		name       string
		contentEnc string
		content    string
	}{
		{
			name:       "[Functional] CMSEncryptDecrypt_MLKEM: DefaultAES256GCM",
			contentEnc: "",
			content:    "ML-KEM round trip test with default encryption",
		},
		{
			name:       "[Functional] CMSEncryptDecrypt_MLKEM: AES256CBC",
			contentEnc: "aes-256-cbc",
			content:    "ML-KEM round trip test with AES-256-CBC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCMSFlags()

			// Create input
			inputPath := tc.writeFile("mlkem-plaintext-"+tt.name+".txt", tt.content)
			encryptedPath := tc.path("mlkem-encrypted-" + tt.name + ".p7m")
			decryptedPath := tc.path("mlkem-decrypted-" + tt.name + ".txt")

			// Encrypt
			encryptArgs := []string{"cms", "encrypt",
				"--recipient", recipientCert,
				"--in", inputPath,
				"--out", encryptedPath,
			}
			if tt.contentEnc != "" {
				encryptArgs = append(encryptArgs, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, encryptArgs...)
			if err != nil {
				t.Fatalf("ML-KEM encrypt failed: %v", err)
			}

			resetCMSFlags()

			// Decrypt with certificate for matching
			_, err = executeCommand(rootCmd, "cms", "decrypt",
				"--key", recipientKey,
				"--cert", recipientCert,
				"--in", encryptedPath,
				"--out", decryptedPath,
			)
			if err != nil {
				t.Fatalf("ML-KEM decrypt failed: %v", err)
			}

			// Verify content matches
			decrypted, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Fatalf("failed to read decrypted file: %v", err)
			}

			if string(decrypted) != tt.content {
				t.Errorf("decrypted content mismatch: got %d bytes, want %d bytes",
					len(decrypted), len(tt.content))
			}
		})
	}
}

// =============================================================================
// CMS Encrypt/Decrypt Round-Trip Tests - Hybrid (Multi-Recipient)
// =============================================================================

func TestF_CMS_EncryptDecrypt_Hybrid_MultiRecipient(t *testing.T) {
	tc := newTestContext(t)

	// Setup RSA recipient
	_, rsaCert, rsaKey := setupCAWithKEMCredential(tc)

	// Setup ML-KEM recipient (separate CA context)
	mlkemDir := tc.path("mlkem-setup")
	if err := os.MkdirAll(mlkemDir, 0755); err != nil {
		t.Fatalf("failed to create ml-kem setup dir: %v", err)
	}
	tc2 := &testContext{t: t, tempDir: mlkemDir}
	_, mlkemCert, mlkemKey := setupCAWithMLKEMCredential(tc2)

	content := "Hybrid encryption test with RSA and ML-KEM recipients"
	inputPath := tc.writeFile("hybrid-plaintext.txt", content)
	encryptedPath := tc.path("hybrid-encrypted.p7m")

	resetCMSFlags()

	// Encrypt with both recipients
	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", rsaCert,
		"--recipient", mlkemCert,
		"--in", inputPath,
		"--out", encryptedPath,
	)
	if err != nil {
		t.Fatalf("hybrid encrypt failed: %v", err)
	}

	// Test 1: Decrypt with RSA key
	t.Run("[Functional] CMSEncryptDecrypt_Hybrid: DecryptWithRSA", func(t *testing.T) {
		resetCMSFlags()
		decryptedPath := tc.path("hybrid-decrypted-rsa.txt")

		_, err := executeCommand(rootCmd, "cms", "decrypt",
			"--key", rsaKey,
			"--cert", rsaCert,
			"--in", encryptedPath,
			"--out", decryptedPath,
		)
		if err != nil {
			t.Fatalf("hybrid decrypt with RSA failed: %v", err)
		}

		decrypted, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Fatalf("failed to read decrypted file: %v", err)
		}

		if string(decrypted) != content {
			t.Errorf("decrypted content mismatch")
		}
	})

	// Test 2: Decrypt with ML-KEM key
	t.Run("[Functional] CMSEncryptDecrypt_Hybrid: DecryptWithMLKEM", func(t *testing.T) {
		resetCMSFlags()
		decryptedPath := tc.path("hybrid-decrypted-mlkem.txt")

		_, err := executeCommand(rootCmd, "cms", "decrypt",
			"--key", mlkemKey,
			"--cert", mlkemCert,
			"--in", encryptedPath,
			"--out", decryptedPath,
		)
		if err != nil {
			t.Fatalf("hybrid decrypt with ML-KEM failed: %v", err)
		}

		decrypted, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Fatalf("failed to read decrypted file: %v", err)
		}

		if string(decrypted) != content {
			t.Errorf("decrypted content mismatch")
		}
	})
}

// =============================================================================
// Unit Tests for Format Functions
// =============================================================================

func TestU_FormatCMSContentType(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{
			name:     "Data",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
			expected: "Data (1.2.840.113549.1.7.1)",
		},
		{
			name:     "SignedData",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
			expected: "SignedData (1.2.840.113549.1.7.2)",
		},
		{
			name:     "EnvelopedData",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3},
			expected: "EnvelopedData (1.2.840.113549.1.7.3)",
		},
		{
			name:     "TSTInfo",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4},
			expected: "TSTInfo (1.2.840.113549.1.9.16.1.4)",
		},
		{
			name:     "Unknown OID",
			oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expected: "1.2.3.4.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatCMSContentType(tt.oid)
			if result != tt.expected {
				t.Errorf("formatCMSContentType(%v) = %q, want %q", tt.oid, result, tt.expected)
			}
		})
	}
}

func TestU_FormatAlgorithmOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		// Digest algorithms
		{
			name:     "SHA-256",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			expected: "SHA-256",
		},
		{
			name:     "SHA-384",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2},
			expected: "SHA-384",
		},
		{
			name:     "SHA-512",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3},
			expected: "SHA-512",
		},
		// Signature algorithms
		{
			name:     "ECDSA-SHA256",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			expected: "ECDSA-SHA256",
		},
		{
			name:     "Ed25519",
			oid:      asn1.ObjectIdentifier{1, 3, 101, 112},
			expected: "Ed25519",
		},
		{
			name:     "RSA-SHA256",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
			expected: "RSA-SHA256",
		},
		// Content encryption
		{
			name:     "AES-256-GCM",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46},
			expected: "AES-256-GCM",
		},
		{
			name:     "AES-256-CBC",
			oid:      asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42},
			expected: "AES-256-CBC",
		},
		// Key encryption
		{
			name:     "RSA-OAEP",
			oid:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7},
			expected: "RSA-OAEP",
		},
		// Unknown
		{
			name:     "Unknown OID",
			oid:      asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
			expected: "1.2.3.4.5.6.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAlgorithmOID(tt.oid)
			if result != tt.expected {
				t.Errorf("formatAlgorithmOID(%v) = %q, want %q", tt.oid, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Unit Tests for parseCACertsFromPEM
// =============================================================================

func TestU_ParseCACertsFromPEM_ChainFile(t *testing.T) {
	// Test: Chain file with signer cert + CA cert should filter only CA
	tc := newTestContext(t)

	// Create CA and signer certificates
	caPriv, caPub := generateRSAKeyPair(t, 2048)
	caCert := generateSelfSignedCACert(t, caPriv, caPub)

	signerPriv, signerPub := generateRSAKeyPair(t, 2048)
	signerCert := generateCertSignedBy(t, signerPriv, signerPub, caCert, caPriv)

	// Write chain.pem (signer + CA)
	chainPath := tc.path("chain.pem")
	chainPEM := certToPEM(signerCert) + certToPEM(caCert)
	if err := os.WriteFile(chainPath, []byte(chainPEM), 0644); err != nil {
		t.Fatalf("failed to write chain: %v", err)
	}

	// Parse and verify
	caCerts, rootCert, err := parseCACertsFromPEM([]byte(chainPEM))
	if err != nil {
		t.Fatalf("parseCACertsFromPEM() error = %v", err)
	}

	// Should return only CA certificate
	if len(caCerts) != 1 {
		t.Errorf("got %d CA certs, want 1", len(caCerts))
	}

	// Root should be the CA cert (self-signed)
	if rootCert == nil {
		t.Error("rootCert should not be nil")
	} else if rootCert.Subject.String() != caCert.Subject.String() {
		t.Errorf("rootCert subject = %v, want %v", rootCert.Subject, caCert.Subject)
	}

	// Verify it's the CA, not the signer
	if len(caCerts) > 0 && !caCerts[0].IsCA {
		t.Error("returned certificate should be a CA")
	}
}

func TestU_ParseCACertsFromPEM_SingleCACert(t *testing.T) {
	// Test: Single CA cert should return it
	caPriv, caPub := generateRSAKeyPair(t, 2048)
	caCert := generateSelfSignedCACert(t, caPriv, caPub)

	caPEM := certToPEM(caCert)

	caCerts, rootCert, err := parseCACertsFromPEM([]byte(caPEM))
	if err != nil {
		t.Fatalf("parseCACertsFromPEM() error = %v", err)
	}

	if len(caCerts) != 1 {
		t.Errorf("got %d CA certs, want 1", len(caCerts))
	}

	if rootCert == nil {
		t.Error("rootCert should not be nil")
	}
}

func TestU_ParseCACertsFromPEM_SingleNonCACert(t *testing.T) {
	// Test: Single non-CA cert should still work (backward compatibility)
	priv, pub := generateRSAKeyPair(t, 2048)
	cert := generateSelfSignedCert(t, priv, pub) // Not a CA

	certPEM := certToPEM(cert)

	caCerts, rootCert, err := parseCACertsFromPEM([]byte(certPEM))
	if err != nil {
		t.Fatalf("parseCACertsFromPEM() error = %v", err)
	}

	// Backward compatibility: single non-CA cert should be returned
	if len(caCerts) != 1 {
		t.Errorf("got %d certs, want 1 (backward compatibility)", len(caCerts))
	}

	if rootCert == nil {
		t.Error("rootCert should not be nil (backward compatibility)")
	}
}

func TestU_ParseCACertsFromPEM_EmptyPEM(t *testing.T) {
	// Test: Empty PEM should return error
	_, _, err := parseCACertsFromPEM([]byte(""))
	if err == nil {
		t.Error("expected error for empty PEM")
	}
}

func TestU_ParseCACertsFromPEM_InvalidPEM(t *testing.T) {
	// Test: Invalid PEM should return error
	_, _, err := parseCACertsFromPEM([]byte("not a valid PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestU_ParseCACertsFromPEM_MultipleCAs(t *testing.T) {
	// Test: Multiple CA certs (root + intermediate) should return all
	rootPriv, rootPub := generateRSAKeyPair(t, 2048)
	rootCert := generateSelfSignedCACert(t, rootPriv, rootPub)

	intPriv, intPub := generateRSAKeyPair(t, 2048)
	intCert := generateIntermediateCACert(t, intPriv, intPub, rootCert, rootPriv)

	chainPEM := certToPEM(intCert) + certToPEM(rootCert)

	caCerts, rootCertResult, err := parseCACertsFromPEM([]byte(chainPEM))
	if err != nil {
		t.Fatalf("parseCACertsFromPEM() error = %v", err)
	}

	// Should return both CA certs
	if len(caCerts) != 2 {
		t.Errorf("got %d CA certs, want 2", len(caCerts))
	}

	// Root should be the self-signed one
	if rootCertResult == nil {
		t.Error("rootCert should not be nil")
	} else if rootCertResult.Subject.String() != rootCert.Subject.String() {
		t.Errorf("rootCert subject = %v, want %v", rootCertResult.Subject, rootCert.Subject)
	}
}
