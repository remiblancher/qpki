package tsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// TSA Concurrency Tests
// =============================================================================

// createTestTSASetup creates a test TSA certificate and key pair.
func createTestTSASetup(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test TSA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

// TestConcurrency_CreateToken_Concurrent tests concurrent token creation.
// This validates that CreateToken can safely handle multiple simultaneous calls
// without race conditions when accessing the signer.
func TestConcurrency_CreateToken_Concurrent(t *testing.T) {
	cert, signer := createTestTSASetup(t)

	config := &TokenConfig{
		Certificate: cert,
		Signer:      signer,
		Policy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1},
		IncludeTSA:  true,
	}

	serialGen := &RandomSerialGenerator{}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)
	tokens := make(chan *Token, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine creates a token for different data
			testData := []byte(fmt.Sprintf("test data %d", id))
			hash := sha256.Sum256(testData)

			req := &TimeStampReq{
				Version:        1,
				MessageImprint: NewMessageImprint(crypto.SHA256, hash[:]),
				Nonce:          big.NewInt(int64(id + 1)),
				CertReq:        true,
			}

			token, err := CreateToken(context.Background(), req, config, serialGen)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: CreateToken failed: %w", id, err)
				return
			}

			if token == nil || token.Info == nil {
				errors <- fmt.Errorf("goroutine %d: CreateToken returned nil token or info", id)
				return
			}

			if token.Info.SerialNumber == nil {
				errors <- fmt.Errorf("goroutine %d: token has nil serial number", id)
				return
			}

			tokens <- token
			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errors)
	close(tokens)

	for err := range errors {
		t.Error(err)
	}

	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful tokens, got %d", numGoroutines, successCount)
	}

	// Verify all serial numbers are unique
	serialNumbers := make(map[string]bool)
	for token := range tokens {
		serialStr := token.Info.SerialNumber.String()
		if serialNumbers[serialStr] {
			t.Errorf("Duplicate serial number found: %s", serialStr)
		}
		serialNumbers[serialStr] = true
	}
}

// TestConcurrency_SerialGenerator_Concurrent tests the thread-safety of RandomSerialGenerator.
func TestConcurrency_SerialGenerator_Concurrent(t *testing.T) {
	gen := &RandomSerialGenerator{}

	const numGoroutines = 100
	var wg sync.WaitGroup
	serialNumbers := make(chan *big.Int, numGoroutines)
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			serial, err := gen.Next()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: Next() failed: %w", id, err)
				return
			}

			if serial == nil {
				errors <- fmt.Errorf("goroutine %d: Next() returned nil", id)
				return
			}

			serialNumbers <- serial
		}(i)
	}

	wg.Wait()
	close(serialNumbers)
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify all serial numbers are unique
	seen := make(map[string]bool)
	count := 0
	for serial := range serialNumbers {
		serialStr := serial.String()
		if seen[serialStr] {
			t.Errorf("Duplicate serial number: %s", serialStr)
		}
		seen[serialStr] = true
		count++
	}

	if count != numGoroutines {
		t.Errorf("Expected %d serial numbers, got %d", numGoroutines, count)
	}
}

// TestConcurrency_CreateToken_MixedAlgorithms tests concurrent token creation with different keys.
func TestConcurrency_CreateToken_MixedAlgorithms(t *testing.T) {
	// Create multiple TSA setups with different keys
	type tsaSetup struct {
		cert   *x509.Certificate
		signer crypto.Signer
	}

	numSetups := 3
	setups := make([]tsaSetup, numSetups)
	for i := 0; i < numSetups; i++ {
		cert, signer := createTestTSASetup(t)
		setups[i] = tsaSetup{cert: cert, signer: signer}
	}

	serialGen := &RandomSerialGenerator{}

	const numGoroutines = 60
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine uses a different TSA setup
			setup := setups[id%numSetups]

			config := &TokenConfig{
				Certificate: setup.cert,
				Signer:      setup.signer,
				Policy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1},
				IncludeTSA:  true,
			}

			testData := []byte(fmt.Sprintf("test data for setup %d goroutine %d", id%numSetups, id))
			hash := sha256.Sum256(testData)

			req := &TimeStampReq{
				Version:        1,
				MessageImprint: NewMessageImprint(crypto.SHA256, hash[:]),
				Nonce:          big.NewInt(int64(id + 1)),
				CertReq:        true,
			}

			token, err := CreateToken(context.Background(), req, config, serialGen)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: CreateToken failed: %w", id, err)
				return
			}

			if token == nil || token.Info == nil {
				errors <- fmt.Errorf("goroutine %d: CreateToken returned nil", id)
				return
			}

			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful tokens, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_ParseToken_Concurrent tests concurrent token parsing.
func TestConcurrency_ParseToken_Concurrent(t *testing.T) {
	cert, signer := createTestTSASetup(t)

	config := &TokenConfig{
		Certificate: cert,
		Signer:      signer,
		Policy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1},
		IncludeTSA:  true,
	}

	// Pre-create multiple tokens
	const numTokens = 5
	tokenData := make([][]byte, numTokens)
	serialGen := &RandomSerialGenerator{}

	for i := 0; i < numTokens; i++ {
		testData := []byte(fmt.Sprintf("test data %d", i))
		hash := sha256.Sum256(testData)

		req := &TimeStampReq{
			Version:        1,
			MessageImprint: NewMessageImprint(crypto.SHA256, hash[:]),
			Nonce:          big.NewInt(int64(i + 1)),
			CertReq:        true,
		}

		token, err := CreateToken(context.Background(), req, config, serialGen)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}

		tokenData[i] = token.SignedData
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine parses a different token
			data := tokenData[id%numTokens]

			token, err := ParseToken(data)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ParseToken failed: %w", id, err)
				return
			}

			if token == nil || token.Info == nil {
				errors <- fmt.Errorf("goroutine %d: ParseToken returned nil", id)
				return
			}

			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful parses, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_Request_MarshalParse tests concurrent request marshaling and parsing.
func TestConcurrency_Request_MarshalParse(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			testData := []byte(fmt.Sprintf("test data for request %d", id))

			req, err := CreateRequest(testData, crypto.SHA256, big.NewInt(int64(id+1)), true)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: CreateRequest failed: %w", id, err)
				return
			}

			// Marshal
			data, err := req.Marshal()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: Marshal failed: %w", id, err)
				return
			}

			// Parse back
			parsed, err := ParseRequest(data)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ParseRequest failed: %w", id, err)
				return
			}

			// Verify data integrity
			if parsed.Version != 1 {
				errors <- fmt.Errorf("goroutine %d: version mismatch", id)
				return
			}

			if len(parsed.MessageImprint.HashedMessage) != sha256.Size {
				errors <- fmt.Errorf("goroutine %d: hash length mismatch", id)
				return
			}

			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful operations, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_Response_MarshalParse tests concurrent response marshaling and parsing.
func TestConcurrency_Response_MarshalParse(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			var resp *Response
			if id%2 == 0 {
				resp = NewGrantedResponse(nil)
			} else {
				resp = NewRejectionResponse(FailBadRequest, fmt.Sprintf("error %d", id))
			}

			// Marshal
			data, err := resp.Marshal()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: Marshal failed: %w", id, err)
				return
			}

			// Parse back
			parsed, err := ParseResponse(data)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ParseResponse failed: %w", id, err)
				return
			}

			// Verify status
			if id%2 == 0 {
				if !parsed.IsGranted() {
					errors <- fmt.Errorf("goroutine %d: expected granted", id)
					return
				}
			} else {
				if parsed.IsGranted() {
					errors <- fmt.Errorf("goroutine %d: expected rejection", id)
					return
				}
			}

			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful operations, got %d", numGoroutines, successCount)
	}
}
