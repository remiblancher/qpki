package ocsp

import (
	"context"
	"crypto"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

// =============================================================================
// OCSP Responder Concurrency Tests
// =============================================================================

// TestConcurrency_Responder_ConcurrentRequests tests concurrent OCSP request handling.
// This validates that the Responder can safely handle multiple simultaneous requests
// without race conditions when accessing the signer.
func TestConcurrency_Responder_ConcurrentRequests(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Create multiple valid certificate serials
	const numCerts = 10
	index := make([]ca.IndexEntry, numCerts)
	for i := 0; i < numCerts; i++ {
		index[i] = ca.IndexEntry{
			Status: "V",
			Serial: big.NewInt(int64(1000 + i)).Bytes(),
			Expiry: time.Now().Add(24 * time.Hour),
		}
	}

	store := &mockCAStore{
		caCert: caCert,
		index:  index,
	}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine requests status for a different certificate
			serial := big.NewInt(int64(1000 + (id % numCerts)))
			certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: NewCertIDFromSerial failed: %w", id, err)
				return
			}

			req := &OCSPRequest{
				TBSRequest: TBSRequest{
					RequestList: []Request{
						{ReqCert: *certID},
					},
				},
			}

			responseBytes, err := responder.Respond(context.Background(), req)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: Respond failed: %w", id, err)
				return
			}

			if responseBytes == nil {
				errors <- fmt.Errorf("goroutine %d: Respond returned nil", id)
				return
			}

			// Parse response to verify it's valid
			resp, err := ParseResponse(responseBytes)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ParseResponse failed: %w", id, err)
				return
			}

			if resp == nil {
				errors <- fmt.Errorf("goroutine %d: parsed response is nil", id)
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
		t.Errorf("Expected %d successful responses, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_Responder_MixedStatuses tests concurrent requests for certificates
// with different statuses (valid, revoked, unknown).
func TestConcurrency_Responder_MixedStatuses(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	revTime := time.Now().Add(-1 * time.Hour)

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{Status: "V", Serial: big.NewInt(1001).Bytes(), Expiry: time.Now().Add(24 * time.Hour)},
			{Status: "V", Serial: big.NewInt(1002).Bytes(), Expiry: time.Now().Add(24 * time.Hour)},
			{Status: "R", Serial: big.NewInt(2001).Bytes(), Revocation: revTime},
			{Status: "R", Serial: big.NewInt(2002).Bytes(), Revocation: revTime},
			{Status: "E", Serial: big.NewInt(3001).Bytes()},
		},
	}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	// Define test cases with expected statuses
	testCases := []struct {
		serial         int64
		expectedStatus CertStatus
	}{
		{1001, CertStatusGood},
		{1002, CertStatusGood},
		{2001, CertStatusRevoked},
		{2002, CertStatusRevoked},
		{3001, CertStatusGood}, // Expired certs still return "good"
		{9999, CertStatusUnknown},
	}

	const numGoroutines = 60
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			tc := testCases[id%len(testCases)]
			serial := big.NewInt(tc.serial)

			status, err := responder.CheckStatusBySerial(context.Background(), serial)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d (serial %d): CheckStatusBySerial failed: %w", id, tc.serial, err)
				return
			}

			if status.Status != tc.expectedStatus {
				errors <- fmt.Errorf("goroutine %d (serial %d): expected status %v, got %v", id, tc.serial, tc.expectedStatus, status.Status)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestConcurrency_CheckStatus_Concurrent tests concurrent CheckStatus calls.
func TestConcurrency_CheckStatus_Concurrent(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{Status: "V", Serial: serial.Bytes()},
		},
	}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
	if err != nil {
		t.Fatalf("NewCertIDFromSerial() error = %v", err)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			status, err := responder.CheckStatus(context.Background(), certID)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: CheckStatus failed: %w", id, err)
				return
			}

			if status.Status != CertStatusGood {
				errors <- fmt.Errorf("goroutine %d: expected status Good, got %v", id, status.Status)
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
		t.Errorf("Expected %d successful checks, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_ServeOCSP_Concurrent tests concurrent ServeOCSP calls.
func TestConcurrency_ServeOCSP_Concurrent(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Create multiple certificates
	const numCerts = 5
	index := make([]ca.IndexEntry, numCerts)
	for i := 0; i < numCerts; i++ {
		index[i] = ca.IndexEntry{
			Status: "V",
			Serial: big.NewInt(int64(100 + i)).Bytes(),
		}
	}

	store := &mockCAStore{
		caCert: caCert,
		index:  index,
	}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	// Pre-create request bytes for each certificate
	requestBytes := make([][]byte, numCerts)
	for i := 0; i < numCerts; i++ {
		serial := big.NewInt(int64(100 + i))
		certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
		if err != nil {
			t.Fatalf("NewCertIDFromSerial() error = %v", err)
		}

		req := &OCSPRequest{
			TBSRequest: TBSRequest{
				RequestList: []Request{{ReqCert: *certID}},
			},
		}

		reqBytes, err := req.Marshal()
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		requestBytes[i] = reqBytes
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine uses a different request
			reqBytes := requestBytes[id%numCerts]

			responseBytes, err := responder.ServeOCSP(context.Background(), reqBytes)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ServeOCSP failed: %w", id, err)
				return
			}

			if responseBytes == nil {
				errors <- fmt.Errorf("goroutine %d: ServeOCSP returned nil", id)
				return
			}

			// Verify response can be parsed
			resp, err := ParseResponse(responseBytes)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: ParseResponse failed: %w", id, err)
				return
			}

			if resp == nil {
				errors <- fmt.Errorf("goroutine %d: parsed response is nil", id)
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
		t.Errorf("Expected %d successful responses, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_CreateResponseForSerial_Concurrent tests concurrent response creation.
func TestConcurrency_CreateResponseForSerial_Concurrent(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			serial := big.NewInt(int64(id + 1))
			status := CertStatusGood
			if id%3 == 0 {
				status = CertStatusRevoked
			}

			revTime := time.Time{}
			if status == CertStatusRevoked {
				revTime = time.Now().Add(-1 * time.Hour)
			}

			responseBytes, err := responder.CreateResponseForSerial(serial, status, revTime, ReasonUnspecified)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: CreateResponseForSerial failed: %w", id, err)
				return
			}

			if responseBytes == nil {
				errors <- fmt.Errorf("goroutine %d: CreateResponseForSerial returned nil", id)
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
		t.Errorf("Expected %d successful creations, got %d", numGoroutines, successCount)
	}
}
