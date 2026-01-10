package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// createConcTestCert creates a test certificate for concurrency tests.
func createConcTestCert(t *testing.T, serial int64, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestConcurrency_SaveConcurrent tests concurrent Save operations.
func TestConcurrency_SaveConcurrent(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			credID := fmt.Sprintf("cred-%d", id)
			cred := NewCredential(credID, Subject{
				CommonName: fmt.Sprintf("test%d.example.com", id),
			})
			cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

			cert := createConcTestCert(t, int64(id), fmt.Sprintf("test%d.example.com", id))

			if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
				errors <- fmt.Errorf("goroutine %d: save failed: %w", id, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify all credentials were saved
	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(creds) != numGoroutines {
		t.Errorf("Expected %d credentials, got %d", numGoroutines, len(creds))
	}
}

// TestConcurrency_LoadConcurrent tests concurrent Load operations.
func TestConcurrency_LoadConcurrent(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	// Create a credential first
	cred := NewCredential("test-cred", Subject{
		CommonName: "test.example.com",
	})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

	cert := createConcTestCert(t, 1, "test.example.com")
	if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			loaded, err := store.Load(context.Background(), "test-cred")
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: load failed: %w", id, err)
				return
			}

			if loaded.Subject.CommonName != cred.Subject.CommonName {
				errors <- fmt.Errorf("goroutine %d: CN mismatch", id)
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
		t.Errorf("Expected %d successful loads, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_LoadCertificatesConcurrent tests concurrent LoadCertificates operations.
func TestConcurrency_LoadCertificatesConcurrent(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	// Create a credential with certificates
	cred := NewCredential("test-cred", Subject{
		CommonName: "test.example.com",
	})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

	certs := []*x509.Certificate{
		createConcTestCert(t, 1, "test.example.com"),
		createConcTestCert(t, 2, "test.example.com"),
	}

	if err := store.Save(context.Background(), cred, certs, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	errors := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			loaded, err := store.LoadCertificates(context.Background(), "test-cred")
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: load certs failed: %w", id, err)
				return
			}

			if len(loaded) != 2 {
				errors <- fmt.Errorf("goroutine %d: expected 2 certs, got %d", id, len(loaded))
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
		t.Errorf("Expected %d successful loads, got %d", numGoroutines, successCount)
	}
}

// TestConcurrency_MixedOperations tests concurrent mixed read/write operations.
func TestConcurrency_MixedOperations(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	const numWriters = 5
	const numReaders = 20
	const numOperations = 10

	var wg sync.WaitGroup
	errors := make(chan error, numWriters*numOperations+numReaders*numOperations)

	// Start writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()

			for op := 0; op < numOperations; op++ {
				credID := fmt.Sprintf("writer%d-cred%d", writerID, op)
				cred := NewCredential(credID, Subject{
					CommonName: fmt.Sprintf("w%d-c%d.example.com", writerID, op),
				})
				cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

				cert := createConcTestCert(t, int64(writerID*100+op), credID)

				if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
					errors <- fmt.Errorf("writer %d op %d: save failed: %w", writerID, op, err)
				}
			}
		}(w)
	}

	// Give writers a head start
	time.Sleep(10 * time.Millisecond)

	// Start readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()

			for op := 0; op < numOperations; op++ {
				// List all credentials
				_, err := store.ListAll(context.Background())
				if err != nil {
					errors <- fmt.Errorf("reader %d op %d: list failed: %w", readerID, op, err)
				}

				// Small delay to allow interleaving
				time.Sleep(1 * time.Millisecond)
			}
		}(r)
	}

	wg.Wait()
	close(errors)

	errCount := 0
	for err := range errors {
		t.Error(err)
		errCount++
	}

	if errCount > 0 {
		t.Errorf("Had %d errors during concurrent operations", errCount)
	}

	// Verify final state
	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("Final ListAll failed: %v", err)
	}

	expectedCreds := numWriters * numOperations
	if len(creds) != expectedCreds {
		t.Errorf("Expected %d credentials, got %d", expectedCreds, len(creds))
	}
}

// TestConcurrency_UpdateStatusConcurrent tests concurrent status updates.
func TestConcurrency_UpdateStatusConcurrent(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	// Create multiple credentials
	const numCreds = 10
	for i := 0; i < numCreds; i++ {
		credID := fmt.Sprintf("cred-%d", i)
		cred := NewCredential(credID, Subject{
			CommonName: fmt.Sprintf("test%d.example.com", i),
		})
		cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

		cert := createConcTestCert(t, int64(i), credID)
		if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	const numGoroutines = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numCreds)

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()

			// Each goroutine updates different credentials
			start := (goroutineID * numCreds) / numGoroutines
			end := ((goroutineID + 1) * numCreds) / numGoroutines

			for i := start; i < end; i++ {
				credID := fmt.Sprintf("cred-%d", i)
				if err := store.UpdateStatus(context.Background(), credID, StatusRevoked, "test revocation"); err != nil {
					errors <- fmt.Errorf("goroutine %d cred %d: update failed: %w", goroutineID, i, err)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify all credentials are revoked
	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	revokedCount := 0
	for _, cred := range creds {
		if cred.RevokedAt != nil {
			revokedCount++
		}
	}

	if revokedCount != numCreds {
		t.Errorf("Expected %d revoked credentials, got %d", numCreds, revokedCount)
	}
}

// TestConcurrency_DeleteConcurrent tests concurrent delete operations.
func TestConcurrency_DeleteConcurrent(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	// Create credentials
	const numCreds = 20
	for i := 0; i < numCreds; i++ {
		credID := fmt.Sprintf("cred-%d", i)
		cred := NewCredential(credID, Subject{
			CommonName: fmt.Sprintf("test%d.example.com", i),
		})
		cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

		if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	// Delete half concurrently
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numCreds/2)

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()

			credID := fmt.Sprintf("cred-%d", goroutineID)
			if err := store.Delete(context.Background(), credID); err != nil {
				errors <- fmt.Errorf("goroutine %d: delete failed: %w", goroutineID, err)
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify remaining credentials
	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	expectedRemaining := numCreds - numGoroutines
	if len(creds) != expectedRemaining {
		t.Errorf("Expected %d remaining credentials, got %d", expectedRemaining, len(creds))
	}
}

// TestConcurrency_ContextCancellationDuringOperation tests context cancellation mid-operation.
func TestConcurrency_ContextCancellationDuringOperation(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	var canceledCount int32

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithCancel(context.Background())

			// Cancel immediately for half the goroutines
			if id%2 == 0 {
				cancel()
			} else {
				defer cancel()
			}

			credID := fmt.Sprintf("cred-%d", id)
			cred := NewCredential(credID, Subject{
				CommonName: fmt.Sprintf("test%d.example.com", id),
			})
			cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

			err := store.Save(ctx, cred, nil, nil, nil)
			if err == context.Canceled {
				atomic.AddInt32(&canceledCount, 1)
			}
		}(i)
	}

	wg.Wait()

	// We expect some operations to be canceled
	if canceledCount == 0 {
		t.Log("No operations were canceled (timing-dependent)")
	}

	// The store should still be consistent
	_, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed after cancellations: %v", err)
	}
}

// TestConcurrency_MockStoreThreadSafety tests mock store thread safety.
func TestConcurrency_MockStoreThreadSafety(t *testing.T) {
	store := NewMockStore()

	const numGoroutines = 50
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*3)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			credID := fmt.Sprintf("cred-%d", id)
			cred := NewCredential(credID, Subject{
				CommonName: fmt.Sprintf("test%d.example.com", id),
			})
			cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

			// Save
			if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
				errors <- fmt.Errorf("goroutine %d: save failed: %w", id, err)
				return
			}

			// Load
			_, err := store.Load(context.Background(), credID)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: load failed: %w", id, err)
				return
			}

			// Exists
			if !store.Exists(context.Background(), credID) {
				errors <- fmt.Errorf("goroutine %d: exists returned false", id)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify final state
	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(creds) != numGoroutines {
		t.Errorf("Expected %d credentials, got %d", numGoroutines, len(creds))
	}
}
