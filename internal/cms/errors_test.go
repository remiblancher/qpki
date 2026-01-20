package cms

import (
	"errors"
	"testing"
)

func TestU_CMSError_Error(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		err      error
		expected string
	}{
		{
			name:     "sign operation",
			op:       "sign",
			err:      errors.New("key not found"),
			expected: "cms sign: key not found",
		},
		{
			name:     "verify operation",
			op:       "verify",
			err:      ErrInvalidSignature,
			expected: "cms verify: invalid signature",
		},
		{
			name:     "encrypt operation",
			op:       "encrypt",
			err:      ErrEncryptFailed,
			expected: "cms encrypt: encryption failed",
		},
		{
			name:     "decrypt operation",
			op:       "decrypt",
			err:      ErrDecryptFailed,
			expected: "cms decrypt: decryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &CMSError{Op: tt.op, Err: tt.err}
			if e.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", e.Error(), tt.expected)
			}
		})
	}
}

func TestU_CMSError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	e := &CMSError{Op: "test", Err: underlying}

	unwrapped := e.Unwrap()
	if unwrapped != underlying {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
	}
}

func TestU_CMSError_ErrorsIs(t *testing.T) {
	e := &CMSError{Op: "verify", Err: ErrInvalidSignature}

	if !errors.Is(e, ErrInvalidSignature) {
		t.Error("errors.Is() should return true for underlying error")
	}

	if errors.Is(e, ErrDecryptFailed) {
		t.Error("errors.Is() should return false for different error")
	}
}

func TestU_NewCMSError(t *testing.T) {
	tests := []struct {
		name string
		op   string
		err  error
	}{
		{"sign", "sign", ErrNoSigner},
		{"verify", "verify", ErrInvalidSignature},
		{"encrypt", "encrypt", ErrEncryptFailed},
		{"decrypt", "decrypt", ErrNoRecipient},
		{"parse", "parse", ErrInvalidContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewCMSError(tt.op, tt.err)

			if e == nil {
				t.Fatal("NewCMSError() returned nil")
			}
			if e.Op != tt.op {
				t.Errorf("Op = %q, want %q", e.Op, tt.op)
			}
			if e.Err != tt.err {
				t.Errorf("Err = %v, want %v", e.Err, tt.err)
			}
		})
	}
}

func TestU_SentinelErrors(t *testing.T) {
	// Verify sentinel errors are distinct
	sentinels := []error{
		ErrInvalidSignature,
		ErrNoCertificate,
		ErrDecryptFailed,
		ErrEncryptFailed,
		ErrInvalidContent,
		ErrNoSigner,
		ErrUnsupportedAlgorithm,
		ErrMissingAttribute,
		ErrInvalidRecipient,
		ErrNoRecipient,
	}

	for i, e1 := range sentinels {
		if e1 == nil {
			t.Errorf("Sentinel error %d is nil", i)
		}
		for j, e2 := range sentinels {
			if i != j && errors.Is(e1, e2) {
				t.Errorf("Sentinel error %d (%v) should not match error %d (%v)", i, e1, j, e2)
			}
		}
	}
}
