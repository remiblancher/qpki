package audit

import (
	"fmt"
	"sync"
)

var (
	// globalWriter is the default audit writer.
	globalWriter Writer = NopWriter{}
	globalMu     sync.RWMutex

	// enabled tracks whether audit logging is active.
	enabled bool
)

// Init initializes the global audit logger with the given writer.
// Must be called before any audit events are logged.
// Returns an error if initialization fails.
func Init(w Writer) error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if w == nil {
		globalWriter = NopWriter{}
		enabled = false
		return nil
	}

	globalWriter = w
	enabled = true
	return nil
}

// InitFile initializes the global audit logger with a file writer.
// This is a convenience function for the common case.
func InitFile(path string) error {
	if path == "" {
		return Init(nil)
	}

	w, err := NewFileWriter(path)
	if err != nil {
		return err
	}

	return Init(w)
}

// Close closes the global audit writer.
// Should be called when the application exits.
func Close() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalWriter != nil {
		err := globalWriter.Close()
		globalWriter = NopWriter{}
		enabled = false
		return err
	}
	return nil
}

// Enabled returns whether audit logging is active.
func Enabled() bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return enabled
}

// Log writes an audit event to the global writer.
// Returns an error if the write fails.
//
// IMPORTANT: If audit logging is enabled and this returns an error,
// the calling operation SHOULD fail. Audit logs are critical for
// compliance and security.
func Log(event *Event) error {
	globalMu.RLock()
	w := globalWriter
	globalMu.RUnlock()

	return w.Write(event)
}

// MustLog writes an audit event and returns an error suitable for
// failing the parent operation if audit logging fails.
//
// Usage:
//
//	if err := audit.MustLog(event); err != nil {
//	    return nil, err // Operation fails if audit fails
//	}
func MustLog(event *Event) error {
	if err := Log(event); err != nil {
		return fmt.Errorf("audit log failed: %w", err)
	}
	return nil
}

// LogCACreated logs a CA creation event.
func LogCACreated(caPath, subject, algorithm string, success bool) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventCACreated, result).
		WithObject(Object{
			Type:    "ca",
			Path:    caPath,
			Subject: subject,
		}).
		WithContext(Context{
			Algorithm: algorithm,
		})

	return MustLog(event)
}

// LogCALoaded logs a CA load event.
func LogCALoaded(caPath, subject string, success bool) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventCALoaded, result).
		WithObject(Object{
			Type:    "ca",
			Path:    caPath,
			Subject: subject,
		})

	return MustLog(event)
}

// LogKeyAccessed logs a key access event.
func LogKeyAccessed(caPath string, success bool, reason string) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventKeyAccessed, result).
		WithObject(Object{
			Type: "key",
			Path: caPath,
		}).
		WithContext(Context{
			Reason: reason,
		})

	return MustLog(event)
}

// LogCertIssued logs a certificate issuance event.
func LogCertIssued(caPath, serial, subject, profile, algorithm string, success bool) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventCertIssued, result).
		WithObject(Object{
			Type:    "certificate",
			Serial:  serial,
			Subject: subject,
		}).
		WithContext(Context{
			CA:        caPath,
			Profile:   profile,
			Algorithm: algorithm,
		})

	return MustLog(event)
}

// LogCertRevoked logs a certificate revocation event.
func LogCertRevoked(caPath, serial, subject, reason string, success bool) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventCertRevoked, result).
		WithObject(Object{
			Type:    "certificate",
			Serial:  serial,
			Subject: subject,
		}).
		WithContext(Context{
			CA:     caPath,
			Reason: reason,
		})

	return MustLog(event)
}

// LogCRLGenerated logs a CRL generation event.
func LogCRLGenerated(caPath string, revokedCount int, success bool) error {
	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	event := NewEvent(EventCRLGenerated, result).
		WithObject(Object{
			Type: "crl",
			Path: caPath,
		}).
		WithContext(Context{
			CA:     caPath,
			Reason: fmt.Sprintf("%d certificates revoked", revokedCount),
		})

	return MustLog(event)
}

// LogAuthFailed logs an authentication failure event.
func LogAuthFailed(caPath, reason string) error {
	event := NewEvent(EventAuthFailed, ResultFailure).
		WithObject(Object{
			Type: "ca",
			Path: caPath,
		}).
		WithContext(Context{
			CA:     caPath,
			Reason: reason,
		})

	return MustLog(event)
}

// LogCARotated logs a CA rotation event.
func LogCARotated(caPath, versionID, profile string, crossSigned bool) error {
	reason := fmt.Sprintf("version=%s, profile=%s", versionID, profile)
	if crossSigned {
		reason += ", cross-signed=true"
	}

	event := NewEvent(EventCARotated, ResultSuccess).
		WithObject(Object{
			Type: "ca",
			Path: caPath,
		}).
		WithContext(Context{
			CA:      caPath,
			Profile: profile,
			Reason:  reason,
		})

	return MustLog(event)
}
