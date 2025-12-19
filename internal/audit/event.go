// Package audit provides secure audit logging for PKI operations.
//
// Audit logs are separate from technical logs and designed for:
//   - Compliance (eIDAS, ETSI EN 319 401)
//   - SIEM integration
//   - Tamper evidence via cryptographic hash chaining
//
// Key principles:
//   - Audit failure = Operation failure
//   - Never log secrets (private keys, passphrases)
//   - All timestamps in UTC
//   - Hash chain for integrity verification
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EventType represents the category of audit event.
type EventType string

const (
	// CA lifecycle events
	EventCACreated EventType = "CA_CREATED"
	EventCALoaded  EventType = "CA_LOADED"

	// Key access events
	EventKeyAccessed EventType = "KEY_ACCESSED"

	// Certificate events
	EventCertIssued  EventType = "CERT_ISSUED"
	EventCertRevoked EventType = "CERT_REVOKED"

	// CRL events
	EventCRLGenerated EventType = "CRL_GENERATED"

	// Security events
	EventAuthFailed EventType = "AUTH_FAILED"

	// TSA events
	EventTSASign     EventType = "TSA_SIGN"
	EventTSAVerify   EventType = "TSA_VERIFY"
	EventTSARequest  EventType = "TSA_REQUEST"
	EventTSAResponse EventType = "TSA_RESPONSE"
	EventTSAServe    EventType = "TSA_SERVE"

	// CMS events
	EventCMSSign   EventType = "CMS_SIGN"
	EventCMSVerify EventType = "CMS_VERIFY"
)

// Result represents the outcome of an audited operation.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// Actor represents who performed the action.
type Actor struct {
	Type string `json:"type"`           // "user", "system", "service"
	ID   string `json:"id"`             // username or service identifier
	Host string `json:"host,omitempty"` // hostname where action occurred
}

// Object represents what was acted upon.
type Object struct {
	Type    string `json:"type"`              // "certificate", "ca", "crl", "key"
	Serial  string `json:"serial,omitempty"`  // certificate serial number
	Subject string `json:"subject,omitempty"` // certificate subject DN
	Path    string `json:"path,omitempty"`    // file or CA path
}

// Context provides additional details about the operation.
type Context struct {
	Profile   string `json:"profile,omitempty"`    // certificate profile used
	CA        string `json:"ca,omitempty"`         // CA directory path
	Algorithm string `json:"algorithm,omitempty"`  // cryptographic algorithm
	Reason    string `json:"reason,omitempty"`     // revocation reason, failure reason
	Policy    string `json:"policy,omitempty"`     // TSA policy OID
	GenTime   string `json:"gen_time,omitempty"`   // TSA token generation time
	Accuracy  int    `json:"accuracy,omitempty"`   // TSA accuracy in seconds
	Verified  bool   `json:"verified,omitempty"`   // TSA verification result
	HashMatch bool   `json:"hash_match,omitempty"` // TSA data hash match result
	Detached  bool   `json:"detached,omitempty"`   // CMS detached signature
}

// Event represents a single audit log entry.
type Event struct {
	EventType EventType `json:"event_type"`
	Timestamp string    `json:"timestamp"` // RFC3339 UTC
	Actor     Actor     `json:"actor"`
	Object    Object    `json:"object"`
	Context   Context   `json:"context,omitempty"`
	Result    Result    `json:"result"`
	HashPrev  string    `json:"hash_prev"` // SHA-256 hash of previous event
	Hash      string    `json:"hash"`      // SHA-256 hash of this event
}

// NewEvent creates a new audit event with current timestamp and actor info.
func NewEvent(eventType EventType, result Result) *Event {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "unknown"
	}

	return &Event{
		EventType: eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor: Actor{
			Type: "user",
			ID:   username,
			Host: hostname,
		},
		Result: result,
	}
}

// WithObject sets the object field.
func (e *Event) WithObject(obj Object) *Event {
	e.Object = obj
	return e
}

// WithContext sets the context field.
func (e *Event) WithContext(ctx Context) *Event {
	e.Context = ctx
	return e
}

// WithActor overrides the default actor.
func (e *Event) WithActor(actor Actor) *Event {
	e.Actor = actor
	return e
}

// Validate checks that required fields are present.
func (e *Event) Validate() error {
	if e.EventType == "" {
		return fmt.Errorf("event_type is required")
	}
	if e.Timestamp == "" {
		return fmt.Errorf("timestamp is required")
	}
	if e.Actor.Type == "" || e.Actor.ID == "" {
		return fmt.Errorf("actor type and id are required")
	}
	if e.Result == "" {
		return fmt.Errorf("result is required")
	}
	return nil
}

// CanonicalJSON returns the event as canonical JSON for hashing.
// Excludes the Hash field to allow hash calculation.
func (e *Event) CanonicalJSON() ([]byte, error) {
	// Create a copy without Hash for canonical representation
	type eventForHash struct {
		EventType EventType `json:"event_type"`
		Timestamp string    `json:"timestamp"`
		Actor     Actor     `json:"actor"`
		Object    Object    `json:"object"`
		Context   Context   `json:"context,omitempty"`
		Result    Result    `json:"result"`
		HashPrev  string    `json:"hash_prev"`
	}

	canonical := eventForHash{
		EventType: e.EventType,
		Timestamp: e.Timestamp,
		Actor:     e.Actor,
		Object:    e.Object,
		Context:   e.Context,
		Result:    e.Result,
		HashPrev:  e.HashPrev,
	}

	return json.Marshal(canonical)
}

// JSON returns the full event as JSON.
func (e *Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}
