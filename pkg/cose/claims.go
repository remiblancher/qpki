package cose

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CWT Claim keys (RFC 8392).
const (
	ClaimIss int64 = 1 // Issuer
	ClaimSub int64 = 2 // Subject
	ClaimAud int64 = 3 // Audience
	ClaimExp int64 = 4 // Expiration Time
	ClaimNbf int64 = 5 // Not Before
	ClaimIat int64 = 6 // Issued At
	ClaimCti int64 = 7 // CWT ID
)

// Claims represents CWT claims (RFC 8392).
// Standard claims use integer keys 1-7.
// Custom claims can use negative integer keys (private-use) or keys > 7.
type Claims struct {
	// Standard claims (RFC 8392)
	Issuer     string    // iss (1)
	Subject    string    // sub (2)
	Audience   string    // aud (3)
	Expiration time.Time // exp (4) - Unix epoch seconds
	NotBefore  time.Time // nbf (5) - Unix epoch seconds
	IssuedAt   time.Time // iat (6) - Unix epoch seconds
	CWTID      []byte    // cti (7) - Unique identifier

	// Custom claims (negative integer keys for private-use)
	Custom map[int64]interface{}
}

// NewClaims creates a new Claims with default IssuedAt set to now.
func NewClaims() *Claims {
	return &Claims{
		IssuedAt: time.Now().UTC(),
		Custom:   make(map[int64]interface{}),
	}
}

// SetExpiration sets the expiration time relative to now.
func (c *Claims) SetExpiration(d time.Duration) {
	c.Expiration = time.Now().UTC().Add(d)
}

// SetCustom sets a custom claim with a negative integer key.
// Returns an error if the key is >= 0 (use standard claims instead).
func (c *Claims) SetCustom(key int64, value interface{}) error {
	if key >= 0 && key <= 7 {
		return fmt.Errorf("keys 1-7 are reserved for standard claims, use negative keys for custom claims")
	}
	if c.Custom == nil {
		c.Custom = make(map[int64]interface{})
	}
	c.Custom[key] = value
	return nil
}

// GetCustom retrieves a custom claim value.
func (c *Claims) GetCustom(key int64) (interface{}, bool) {
	if c.Custom == nil {
		return nil, false
	}
	v, ok := c.Custom[key]
	return v, ok
}

// IsExpired returns true if the token is expired.
func (c *Claims) IsExpired() bool {
	if c.Expiration.IsZero() {
		return false
	}
	return time.Now().After(c.Expiration)
}

// IsNotYetValid returns true if the token is not yet valid (before NotBefore).
func (c *Claims) IsNotYetValid() bool {
	if c.NotBefore.IsZero() {
		return false
	}
	return time.Now().Before(c.NotBefore)
}

// Validate checks that the claims are currently valid (time-based checks).
func (c *Claims) Validate() error {
	return c.ValidateAt(time.Now())
}

// ValidateAt checks that the claims are valid at the given time.
func (c *Claims) ValidateAt(t time.Time) error {
	if !c.Expiration.IsZero() && t.After(c.Expiration) {
		return fmt.Errorf("token expired at %s", c.Expiration.Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && t.Before(c.NotBefore) {
		return fmt.Errorf("token not valid until %s", c.NotBefore.Format(time.RFC3339))
	}
	return nil
}

// MarshalCBOR encodes the claims as a CBOR map with integer keys.
func (c *Claims) MarshalCBOR() ([]byte, error) {
	// Build the claims map
	m := make(map[int64]interface{})

	if c.Issuer != "" {
		m[ClaimIss] = c.Issuer
	}
	if c.Subject != "" {
		m[ClaimSub] = c.Subject
	}
	if c.Audience != "" {
		m[ClaimAud] = c.Audience
	}
	if !c.Expiration.IsZero() {
		m[ClaimExp] = c.Expiration.Unix()
	}
	if !c.NotBefore.IsZero() {
		m[ClaimNbf] = c.NotBefore.Unix()
	}
	if !c.IssuedAt.IsZero() {
		m[ClaimIat] = c.IssuedAt.Unix()
	}
	if len(c.CWTID) > 0 {
		m[ClaimCti] = c.CWTID
	}

	// Add custom claims
	for k, v := range c.Custom {
		m[k] = v
	}

	// Use canonical encoding for deterministic output
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	return em.Marshal(m)
}

// UnmarshalCBOR decodes CBOR claims into the Claims struct.
func (c *Claims) UnmarshalCBOR(data []byte) error {
	var m map[int64]interface{}
	if err := cbor.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to unmarshal CBOR claims: %w", err)
	}

	c.Custom = make(map[int64]interface{})

	for k, v := range m {
		switch k {
		case ClaimIss:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case ClaimSub:
			if s, ok := v.(string); ok {
				c.Subject = s
			}
		case ClaimAud:
			if s, ok := v.(string); ok {
				c.Audience = s
			}
		case ClaimExp:
			c.Expiration = timeFromCBOR(v)
		case ClaimNbf:
			c.NotBefore = timeFromCBOR(v)
		case ClaimIat:
			c.IssuedAt = timeFromCBOR(v)
		case ClaimCti:
			if b, ok := v.([]byte); ok {
				c.CWTID = b
			}
		default:
			// Custom claim
			c.Custom[k] = v
		}
	}

	return nil
}

// timeFromCBOR converts a CBOR numeric value to time.Time (Unix epoch).
func timeFromCBOR(v interface{}) time.Time {
	switch t := v.(type) {
	case int64:
		return time.Unix(t, 0).UTC()
	case uint64:
		return time.Unix(int64(t), 0).UTC()
	case float64:
		return time.Unix(int64(t), 0).UTC()
	default:
		return time.Time{}
	}
}

// ClaimsFromMap creates Claims from a map (useful for parsing).
func ClaimsFromMap(m map[int64]interface{}) *Claims {
	c := &Claims{
		Custom: make(map[int64]interface{}),
	}

	for k, v := range m {
		switch k {
		case ClaimIss:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case ClaimSub:
			if s, ok := v.(string); ok {
				c.Subject = s
			}
		case ClaimAud:
			if s, ok := v.(string); ok {
				c.Audience = s
			}
		case ClaimExp:
			c.Expiration = timeFromCBOR(v)
		case ClaimNbf:
			c.NotBefore = timeFromCBOR(v)
		case ClaimIat:
			c.IssuedAt = timeFromCBOR(v)
		case ClaimCti:
			if b, ok := v.([]byte); ok {
				c.CWTID = b
			}
		default:
			c.Custom[k] = v
		}
	}

	return c
}
