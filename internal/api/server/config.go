// Package server provides HTTP server configuration and lifecycle management.
package server

import (
	"fmt"
	"time"
)

// Config holds the server configuration.
type Config struct {
	// Port is the default HTTP port for all services.
	Port int

	// Service-specific ports (override Port if non-zero)
	APIPort  int // Port for REST API
	OCSPPort int // Port for OCSP responder
	TSAPort  int // Port for TSA responder

	// Host is the address to bind to (default: "").
	Host string

	// CADir is the path to the CA directory.
	CADir string

	// Services specifies which services to enable.
	// Valid values: "api", "ocsp", "tsa", "all"
	Services []string

	// TLS configuration (optional)
	TLSCert string
	TLSKey  string

	// Timeouts
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Port:            8443,
		Host:            "",
		Services:        []string{"all"},
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
}

// HasService checks if a service is enabled.
func (c *Config) HasService(name string) bool {
	for _, s := range c.Services {
		if s == "all" || s == name {
			return true
		}
	}
	return false
}

// Address returns the full listen address for the default port.
func (c *Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// APIAddress returns the listen address for the REST API.
func (c *Config) APIAddress() string {
	port := c.APIPort
	if port == 0 {
		port = c.Port
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
}

// OCSPAddress returns the listen address for the OCSP responder.
func (c *Config) OCSPAddress() string {
	port := c.OCSPPort
	if port == 0 {
		port = c.Port
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
}

// TSAAddress returns the listen address for the TSA responder.
func (c *Config) TSAAddress() string {
	port := c.TSAPort
	if port == 0 {
		port = c.Port
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
}

// UseSeparatePorts returns true if services should run on separate ports.
func (c *Config) UseSeparatePorts() bool {
	return c.APIPort != 0 || c.OCSPPort != 0 || c.TSAPort != 0
}
