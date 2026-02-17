// Package crypto provides cryptographic primitives for the PKI.
// This file contains HSM configuration types and YAML loader.
package crypto

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// HSMConfig represents the YAML configuration for HSM.
type HSMConfig struct {
	Type   string         `yaml:"type"`
	PKCS11 PKCS11Settings `yaml:"pkcs11"`
}

// PKCS11Settings holds PKCS#11 specific configuration.
type PKCS11Settings struct {
	// Lib is the path to the PKCS#11 library (.so/.dylib/.dll)
	Lib string `yaml:"lib"`

	// Token identifies the token by label (recommended)
	Token string `yaml:"token"`

	// TokenSerial identifies the token by serial number (more precise)
	TokenSerial string `yaml:"token_serial"`

	// Slot identifies the token by slot ID (less portable)
	Slot *uint `yaml:"slot"`

	// PinEnv is the name of the environment variable containing the PIN
	PinEnv string `yaml:"pin_env"`
}

// LoadHSMConfig loads HSM configuration from a YAML file.
func LoadHSMConfig(path string) (*HSMConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read HSM config file: %w", err)
	}

	var cfg HSMConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse HSM config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HSM config: %w", err)
	}

	return &cfg, nil
}

// Validate checks that the HSM configuration is valid.
func (c *HSMConfig) Validate() error {
	if c.Type != "pkcs11" {
		return fmt.Errorf("unsupported HSM type: %s (only 'pkcs11' is supported)", c.Type)
	}

	if c.PKCS11.Lib == "" {
		return fmt.Errorf("pkcs11.lib is required")
	}

	// At least one token identification method is required
	if c.PKCS11.Token == "" && c.PKCS11.TokenSerial == "" && c.PKCS11.Slot == nil {
		return fmt.Errorf("at least one of pkcs11.token, pkcs11.token_serial, or pkcs11.slot is required")
	}

	if c.PKCS11.PinEnv == "" {
		return fmt.Errorf("pkcs11.pin_env is required (PIN must be provided via environment variable)")
	}

	return nil
}

// GetPIN retrieves the PIN from the environment variable.
func (c *HSMConfig) GetPIN() (string, error) {
	pin := os.Getenv(c.PKCS11.PinEnv)
	if pin == "" {
		return "", fmt.Errorf("environment variable %s is not set or empty", c.PKCS11.PinEnv)
	}
	return pin, nil
}

// ToPKCS11Config converts HSMConfig to PKCS11Config for the signer.
func (c *HSMConfig) ToPKCS11Config(keyLabel, keyID string) (*PKCS11Config, error) {
	pin, err := c.GetPIN()
	if err != nil {
		return nil, err
	}

	cfg := &PKCS11Config{
		ModulePath:  c.PKCS11.Lib,
		TokenLabel:  c.PKCS11.Token,
		TokenSerial: c.PKCS11.TokenSerial,
		PIN:         pin,
		KeyLabel:    keyLabel,
		KeyID:       keyID,
		SlotID:      c.PKCS11.Slot,

		// Always logout after each operation (security best practice)
		LogoutAfterUse: true,
	}

	return cfg, nil
}
