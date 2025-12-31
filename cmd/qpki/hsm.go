package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

var hsmCmd = &cobra.Command{
	Use:   "hsm",
	Short: "HSM diagnostic commands",
	Long: `Diagnostic commands for Hardware Security Modules (HSMs) via PKCS#11.

These commands help discover and validate HSM configuration.
For key operations, use 'qpki key gen --hsm-config' and 'qpki key list --hsm-config'.

Examples:
  # List available slots and tokens (discovery, no config needed)
  qpki hsm list --lib /usr/lib/softhsm/libsofthsm2.so

  # Test HSM connectivity and authentication
  qpki hsm test --hsm-config ./hsm.yaml`,
}

var hsmListCmd = &cobra.Command{
	Use:   "list",
	Short: "List HSM slots and tokens",
	Long: `List all available slots and tokens in a PKCS#11 module.

This command does not require authentication and shows:
  - Slot ID and description
  - Token label and serial (if present)
  - Token manufacturer

Examples:
  qpki hsm list --lib /usr/lib/softhsm/libsofthsm2.so
  qpki hsm list --lib /usr/lib/libCryptoki2_64.so`,
	RunE: runHSMList,
}

var hsmTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test HSM connectivity",
	Long: `Test HSM connectivity and authentication.

Verifies that:
  - The PKCS#11 module can be loaded
  - The token can be found
  - Authentication (login) succeeds

Examples:
  qpki hsm test --hsm-config ./hsm.yaml`,
	RunE: runHSMTest,
}

var (
	hsmLib        string
	hsmConfigPath string
)

func init() {
	hsmCmd.AddCommand(hsmListCmd)
	hsmCmd.AddCommand(hsmTestCmd)

	// list command uses --lib directly (discovery without config)
	hsmListCmd.Flags().StringVar(&hsmLib, "lib", "", "Path to PKCS#11 library (required)")
	_ = hsmListCmd.MarkFlagRequired("lib")

	// test command uses --hsm-config
	hsmTestCmd.Flags().StringVar(&hsmConfigPath, "hsm-config", "", "Path to HSM configuration file (required)")
	_ = hsmTestCmd.MarkFlagRequired("hsm-config")
}

func runHSMList(cmd *cobra.Command, args []string) error {
	info, err := crypto.ListHSMSlots(hsmLib)
	if err != nil {
		return fmt.Errorf("failed to list HSM slots: %w", err)
	}

	fmt.Printf("PKCS#11 Module: %s\n\n", info.ModulePath)

	if len(info.Slots) == 0 {
		fmt.Println("No slots found.")
		return nil
	}

	for _, slot := range info.Slots {
		fmt.Printf("Slot %d:\n", slot.ID)
		fmt.Printf("  Description:  %s\n", strings.TrimSpace(slot.Description))

		if slot.HasToken {
			fmt.Printf("  Token Label:  %s\n", strings.TrimSpace(slot.TokenLabel))
			fmt.Printf("  Token Serial: %s\n", maskSerial(slot.TokenSerial))
			if slot.Manufacturer != "" {
				fmt.Printf("  Manufacturer: %s\n", strings.TrimSpace(slot.Manufacturer))
			}
		} else {
			fmt.Printf("  Token:        (not present)\n")
		}
		fmt.Println()
	}

	return nil
}

func runHSMTest(cmd *cobra.Command, args []string) error {
	cfg, err := crypto.LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	fmt.Printf("Testing HSM configuration: %s\n\n", hsmConfigPath)

	// Test 1: Load module
	fmt.Printf("[1/4] Loading PKCS#11 module... ")
	info, err := crypto.ListHSMSlots(cfg.PKCS11.Lib)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("failed to load module: %w", err)
	}
	fmt.Println("OK")

	// Test 2: Find token
	fmt.Printf("[2/4] Finding token %q... ", cfg.PKCS11.Token)
	found := false
	for _, slot := range info.Slots {
		if slot.HasToken && strings.TrimSpace(slot.TokenLabel) == cfg.PKCS11.Token {
			found = true
			break
		}
	}
	if !found {
		fmt.Println("FAILED")
		return fmt.Errorf("token not found")
	}
	fmt.Println("OK")

	// Test 3: Get PIN
	fmt.Printf("[3/4] Reading PIN from $%s... ", cfg.PKCS11.PinEnv)
	pin, err := cfg.GetPIN()
	if err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("OK")

	// Test 4: List keys (requires login)
	fmt.Printf("[4/4] Authenticating and listing keys... ")
	keys, err := crypto.ListHSMKeys(cfg.PKCS11.Lib, cfg.PKCS11.Token, pin)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Printf("OK (%d keys found)\n", len(keys))

	fmt.Println("\nAll tests passed!")
	return nil
}

// maskSerial partially masks a serial number for security.
func maskSerial(serial string) string {
	serial = strings.TrimSpace(serial)
	if len(serial) <= 4 {
		return serial
	}
	return serial[:3] + strings.Repeat("*", len(serial)-4) + serial[len(serial)-1:]
}

