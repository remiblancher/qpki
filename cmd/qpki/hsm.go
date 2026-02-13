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
  # List available slots and tokens
  qpki hsm list --hsm-config ./hsm.yaml

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
  qpki hsm list --hsm-config ./hsm.yaml`,
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

var hsmInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display HSM token information",
	Long: `Display detailed information about an HSM token.

Shows:
  - Token label and serial number
  - Manufacturer and model
  - Firmware and hardware version
  - Supported mechanisms
  - Storage capacity (if available)

Examples:
  qpki hsm info --hsm-config ./hsm.yaml`,
	RunE: runHSMInfo,
}

var hsmMechanismsCmd = &cobra.Command{
	Use:   "mechanisms",
	Short: "List PKCS#11 mechanisms supported by the HSM",
	Long: `List all PKCS#11 mechanisms (algorithms) supported by the HSM.

Shows:
  - Mechanism ID and name
  - Supported operations (sign, verify, encrypt, decrypt, derive, wrap, unwrap)
  - Key size constraints

Use --filter to search for specific mechanisms (e.g., --filter HKDF).

Examples:
  qpki hsm mechanisms --hsm-config ./hsm.yaml
  qpki hsm mechanisms --hsm-config ./hsm.yaml --filter ML
  qpki hsm mechanisms --hsm-config ./hsm.yaml --filter HKDF`,
	RunE: runHSMMechanisms,
}

var (
	hsmListConfigPath       string
	hsmConfigPath           string
	hsmInfoConfigPath       string
	hsmMechanismsConfigPath string
	hsmMechanismsFilter     string
)

func init() {
	hsmCmd.AddCommand(hsmListCmd)
	hsmCmd.AddCommand(hsmTestCmd)
	hsmCmd.AddCommand(hsmInfoCmd)
	hsmCmd.AddCommand(hsmMechanismsCmd)

	// list command uses --hsm-config
	hsmListCmd.Flags().StringVar(&hsmListConfigPath, "hsm-config", "", "Path to HSM configuration file (required)")
	_ = hsmListCmd.MarkFlagRequired("hsm-config")

	// test command uses --hsm-config
	hsmTestCmd.Flags().StringVar(&hsmConfigPath, "hsm-config", "", "Path to HSM configuration file (required)")
	_ = hsmTestCmd.MarkFlagRequired("hsm-config")

	// info command uses --hsm-config
	hsmInfoCmd.Flags().StringVar(&hsmInfoConfigPath, "hsm-config", "", "Path to HSM configuration file (required)")
	_ = hsmInfoCmd.MarkFlagRequired("hsm-config")

	// mechanisms command uses --hsm-config and --filter
	hsmMechanismsCmd.Flags().StringVar(&hsmMechanismsConfigPath, "hsm-config", "", "Path to HSM configuration file (required)")
	_ = hsmMechanismsCmd.MarkFlagRequired("hsm-config")
	hsmMechanismsCmd.Flags().StringVar(&hsmMechanismsFilter, "filter", "", "Filter mechanisms by name (case-insensitive)")
}

func runHSMList(cmd *cobra.Command, args []string) error {
	cfg, err := crypto.LoadHSMConfig(hsmListConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	info, err := crypto.ListHSMSlots(cfg.PKCS11.Lib)
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

func runHSMInfo(cmd *cobra.Command, args []string) error {
	cfg, err := crypto.LoadHSMConfig(hsmInfoConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	// List slots to find the target token
	info, err := crypto.ListHSMSlots(cfg.PKCS11.Lib)
	if err != nil {
		return fmt.Errorf("failed to list HSM slots: %w", err)
	}

	// Find the matching token
	var targetSlot *crypto.SlotInfo
	for i := range info.Slots {
		if info.Slots[i].HasToken && strings.TrimSpace(info.Slots[i].TokenLabel) == cfg.PKCS11.Token {
			targetSlot = &info.Slots[i]
			break
		}
	}

	if targetSlot == nil {
		return fmt.Errorf("token %q not found", cfg.PKCS11.Token)
	}

	fmt.Println("HSM Token Information:")
	fmt.Printf("  Label:         %s\n", strings.TrimSpace(targetSlot.TokenLabel))
	fmt.Printf("  Serial:        %s\n", maskSerial(targetSlot.TokenSerial))
	fmt.Printf("  Manufacturer:  %s\n", strings.TrimSpace(targetSlot.Manufacturer))
	fmt.Printf("  Slot ID:       %d\n", targetSlot.ID)
	fmt.Printf("  Description:   %s\n", strings.TrimSpace(targetSlot.Description))

	fmt.Println("\nConfiguration:")
	fmt.Printf("  Module:        %s\n", cfg.PKCS11.Lib)
	fmt.Printf("  PIN Env:       %s\n", cfg.PKCS11.PinEnv)

	// Get PIN and list keys
	pin, err := cfg.GetPIN()
	if err != nil {
		fmt.Println("\nKeys: (unable to authenticate)")
		return nil
	}

	keys, err := crypto.ListHSMKeys(cfg.PKCS11.Lib, cfg.PKCS11.Token, pin)
	if err != nil {
		fmt.Println("\nKeys: (unable to list)")
		return nil
	}

	fmt.Printf("\nKeys: %d\n", len(keys))
	for _, key := range keys {
		fmt.Printf("  - %s (%s", key.Label, key.Type)
		if key.Size > 0 {
			fmt.Printf(", %d bits", key.Size)
		}
		fmt.Printf(")\n")
	}

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

func runHSMMechanisms(cmd *cobra.Command, args []string) error {
	cfg, err := crypto.LoadHSMConfig(hsmMechanismsConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	// First find the slot ID for the target token
	info, err := crypto.ListHSMSlots(cfg.PKCS11.Lib)
	if err != nil {
		return fmt.Errorf("failed to list HSM slots: %w", err)
	}

	var slotID uint
	found := false
	for _, slot := range info.Slots {
		if slot.HasToken && strings.TrimSpace(slot.TokenLabel) == cfg.PKCS11.Token {
			slotID = slot.ID
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("token %q not found", cfg.PKCS11.Token)
	}

	mechanisms, err := crypto.ListHSMMechanisms(cfg.PKCS11.Lib, slotID)
	if err != nil {
		return fmt.Errorf("failed to list mechanisms: %w", err)
	}

	filter := strings.ToUpper(hsmMechanismsFilter)

	fmt.Printf("PKCS#11 Mechanisms for slot %d (%s):\n\n", slotID, cfg.PKCS11.Token)

	count := 0
	for _, mech := range mechanisms {
		// Apply filter if specified
		if filter != "" && !strings.Contains(strings.ToUpper(mech.Name), filter) {
			continue
		}

		count++
		fmt.Printf("0x%08X  %s\n", mech.ID, mech.Name)

		// Show capabilities
		caps := []string{}
		if mech.CanGenerate {
			caps = append(caps, "generate")
		}
		if mech.CanSign {
			caps = append(caps, "sign")
		}
		if mech.CanVerify {
			caps = append(caps, "verify")
		}
		if mech.CanEncrypt {
			caps = append(caps, "encrypt")
		}
		if mech.CanDecrypt {
			caps = append(caps, "decrypt")
		}
		if mech.CanDerive {
			caps = append(caps, "derive")
		}
		if mech.CanWrap {
			caps = append(caps, "wrap")
		}
		if mech.CanUnwrap {
			caps = append(caps, "unwrap")
		}

		if len(caps) > 0 {
			fmt.Printf("            Capabilities: %s\n", strings.Join(caps, ", "))
		}
		if mech.MinKeySize > 0 || mech.MaxKeySize > 0 {
			fmt.Printf("            Key size: %d - %d bits\n", mech.MinKeySize, mech.MaxKeySize)
		}
	}

	if count == 0 && filter != "" {
		fmt.Printf("No mechanisms found matching filter %q\n", hsmMechanismsFilter)
	} else {
		fmt.Printf("\nTotal: %d mechanisms\n", count)
	}

	return nil
}
