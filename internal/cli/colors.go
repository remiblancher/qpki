package cli

// ANSI color codes for terminal output.
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
)

// FormatStatus returns a colored status string.
func FormatStatus(status string) string {
	switch status {
	case "valid", "active":
		return ColorGreen + status + ColorReset
	case "revoked", "expired", "invalid":
		return ColorRed + status + ColorReset
	case "pending":
		return ColorYellow + status + ColorReset
	default:
		return status
	}
}
