package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/api/server"
)

// Serve command flags
var (
	servePort     int
	serveAPIPort  int
	serveOCSPPort int
	serveTSAPort  int
	serveHost     string
	serveCADir    string
	serveServices string
	serveTLSCert  string
	serveTLSKey   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the QPKI REST API server",
	Long: `Start the QPKI REST API server.

The server exposes a REST API for all PKI operations, plus RFC-compliant
OCSP and TSA responders.

Services can be selectively enabled:
  - api:  REST API endpoints (/api/v1/*)
  - ocsp: RFC 6960 OCSP responder (/ocsp)
  - tsa:  RFC 3161 TSA responder (/tsa)
  - all:  All services (default)

Environment variables:
  QPKI_PORT       Default port for all services
  QPKI_API_PORT   Port for REST API
  QPKI_OCSP_PORT  Port for OCSP responder
  QPKI_TSA_PORT   Port for TSA responder
  QPKI_SERVICES   Comma-separated list of services
  QPKI_CA_DIR     Path to CA directory
  QPKI_TLS_CERT   TLS certificate file
  QPKI_TLS_KEY    TLS private key file

Examples:
  # Start server with all services on one port
  qpki serve --port 8443 --ca-dir ./ca

  # Start only OCSP and TSA responders
  qpki serve --port 8080 --services ocsp,tsa

  # Start services on separate ports
  qpki serve --api-port 8443 --ocsp-port 8080 --tsa-port 8081

  # Start with TLS
  qpki serve --port 8443 --tls-cert server.crt --tls-key server.key

  # Using environment variables
  QPKI_PORT=8443 QPKI_SERVICES=api,ocsp qpki serve`,
	RunE: runServe,
}

func init() {
	// Port flags
	serveCmd.Flags().IntVar(&servePort, "port", 0, "Port for all services (default: 8443, or QPKI_PORT)")
	serveCmd.Flags().IntVar(&serveAPIPort, "api-port", 0, "Port for REST API (overrides --port for API)")
	serveCmd.Flags().IntVar(&serveOCSPPort, "ocsp-port", 0, "Port for OCSP responder (overrides --port for OCSP)")
	serveCmd.Flags().IntVar(&serveTSAPort, "tsa-port", 0, "Port for TSA responder (overrides --port for TSA)")

	// Other flags
	serveCmd.Flags().StringVar(&serveHost, "host", "", "Host to bind to (default: all interfaces)")
	serveCmd.Flags().StringVar(&serveCADir, "ca-dir", "", "Path to CA directory (or QPKI_CA_DIR)")
	serveCmd.Flags().StringVar(&serveServices, "services", "", "Services to enable (or QPKI_SERVICES)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "TLS certificate file (or QPKI_TLS_CERT)")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "TLS private key file (or QPKI_TLS_KEY)")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Apply environment variables for unset flags
	applyServeEnvVars()

	// Parse services
	services := parseServices(serveServices)

	// Create server config
	cfg := server.DefaultConfig()
	cfg.Host = serveHost
	cfg.CADir = serveCADir
	cfg.Services = services
	cfg.TLSCert = serveTLSCert
	cfg.TLSKey = serveTLSKey

	// Configure ports
	cfg.Port = servePort
	cfg.APIPort = serveAPIPort
	cfg.OCSPPort = serveOCSPPort
	cfg.TSAPort = serveTSAPort

	// Create and start server
	srv := server.New(cfg, version)
	return srv.Start()
}

// applyServeEnvVars applies environment variables for unset flags.
func applyServeEnvVars() {
	// Port
	if servePort == 0 {
		if v := os.Getenv("QPKI_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				servePort = p
			}
		}
	}
	if servePort == 0 {
		servePort = 8443 // Default
	}

	// Service-specific ports
	if serveAPIPort == 0 {
		if v := os.Getenv("QPKI_API_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				serveAPIPort = p
			}
		}
	}
	if serveOCSPPort == 0 {
		if v := os.Getenv("QPKI_OCSP_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				serveOCSPPort = p
			}
		}
	}
	if serveTSAPort == 0 {
		if v := os.Getenv("QPKI_TSA_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				serveTSAPort = p
			}
		}
	}

	// Services
	if serveServices == "" {
		if v := os.Getenv("QPKI_SERVICES"); v != "" {
			serveServices = v
		} else {
			serveServices = "all"
		}
	}

	// CA directory
	if serveCADir == "" {
		serveCADir = os.Getenv("QPKI_CA_DIR")
	}

	// TLS
	if serveTLSCert == "" {
		serveTLSCert = os.Getenv("QPKI_TLS_CERT")
	}
	if serveTLSKey == "" {
		serveTLSKey = os.Getenv("QPKI_TLS_KEY")
	}
}

// parseServices parses the comma-separated services string.
func parseServices(s string) []string {
	if s == "" || s == "all" {
		return []string{"all"}
	}

	parts := strings.Split(s, ",")
	services := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			services = append(services, p)
		}
	}

	if len(services) == 0 {
		return []string{"all"}
	}
	return services
}
