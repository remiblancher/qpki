package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// Serve command flags
var (
	servePort     int
	serveOCSPPort int
	serveTSAPort  int
	serveHost     string
	serveCADir    string
	serveTLSCert  string
	serveTLSKey   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start RFC-compliant OCSP and TSA responders",
	Long: `Start RFC-compliant OCSP and TSA responders.

This command starts native protocol responders:
  - RFC 6960 OCSP responder (/ocsp)
  - RFC 3161 TSA responder (/tsa)

For the full REST API, use qpki-server from qpki-enterprise.

Environment variables:
  QPKI_PORT       Default port for all services
  QPKI_OCSP_PORT  Port for OCSP responder
  QPKI_TSA_PORT   Port for TSA responder
  QPKI_CA_DIR     Path to CA directory
  QPKI_TLS_CERT   TLS certificate file
  QPKI_TLS_KEY    TLS private key file

Examples:
  # Start OCSP and TSA responders
  qpki serve --port 8080 --ca-dir ./ca

  # Start on separate ports
  qpki serve --ocsp-port 8080 --tsa-port 8081 --ca-dir ./ca

  # Start with TLS
  qpki serve --port 8443 --tls-cert server.crt --tls-key server.key`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 0, "Port for all services (default: 8080)")
	serveCmd.Flags().IntVar(&serveOCSPPort, "ocsp-port", 0, "Port for OCSP responder")
	serveCmd.Flags().IntVar(&serveTSAPort, "tsa-port", 0, "Port for TSA responder")
	serveCmd.Flags().StringVar(&serveHost, "host", "", "Host to bind to (default: all interfaces)")
	serveCmd.Flags().StringVar(&serveCADir, "ca-dir", "", "Path to CA directory (required)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "TLS certificate file")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "TLS private key file")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	applyServeEnvVars()

	if serveCADir == "" {
		return fmt.Errorf("--ca-dir is required")
	}

	// Determine ports
	port := servePort
	if port == 0 {
		port = 8080
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// RFC 6960 OCSP responder
	mux.HandleFunc("/ocsp", handleOCSP)
	mux.HandleFunc("/ocsp/", handleOCSP)

	// RFC 3161 TSA responder
	mux.HandleFunc("/tsa", handleTSA)

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf("%s:%d", serveHost, port)
	fmt.Printf("Starting OCSP/TSA responders on %s\n", addr)
	fmt.Printf("  OCSP: http://%s/ocsp\n", addr)
	fmt.Printf("  TSA:  http://%s/tsa\n", addr)
	fmt.Printf("  CA dir: %s\n", serveCADir)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if serveTLSCert != "" && serveTLSKey != "" {
		fmt.Println("  TLS: enabled")
		return server.ListenAndServeTLS(serveTLSCert, serveTLSKey)
	}

	return server.ListenAndServe()
}

// handleOCSP handles RFC 6960 OCSP requests.
// TODO: Implement actual OCSP response generation using pkg/ocsp.
func handleOCSP(w http.ResponseWriter, r *http.Request) {
	// RFC 6960 OCSP responder - to be implemented
	http.Error(w, "OCSP responder not yet implemented", http.StatusNotImplemented)
}

// handleTSA handles RFC 3161 TSA requests.
// TODO: Implement actual TSA response generation using pkg/tsa.
func handleTSA(w http.ResponseWriter, r *http.Request) {
	// RFC 3161 TSA responder - to be implemented
	http.Error(w, "TSA responder not yet implemented", http.StatusNotImplemented)
}

func applyServeEnvVars() {
	if servePort == 0 {
		if v := os.Getenv("QPKI_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				servePort = p
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
	if serveCADir == "" {
		serveCADir = os.Getenv("QPKI_CA_DIR")
	}
	if serveTLSCert == "" {
		serveTLSCert = os.Getenv("QPKI_TLS_CERT")
	}
	if serveTLSKey == "" {
		serveTLSKey = os.Getenv("QPKI_TLS_KEY")
	}
}
