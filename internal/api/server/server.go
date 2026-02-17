package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/remiblancher/post-quantum-pki/internal/api/router"
)

// Server represents the HTTP server(s).
type Server struct {
	cfg     *Config
	version string
	servers []*http.Server
}

// New creates a new Server.
func New(cfg *Config, version string) *Server {
	return &Server{
		cfg:     cfg,
		version: version,
	}
}

// Start starts the HTTP server(s) and blocks until shutdown.
func (s *Server) Start() error {
	// Determine if we need separate servers per service
	if s.cfg.UseSeparatePorts() {
		return s.startSeparateServers()
	}
	return s.startSingleServer()
}

// startSingleServer starts all services on a single port.
func (s *Server) startSingleServer() error {
	routerCfg := &router.Config{
		Services: s.cfg.Services,
		Version:  s.version,
		CADir:    s.cfg.CADir,
	}
	handler := router.New(routerCfg)

	srv := &http.Server{
		Addr:         s.cfg.Address(),
		Handler:      handler,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}
	s.servers = []*http.Server{srv}

	s.printStartupInfo()

	return s.runServers()
}

// startSeparateServers starts each service on its own port.
func (s *Server) startSeparateServers() error {
	// API server
	if s.cfg.HasService("api") {
		apiCfg := &router.Config{
			Services: []string{"api"},
			Version:  s.version,
			CADir:    s.cfg.CADir,
		}
		srv := &http.Server{
			Addr:         s.cfg.APIAddress(),
			Handler:      router.New(apiCfg),
			ReadTimeout:  s.cfg.ReadTimeout,
			WriteTimeout: s.cfg.WriteTimeout,
			IdleTimeout:  s.cfg.IdleTimeout,
		}
		s.servers = append(s.servers, srv)
	}

	// OCSP server
	if s.cfg.HasService("ocsp") {
		ocspCfg := &router.Config{
			Services: []string{"ocsp"},
			Version:  s.version,
			CADir:    s.cfg.CADir,
		}
		srv := &http.Server{
			Addr:         s.cfg.OCSPAddress(),
			Handler:      router.New(ocspCfg),
			ReadTimeout:  s.cfg.ReadTimeout,
			WriteTimeout: s.cfg.WriteTimeout,
			IdleTimeout:  s.cfg.IdleTimeout,
		}
		s.servers = append(s.servers, srv)
	}

	// TSA server
	if s.cfg.HasService("tsa") {
		tsaCfg := &router.Config{
			Services: []string{"tsa"},
			Version:  s.version,
			CADir:    s.cfg.CADir,
		}
		srv := &http.Server{
			Addr:         s.cfg.TSAAddress(),
			Handler:      router.New(tsaCfg),
			ReadTimeout:  s.cfg.ReadTimeout,
			WriteTimeout: s.cfg.WriteTimeout,
			IdleTimeout:  s.cfg.IdleTimeout,
		}
		s.servers = append(s.servers, srv)
	}

	s.printStartupInfoSeparate()

	return s.runServers()
}

// runServers starts all servers and handles graceful shutdown.
func (s *Server) runServers() error {
	errChan := make(chan error, len(s.servers))

	// Start all servers
	for _, srv := range s.servers {
		go func(srv *http.Server) {
			if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
				errChan <- srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
			} else {
				errChan <- srv.ListenAndServe()
			}
		}(srv)
	}

	// Wait for shutdown signal or error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		return s.shutdownAll()
	}

	return nil
}

// shutdownAll gracefully shuts down all servers.
func (s *Server) shutdownAll() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, len(s.servers))

	for _, srv := range s.servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(ctx); err != nil {
				errChan <- err
			}
		}(srv)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	for err := range errChan {
		if err != nil {
			return fmt.Errorf("shutdown error: %w", err)
		}
	}

	log.Println("All servers stopped gracefully")
	return nil
}

// printStartupInfo prints server startup information (single server mode).
func (s *Server) printStartupInfo() {
	fmt.Println()
	fmt.Println("QPKI API Server")
	fmt.Println("===============")
	fmt.Printf("  Version:  %s\n", s.version)
	fmt.Printf("  Address:  http://%s\n", s.cfg.Address())
	if s.cfg.TLSCert != "" {
		fmt.Println("  TLS:      enabled")
	}
	fmt.Println()
	fmt.Println("Services:")
	for _, svc := range s.cfg.Services {
		fmt.Printf("  - %s\n", svc)
	}
	fmt.Println()
	s.printEndpoints()
	fmt.Println()
	fmt.Println("Use Ctrl+C to stop")
	fmt.Println()
}

// printStartupInfoSeparate prints startup info for separate server mode.
func (s *Server) printStartupInfoSeparate() {
	fmt.Println()
	fmt.Println("QPKI API Server (Multi-Port Mode)")
	fmt.Println("==================================")
	fmt.Printf("  Version:  %s\n", s.version)
	if s.cfg.TLSCert != "" {
		fmt.Println("  TLS:      enabled")
	}
	fmt.Println()
	fmt.Println("Services:")
	if s.cfg.HasService("api") {
		fmt.Printf("  - api:  http://%s/api/v1/*\n", s.cfg.APIAddress())
	}
	if s.cfg.HasService("ocsp") {
		fmt.Printf("  - ocsp: http://%s/ocsp\n", s.cfg.OCSPAddress())
	}
	if s.cfg.HasService("tsa") {
		fmt.Printf("  - tsa:  http://%s/tsa\n", s.cfg.TSAAddress())
	}
	fmt.Println()
	fmt.Println("Use Ctrl+C to stop")
	fmt.Println()
}

// printEndpoints prints available endpoints.
func (s *Server) printEndpoints() {
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /health              - Health check")
	fmt.Println("  GET  /ready               - Readiness check")
	fmt.Println("  GET  /api/openapi.yaml    - OpenAPI specification")
	if s.cfg.HasService("api") {
		fmt.Println("  *    /api/v1/*            - REST API")
	}
	if s.cfg.HasService("ocsp") {
		fmt.Println("  *    /ocsp                - RFC 6960 OCSP responder")
	}
	if s.cfg.HasService("tsa") {
		fmt.Println("  *    /tsa                 - RFC 3161 TSA responder")
	}
}
