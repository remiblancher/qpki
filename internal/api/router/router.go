// Package router provides HTTP routing configuration using Chi.
package router

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/handler"
	"github.com/remiblancher/post-quantum-pki/internal/api/middleware"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

//go:embed openapi.yaml
var openapiSpec []byte

// Config holds router configuration.
type Config struct {
	Services []string
	Version  string
	CADir    string // Directory containing CAs (for CA service)
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

// New creates a new Chi router with all routes configured.
func New(cfg *Config) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.CORS)

	// Health endpoints (always enabled)
	healthHandler := handler.NewHealthHandler(cfg.Version, cfg.Services)
	r.Get("/health", healthHandler.Health)
	r.Get("/ready", healthHandler.Ready)

	// OpenAPI spec
	r.Get("/api/openapi.yaml", serveOpenAPISpec)

	// API routes
	if cfg.HasService("api") {
		// Create services
		caService := service.NewCAService(cfg.CADir)
		certService := service.NewCertService(cfg.CADir)
		cmsService := service.NewCMSService(cfg.CADir)
		coseService := service.NewCOSEService(cfg.CADir)
		tsaService := service.NewTSAService(cfg.CADir)
		ocspService := service.NewOCSPService(cfg.CADir)
		profileService := service.NewProfileService()
		credentialService := service.NewCredentialService(cfg.CADir)

		// Create handlers
		caHandler := handler.NewCAHandler(caService)
		certHandler := handler.NewCertHandler(certService)
		credentialHandler := handler.NewCredentialHandler(credentialService)
		cmsHandler := handler.NewCMSHandler(cmsService)
		coseHandler := handler.NewCOSEHandler(coseService)
		tsaHandler := handler.NewTSAHandler(tsaService)
		ocspHandler := handler.NewOCSPHandler(ocspService)
		crlHandler := handler.NewCRLHandler()
		csrHandler := handler.NewCSRHandler()
		keyHandler := handler.NewKeyHandler()
		profileHandler := handler.NewProfileHandler(profileService)
		auditHandler := handler.NewAuditHandler()
		inspectHandler := handler.NewInspectHandler()

		r.Route("/api/v1", func(r chi.Router) {
			// Future: r.Use(authMiddleware)

			// CA operations
			r.Route("/ca", func(r chi.Router) {
				r.Post("/init", caHandler.Init)
				r.Get("/", caHandler.List)
				r.Get("/{id}", caHandler.Get)
				r.Post("/{id}/rotate", caHandler.Rotate)
				r.Post("/{id}/activate", caHandler.Activate)
				r.Get("/{id}/export", caHandler.Export)
			})

			// Certificate operations
			r.Route("/certs", func(r chi.Router) {
				r.Post("/issue", certHandler.Issue)
				r.Get("/", certHandler.List)
				r.Get("/{serial}", certHandler.Get)
				r.Post("/{serial}/revoke", certHandler.Revoke)
				r.Post("/verify", certHandler.Verify)
			})

			// Credential operations
			r.Route("/credentials", func(r chi.Router) {
				r.Post("/enroll", credentialHandler.Enroll)
				r.Get("/", credentialHandler.List)
				r.Get("/{id}", credentialHandler.Get)
				r.Post("/{id}/rotate", credentialHandler.Rotate)
				r.Post("/{id}/revoke", credentialHandler.Revoke)
				r.Get("/{id}/export", credentialHandler.Export)
				r.Post("/{id}/activate", credentialHandler.Activate)
			})

			// CMS operations
			r.Route("/cms", func(r chi.Router) {
				r.Post("/sign", cmsHandler.Sign)
				r.Post("/verify", cmsHandler.Verify)
				r.Post("/encrypt", cmsHandler.Encrypt)
				r.Post("/decrypt", cmsHandler.Decrypt)
				r.Post("/info", cmsHandler.Info)
			})

			// COSE/CWT operations
			r.Route("/cose", func(r chi.Router) {
				r.Post("/sign", coseHandler.Sign)
				r.Post("/verify", coseHandler.Verify)
				r.Post("/info", coseHandler.Info)
			})
			r.Route("/cwt", func(r chi.Router) {
				r.Post("/issue", coseHandler.CWTIssue)
				r.Post("/verify", coseHandler.CWTVerify)
			})

			// TSA operations (REST)
			r.Route("/tsa", func(r chi.Router) {
				r.Post("/sign", tsaHandler.Sign)
				r.Post("/verify", tsaHandler.Verify)
				r.Post("/info", tsaHandler.Info)
			})

			// OCSP operations (REST)
			r.Route("/ocsp", func(r chi.Router) {
				r.Post("/query", ocspHandler.Query)
				r.Post("/verify", ocspHandler.Verify)
			})

			// CRL operations
			r.Route("/crl", func(r chi.Router) {
				r.Post("/generate", crlHandler.Generate)
				r.Get("/", crlHandler.List)
				r.Get("/{id}", crlHandler.Get)
				r.Post("/verify", crlHandler.Verify)
			})

			// CSR operations
			r.Route("/csr", func(r chi.Router) {
				r.Post("/generate", csrHandler.Generate)
				r.Post("/info", csrHandler.Info)
				r.Post("/verify", csrHandler.Verify)
			})

			// Key operations
			r.Route("/keys", func(r chi.Router) {
				r.Post("/generate", keyHandler.Generate)
				r.Post("/info", keyHandler.Info)
			})

			// Profile operations
			r.Route("/profiles", func(r chi.Router) {
				r.Get("/", profileHandler.List)
				r.Get("/{name}", profileHandler.Get)
				r.Get("/{name}/vars", profileHandler.GetVars)
				r.Post("/validate", profileHandler.Validate)
			})

			// Audit operations
			r.Route("/audit", func(r chi.Router) {
				r.Get("/logs", auditHandler.Logs)
				r.Post("/verify", auditHandler.Verify)
			})

			// Inspect (auto-detect)
			r.Post("/inspect", inspectHandler.Inspect)
		})
	}

	// RFC protocol endpoints (without auth, for standard clients)
	if cfg.HasService("ocsp") {
		// RFC 6960 OCSP responder
		r.HandleFunc("/ocsp", notImplementedRFC)
		r.HandleFunc("/ocsp/*", notImplementedRFC)
	}

	if cfg.HasService("tsa") {
		// RFC 3161 TSA responder
		r.HandleFunc("/tsa", notImplementedRFC)
	}

	return r
}

// notImplementedRFC returns a 501 for RFC protocol endpoints.
func notImplementedRFC(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}

// serveOpenAPISpec serves the OpenAPI specification file.
func serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}
