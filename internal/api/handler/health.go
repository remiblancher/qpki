// Package handler provides HTTP handlers for the REST API.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// HealthHandler handles health and readiness endpoints.
type HealthHandler struct {
	version  string
	services []string
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(version string, services []string) *HealthHandler {
	return &HealthHandler{
		version:  version,
		services: services,
	}
}

// Health handles GET /health.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	serviceStatus := make(map[string]string)
	for _, s := range h.services {
		serviceStatus[s] = "ok"
	}

	resp := dto.HealthResponse{
		Status:   "ok",
		Version:  h.version,
		Services: serviceStatus,
	}

	respondJSON(w, http.StatusOK, resp)
}

// Ready handles GET /ready.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]bool{
		"server": true,
	}

	allReady := true
	for _, ready := range checks {
		if !ready {
			allReady = false
			break
		}
	}

	resp := dto.ReadyResponse{
		Ready:  allReady,
		Checks: checks,
	}

	status := http.StatusOK
	if !allReady {
		status = http.StatusServiceUnavailable
	}

	respondJSON(w, status, resp)
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// respondError writes an error response.
func respondError(w http.ResponseWriter, status int, apiErr *dto.APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiErr)
}
