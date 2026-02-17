package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// CredentialHandler handles credential-related HTTP requests.
type CredentialHandler struct {
	service *service.CredentialService
}

// NewCredentialHandler creates a new CredentialHandler.
func NewCredentialHandler(credService *service.CredentialService) *CredentialHandler {
	return &CredentialHandler{service: credService}
}

// Enroll handles POST /api/v1/credentials/enroll
func (h *CredentialHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	var req dto.CredentialEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement credential enrollment (requires CA integration)
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Credential enrollment is not yet implemented",
	})
}

// List handles GET /api/v1/credentials
func (h *CredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.List(r.Context(), nil)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/credentials/{id}
func (h *CredentialHandler) Get(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "id")
	if credID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Credential ID is required",
		})
		return
	}

	resp, err := h.service.Get(r.Context(), credID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Rotate handles POST /api/v1/credentials/{id}/rotate
func (h *CredentialHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "id")
	if credID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Credential ID is required",
		})
		return
	}

	var req dto.CredentialRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength > 0 {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement credential rotation (requires CA integration)
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Credential rotation is not yet implemented",
	})
}

// Revoke handles POST /api/v1/credentials/{id}/revoke
func (h *CredentialHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "id")
	if credID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Credential ID is required",
		})
		return
	}

	var req dto.CredentialRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength > 0 {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement credential revocation (requires CA integration)
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Credential revocation is not yet implemented",
	})
}

// Export handles GET /api/v1/credentials/{id}/export
func (h *CredentialHandler) Export(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "id")
	if credID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Credential ID is required",
		})
		return
	}

	// TODO: Implement credential export
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Credential export is not yet implemented",
	})
}

// Activate handles POST /api/v1/credentials/{id}/activate
func (h *CredentialHandler) Activate(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "id")
	if credID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Credential ID is required",
		})
		return
	}

	// TODO: Implement credential activation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Credential activation is not yet implemented",
	})
}
