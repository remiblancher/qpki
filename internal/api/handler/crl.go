package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// CRLHandler handles CRL-related HTTP requests.
type CRLHandler struct{}

// NewCRLHandler creates a new CRLHandler.
func NewCRLHandler() *CRLHandler {
	return &CRLHandler{}
}

// Generate handles POST /api/v1/crl/generate
func (h *CRLHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req dto.CRLGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength > 0 {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement CRL generation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CRL generation is not yet implemented",
	})
}

// List handles GET /api/v1/crl
func (h *CRLHandler) List(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement CRL listing
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CRL listing is not yet implemented",
	})
}

// Get handles GET /api/v1/crl/{id}
func (h *CRLHandler) Get(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "id")
	if crlID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "CRL ID is required",
		})
		return
	}

	// TODO: Implement CRL retrieval
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CRL retrieval is not yet implemented",
	})
}

// Verify handles POST /api/v1/crl/verify
func (h *CRLHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.CRLVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement CRL verification
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CRL verification is not yet implemented",
	})
}
