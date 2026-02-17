package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// CSRHandler handles CSR-related HTTP requests.
type CSRHandler struct{}

// NewCSRHandler creates a new CSRHandler.
func NewCSRHandler() *CSRHandler {
	return &CSRHandler{}
}

// Generate handles POST /api/v1/csr/generate
func (h *CSRHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req dto.CSRGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement CSR generation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CSR generation is not yet implemented",
	})
}

// Info handles POST /api/v1/csr/info
func (h *CSRHandler) Info(w http.ResponseWriter, r *http.Request) {
	var req dto.CSRInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement CSR info
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CSR info is not yet implemented",
	})
}

// Verify handles POST /api/v1/csr/verify
func (h *CSRHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.CSRVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement CSR verification
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CSR verification is not yet implemented",
	})
}
