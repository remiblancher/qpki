package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// OCSPHandler handles OCSP-related HTTP requests.
type OCSPHandler struct {
	service *service.OCSPService
}

// NewOCSPHandler creates a new OCSPHandler.
func NewOCSPHandler(ocspService *service.OCSPService) *OCSPHandler {
	return &OCSPHandler{service: ocspService}
}

// Query handles POST /api/v1/ocsp/query
func (h *OCSPHandler) Query(w http.ResponseWriter, r *http.Request) {
	var req dto.OCSPQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Query(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Verify handles POST /api/v1/ocsp/verify
func (h *OCSPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.OCSPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Verify(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
