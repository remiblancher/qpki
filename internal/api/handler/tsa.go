package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// TSAHandler handles TSA-related HTTP requests.
type TSAHandler struct {
	service *service.TSAService
}

// NewTSAHandler creates a new TSAHandler.
func NewTSAHandler(tsaService *service.TSAService) *TSAHandler {
	return &TSAHandler{service: tsaService}
}

// Sign handles POST /api/v1/tsa/sign
func (h *TSAHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var req dto.TSASignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Sign(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Verify handles POST /api/v1/tsa/verify
func (h *TSAHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.TSAVerifyRequest
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

// Info handles POST /api/v1/tsa/info
func (h *TSAHandler) Info(w http.ResponseWriter, r *http.Request) {
	var req dto.TSAInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Info(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
