package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
)

// CertHandler handles certificate-related HTTP requests.
type CertHandler struct {
	service *service.CertService
}

// NewCertHandler creates a new CertHandler.
func NewCertHandler(certService *service.CertService) *CertHandler {
	return &CertHandler{service: certService}
}

// Issue handles POST /api/v1/certs/issue
func (h *CertHandler) Issue(w http.ResponseWriter, r *http.Request) {
	var req dto.CertIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// Get CA ID from query parameter or default
	caID := r.URL.Query().Get("ca")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "MISSING_CA",
			Message: "CA identifier is required (use ?ca=<id>)",
		})
		return
	}

	resp, err := h.service.Issue(r.Context(), caID, &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, resp)
}

// List handles GET /api/v1/certs
func (h *CertHandler) List(w http.ResponseWriter, r *http.Request) {
	caID := r.URL.Query().Get("ca")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "MISSING_CA",
			Message: "CA identifier is required (use ?ca=<id>)",
		})
		return
	}

	pagination := parsePagination(r)
	resp, err := h.service.List(r.Context(), caID, pagination)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/certs/{serial}
func (h *CertHandler) Get(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	if serial == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Serial number is required",
		})
		return
	}

	caID := r.URL.Query().Get("ca")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "MISSING_CA",
			Message: "CA identifier is required (use ?ca=<id>)",
		})
		return
	}

	resp, err := h.service.Get(r.Context(), caID, serial)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Revoke handles POST /api/v1/certs/{serial}/revoke
func (h *CertHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	if serial == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Serial number is required",
		})
		return
	}

	caID := r.URL.Query().Get("ca")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "MISSING_CA",
			Message: "CA identifier is required (use ?ca=<id>)",
		})
		return
	}

	var req dto.CertRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength > 0 {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Revoke(r.Context(), caID, serial, &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Verify handles POST /api/v1/certs/verify
func (h *CertHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.CertVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	caID := r.URL.Query().Get("ca")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "MISSING_CA",
			Message: "CA identifier is required (use ?ca=<id>)",
		})
		return
	}

	resp, err := h.service.Verify(r.Context(), caID, &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// handleServiceError maps service errors to HTTP responses.
func handleServiceError(w http.ResponseWriter, err error) {
	switch err {
	case ca.ErrCANotInitialized:
		respondError(w, http.StatusNotFound, &dto.APIError{
			Code:    "CA_NOT_FOUND",
			Message: "CA not found or not initialized",
		})
	case ca.ErrCertNotFound:
		respondError(w, http.StatusNotFound, &dto.APIError{
			Code:    "CERT_NOT_FOUND",
			Message: "Certificate not found",
		})
	default:
		respondError(w, http.StatusInternalServerError, &dto.APIError{
			Code:    "INTERNAL_ERROR",
			Message: err.Error(),
		})
	}
}
