package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	apierrors "github.com/remiblancher/post-quantum-pki/internal/api/errors"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// CAHandler handles CA-related HTTP requests.
type CAHandler struct {
	service *service.CAService
}

// NewCAHandler creates a new CAHandler.
func NewCAHandler(caService *service.CAService) *CAHandler {
	return &CAHandler{service: caService}
}

// Init handles POST /api/v1/ca/init
func (h *CAHandler) Init(w http.ResponseWriter, r *http.Request) {
	var req dto.CAInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	resp, err := h.service.Initialize(r.Context(), &req)
	if err != nil {
		status, apiErr := apierrors.MapError(err)
		respondError(w, status, apiErr)
		return
	}

	respondJSON(w, http.StatusCreated, resp)
}

// List handles GET /api/v1/ca
func (h *CAHandler) List(w http.ResponseWriter, r *http.Request) {
	pagination := parsePagination(r)

	resp, err := h.service.List(r.Context(), pagination)
	if err != nil {
		status, apiErr := apierrors.MapError(err)
		respondError(w, status, apiErr)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/ca/{id}
func (h *CAHandler) Get(w http.ResponseWriter, r *http.Request) {
	caID := chi.URLParam(r, "id")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "CA ID is required",
		})
		return
	}

	resp, err := h.service.Get(r.Context(), caID)
	if err != nil {
		status, apiErr := apierrors.MapError(err)
		respondError(w, status, apiErr)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Rotate handles POST /api/v1/ca/{id}/rotate
func (h *CAHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	caID := chi.URLParam(r, "id")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "CA ID is required",
		})
		return
	}

	var req dto.CARotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
		// Allow empty body for rotation with defaults
		if r.ContentLength > 0 {
			respondError(w, http.StatusBadRequest, &dto.APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid JSON request body",
				Details: map[string]string{"error": err.Error()},
			})
			return
		}
	}

	// TODO: Implement rotation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CA rotation is not yet implemented",
	})
}

// Activate handles POST /api/v1/ca/{id}/activate
func (h *CAHandler) Activate(w http.ResponseWriter, r *http.Request) {
	caID := chi.URLParam(r, "id")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "CA ID is required",
		})
		return
	}

	var req dto.CAActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	// TODO: Implement activation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "CA version activation is not yet implemented",
	})
}

// Export handles GET /api/v1/ca/{id}/export
func (h *CAHandler) Export(w http.ResponseWriter, r *http.Request) {
	caID := chi.URLParam(r, "id")
	if caID == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "CA ID is required",
		})
		return
	}

	req := &dto.CAExportRequest{
		Bundle:  r.URL.Query().Get("bundle"),
		Format:  r.URL.Query().Get("format"),
		Version: r.URL.Query().Get("version"),
	}

	resp, err := h.service.Export(r.Context(), caID, req)
	if err != nil {
		status, apiErr := apierrors.MapError(err)
		respondError(w, status, apiErr)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// parsePagination extracts pagination parameters from the request.
func parsePagination(r *http.Request) *dto.PaginationRequest {
	q := r.URL.Query()
	pagination := &dto.PaginationRequest{}

	if limit := q.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			pagination.Limit = l
		}
	}

	if offset := q.Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			pagination.Offset = o
		}
	}

	pagination.Filter = q.Get("filter")

	return pagination
}
