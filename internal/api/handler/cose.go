package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// COSEHandler handles COSE-related HTTP requests.
type COSEHandler struct {
	service *service.COSEService
}

// NewCOSEHandler creates a new COSEHandler.
func NewCOSEHandler(coseService *service.COSEService) *COSEHandler {
	return &COSEHandler{service: coseService}
}

// Sign handles POST /api/v1/cose/sign
func (h *COSEHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var req dto.COSESignRequest
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

// Verify handles POST /api/v1/cose/verify
func (h *COSEHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.COSEVerifyRequest
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

// Info handles POST /api/v1/cose/info
func (h *COSEHandler) Info(w http.ResponseWriter, r *http.Request) {
	var req dto.COSEInfoRequest
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

// CWTIssue handles POST /api/v1/cwt/issue
func (h *COSEHandler) CWTIssue(w http.ResponseWriter, r *http.Request) {
	var req dto.CWTIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.CWTIssue(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// CWTVerify handles POST /api/v1/cwt/verify
func (h *COSEHandler) CWTVerify(w http.ResponseWriter, r *http.Request) {
	var req dto.CWTVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.CWTVerify(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
