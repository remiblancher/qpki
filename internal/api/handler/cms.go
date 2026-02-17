package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// CMSHandler handles CMS-related HTTP requests.
type CMSHandler struct {
	service *service.CMSService
}

// NewCMSHandler creates a new CMSHandler.
func NewCMSHandler(cmsService *service.CMSService) *CMSHandler {
	return &CMSHandler{service: cmsService}
}

// Sign handles POST /api/v1/cms/sign
func (h *CMSHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var req dto.CMSSignRequest
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

// Verify handles POST /api/v1/cms/verify
func (h *CMSHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.CMSVerifyRequest
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

// Encrypt handles POST /api/v1/cms/encrypt
func (h *CMSHandler) Encrypt(w http.ResponseWriter, r *http.Request) {
	var req dto.CMSEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Encrypt(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Decrypt handles POST /api/v1/cms/decrypt
func (h *CMSHandler) Decrypt(w http.ResponseWriter, r *http.Request) {
	var req dto.CMSDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Decrypt(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Info handles POST /api/v1/cms/info
func (h *CMSHandler) Info(w http.ResponseWriter, r *http.Request) {
	var req dto.CMSInfoRequest
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
