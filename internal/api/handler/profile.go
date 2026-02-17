package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/api/service"
)

// ProfileHandler handles profile-related HTTP requests.
type ProfileHandler struct {
	service *service.ProfileService
}

// NewProfileHandler creates a new ProfileHandler.
func NewProfileHandler(profileService *service.ProfileService) *ProfileHandler {
	return &ProfileHandler{service: profileService}
}

// List handles GET /api/v1/profiles
func (h *ProfileHandler) List(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.List(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/profiles/{name}
func (h *ProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Profile name is required",
		})
		return
	}

	resp, err := h.service.Get(r.Context(), name)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// GetVars handles GET /api/v1/profiles/{name}/vars
func (h *ProfileHandler) GetVars(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Profile name is required",
		})
		return
	}

	resp, err := h.service.GetVars(r.Context(), name)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Validate handles POST /api/v1/profiles/validate
func (h *ProfileHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req dto.ProfileValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	resp, err := h.service.Validate(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
