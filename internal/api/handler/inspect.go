package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// InspectHandler handles inspect-related HTTP requests.
type InspectHandler struct{}

// NewInspectHandler creates a new InspectHandler.
func NewInspectHandler() *InspectHandler {
	return &InspectHandler{}
}

// Inspect handles POST /api/v1/inspect
func (h *InspectHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	var req dto.InspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement auto-detection inspection
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Inspect is not yet implemented",
	})
}
