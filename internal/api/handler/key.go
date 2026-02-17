package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// KeyHandler handles key-related HTTP requests.
type KeyHandler struct{}

// NewKeyHandler creates a new KeyHandler.
func NewKeyHandler() *KeyHandler {
	return &KeyHandler{}
}

// Generate handles POST /api/v1/keys/generate
func (h *KeyHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req dto.KeyGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement key generation
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Key generation is not yet implemented",
	})
}

// Info handles POST /api/v1/keys/info
func (h *KeyHandler) Info(w http.ResponseWriter, r *http.Request) {
	var req dto.KeyInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement key info
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Key info is not yet implemented",
	})
}
