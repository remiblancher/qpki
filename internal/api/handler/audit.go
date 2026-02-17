package handler

import (
	"encoding/json"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
)

// AuditHandler handles audit-related HTTP requests.
type AuditHandler struct{}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler() *AuditHandler {
	return &AuditHandler{}
}

// Logs handles GET /api/v1/audit/logs
func (h *AuditHandler) Logs(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement audit logs retrieval
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Audit logs is not yet implemented",
	})
}

// Verify handles POST /api/v1/audit/verify
func (h *AuditHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req dto.AuditVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength > 0 {
		respondError(w, http.StatusBadRequest, &dto.APIError{
			Code:    "INVALID_REQUEST",
			Message: "Invalid JSON request body",
		})
		return
	}

	// TODO: Implement audit verification
	respondError(w, http.StatusNotImplemented, &dto.APIError{
		Code:    "NOT_IMPLEMENTED",
		Message: "Audit verification is not yet implemented",
	})
}
