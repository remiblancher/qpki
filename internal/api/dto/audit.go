package dto

// AuditLogsRequest represents an audit logs request.
type AuditLogsRequest struct {
	// StartTime filters logs after this time (RFC3339).
	StartTime string `json:"start_time,omitempty"`

	// EndTime filters logs before this time (RFC3339).
	EndTime string `json:"end_time,omitempty"`

	// Operation filters by operation type.
	Operation string `json:"operation,omitempty"`

	// Subject filters by subject (certificate CN, etc.).
	Subject string `json:"subject,omitempty"`

	// Success filters by success status.
	Success *bool `json:"success,omitempty"`

	// Pagination for the request.
	Pagination PaginationRequest `json:"pagination,omitempty"`
}

// AuditLogsResponse represents audit logs.
type AuditLogsResponse struct {
	// Logs is the list of audit entries.
	Logs []AuditEntry `json:"logs"`

	// Pagination contains pagination information.
	Pagination PaginationResponse `json:"pagination"`
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	// Timestamp is when the event occurred.
	Timestamp string `json:"timestamp"`

	// Operation is the operation type.
	Operation string `json:"operation"`

	// Subject is the subject of the operation.
	Subject string `json:"subject,omitempty"`

	// Details contains operation-specific details.
	Details map[string]string `json:"details,omitempty"`

	// Success indicates if the operation succeeded.
	Success bool `json:"success"`

	// Error is present if the operation failed.
	Error string `json:"error,omitempty"`

	// Hash is the entry hash for verification.
	Hash string `json:"hash,omitempty"`
}

// AuditVerifyRequest represents an audit log verification request.
type AuditVerifyRequest struct {
	// LogFile is the audit log file path.
	LogFile string `json:"log_file,omitempty"`

	// StartTime filters verification after this time.
	StartTime string `json:"start_time,omitempty"`

	// EndTime filters verification before this time.
	EndTime string `json:"end_time,omitempty"`
}

// AuditVerifyResponse represents audit verification result.
type AuditVerifyResponse struct {
	// Valid indicates if the audit log is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// EntryCount is the number of entries verified.
	EntryCount int `json:"entry_count"`

	// FirstEntry is the first entry timestamp.
	FirstEntry string `json:"first_entry,omitempty"`

	// LastEntry is the last entry timestamp.
	LastEntry string `json:"last_entry,omitempty"`
}
