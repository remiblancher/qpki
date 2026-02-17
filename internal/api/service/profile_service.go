// Package service provides business logic for the REST API.
package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// ProfileService provides profile operations for the REST API.
type ProfileService struct{}

// NewProfileService creates a new ProfileService.
func NewProfileService() *ProfileService {
	return &ProfileService{}
}

// List returns all available profiles.
func (s *ProfileService) List(ctx context.Context) (*dto.ProfileListResponse, error) {
	// Get builtin profile names
	names, err := profile.ListBuiltinProfileNames()
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	var profiles []dto.ProfileListItem
	for _, name := range names {
		prof, err := profile.GetBuiltinProfile(name)
		if err != nil {
			continue
		}

		item := dto.ProfileListItem{
			Name:        name,
			Description: prof.Description,
			Category:    extractCategory(name),
			Algorithm:   string(prof.Algorithm),
			IsCA:        isCAProfile(prof),
		}
		profiles = append(profiles, item)
	}

	return &dto.ProfileListResponse{
		Profiles: profiles,
	}, nil
}

// Get returns detailed information about a profile.
func (s *ProfileService) Get(ctx context.Context, name string) (*dto.ProfileInfoResponse, error) {
	prof, err := profile.LoadProfile(name)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	resp := &dto.ProfileInfoResponse{
		Name:        name,
		Description: prof.Description,
		Category:    extractCategory(name),
		Algorithm: dto.AlgorithmInfo{
			ID: string(prof.Algorithm),
		},
		IsCA:     isCAProfile(prof),
		Validity: formatDuration(prof.Validity),
	}

	// Set path length for CA
	if isCAProfile(prof) && prof.Extensions != nil && prof.Extensions.BasicConstraints != nil {
		if prof.Extensions.BasicConstraints.PathLen != nil {
			pathLen := *prof.Extensions.BasicConstraints.PathLen
			resp.PathLen = &pathLen
		}
	}

	// Key usage
	if prof.Extensions != nil && prof.Extensions.KeyUsage != nil {
		resp.KeyUsage = prof.Extensions.KeyUsage.Values
	}

	// Extended key usage
	if prof.Extensions != nil && prof.Extensions.ExtKeyUsage != nil {
		resp.ExtKeyUsage = prof.Extensions.ExtKeyUsage.Values
	}

	// Variables
	resp.Variables = extractVariables(prof)

	return resp, nil
}

// GetVars returns the variables for a profile.
func (s *ProfileService) GetVars(ctx context.Context, name string) (*dto.ProfileVarsResponse, error) {
	prof, err := profile.LoadProfile(name)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	return &dto.ProfileVarsResponse{
		Variables: extractVariables(prof),
	}, nil
}

// Validate validates a profile YAML.
func (s *ProfileService) Validate(ctx context.Context, req *dto.ProfileValidateRequest) (*dto.ProfileValidateResponse, error) {
	if req.YAML == "" {
		return &dto.ProfileValidateResponse{
			Valid:  false,
			Errors: []string{"YAML content is required"},
		}, nil
	}

	// Parse the profile
	prof, err := profile.LoadProfileFromBytes([]byte(req.YAML))
	if err != nil {
		return &dto.ProfileValidateResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	// Validate the profile
	var warnings []string
	if prof.Description == "" {
		warnings = append(warnings, "Profile has no description")
	}

	// Build profile info response
	info := &dto.ProfileInfoResponse{
		Name:        prof.Name,
		Description: prof.Description,
		Algorithm: dto.AlgorithmInfo{
			ID: string(prof.Algorithm),
		},
		IsCA:      isCAProfile(prof),
		Validity:  formatDuration(prof.Validity),
		Variables: extractVariables(prof),
	}

	return &dto.ProfileValidateResponse{
		Valid:    true,
		Warnings: warnings,
		Profile:  info,
	}, nil
}

// isCAProfile checks if a profile is for a CA.
func isCAProfile(prof *profile.Profile) bool {
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil {
		return prof.Extensions.BasicConstraints.CA
	}
	return false
}

// formatDuration formats a duration as a human-readable string.
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 365 {
		years := days / 365
		return fmt.Sprintf("%d years", years)
	}
	return fmt.Sprintf("%d days", days)
}

// extractCategory extracts the category from a profile name.
func extractCategory(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 1 {
		return parts[0]
	}
	return "other"
}

// extractVariables extracts variables from a profile.
func extractVariables(prof *profile.Profile) []dto.ProfileVariable {
	var vars []dto.ProfileVariable

	if prof.Variables == nil {
		return vars
	}

	for name, v := range prof.Variables {
		pv := dto.ProfileVariable{
			Name:        name,
			Description: v.Description,
			Type:        string(v.Type),
			Required:    v.Required,
			Default:     v.Default,
		}

		// Add validation if any constraints are set
		if v.Pattern != "" || v.MinLength > 0 || v.MaxLength > 0 || len(v.Enum) > 0 {
			pv.Validation = &dto.VariableValidation{
				Pattern:   v.Pattern,
				MinLength: v.MinLength,
				MaxLength: v.MaxLength,
				Enum:      v.Enum,
			}
		}

		vars = append(vars, pv)
	}

	return vars
}
