package profile

import (
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: CRL Profile IsCritical Functions
// =============================================================================

func TestU_IssuingDistributionPointConfig_IsCritical_DefaultTrue(t *testing.T) {
	cfg := &IssuingDistributionPointConfig{}
	if !cfg.IsCritical() {
		t.Error("IsCritical() should return true when Critical is nil (RFC 5280 default)")
	}
}

func TestU_IssuingDistributionPointConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &IssuingDistributionPointConfig{Critical: &critical}
	if !cfg.IsCritical() {
		t.Error("IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_IssuingDistributionPointConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &IssuingDistributionPointConfig{Critical: &critical}
	if cfg.IsCritical() {
		t.Error("IsCritical() should return false when Critical is explicitly false")
	}
}

func TestU_DeltaCRLIndicatorConfig_IsCritical_DefaultTrue(t *testing.T) {
	cfg := &DeltaCRLIndicatorConfig{}
	if !cfg.IsCritical() {
		t.Error("IsCritical() should return true when Critical is nil (RFC 5280 default)")
	}
}

func TestU_DeltaCRLIndicatorConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &DeltaCRLIndicatorConfig{Critical: &critical}
	if !cfg.IsCritical() {
		t.Error("IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_DeltaCRLIndicatorConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &DeltaCRLIndicatorConfig{Critical: &critical}
	if cfg.IsCritical() {
		t.Error("IsCritical() should return false when Critical is explicitly false")
	}
}

// =============================================================================
// Unit Tests: DefaultCRLProfile
// =============================================================================

func TestU_DefaultCRLProfile_ReturnsValidProfile(t *testing.T) {
	profile := DefaultCRLProfile()

	if profile == nil {
		t.Fatal("DefaultCRLProfile() returned nil")
	}

	if profile.Name != "default" {
		t.Errorf("DefaultCRLProfile().Name = %q, want %q", profile.Name, "default")
	}

	if profile.Description != "Default CRL profile" {
		t.Errorf("DefaultCRLProfile().Description = %q, want %q", profile.Description, "Default CRL profile")
	}

	expectedValidity := 7 * 24 * time.Hour
	if profile.Validity != expectedValidity {
		t.Errorf("DefaultCRLProfile().Validity = %v, want %v", profile.Validity, expectedValidity)
	}

	if profile.Extensions != nil {
		t.Error("DefaultCRLProfile().Extensions should be nil")
	}
}

// =============================================================================
// Unit Tests: CRLProfileStore
// =============================================================================

func TestU_NewCRLProfileStore_ReturnsEmptyStore(t *testing.T) {
	store := NewCRLProfileStore()

	if store == nil {
		t.Fatal("NewCRLProfileStore() returned nil")
	}

	if store.profiles == nil {
		t.Error("NewCRLProfileStore().profiles should not be nil")
	}

	if len(store.profiles) != 0 {
		t.Errorf("NewCRLProfileStore() should be empty, got %d profiles", len(store.profiles))
	}
}

func TestU_CRLProfileStore_Add(t *testing.T) {
	store := NewCRLProfileStore()

	profile := &CRLProfile{
		Name:        "test-profile",
		Description: "Test CRL profile",
		Validity:    24 * time.Hour,
	}

	store.Add(profile)

	if len(store.profiles) != 1 {
		t.Errorf("Store should have 1 profile, got %d", len(store.profiles))
	}

	if store.profiles["test-profile"] != profile {
		t.Error("Profile was not stored correctly")
	}
}

func TestU_CRLProfileStore_Add_OverwritesExisting(t *testing.T) {
	store := NewCRLProfileStore()

	profile1 := &CRLProfile{
		Name:        "test-profile",
		Description: "First profile",
		Validity:    24 * time.Hour,
	}
	profile2 := &CRLProfile{
		Name:        "test-profile",
		Description: "Second profile",
		Validity:    48 * time.Hour,
	}

	store.Add(profile1)
	store.Add(profile2)

	if len(store.profiles) != 1 {
		t.Errorf("Store should have 1 profile, got %d", len(store.profiles))
	}

	if store.profiles["test-profile"].Description != "Second profile" {
		t.Error("Profile was not overwritten correctly")
	}
}

func TestU_CRLProfileStore_Get_Found(t *testing.T) {
	store := NewCRLProfileStore()

	profile := &CRLProfile{
		Name:        "test-profile",
		Description: "Test CRL profile",
		Validity:    24 * time.Hour,
	}

	store.Add(profile)

	got, ok := store.Get("test-profile")
	if !ok {
		t.Error("Get() should return ok=true for existing profile")
	}
	if got != profile {
		t.Error("Get() returned wrong profile")
	}
}

func TestU_CRLProfileStore_Get_NotFound(t *testing.T) {
	store := NewCRLProfileStore()

	got, ok := store.Get("nonexistent")
	if ok {
		t.Error("Get() should return ok=false for nonexistent profile")
	}
	if got != nil {
		t.Error("Get() should return nil for nonexistent profile")
	}
}

func TestU_CRLProfileStore_GetOrDefault_Found(t *testing.T) {
	store := NewCRLProfileStore()

	profile := &CRLProfile{
		Name:        "test-profile",
		Description: "Test CRL profile",
		Validity:    24 * time.Hour,
	}

	store.Add(profile)

	got := store.GetOrDefault("test-profile")
	if got != profile {
		t.Error("GetOrDefault() should return the existing profile")
	}
}

func TestU_CRLProfileStore_GetOrDefault_NotFound(t *testing.T) {
	store := NewCRLProfileStore()

	got := store.GetOrDefault("nonexistent")
	if got == nil {
		t.Fatal("GetOrDefault() should return default profile, got nil")
	}
	if got.Name != "default" {
		t.Errorf("GetOrDefault() should return default profile, got %q", got.Name)
	}
}

func TestU_CRLProfileStore_List_Empty(t *testing.T) {
	store := NewCRLProfileStore()

	names := store.List()
	if len(names) != 0 {
		t.Errorf("List() should return empty slice for empty store, got %d names", len(names))
	}
}

func TestU_CRLProfileStore_List_WithProfiles(t *testing.T) {
	store := NewCRLProfileStore()

	store.Add(&CRLProfile{Name: "profile-a", Validity: 24 * time.Hour})
	store.Add(&CRLProfile{Name: "profile-b", Validity: 48 * time.Hour})
	store.Add(&CRLProfile{Name: "profile-c", Validity: 72 * time.Hour})

	names := store.List()
	if len(names) != 3 {
		t.Errorf("List() should return 3 names, got %d", len(names))
	}

	// Check all names are present (order is not guaranteed)
	nameSet := make(map[string]bool)
	for _, name := range names {
		nameSet[name] = true
	}

	expectedNames := []string{"profile-a", "profile-b", "profile-c"}
	for _, expected := range expectedNames {
		if !nameSet[expected] {
			t.Errorf("List() should contain %q", expected)
		}
	}
}

// =============================================================================
// Unit Tests: CRLProfile with Extensions
// =============================================================================

func TestU_CRLProfile_WithIssuingDistributionPoint(t *testing.T) {
	critical := true
	profile := &CRLProfile{
		Name:        "with-idp",
		Description: "CRL profile with IDP",
		Validity:    7 * 24 * time.Hour,
		Extensions: &CRLExtensionsConfig{
			IssuingDistributionPoint: &IssuingDistributionPointConfig{
				Critical:              &critical,
				FullName:              "http://crl.example.com/ca.crl",
				OnlyContainsUserCerts: true,
			},
		},
	}

	if profile.Extensions == nil {
		t.Fatal("Extensions should not be nil")
	}

	if profile.Extensions.IssuingDistributionPoint == nil {
		t.Fatal("IssuingDistributionPoint should not be nil")
	}

	idp := profile.Extensions.IssuingDistributionPoint
	if !idp.IsCritical() {
		t.Error("IDP should be critical")
	}
	if idp.FullName != "http://crl.example.com/ca.crl" {
		t.Errorf("IDP.FullName = %q, want %q", idp.FullName, "http://crl.example.com/ca.crl")
	}
	if !idp.OnlyContainsUserCerts {
		t.Error("IDP.OnlyContainsUserCerts should be true")
	}
}

func TestU_CRLProfile_WithDeltaCRLIndicator(t *testing.T) {
	profile := &CRLProfile{
		Name:        "delta-crl",
		Description: "Delta CRL profile",
		Validity:    1 * 24 * time.Hour,
		Extensions: &CRLExtensionsConfig{
			DeltaCRLIndicator: &DeltaCRLIndicatorConfig{
				BaseCRLNumber: 42,
			},
		},
	}

	if profile.Extensions == nil {
		t.Fatal("Extensions should not be nil")
	}

	if profile.Extensions.DeltaCRLIndicator == nil {
		t.Fatal("DeltaCRLIndicator should not be nil")
	}

	delta := profile.Extensions.DeltaCRLIndicator
	if !delta.IsCritical() {
		t.Error("DeltaCRLIndicator should be critical by default")
	}
	if delta.BaseCRLNumber != 42 {
		t.Errorf("DeltaCRLIndicator.BaseCRLNumber = %d, want %d", delta.BaseCRLNumber, 42)
	}
}

func TestU_IssuingDistributionPointConfig_AllFields(t *testing.T) {
	critical := true
	cfg := &IssuingDistributionPointConfig{
		Critical:                   &critical,
		FullName:                   "http://crl.example.com/ca.crl",
		OnlyContainsUserCerts:      true,
		OnlyContainsCACerts:        false,
		OnlyContainsAttributeCerts: false,
		IndirectCRL:                false,
	}

	if !cfg.IsCritical() {
		t.Error("IsCritical() should return true")
	}
	if cfg.FullName != "http://crl.example.com/ca.crl" {
		t.Errorf("FullName = %q, want %q", cfg.FullName, "http://crl.example.com/ca.crl")
	}
	if !cfg.OnlyContainsUserCerts {
		t.Error("OnlyContainsUserCerts should be true")
	}
	if cfg.OnlyContainsCACerts {
		t.Error("OnlyContainsCACerts should be false")
	}
	if cfg.OnlyContainsAttributeCerts {
		t.Error("OnlyContainsAttributeCerts should be false")
	}
	if cfg.IndirectCRL {
		t.Error("IndirectCRL should be false")
	}
}
