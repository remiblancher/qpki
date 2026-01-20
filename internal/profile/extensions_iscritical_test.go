package profile

import (
	"testing"
)

// =============================================================================
// Unit Tests: Extension IsCritical Functions
// =============================================================================

// Tests for KeyUsageConfig.IsCritical()
func TestU_KeyUsageConfig_IsCritical_DefaultTrue(t *testing.T) {
	cfg := &KeyUsageConfig{
		Values: []string{"digitalSignature"},
	}
	if !cfg.IsCritical() {
		t.Error("KeyUsageConfig.IsCritical() should return true when Critical is nil (RFC 5280 default)")
	}
}

func TestU_KeyUsageConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &KeyUsageConfig{
		Critical: &critical,
		Values:   []string{"digitalSignature"},
	}
	if !cfg.IsCritical() {
		t.Error("KeyUsageConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_KeyUsageConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &KeyUsageConfig{
		Critical: &critical,
		Values:   []string{"digitalSignature"},
	}
	if cfg.IsCritical() {
		t.Error("KeyUsageConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for ExtKeyUsageConfig.IsCritical()
func TestU_ExtKeyUsageConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &ExtKeyUsageConfig{
		Values: []string{"serverAuth"},
	}
	if cfg.IsCritical() {
		t.Error("ExtKeyUsageConfig.IsCritical() should return false when Critical is nil (default)")
	}
}

func TestU_ExtKeyUsageConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &ExtKeyUsageConfig{
		Critical: &critical,
		Values:   []string{"serverAuth"},
	}
	if !cfg.IsCritical() {
		t.Error("ExtKeyUsageConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_ExtKeyUsageConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &ExtKeyUsageConfig{
		Critical: &critical,
		Values:   []string{"serverAuth"},
	}
	if cfg.IsCritical() {
		t.Error("ExtKeyUsageConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for BasicConstraintsConfig.IsCritical()
func TestU_BasicConstraintsConfig_IsCritical_DefaultTrue(t *testing.T) {
	cfg := &BasicConstraintsConfig{
		CA: true,
	}
	if !cfg.IsCritical() {
		t.Error("BasicConstraintsConfig.IsCritical() should return true when Critical is nil (RFC 5280 default)")
	}
}

func TestU_BasicConstraintsConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &BasicConstraintsConfig{
		Critical: &critical,
		CA:       true,
	}
	if !cfg.IsCritical() {
		t.Error("BasicConstraintsConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_BasicConstraintsConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &BasicConstraintsConfig{
		Critical: &critical,
		CA:       false,
	}
	if cfg.IsCritical() {
		t.Error("BasicConstraintsConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for SubjectAltNameConfig.IsCritical()
func TestU_SubjectAltNameConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &SubjectAltNameConfig{
		DNS: []string{"example.com"},
	}
	if cfg.IsCritical() {
		t.Error("SubjectAltNameConfig.IsCritical() should return false when Critical is nil (default)")
	}
}

func TestU_SubjectAltNameConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &SubjectAltNameConfig{
		Critical: &critical,
		DNS:      []string{"example.com"},
	}
	if !cfg.IsCritical() {
		t.Error("SubjectAltNameConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_SubjectAltNameConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &SubjectAltNameConfig{
		Critical: &critical,
		DNS:      []string{"example.com"},
	}
	if cfg.IsCritical() {
		t.Error("SubjectAltNameConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for CRLDistributionPointsConfig.IsCritical()
func TestU_CRLDistributionPointsConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &CRLDistributionPointsConfig{
		URLs: []string{"http://crl.example.com/ca.crl"},
	}
	if cfg.IsCritical() {
		t.Error("CRLDistributionPointsConfig.IsCritical() should return false when Critical is nil (RFC 5280 default)")
	}
}

func TestU_CRLDistributionPointsConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &CRLDistributionPointsConfig{
		Critical: &critical,
		URLs:     []string{"http://crl.example.com/ca.crl"},
	}
	if !cfg.IsCritical() {
		t.Error("CRLDistributionPointsConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_CRLDistributionPointsConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &CRLDistributionPointsConfig{
		Critical: &critical,
		URLs:     []string{"http://crl.example.com/ca.crl"},
	}
	if cfg.IsCritical() {
		t.Error("CRLDistributionPointsConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for AuthorityInfoAccessConfig.IsCritical()
func TestU_AuthorityInfoAccessConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &AuthorityInfoAccessConfig{
		OCSP: []string{"http://ocsp.example.com"},
	}
	if cfg.IsCritical() {
		t.Error("AuthorityInfoAccessConfig.IsCritical() should return false when Critical is nil (RFC 5280 MUST be non-critical)")
	}
}

func TestU_AuthorityInfoAccessConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &AuthorityInfoAccessConfig{
		Critical: &critical,
		OCSP:     []string{"http://ocsp.example.com"},
	}
	if !cfg.IsCritical() {
		t.Error("AuthorityInfoAccessConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_AuthorityInfoAccessConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &AuthorityInfoAccessConfig{
		Critical: &critical,
		OCSP:     []string{"http://ocsp.example.com"},
	}
	if cfg.IsCritical() {
		t.Error("AuthorityInfoAccessConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for CertificatePoliciesConfig.IsCritical()
func TestU_CertificatePoliciesConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &CertificatePoliciesConfig{
		Policies: []PolicyConfig{{OID: "1.2.3.4"}},
	}
	if cfg.IsCritical() {
		t.Error("CertificatePoliciesConfig.IsCritical() should return false when Critical is nil (default)")
	}
}

func TestU_CertificatePoliciesConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &CertificatePoliciesConfig{
		Critical: &critical,
		Policies: []PolicyConfig{{OID: "1.2.3.4"}},
	}
	if !cfg.IsCritical() {
		t.Error("CertificatePoliciesConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_CertificatePoliciesConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &CertificatePoliciesConfig{
		Critical: &critical,
		Policies: []PolicyConfig{{OID: "1.2.3.4"}},
	}
	if cfg.IsCritical() {
		t.Error("CertificatePoliciesConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for NameConstraintsConfig.IsCritical()
func TestU_NameConstraintsConfig_IsCritical_DefaultTrue(t *testing.T) {
	cfg := &NameConstraintsConfig{
		Permitted: &NameConstraintsSubtrees{
			DNS: []string{".example.com"},
		},
	}
	if !cfg.IsCritical() {
		t.Error("NameConstraintsConfig.IsCritical() should return true when Critical is nil (RFC 5280 default)")
	}
}

func TestU_NameConstraintsConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &NameConstraintsConfig{
		Critical: &critical,
		Permitted: &NameConstraintsSubtrees{
			DNS: []string{".example.com"},
		},
	}
	if !cfg.IsCritical() {
		t.Error("NameConstraintsConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_NameConstraintsConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &NameConstraintsConfig{
		Critical: &critical,
		Permitted: &NameConstraintsSubtrees{
			DNS: []string{".example.com"},
		},
	}
	if cfg.IsCritical() {
		t.Error("NameConstraintsConfig.IsCritical() should return false when Critical is explicitly false")
	}
}

// Tests for OCSPNoCheckConfig.IsCritical()
func TestU_OCSPNoCheckConfig_IsCritical_DefaultFalse(t *testing.T) {
	cfg := &OCSPNoCheckConfig{}
	if cfg.IsCritical() {
		t.Error("OCSPNoCheckConfig.IsCritical() should return false when Critical is nil (RFC 6960 default)")
	}
}

func TestU_OCSPNoCheckConfig_IsCritical_ExplicitTrue(t *testing.T) {
	critical := true
	cfg := &OCSPNoCheckConfig{Critical: &critical}
	if !cfg.IsCritical() {
		t.Error("OCSPNoCheckConfig.IsCritical() should return true when Critical is explicitly true")
	}
}

func TestU_OCSPNoCheckConfig_IsCritical_ExplicitFalse(t *testing.T) {
	critical := false
	cfg := &OCSPNoCheckConfig{Critical: &critical}
	if cfg.IsCritical() {
		t.Error("OCSPNoCheckConfig.IsCritical() should return false when Critical is explicitly false")
	}
}
