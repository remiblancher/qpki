package pki

import (
	"testing"
)

// =============================================================================
// RevocationReason.String Tests
// =============================================================================

func TestU_RevocationReason_String(t *testing.T) {
	tests := []struct {
		reason   RevocationReason
		expected string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "cACompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonRemoveFromCRL, "removeFromCRL"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ReasonAACompromise, "aACompromise"},
	}

	for _, tt := range tests {
		t.Run("[Unit] RevocationReason.String: "+tt.expected, func(t *testing.T) {
			result := tt.reason.String()
			if result != tt.expected {
				t.Errorf("RevocationReason(%d).String() = %s, want %s", tt.reason, result, tt.expected)
			}
		})
	}

	t.Run("[Unit] RevocationReason.String: unknown reason", func(t *testing.T) {
		result := RevocationReason(99).String()
		if result != "unknown" {
			t.Errorf("RevocationReason(99).String() = %s, want unknown", result)
		}
	})

	t.Run("[Unit] RevocationReason.String: negative reason", func(t *testing.T) {
		result := RevocationReason(-1).String()
		if result != "unknown" {
			t.Errorf("RevocationReason(-1).String() = %s, want unknown", result)
		}
	})
}

// =============================================================================
// Algorithm Constants Tests
// =============================================================================

func TestU_AlgorithmConstants(t *testing.T) {
	t.Run("[Unit] AlgorithmConstants: classical algorithms are defined", func(t *testing.T) {
		algorithms := []Algorithm{
			AlgRSA2048,
			AlgRSA3072,
			AlgRSA4096,
			AlgECDSAP256,
			AlgECDSAP384,
			AlgECDSAP521,
			AlgEd25519,
			AlgEd448,
		}

		for _, alg := range algorithms {
			if alg == "" {
				t.Errorf("Algorithm constant is empty")
			}
		}
	})

	t.Run("[Unit] AlgorithmConstants: PQC algorithms are defined", func(t *testing.T) {
		algorithms := []Algorithm{
			AlgMLDSA44,
			AlgMLDSA65,
			AlgMLDSA87,
			AlgSLHDSASHA2128s,
			AlgSLHDSASHA2128f,
			AlgSLHDSASHA2192s,
			AlgSLHDSASHA2192f,
			AlgSLHDSASHA2256s,
			AlgSLHDSASHA2256f,
		}

		for _, alg := range algorithms {
			if alg == "" {
				t.Errorf("Algorithm constant is empty")
			}
		}
	})
}

// =============================================================================
// ProfileMode Constants Tests
// =============================================================================

func TestU_ProfileModeConstants(t *testing.T) {
	t.Run("[Unit] ProfileModeConstants: are defined", func(t *testing.T) {
		modes := []ProfileMode{
			ModeSimple,
			ModeCatalyst,
			ModeComposite,
		}

		for _, mode := range modes {
			if mode == "" {
				t.Errorf("ProfileMode constant is empty")
			}
		}
	})
}

// =============================================================================
// AuditEventType Constants Tests
// =============================================================================

func TestU_AuditEventTypeConstants(t *testing.T) {
	t.Run("[Unit] AuditEventTypeConstants: are defined", func(t *testing.T) {
		eventTypes := []AuditEventType{
			EventCertIssued,
			EventCertRevoked,
			EventCRLGenerated,
			EventCAInitialized,
			EventCARotated,
			EventKeyGenerated,
		}

		for _, et := range eventTypes {
			if et == "" {
				t.Errorf("AuditEventType constant is empty")
			}
		}
	})
}

// =============================================================================
// Type Instantiation Tests
// =============================================================================

func TestU_TypesInstantiation(t *testing.T) {
	t.Run("[Unit] RevokedCertificate: can be instantiated", func(t *testing.T) {
		rc := &RevokedCertificate{
			Serial: []byte{1, 2, 3},
			Reason: ReasonKeyCompromise,
		}
		if rc.Reason != ReasonKeyCompromise {
			t.Error("RevokedCertificate.Reason mismatch")
		}
	})

	t.Run("[Unit] CertificateFilter: can be instantiated", func(t *testing.T) {
		filter := &CertificateFilter{
			Subject:    "test",
			NotExpired: true,
			NotRevoked: true,
			Limit:      10,
		}
		if filter.Limit != 10 {
			t.Error("CertificateFilter.Limit mismatch")
		}
	})

	t.Run("[Unit] SubjectTemplate: can be instantiated", func(t *testing.T) {
		st := &SubjectTemplate{
			CommonName:   "Test",
			Organization: []string{"Org"},
		}
		if st.CommonName != "Test" {
			t.Error("SubjectTemplate.CommonName mismatch")
		}
	})

	t.Run("[Unit] ExtensionSet: can be instantiated", func(t *testing.T) {
		es := &ExtensionSet{
			KeyUsage: []string{"digitalSignature"},
		}
		if len(es.KeyUsage) != 1 {
			t.Error("ExtensionSet.KeyUsage length mismatch")
		}
	})

	t.Run("[Unit] BasicConstraints: can be instantiated", func(t *testing.T) {
		bc := &BasicConstraints{
			IsCA:       true,
			MaxPathLen: 1,
		}
		if !bc.IsCA {
			t.Error("BasicConstraints.IsCA should be true")
		}
	})

	t.Run("[Unit] SubjectAltName: can be instantiated", func(t *testing.T) {
		san := &SubjectAltName{
			DNSNames: []string{"example.com"},
		}
		if len(san.DNSNames) != 1 {
			t.Error("SubjectAltName.DNSNames length mismatch")
		}
	})

	t.Run("[Unit] VariableDefinition: can be instantiated", func(t *testing.T) {
		vd := &VariableDefinition{
			Type:     "string",
			Required: true,
		}
		if !vd.Required {
			t.Error("VariableDefinition.Required should be true")
		}
	})

	t.Run("[Unit] AuditEvent: can be instantiated", func(t *testing.T) {
		ae := &AuditEvent{
			EventType: EventCertIssued,
			Action:    "issue",
		}
		if ae.EventType != EventCertIssued {
			t.Error("AuditEvent.EventType mismatch")
		}
	})
}
