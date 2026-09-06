package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestAddGMExtensions(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	gmExt := &GMExtension{
		EnableIdentityExtension: true,
		IdentityValue:           "test-identity",
		EnableGMExtension:       true,
		GMExtensionValue:        "custom-gm-value",
	}

	beforeCount := len(tmpl.ExtraExtensions)
	if err := AddGMExtensions(tmpl, gmExt); err != nil {
		t.Fatalf("AddGMExtensions() error = %v", err)
	}
	if len(tmpl.ExtraExtensions) != beforeCount+2 {
		t.Errorf("ExtraExtensions count = %d, want %d", len(tmpl.ExtraExtensions), beforeCount+2)
	}
}

func TestAddGMExtensionsNil(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
	}
	if err := AddGMExtensions(tmpl, nil); err != nil {
		t.Errorf("AddGMExtensions(nil) should not error: %v", err)
	}
}

func TestAddGMExtensionsDefaultIdentity(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "auto-identity.example.com",
		},
	}
	gmExt := &GMExtension{
		EnableIdentityExtension: true,
		// IdentityValue empty – should default to CommonName
	}
	if err := AddGMExtensions(tmpl, gmExt); err != nil {
		t.Fatalf("AddGMExtensions() error = %v", err)
	}
}

func TestAddCRLDistributionPoints(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "test"},
	}

	dp := &CRLDistributionPoint{URI: "http://ca.example.com/crl/test.crl"}
	if err := AddCRLDistributionPoints(tmpl, dp); err != nil {
		t.Fatalf("AddCRLDistributionPoints() error = %v", err)
	}
	if len(tmpl.ExtraExtensions) != 1 {
		t.Errorf("ExtraExtensions count = %d, want 1", len(tmpl.ExtraExtensions))
	}
}

func TestAddCRLDistributionPointsNil(t *testing.T) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5)}
	if err := AddCRLDistributionPoints(tmpl, nil); err != nil {
		t.Errorf("AddCRLDistributionPoints(nil) should not error: %v", err)
	}
}

func TestAddCRLDistributionPointsEmptyURI(t *testing.T) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(6)}
	dp := &CRLDistributionPoint{URI: ""}
	if err := AddCRLDistributionPoints(tmpl, dp); err != nil {
		t.Errorf("AddCRLDistributionPoints(empty) should not error: %v", err)
	}
}

func TestGenerateIdentityValue(t *testing.T) {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test-cn",
			Organization: []string{"TestOrg"},
			Country:      []string{"CN"},
		},
	}

	id := GenerateIdentityValue(tmpl)
	if id == "" {
		t.Error("GenerateIdentityValue() returned empty string")
	}
	if len(id) == 0 {
		t.Error("GenerateIdentityValue() returned empty")
	}
}

func TestGenerateIdentityValueEmpty(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
	}
	id := GenerateIdentityValue(tmpl)
	if id == "" {
		t.Error("GenerateIdentityValue() should fallback to serial number")
	}
}

func TestAddNetscapeCertType(t *testing.T) {
	tests := []struct {
		name     string
		certType string
		wantErr  bool
	}{
		{"SSL Client", "SSL Client", false},
		{"SSL Server", "SSL Server", false},
		{"S/MIME", "S/MIME", false},
		{"Object Signing", "Object Signing", false},
		{"empty", "", false},
		{"unknown defaults", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(7)}
			err := AddNetscapeCertType(tmpl, tt.certType)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddNetscapeCertType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnhanceCertificateWithGMExtensions(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject: pkix.Name{
			CommonName:   "gm-test",
			Organization: []string{"Org"},
			Country:      []string{"CN"},
		},
	}
	if err := EnhanceCertificateWithGMExtensions(tmpl, "SSL Server", "http://crl.example.com/test.crl"); err != nil {
		t.Fatalf("EnhanceCertificateWithGMExtensions() error = %v", err)
	}
	if len(tmpl.ExtraExtensions) < 1 {
		t.Error("ExtraExtensions should have been added")
	}
}
