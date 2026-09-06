package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
)

func TestParseKeyUsage(t *testing.T) {
	tests := []struct {
		name    string
		usages  []string
		want    x509.KeyUsage
		wantErr bool
	}{
		{"single", []string{"digitalSignature"}, x509.KeyUsageDigitalSignature, false},
		{"multiple", []string{"digitalSignature", "keyEncipherment"}, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, false},
		{"all CA", []string{"certSign", "crlSign"}, x509.KeyUsageCertSign | x509.KeyUsageCRLSign, false},
		{"with alias", []string{"nonRepudiation"}, x509.KeyUsageContentCommitment, false},
		{"empty", []string{}, 0, false},
		{"whitespace skip", []string{" digitalSignature "}, x509.KeyUsageDigitalSignature, false},
		{"unknown", []string{"unknownUsage"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyUsage(tt.usages)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("ParseKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	tests := []struct {
		name    string
		usages  []string
		wantLen int
		wantErr bool
	}{
		{"serverAuth", []string{"serverAuth"}, 1, false},
		{"dual", []string{"serverAuth", "clientAuth"}, 2, false},
		{"empty", []string{}, 0, false},
		{"unknown", []string{"unknownEKU"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExtKeyUsage(tt.usages)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseExtKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(got) != tt.wantLen {
				t.Errorf("ParseExtKeyUsage() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestApplyCertTemplate(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	cfg := config.CertTemplateConfig{
		KeyUsage:    []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsage: []string{"serverAuth", "clientAuth"},
	}

	if err := ApplyCertTemplate(tmpl, cfg); err != nil {
		t.Fatalf("ApplyCertTemplate() error = %v", err)
	}
	if tmpl.KeyUsage == 0 {
		t.Error("KeyUsage not set")
	}
	if len(tmpl.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage len = %d, want 2", len(tmpl.ExtKeyUsage))
	}
}

func TestApplyCertTemplateEmpty(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
	}

	cfg := config.CertTemplateConfig{}

	if err := ApplyCertTemplate(tmpl, cfg); err != nil {
		t.Fatalf("ApplyCertTemplate() error = %v", err)
	}
	// empty config should not change template
	if tmpl.KeyUsage != 0 {
		t.Error("KeyUsage should be 0 for empty config")
	}
}
