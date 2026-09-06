package core

import (
	crand "crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	opengmcrypto "github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/model"
)

func TestGenerateKeyID(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  interface{}
		wantErr bool
	}{
		{"SM2", func() interface{} {
			k, _ := sm2.GenerateKey(crand.Reader)
			return &k.PublicKey
		}(), false},
		{"RSA", func() interface{} {
			k, _ := rsa.GenerateKey(crand.Reader, 2048)
			return &k.PublicKey
		}(), false},
		{"ECDSA", func() interface{} {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
			return &k.PublicKey
		}(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := GenerateKeyID(tt.pubKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateKeyID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(keyID) != 20 {
				t.Errorf("GenerateKeyID() length = %d, want 20 (RFC 5280)", len(keyID))
			}
		})
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sn, err := generateSerialNumber()
		if err != nil {
			t.Fatalf("generateSerialNumber() error = %v", err)
		}
		if sn.Sign() <= 0 {
			t.Errorf("generateSerialNumber() got non-positive: %v", sn)
		}
		hex := sn.Text(16)
		if seen[hex] {
			t.Errorf("generateSerialNumber() collision at iteration %d: %s", i, hex)
		}
		seen[hex] = true
		// 128-bit serial should have at most 32 hex chars
		if len(hex) > 32 {
			t.Errorf("generateSerialNumber() too large: %d hex chars", len(hex))
		}
	}
}

func TestPemEncode(t *testing.T) {
	data := []byte("test certificate data")
	result := opengmcrypto.PemEncode(data, "CERTIFICATE")
	block, _ := pem.Decode([]byte(result))
	if block == nil {
		t.Fatal("PemEncode() produced invalid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PemEncode() type = %s, want CERTIFICATE", block.Type)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	gen := opengmcrypto.NewKeyGenerator()
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"SM2", "SM2", false},
		{"RSA2048", "RSA2048", false},
		{"RSA4096", "RSA4096", false},
		{"EC256", "EC256", false},
		{"EC384", "EC384", false},
		{"invalid", "INVALID", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub, err := gen.GenerateKeyPair(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if priv == nil || pub == nil {
					t.Error("GenerateKeyPair() returned nil keys")
				}
			}
		})
	}
}

func TestBuildCertTemplate(t *testing.T) {
	req := &model.CertificateRequest{
		CertType:     "SSL",
		Algorithm:    "SM2",
		ValidityDays: 365,
		Subject: model.SubjectInfo{
			CommonName:         "test.example.com",
			Organization:       "TestOrg",
			Country:            "CN",
			OrganizationalUnit: "IT",
			State:              "Beijing",
			Locality:           "Haidian",
		},
		Extensions: model.CertExtensions{
			KeyUsage:    []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsage: []string{"serverAuth", "clientAuth"},
			SubjectAltNames: []model.SubjectAltName{
				{Type: "dns", Value: "test.example.com"},
				{Type: "dns", Value: "www.example.com"},
			},
		},
	}

	tmpl, err := buildCertTemplate(req)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if tmpl.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %s, want test.example.com", tmpl.Subject.CommonName)
	}
	if tmpl.Subject.Organization[0] != "TestOrg" {
		t.Errorf("Organization = %v", tmpl.Subject.Organization)
	}
	if tmpl.Subject.Country[0] != "CN" {
		t.Errorf("Country = %v", tmpl.Subject.Country)
	}
	if tmpl.IsCA {
		t.Error("IsCA should be false for end-entity cert")
	}
	if tmpl.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage missing digitalSignature")
	}
	if len(tmpl.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage length = %d, want 2", len(tmpl.ExtKeyUsage))
	}
	// DNSNames are set by the service layer, not the core template builder
	if tmpl.SerialNumber == nil {
		t.Error("SerialNumber is nil")
	}
	if tmpl.NotAfter.Before(tmpl.NotBefore) {
		t.Error("NotAfter before NotBefore")
	}
}

func TestBuildCertTemplateMinimal(t *testing.T) {
	req := &model.CertificateRequest{
		CertType:     "AUTH",
		Algorithm:    "SM2",
		ValidityDays: 30,
		Subject: model.SubjectInfo{
			CommonName: "user@example.com",
		},
	}

	tmpl, err := buildCertTemplate(req)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}
	if tmpl.Subject.CommonName != "user@example.com" {
		t.Errorf("CommonName = %s", tmpl.Subject.CommonName)
	}
	if len(tmpl.DNSNames) != 0 {
		t.Errorf("DNSNames should be empty, got %v", tmpl.DNSNames)
	}
}
