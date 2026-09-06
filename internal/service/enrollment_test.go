package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/opengm-ca/opengm-ca/internal/model"
)

func TestSanitizeSubject(t *testing.T) {
	tests := []struct {
		name    string
		subject model.SubjectInfo
		wantErr bool
	}{
		{
			name:    "clean",
			subject: model.SubjectInfo{CommonName: "test.example.com", Organization: "TestOrg", Country: "CN"},
			wantErr: false,
		},
		{
			name:    "null byte in CN",
			subject: model.SubjectInfo{CommonName: "bad\x00name"},
			wantErr: true,
		},
		{
			name:    "newline in Org",
			subject: model.SubjectInfo{CommonName: "ok", Organization: "bad\norg"},
			wantErr: true,
		},
		{
			name:    "carriage return in CN",
			subject: model.SubjectInfo{CommonName: "bad\rcn"},
			wantErr: true,
		},
		{
			name:    "DEL in locality",
			subject: model.SubjectInfo{CommonName: "ok", Locality: "bad\x7f"},
			wantErr: true,
		},
		{
			name:    "all fields ok",
			subject: model.SubjectInfo{CommonName: "cn", Organization: "org", OrganizationalUnit: "ou", Country: "CN", State: "state", Locality: "city"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sanitizeSubject(&tt.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeSubject() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSelectCA(t *testing.T) {
	es := &EnrollmentService{}
	tests := []struct {
		certType string
		wantCA   string
		wantErr  bool
	}{
		{"SSL", "SSL-CA", false},
		{"AUTH", "AUTH-CA", false},
		{"VPN", "VPN-CA", false},
		{"VPN_SIGN", "VPN-CA", false},
		{"VPN_ENC", "VPN-CA", false},
		{"INVALID", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.certType, func(t *testing.T) {
			ca, err := es.selectCA(tt.certType)
			if (err != nil) != tt.wantErr {
				t.Errorf("selectCA(%s) error = %v, wantErr %v", tt.certType, err, tt.wantErr)
			}
			if ca != tt.wantCA {
				t.Errorf("selectCA(%s) = %s, want %s", tt.certType, ca, tt.wantCA)
			}
		})
	}
}

func TestFirstOrEmpty(t *testing.T) {
	if got := firstOrEmpty(nil); got != "" {
		t.Errorf("firstOrEmpty(nil) = %q", got)
	}
	if got := firstOrEmpty([]string{}); got != "" {
		t.Errorf("firstOrEmpty(empty) = %q", got)
	}
	if got := firstOrEmpty([]string{"a", "b"}); got != "a" {
		t.Errorf("firstOrEmpty([a,b]) = %q", got)
	}
}

func TestValidatePublicKeyStrength(t *testing.T) {
	tests := []struct {
		name      string
		pubKey    interface{}
		algorithm string
		wantErr   bool
	}{
		{
			name: "RSA 2048 ok",
			pubKey: func() interface{} {
				k, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &k.PublicKey
			}(),
			algorithm: "RSA2048",
			wantErr:   false,
		},
		{
			name: "RSA 1024 too weak",
			pubKey: func() interface{} {
				k, _ := rsa.GenerateKey(rand.Reader, 1024)
				return &k.PublicKey
			}(),
			algorithm: "RSA2048",
			wantErr:   true,
		},
		{
			name: "SM2 ok",
			pubKey: func() interface{} {
				k, _ := sm2.GenerateKey(rand.Reader)
				return &k.PublicKey
			}(),
			algorithm: "SM2",
			wantErr:   false,
		},
		{
			name: "ECDSA P256 ok",
			pubKey: func() interface{} {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &k.PublicKey
			}(),
			algorithm: "EC256",
			wantErr:   false,
		},
		{
			name: "SM2 key with RSA algorithm",
			pubKey: func() interface{} {
				k, _ := sm2.GenerateKey(rand.Reader)
				return &k.PublicKey
			}(),
			algorithm: "RSA2048",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublicKeyStrength(tt.pubKey, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePublicKeyStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMapPublicKeyAlgorithm(t *testing.T) {
	es := &EnrollmentService{}
	tests := []struct {
		algo string
		want model.PublicKeyAlgorithm
	}{
		{"SM2", model.PubKeySM2},
		{"RSA2048", model.PubKeyRSA},
		{"RSA4096", model.PubKeyRSA},
		{"EC256", model.PubKeyEC},
		{"EC384", model.PubKeyEC},
		{"UNKNOWN", model.PubKeySM2},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := es.mapPublicKeyAlgorithm(tt.algo)
			if got != tt.want {
				t.Errorf("mapPublicKeyAlgorithm(%s) = %s, want %s", tt.algo, got, tt.want)
			}
		})
	}
}
