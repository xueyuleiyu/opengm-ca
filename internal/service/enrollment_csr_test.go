package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
)

func generateTestCSR(t *testing.T, commonName string, org []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: org,
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestParseCSR(t *testing.T) {
	t.Run("valid rsa csr", func(t *testing.T) {
		csrPEM := generateTestCSR(t, "test.example.com", []string{"TestOrg"})
		pubKey, subject, err := (&EnrollmentService{}).parseCSR(csrPEM)
		if err != nil {
			t.Fatalf("parseCSR() error = %v", err)
		}
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			t.Fatalf("parseCSR() public key type = %T, want *rsa.PublicKey", pubKey)
		}
		if subject.CommonName != "test.example.com" {
			t.Errorf("parseCSR() CommonName = %q, want test.example.com", subject.CommonName)
		}
		if subject.Organization != "TestOrg" {
			t.Errorf("parseCSR() Organization = %q, want TestOrg", subject.Organization)
		}
	})

	t.Run("malformed pem", func(t *testing.T) {
		_, _, err := (&EnrollmentService{}).parseCSR("not-a-pem")
		if err == nil || err.Error() != "无效的CSR PEM格式" {
			t.Fatalf("parseCSR(malformed) error = %v, want 无效的CSR PEM格式", err)
		}
	})

	t.Run("empty csr", func(t *testing.T) {
		_, _, err := (&EnrollmentService{}).parseCSR("")
		if err == nil || err.Error() != "无效的CSR PEM格式" {
			t.Fatalf("parseCSR(empty) error = %v, want 无效的CSR PEM格式", err)
		}
	})

	t.Run("valid pem but not csr", func(t *testing.T) {
		garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}))
		_, _, err := (&EnrollmentService{}).parseCSR(garbage)
		if err == nil || !strings.Contains(err.Error(), "解析CSR失败") {
			t.Fatalf("parseCSR(garbage) error = %v, want 解析CSR失败", err)
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		csrPEM := generateTestCSR(t, "test.example.com", nil)
		block, _ := pem.Decode([]byte(csrPEM))
		der := make([]byte, len(block.Bytes))
		copy(der, block.Bytes)
		der[len(der)-1] ^= 0xFF // 篡改签名区最后一个字节
		tampered := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

		_, _, err := (&EnrollmentService{}).parseCSR(tampered)
		if err == nil || !strings.Contains(err.Error(), "CSR签名验证失败") {
			t.Fatalf("parseCSR(tampered) error = %v, want CSR签名验证失败", err)
		}
	})
}

func TestExtractSubjectFromCSR(t *testing.T) {
	subj := pkix.Name{
		CommonName:         "cn",
		Organization:       []string{"org1", "org2"},
		OrganizationalUnit: []string{"ou1"},
		Country:            []string{"CN"},
		Province:           []string{"state"},
		Locality:           []string{"city"},
	}

	got := extractSubjectFromCSR(subj, nil)

	if got.CommonName != "cn" {
		t.Errorf("CommonName = %q, want cn", got.CommonName)
	}
	if got.Organization != "org1" {
		t.Errorf("Organization = %q, want org1 (first)", got.Organization)
	}
	if got.OrganizationalUnit != "ou1" {
		t.Errorf("OrganizationalUnit = %q, want ou1", got.OrganizationalUnit)
	}
	if got.Country != "CN" {
		t.Errorf("Country = %q, want CN", got.Country)
	}
	if got.State != "state" {
		t.Errorf("State = %q, want state", got.State)
	}
	if got.Locality != "city" {
		t.Errorf("Locality = %q, want city", got.Locality)
	}
}

func TestExtractSubjectFromCSREmpty(t *testing.T) {
	got := extractSubjectFromCSR(pkix.Name{}, nil)
	if got.CommonName != "" || got.Organization != "" || got.Country != "" {
		t.Fatalf("extractSubjectFromCSR(empty) = %+v, want all empty", got)
	}
}

func TestValidateRequest(t *testing.T) {
	baseCfg := func() *config.Config {
		return &config.Config{
			CertPolicy: config.CertPolicyConfig{
				MaxValidityDays:   365,
				AllowedAlgorithms: []string{"SM2", "RSA2048", "RSA4096", "EC256", "EC384"},
			},
		}
	}

	tests := []struct {
		name    string
		cfg     *config.Config
		req     *model.CertificateRequest
		wantErr string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			req:     &model.CertificateRequest{},
			wantErr: "服务配置未初始化",
		},
		{
			name: "validity zero",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 0,
				Subject:      model.SubjectInfo{CommonName: "cn"},
			},
			wantErr: "有效期必须在1-365天之间",
		},
		{
			name: "validity over max",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 366,
				Subject:      model.SubjectInfo{CommonName: "cn"},
			},
			wantErr: "有效期必须在1-365天之间",
		},
		{
			name: "unsupported algorithm",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "FOO",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{CommonName: "cn"},
			},
			wantErr: "不支持的算法: FOO",
		},
		{
			name: "missing common name",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{},
			},
			wantErr: "缺少证书主题CommonName",
		},
		{
			name: "subject control char",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{CommonName: "bad\ncn"},
			},
			wantErr: "主题字段非法",
		},
		{
			name: "dns san newline",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{CommonName: "cn"},
				Extensions: model.CertExtensions{
					SubjectAltNames: []model.SubjectAltName{{Type: "dns", Value: "bad\nname"}},
				},
			},
			wantErr: "DNS SAN包含非法字符",
		},
		{
			name: "invalid ip san",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{CommonName: "cn"},
				Extensions: model.CertExtensions{
					SubjectAltNames: []model.SubjectAltName{{Type: "ip", Value: "not-an-ip"}},
				},
			},
			wantErr: "IP SAN格式无效",
		},
		{
			name: "valid request",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				Algorithm:    "RSA2048",
				ValidityDays: 30,
				Subject:      model.SubjectInfo{CommonName: "cn"},
			},
			wantErr: "",
		},
		{
			name: "valid request with csr and empty subject",
			cfg:  baseCfg(),
			req: &model.CertificateRequest{
				CertType:     "SSL",
				ValidityDays: 30,
				CSRPEM:       generateTestCSR(t, "csr-cn", nil),
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := &EnrollmentService{cfg: tt.cfg}
			err := es.validateRequest(tt.req)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRequest() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRequest() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRequest() error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEncodePrivateKey(t *testing.T) {
	es := &EnrollmentService{}

	t.Run("rsa", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pemStr, err := es.encodePrivateKey(key, "RSA2048")
		if err != nil {
			t.Fatalf("encodePrivateKey(rsa) error = %v", err)
		}
		if !strings.HasPrefix(pemStr, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Fatalf("encodePrivateKey(rsa) = %q, want RSA PRIVATE KEY PEM", pemStr[:64])
		}
	})

	t.Run("ecdsa", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pemStr, err := es.encodePrivateKey(key, "EC256")
		if err != nil {
			t.Fatalf("encodePrivateKey(ec) error = %v", err)
		}
		if !strings.HasPrefix(pemStr, "-----BEGIN EC PRIVATE KEY-----") {
			t.Fatalf("encodePrivateKey(ec) = %q, want EC PRIVATE KEY PEM", pemStr[:64])
		}
	})

	t.Run("sm2", func(t *testing.T) {
		key, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pemStr, err := es.encodePrivateKey(key, "SM2")
		if err != nil {
			t.Fatalf("encodePrivateKey(sm2) error = %v", err)
		}
		if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
			t.Fatalf("encodePrivateKey(sm2) = %q, want PKCS#8 PRIVATE KEY PEM", pemStr[:64])
		}
	})

	t.Run("unknown algorithm falls back to pkcs8", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pemStr, err := es.encodePrivateKey(key, "UNKNOWN")
		if err != nil {
			t.Fatalf("encodePrivateKey(unknown) error = %v", err)
		}
		if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
			t.Fatalf("encodePrivateKey(unknown) = %q, want PKCS#8 PRIVATE KEY PEM", pemStr[:64])
		}
	})
}
