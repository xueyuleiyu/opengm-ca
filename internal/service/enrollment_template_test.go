package service

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/model"
)

func TestBuildCertTemplateDefault(t *testing.T) {
	es := &EnrollmentService{cfg: &config.Config{}}
	ca := &model.CAChain{ValidTo: time.Now().AddDate(0, 0, 60)}

	tmpl, err := es.buildCertTemplate(
		&model.CertificateRequest{CertType: "SSL", ValidityDays: 30},
		&model.Subject{CommonName: "test.example.com", Organization: "TestOrg"},
		ca,
	)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if tmpl.IsCA {
		t.Error("buildCertTemplate() IsCA = true, want false (leaf cert)")
	}
	if tmpl.SerialNumber == nil {
		t.Error("buildCertTemplate() SerialNumber = nil")
	}
	if tmpl.Subject.CommonName != "test.example.com" {
		t.Errorf("buildCertTemplate() CommonName = %q, want test.example.com", tmpl.Subject.CommonName)
	}
	if len(tmpl.Subject.Organization) != 1 || tmpl.Subject.Organization[0] != "TestOrg" {
		t.Errorf("buildCertTemplate() Organization = %v, want [TestOrg]", tmpl.Subject.Organization)
	}
	if want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment; tmpl.KeyUsage != want {
		t.Errorf("buildCertTemplate() KeyUsage = %v, want %v", tmpl.KeyUsage, want)
	}
}

func TestBuildCertTemplateAuthKeyUsage(t *testing.T) {
	es := &EnrollmentService{cfg: &config.Config{}}
	ca := &model.CAChain{ValidTo: time.Now().AddDate(0, 0, 60)}

	tmpl, err := es.buildCertTemplate(
		&model.CertificateRequest{CertType: "AUTH", ValidityDays: 30},
		&model.Subject{CommonName: "auth-cn"},
		ca,
	)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if want := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment; tmpl.KeyUsage != want {
		t.Errorf("buildCertTemplate(AUTH) KeyUsage = %v, want %v", tmpl.KeyUsage, want)
	}
}

func TestBuildCertTemplateValidityClamp(t *testing.T) {
	es := &EnrollmentService{cfg: &config.Config{}}
	now := time.Now()
	ca := &model.CAChain{ValidTo: now.AddDate(0, 0, 1)} // CA 只剩 1 天

	tmpl, err := es.buildCertTemplate(
		&model.CertificateRequest{CertType: "SSL", ValidityDays: 30},
		&model.Subject{CommonName: "cn"},
		ca,
	)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if !tmpl.NotAfter.Equal(ca.ValidTo) {
		t.Errorf("buildCertTemplate() NotAfter = %v, want clamped to CA ValidTo %v", tmpl.NotAfter, ca.ValidTo)
	}
}

func TestBuildCertTemplateSANs(t *testing.T) {
	es := &EnrollmentService{cfg: &config.Config{}}
	ca := &model.CAChain{ValidTo: time.Now().AddDate(0, 0, 60)}

	tmpl, err := es.buildCertTemplate(
		&model.CertificateRequest{
			CertType:     "SSL",
			ValidityDays: 30,
			Extensions: model.CertExtensions{
				SubjectAltNames: []model.SubjectAltName{
					{Type: "dns", Value: "a.example.com"},
					{Type: "ip", Value: "10.0.0.1"},
				},
			},
		},
		&model.Subject{CommonName: "cn"},
		ca,
	)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if len(tmpl.DNSNames) != 1 || tmpl.DNSNames[0] != "a.example.com" {
		t.Errorf("buildCertTemplate() DNSNames = %v, want [a.example.com]", tmpl.DNSNames)
	}
	if len(tmpl.IPAddresses) != 1 || !tmpl.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("buildCertTemplate() IPAddresses = %v, want [10.0.0.1]", tmpl.IPAddresses)
	}
}

func TestBuildCertTemplateWithConfig(t *testing.T) {
	es := &EnrollmentService{
		cfg: &config.Config{
			CertTemplates: map[string]config.CertTemplateConfig{
				"SSL": {
					KeyUsage:    []string{"digitalSignature"},
					ExtKeyUsage: []string{"serverAuth", "clientAuth"},
				},
			},
		},
	}
	ca := &model.CAChain{ValidTo: time.Now().AddDate(0, 0, 60)}

	tmpl, err := es.buildCertTemplate(
		&model.CertificateRequest{CertType: "SSL", ValidityDays: 30},
		&model.Subject{CommonName: "cn"},
		ca,
	)
	if err != nil {
		t.Fatalf("buildCertTemplate() error = %v", err)
	}

	if tmpl.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("buildCertTemplate() KeyUsage = %v, want DigitalSignature only", tmpl.KeyUsage)
	}
	if len(tmpl.ExtKeyUsage) != 2 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("buildCertTemplate() ExtKeyUsage = %v, want [ServerAuth ClientAuth]", tmpl.ExtKeyUsage)
	}
}
