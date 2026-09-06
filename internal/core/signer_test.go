package core

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		pubKeyAlgo string
		hashAlgo   string
		want       SignatureAlgorithm
	}{
		{"SM2", "", SM2WithSM3},
		{"SM2", "SHA256", SM2WithSM3},
		{"RSA", "SHA256", SHA256WithRSA},
		{"RSA", "SHA384", SHA384WithRSA},
		{"RSA", "SHA512", SHA512WithRSA},
		{"RSA", "UNKNOWN", UnknownSignatureAlgorithm},
		{"EC", "SHA256", ECDSAWithSHA256},
		{"EC", "SHA384", ECDSAWithSHA384},
		{"EC", "SHA512", ECDSAWithSHA512},
		{"EC", "UNKNOWN", UnknownSignatureAlgorithm},
		{"UNKNOWN", "SHA256", UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		if got := GetSignatureAlgorithm(tt.pubKeyAlgo, tt.hashAlgo); got != tt.want {
			t.Errorf("GetSignatureAlgorithm(%q, %q) = %d, want %d", tt.pubKeyAlgo, tt.hashAlgo, got, tt.want)
		}
	}
}

func TestSignerFactoryCreateSigner(t *testing.T) {
	f := NewSignerFactory()

	if _, err := f.CreateSigner("SM2", &rsa.PublicKey{}); err == nil {
		t.Error("CreateSigner(SM2, rsa.PublicKey) = nil error, want type mismatch error")
	}
	if _, err := f.CreateSigner("RSA2048", nil); err == nil {
		t.Error("CreateSigner(RSA2048) = nil error, want unsupported algorithm error")
	}

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	signer, err := f.CreateSigner("SM2", key)
	if err != nil {
		t.Fatalf("CreateSigner(SM2, sm2.PrivateKey) error = %v", err)
	}
	if signer == nil {
		t.Fatal("CreateSigner() returned nil signer")
	}
	if signer.Algorithm() != SM2WithSM3 {
		t.Errorf("signer.Algorithm() = %d, want SM2WithSM3", signer.Algorithm())
	}
}

func TestSM2Signer(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	signer, err := NewSM2Signer(key)
	if err != nil {
		t.Fatalf("NewSM2Signer() error = %v", err)
	}

	if signer.Algorithm() != SM2WithSM3 {
		t.Errorf("Algorithm() = %d, want SM2WithSM3", signer.Algorithm())
	}
	if signer.PublicKey() == nil {
		t.Error("PublicKey() = nil")
	}
	if signer.HashFunc() == nil {
		t.Error("HashFunc() = nil")
	}

	sig, err := signer.Sign([]byte("hello world"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("Sign() returned empty signature")
	}

	dig, err := signer.SignDigest([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}
	if len(dig) == 0 {
		t.Error("SignDigest() returned empty signature")
	}
}

func TestResolveSM2UID(t *testing.T) {
	t.Setenv("CA_SM2_USER_ID", "fixed-uid")
	uid, err := resolveSM2UID()
	if err != nil {
		t.Fatalf("resolveSM2UID() error = %v", err)
	}
	if string(uid) != "fixed-uid" {
		t.Errorf("resolveSM2UID() = %q, want fixed-uid", uid)
	}

	t.Setenv("CA_SM2_USER_ID", "")
	uid, err = resolveSM2UID()
	if err != nil {
		t.Fatalf("resolveSM2UID(random) error = %v", err)
	}
	if len(uid) != 16 {
		t.Errorf("resolveSM2UID(random) length = %d, want 16", len(uid))
	}
}
