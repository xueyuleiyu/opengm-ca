package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
)

// selfSignedSM2Cert 生成一对SM2密钥并自签名一张证书，返回证书与私钥
func selfSignedSM2Cert(t *testing.T) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成SM2密钥失败: %v", err)
	}
	serial, err := generateSerialNumber()
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-pair-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("自签名证书失败: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return cert, priv
}

// fingerprintOf 独立计算公钥DER的SHA256指纹前16个hex字符，避免测试与实现共享同一处bug
func fingerprintOf(t *testing.T, pub any) string {
	t.Helper()
	der, err := smx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("序列化公钥失败: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

func TestVerifyCertKeyPairMatch(t *testing.T) {
	cert, priv := selfSignedSM2Cert(t)

	certDER, err := smx509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("序列化证书公钥失败: %v", err)
	}
	keyDER, err := smx509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("序列化私钥公钥失败: %v", err)
	}
	if !bytes.Equal(certDER, keyDER) {
		t.Fatal("测试夹具错误：证书公钥与私钥公钥应当配对")
	}

	if err := verifyCertKeyPair(cert, priv); err != nil {
		t.Fatalf("verifyCertKeyPair(配对) error = %v, want nil", err)
	}
}

func TestVerifyCertKeyPairMismatch(t *testing.T) {
	cert, _ := selfSignedSM2Cert(t)
	wrongPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成错误私钥失败: %v", err)
	}

	err = verifyCertKeyPair(cert, wrongPriv)
	if err == nil {
		t.Fatal("verifyCertKeyPair(失配) error = nil, want error")
	}

	certFp := fingerprintOf(t, cert.PublicKey)
	keyFp := fingerprintOf(t, wrongPriv.Public())
	if certFp == keyFp {
		t.Fatalf("测试夹具错误：两侧指纹应当不同，均为 %s", certFp)
	}

	msg := err.Error()
	if !strings.Contains(msg, certFp) {
		t.Errorf("错误文案缺少证书公钥指纹 %s: %s", certFp, msg)
	}
	if !strings.Contains(msg, keyFp) {
		t.Errorf("错误文案缺少私钥公钥指纹 %s: %s", keyFp, msg)
	}
}

func TestVerifyCertKeyPairAlgorithmCross(t *testing.T) {
	cert, _ := selfSignedSM2Cert(t)
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成ECDSA P256密钥失败: %v", err)
	}

	err = verifyCertKeyPair(cert, ecdsaPriv)
	if err == nil {
		t.Fatal("verifyCertKeyPair(SM2证书, ECDSA P256私钥) error = nil, want error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "证书公钥指纹") {
		t.Errorf("跨算法错误文案缺少证书公钥指纹段: %s", msg)
	}
	if !strings.Contains(msg, "私钥公钥指纹") {
		t.Errorf("跨算法错误文案缺少私钥公钥指纹段: %s", msg)
	}
}
