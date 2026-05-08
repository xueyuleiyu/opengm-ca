package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"
	"fmt"
	smx509 "github.com/emmansun/gmsm/smx509"
	"math/big"
	"os"
	"time"

	"github.com/opengm-ca/opengm-ca/internal/config"
	"github.com/opengm-ca/opengm-ca/internal/core"
	"github.com/opengm-ca/opengm-ca/internal/crypto"
	"github.com/opengm-ca/opengm-ca/internal/repository"
)

// keyEncryptorAdapter 适配 crypto.KeyStore 到 core.KeyEncryptor 接口
type keyEncryptorAdapter struct {
	ks *crypto.KeyStore
}

func (a *keyEncryptorAdapter) EncryptPrivateKey(plaintext []byte) (ciphertext, salt, nonce, tag []byte, err error) {
	if a.ks == nil {
		return nil, nil, nil, nil, fmt.Errorf("keystore未初始化")
	}
	return a.ks.EncryptPrivateKey(plaintext)
}

func (a *keyEncryptorAdapter) DecryptPrivateKey(ciphertext, salt, nonce, tag []byte) ([]byte, error) {
	if a.ks == nil {
		return nil, fmt.Errorf("keystore未初始化")
	}
	return a.ks.DecryptPrivateKey(ciphertext, salt, nonce, tag)
}

func main() {
	cfg, err := config.Load("./configs/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	db, err := repository.NewDB(&cfg.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "数据库连接失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	keyStore, err := crypto.NewKeyStore(cfg.KeyManagement.MasterKey.EnvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "主密钥加载失败: %v\n", err)
		os.Exit(1)
	}

	caRepo := repository.NewCAChainRepository(db.DB)
	caEngine := core.NewCAEngine(&cfg.CA)
	keyEncryptor := &keyEncryptorAdapter{ks: keyStore}
	if err := caEngine.LoadFromDB(context.Background(), caRepo, keyEncryptor, "./data/ca_keys"); err != nil {
		fmt.Fprintf(os.Stderr, "CA引擎加载失败: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll("data/certs", 0700); err != nil {
		fmt.Fprintf(os.Stderr, "创建目录失败: %v\n", err)
		os.Exit(1)
	}

	// 1. 生成 OCSP Responder 证书（使用 SSL-CA 签名）
	if err := generateOCSPResponderCert(caEngine, "SSL-CA"); err != nil {
		fmt.Fprintf(os.Stderr, "生成OCSP证书失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ OCSP Responder 证书已生成: data/certs/ocsp_responder.crt")

	// 2. 生成 TLS 服务器证书（使用 SSL-CA 签名）
	if err := generateTLSCert(caEngine, "SSL-CA", "localhost"); err != nil {
		fmt.Fprintf(os.Stderr, "生成TLS证书失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ TLS 服务器证书已生成: data/certs/server.crt")
	fmt.Println("✅ TLS 服务器私钥已生成: data/certs/server.key")

	fmt.Println("\n请在 configs/config.yaml 中更新以下路径:")
	fmt.Println("  ocsp.responder_cert_file: \"data/certs/ocsp_responder.crt\"")
	fmt.Println("  ocsp.responder_key_file:  \"data/certs/ocsp_responder.key\"")
	fmt.Println("  server.tls.cert_file:     \"data/certs/server.crt\"")
	fmt.Println("  server.tls.key_file:      \"data/certs/server.key\"")
}

func generateOCSPResponderCert(caEngine *core.CAEngine, caName string) error {
	caInstance, err := caEngine.GetCA(caName)
	if err != nil {
		return err
	}

	ocspKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "openGM-CA OCSP Responder",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := smx509.CreateCertificate(rand.Reader, template, caInstance.Cert, &ocspKey.PublicKey, caInstance.Signer)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile("data/certs/ocsp_responder.crt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	keyOut, err := os.OpenFile("data/certs/ocsp_responder.key", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(ocspKey)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return nil
}

func generateTLSCert(caEngine *core.CAEngine, caName, commonName string) error {
	caInstance, err := caEngine.GetCA(caName)
	if err != nil {
		return err
	}

	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{commonName, "*." + commonName},
	}

	certBytes, err := smx509.CreateCertificate(rand.Reader, template, caInstance.Cert, &tlsKey.PublicKey, caInstance.Signer)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile("data/certs/server.crt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	keyOut, err := os.OpenFile("data/certs/server.key", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return nil
}
